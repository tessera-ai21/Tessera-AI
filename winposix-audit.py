#!/usr/bin/env python3
"""
winposix-audit.py -- read-only audit of Windows/POSIX boundary failure modes.

Companion tool for the field guide at:
    https://tessera-ai21.github.io/Tessera-AI/

WHAT THIS SCRIPT DOES
    It inspects your machine's environment and (optionally) a git repository
    and reports which of the failure modes documented on that page you are
    currently exposed to: line-ending mangling (core.autocrlf), missing
    .gitattributes, lost executable bits (core.filemode), symlinks silently
    turning into copies, Developer Mode / long-path registry settings,
    case-insensitive filesystem collisions, PATH shadowing between multiple
    Python/Node/git installs, and MSYS/Git-Bash path mangling.

WHAT THIS SCRIPT DOES NOT DO
    It never writes to, modifies, or deletes anything in the target
    repository or anywhere else on disk. It never touches the Windows
    registry (registry keys are opened strictly KEY_READ, never written).
    It never modifies git config. It makes no network connections.
    The ONLY filesystem writes it ever performs are small, throwaway probe
    files inside a fresh directory created by tempfile.mkdtemp() (a
    location the OS reserves for temporary files), and that directory is
    always removed before the script exits. Pass --no-probe to skip those
    probes entirely and run with zero writes anywhere, including temp.

Run "python winposix-audit.py --help" for usage.
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_NAME = "winposix-audit"
TOOL_VERSION = "0.1.0"
BASE_URL = "https://tessera-ai21.github.io/Tessera-AI/"

# Severity display/grouping order for the text report and for the summary.
SEVERITY_ORDER = ["HIGH", "MEDIUM", "INFO", "UNKNOWN", "OK"]

# Fixed list of executable names scanned for PATH shadowing (check 8).
PATH_SHADOW_NAMES = [
    "python", "python3", "pip", "pip3", "bash", "sh",
    "git", "node", "npm", "npx", "make",
]

SUBPROCESS_TIMEOUT = 8  # seconds, generous for a local `git config` call


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

class CmdResult:
    """Result of attempting to run an external command."""

    def __init__(self, ok, returncode=None, stdout="", stderr="", error=None):
        self.ok = ok                # True if the process was launched at all
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error          # human-readable reason when ok is False


def run_cmd(args, cwd=None, timeout=SUBPROCESS_TIMEOUT):
    """Run a command safely. Never raises. Always returns a CmdResult.

    Uses a list argv (no shell), captures output as text, and enforces a
    timeout so a hung subprocess can never hang the audit.
    """
    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CmdResult(True, proc.returncode, proc.stdout, proc.stderr, None)
    except FileNotFoundError:
        return CmdResult(False, error="executable not found: %s" % args[0])
    except subprocess.TimeoutExpired:
        return CmdResult(False, error="command timed out after %ss" % timeout)
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return CmdResult(False, error="%s: %s" % (type(exc).__name__, exc))


def new_finding(check_id, title, severity, observed, means, do, anchor=None):
    """Build a finding dict in the shared shape used throughout."""
    if isinstance(observed, str):
        observed = [observed]
    url = BASE_URL + ("#" + anchor if anchor else "")
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "observed": list(observed),
        "means": means,
        "do": do,
        "url": url,
    }


def unknown_finding(check_id, title, reason, anchor=None):
    return new_finding(
        check_id, title, "UNKNOWN",
        observed=["could not complete this check"],
        means="The check itself failed, so no conclusion could be drawn.",
        do="Reason: %s" % reason,
        anchor=anchor,
    )


def safe_check(func):
    """Decorator: guarantee a check function never raises. On any unhandled
    exception, downgrade the result to an UNKNOWN finding carrying the
    exception message, instead of crashing the whole audit."""
    def wrapper(*args, **kwargs):
        check_id = kwargs.get("check_id") or (args[0] if args else "unknown")
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - defensive catch-all
            return unknown_finding(
                check_id,
                title=check_id,
                reason="unexpected error: %s: %s" % (type(exc).__name__, exc),
            )
    return wrapper


def git_config_get(cwd, key):
    """Return (value_or_None, error_or_None) for a single git config key.

    value is None and error is None when the key is simply unset.
    """
    result = run_cmd(["git", "config", "--get", key], cwd=cwd)
    if not result.ok:
        return None, result.error
    if result.returncode == 0:
        return result.stdout.strip(), None
    if result.returncode == 1:
        return None, None  # key not set -- not an error
    return None, (result.stderr.strip() or "git config exited %s" % result.returncode)


def git_config_show_origin_all(cwd, key):
    """Return (lines, error) for --show-origin --show-scope --get-all."""
    result = run_cmd(
        ["git", "config", "--show-origin", "--show-scope", "--get-all", key],
        cwd=cwd,
    )
    if not result.ok:
        return [], result.error
    if result.returncode == 0:
        return [ln for ln in result.stdout.splitlines() if ln.strip()], None
    if result.returncode == 1:
        return [], None  # unset in all scopes
    return [], (result.stderr.strip() or "git config exited %s" % result.returncode)


# ---------------------------------------------------------------------------
# Repository context
# ---------------------------------------------------------------------------

class RepoContext:
    """Everything the checks need to know about the target and git."""

    def __init__(self, target):
        self.target = target
        self.git_installed = True
        self.is_repo = False
        self.repo_root = target  # best-effort fallback for plain file checks

        probe = run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=target)
        if not probe.ok:
            # Either git isn't installed, or the command otherwise couldn't run.
            self.git_installed = "not found" not in (probe.error or "")
            self.is_repo = False
            return

        self.is_repo = (probe.returncode == 0 and probe.stdout.strip() == "true")
        if self.is_repo:
            top = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=target)
            if top.ok and top.returncode == 0 and top.stdout.strip():
                # Normalize to the OS's native separators for display/use.
                self.repo_root = os.path.normpath(top.stdout.strip())


# ---------------------------------------------------------------------------
# Checks 1-3: git config / .gitattributes
# ---------------------------------------------------------------------------

def has_text_auto_declaration(gitattributes_path):
    """Best-effort check for a '* text=auto'-style declaration.

    Returns (present_file, has_declaration).
    """
    if not os.path.isfile(gitattributes_path):
        return False, False
    try:
        with open(gitattributes_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return True, False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if tokens and tokens[0] == "*":
            for tok in tokens[1:]:
                if tok in ("text=auto", "text"):
                    return True, True
    return True, False


@safe_check
def check_autocrlf(ctx, check_id="autocrlf"):
    title = "core.autocrlf line-ending translation"
    anchor = "autocrlf"
    if not ctx.git_installed:
        return unknown_finding(check_id, title, "git executable not found on PATH", anchor)
    if not ctx.is_repo:
        return new_finding(
            check_id, title, "INFO",
            observed=["target is not inside a git work tree -- skipped"],
            means="This check only applies inside a git repository.",
            do="Run the audit against a path that is inside a git clone.",
            anchor=anchor,
        )

    effective, err = git_config_get(ctx.repo_root, "core.autocrlf")
    scoped_lines, _ = git_config_show_origin_all(ctx.repo_root, "core.autocrlf")
    if err:
        return unknown_finding(check_id, title, err, anchor)

    gitattributes_path = os.path.join(ctx.repo_root, ".gitattributes")
    _, declared = has_text_auto_declaration(gitattributes_path)

    observed = ["effective core.autocrlf = %s" % (effective if effective else "(unset)")]
    if scoped_lines:
        observed.append("set by:")
        observed.extend("  " + ln for ln in scoped_lines)
    else:
        observed.append("not explicitly set in any scope (using git's built-in default)")

    if effective == "true":
        if declared:
            severity = "MEDIUM"
            do = ("autocrlf=true is redundant with a .gitattributes declaration and can "
                  "still surprise contributors without one; prefer relying on "
                  ".gitattributes alone and setting core.autocrlf=false or input.")
        else:
            severity = "HIGH"
            do = ("Add a .gitattributes with an explicit 'text=auto' policy and set "
                  "core.autocrlf to 'input' (Linux/macOS) or 'false' (Windows), so line "
                  "endings are controlled by the repo, not per-developer machine state.")
        means = "Git rewrites line endings on checkout/commit; this is a common source of huge phantom diffs and CRLF-in-shell-scripts breakage."
    elif effective in ("input", "false"):
        severity = "OK"
        means = "Git will not rewrite line endings based on this setting."
        do = "No action needed for this setting."
    else:
        severity = "INFO"
        means = "core.autocrlf is unset; git falls back to platform default behaviour."
        do = "Consider setting it explicitly (input/false) alongside .gitattributes."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


@safe_check
def check_gitattributes(ctx, check_id="gitattributes"):
    title = ".gitattributes presence and text=auto declaration"
    anchor = "eol-lf-phantom"
    root = ctx.repo_root
    path = os.path.join(root, ".gitattributes")
    present, declared = has_text_auto_declaration(path)

    observed = []
    if not ctx.is_repo:
        observed.append("target is not inside a git work tree; checked as a plain directory")
    observed.append(".gitattributes present: %s" % ("yes" if present else "no"))
    if present:
        observed.append("'* text=auto' style declaration found: %s" % ("yes" if declared else "no"))

    if not present:
        severity = "MEDIUM"
        means = "Without .gitattributes, line-ending handling depends entirely on each contributor's local core.autocrlf setting."
        do = "Add a .gitattributes with at least '* text=auto' to make line-ending handling explicit and repo-controlled."
    elif not declared:
        severity = "MEDIUM"
        means = ".gitattributes exists but does not declare a blanket text-handling policy."
        do = "Add a '* text=auto' (or equivalent explicit per-pattern) rule."
    else:
        severity = "OK"
        means = "Line-ending handling is declared explicitly in the repo."
        do = "No action needed."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


@safe_check
def check_filemode(ctx, check_id="filemode"):
    title = "core.filemode executable-bit tracking"
    anchor = "filemode"
    if not ctx.git_installed:
        return unknown_finding(check_id, title, "git executable not found on PATH", anchor)
    if not ctx.is_repo:
        return new_finding(
            check_id, title, "INFO",
            observed=["target is not inside a git work tree -- skipped"],
            means="This check only applies inside a git repository.",
            do="Run the audit against a path that is inside a git clone.",
            anchor=anchor,
        )

    value, err = git_config_get(ctx.repo_root, "core.filemode")
    if err:
        return unknown_finding(check_id, title, err, anchor)

    observed = ["core.filemode = %s" % (value if value else "(unset, platform default applies)")]

    if value is None:
        severity = "INFO"
        means = "Not explicitly set; git guesses based on whether the filesystem reliably tracks the executable bit."
        do = "No action required unless you see spurious chmod diffs; then set explicitly."
    elif value.lower() == "false":
        severity = "MEDIUM"
        means = "Git will not track executable-bit changes, which can silently drop +x on scripts committed from a POSIX machine."
        do = "This is usually correct on Windows. If scripts lose +x when checked out elsewhere, verify intentionally with a .gitattributes 'filter' or CI check."
    else:
        severity = "OK"
        means = "Git tracks the executable bit for files in this repo."
        do = "No action needed."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


# ---------------------------------------------------------------------------
# Check 4: symlinks
# ---------------------------------------------------------------------------

@safe_check
def check_symlinks(ctx, no_probe, check_id="symlinks"):
    title = "Symlink creation (core.symlinks + live probe)"
    anchor = "ln-s-copy"
    observed = []

    git_value = None
    if ctx.git_installed and ctx.is_repo:
        git_value, err = git_config_get(ctx.repo_root, "core.symlinks")
        observed.append("core.symlinks = %s" % (git_value if git_value else "(unset)"))
        if err:
            observed.append("git config lookup error: %s" % err)
    elif not ctx.git_installed:
        observed.append("git config lookup skipped: git executable not found on PATH")
    else:
        observed.append("core.symlinks lookup skipped: target is not inside a git work tree")

    if no_probe:
        observed.append("live symlink probe skipped (--no-probe)")
        severity = "MEDIUM" if git_value == "false" else "INFO"
        means = "Without a live probe this only reflects git's own setting, not what the OS actually does."
        do = "Re-run without --no-probe for a definitive real-world symlink test."
        return new_finding(check_id, title, severity, observed, means, do, anchor)

    probe_result, probe_detail = probe_symlink_behavior()
    observed.append("live probe: %s" % probe_detail)

    if probe_result == "real_symlink":
        severity = "OK"
        means = "This machine/user can create real symlinks right now."
        do = "No action needed for this machine, but every clone of your repo may not have this enabled."
    elif probe_result == "fallback_copy":
        severity = "HIGH"
        means = "Symlink creation silently produced a plain file/copy instead of a real link -- code that relies on symlinks will behave incorrectly with no error."
        do = "Enable Developer Mode (or run elevated) and set git config core.symlinks=true, or avoid relying on symlinks in this repo."
    elif probe_result == "os_error":
        severity = "HIGH"
        means = "Symlink creation raised an OS-level error -- symlinks cannot be created under the current privileges."
        do = "Enable Windows Developer Mode, or run as Administrator, or avoid relying on symlinks in this repo."
    else:
        severity = "UNKNOWN"
        means = "The probe could not determine symlink behaviour."
        do = "Investigate manually: try creating a symlink in a scratch directory."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


def probe_symlink_behavior():
    """Try to create a real symlink in a throwaway temp dir. Always cleans up.

    Returns (result_code, human_detail) where result_code is one of:
        "real_symlink", "fallback_copy", "os_error", "probe_error"
    """
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="winposix_audit_")
        src = os.path.join(tmp_dir, "source.txt")
        link = os.path.join(tmp_dir, "link.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("winposix-audit symlink probe\n")

        try:
            os.symlink(src, link)
        except OSError as exc:
            winerr = getattr(exc, "winerror", None)
            detail = "OSError creating symlink (errno=%s%s)" % (
                exc.errno, ", winerror=%s" % winerr if winerr is not None else ""
            )
            return "os_error", detail

        if os.path.islink(link):
            return "real_symlink", "real symlink created successfully"
        elif os.path.exists(link):
            return "fallback_copy", "a file was created but it is not a real symlink (silent fallback)"
        else:
            return "probe_error", "os.symlink() returned without error but no file appeared"
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return "probe_error", "probe itself failed: %s: %s" % (type(exc).__name__, exc)
    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Checks 5-6: Windows registry (read-only)
# ---------------------------------------------------------------------------

def read_registry_dword(hive, subkey, value_name):
    """Read a single DWORD registry value, read-only. Returns (value, error).

    value is None (with error set) if the key/value is absent or unreadable.
    Never writes to the registry.
    """
    try:
        import winreg  # only available on Windows
    except ImportError:
        return None, "winreg module not available on this platform"

    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _regtype = winreg.QueryValueEx(key, value_name)
            return value, None
    except FileNotFoundError:
        return None, "registry key or value not present"
    except PermissionError:
        return None, "permission denied reading registry"
    except OSError as exc:
        return None, "OSError reading registry: %s" % exc


@safe_check
def check_developer_mode(check_id="developer_mode"):
    title = "Windows Developer Mode (symlinks without elevation)"
    anchor = "ln-s-copy"
    if sys.platform != "win32":
        return new_finding(
            check_id, title, "INFO",
            observed=["not applicable on this platform"],
            means="Developer Mode is a Windows-only concept.",
            do="No action needed on this platform.",
            anchor=anchor,
        )

    import winreg  # safe: sys.platform == "win32" here
    value, err = read_registry_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
        "AllowDevelopmentWithoutDevLicense",
    )

    if err and value is None:
        return new_finding(
            check_id, title, "INFO",
            observed=["AllowDevelopmentWithoutDevLicense: absent (%s)" % err],
            means="Developer Mode registry key not found; likely disabled or never configured.",
            do="Enable Developer Mode in Windows Settings if you need unprivileged symlink creation.",
            anchor=anchor,
        )

    if value == 1:
        severity = "OK"
        observed = ["AllowDevelopmentWithoutDevLicense = 1 (enabled)"]
        means = "Developer Mode is enabled, which allows creating symlinks without running elevated."
        do = "No action needed."
    else:
        severity = "MEDIUM"
        observed = ["AllowDevelopmentWithoutDevLicense = %s (disabled)" % value]
        means = "Without Developer Mode, creating symlinks normally requires an elevated (Administrator) process."
        do = "Enable Developer Mode in Windows Settings > Privacy & Security > For Developers, or run as Administrator when symlinks are required."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


@safe_check
def check_long_paths(ctx, check_id="long_paths"):
    title = "Long path support (registry + core.longpaths)"
    if sys.platform != "win32":
        return new_finding(
            check_id, title, "INFO",
            observed=["not applicable on this platform"],
            means="The 260-character MAX_PATH limit is a Windows-specific historical default.",
            do="No action needed on this platform.",
        )

    import winreg
    reg_value, reg_err = read_registry_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\FileSystem",
        "LongPathsEnabled",
    )

    git_value = None
    git_err = None
    if ctx.git_installed:
        git_value, git_err = git_config_get(ctx.repo_root, "core.longpaths")

    observed = []
    if reg_err and reg_value is None:
        observed.append("registry LongPathsEnabled: absent (%s)" % reg_err)
    else:
        observed.append("registry LongPathsEnabled = %s" % reg_value)
    if not ctx.git_installed:
        observed.append("git core.longpaths: skipped, git not found on PATH")
    elif git_err:
        observed.append("git core.longpaths: lookup error: %s" % git_err)
    else:
        observed.append("git core.longpaths = %s" % (git_value if git_value else "(unset)"))

    long_paths_off = (reg_value in (None, 0))
    if long_paths_off:
        severity = "MEDIUM"
        means = "Without LongPathsEnabled, paths beyond ~260 characters can fail unpredictably in Win32 APIs even if git itself copes."
        do = "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\LongPathsEnabled=1 (requires admin) and consider git config core.longpaths=true."
    else:
        severity = "OK"
        means = "The system-wide long path opt-in is enabled."
        do = "No action needed."

    return new_finding(check_id, title, severity, observed, means, do)


# ---------------------------------------------------------------------------
# Check 7: case-insensitive filesystem
# ---------------------------------------------------------------------------

@safe_check
def check_case_insensitive_fs(ctx, no_probe, check_id="case_insensitive_fs"):
    title = "Case-insensitive filesystem (core.ignorecase + live probe)"
    anchor = "case-rename-clobber"
    observed = []

    git_value = None
    if ctx.git_installed and ctx.is_repo:
        git_value, err = git_config_get(ctx.repo_root, "core.ignorecase")
        observed.append("core.ignorecase = %s" % (git_value if git_value else "(unset)"))
        if err:
            observed.append("git config lookup error: %s" % err)
    elif not ctx.git_installed:
        observed.append("git config lookup skipped: git executable not found on PATH")
    else:
        observed.append("core.ignorecase lookup skipped: target is not inside a git work tree")

    if no_probe:
        observed.append("live filesystem probe skipped (--no-probe)")
        default_guess = "likely case-insensitive" if sys.platform in ("win32", "darwin") else "likely case-sensitive"
        observed.append("platform default guess (%s): %s" % (sys.platform, default_guess))
        severity = "INFO"
        means = "Without a live probe this is only a platform default guess, not a measurement."
        do = "Re-run without --no-probe for a definitive real-world filesystem test."
        return new_finding(check_id, title, severity, observed, means, do, anchor)

    result, detail = probe_case_insensitivity()
    observed.append("live probe: %s" % detail)

    if result == "case_insensitive":
        # Deliberately MEDIUM, not HIGH: this is the platform default on Windows
        # and on stock macOS, and it is not a misconfiguration you can fix -- only
        # one you can avoid tripping over. HIGH is reserved for things you can change.
        severity = "MEDIUM"
        means = "Two files differing only by case are the same file here, so a case-only rename can silently clobber, and a clone containing both will collide."
        do = "Not fixable, only avoidable: never let two paths differ only by case, and use 'git mv' in two steps for case-only renames."
    elif result == "case_sensitive":
        severity = "OK"
        means = "Filenames differing only by case are treated as distinct files."
        do = "No action needed, but be aware collaborators on Windows/macOS may not have this protection."
    else:
        severity = "UNKNOWN"
        means = "The probe could not determine filesystem case sensitivity."
        do = "Investigate manually in a scratch directory."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


def probe_case_insensitivity():
    """Create casetest.tmp and check whether CASETEST.TMP resolves to it.

    Always cleans up. Returns (result_code, detail).
    """
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="winposix_audit_")
        lower_path = os.path.join(tmp_dir, "casetest.tmp")
        upper_path = os.path.join(tmp_dir, "CASETEST.TMP")
        with open(lower_path, "w", encoding="utf-8") as f:
            f.write("winposix-audit case probe\n")

        if os.path.exists(upper_path):
            return "case_insensitive", "CASETEST.TMP resolved to the same file as casetest.tmp"
        else:
            return "case_sensitive", "CASETEST.TMP did not resolve to casetest.tmp (distinct files)"
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return "probe_error", "probe itself failed: %s: %s" % (type(exc).__name__, exc)
    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Check 8: PATH shadowing
# ---------------------------------------------------------------------------

@safe_check
def check_path_shadowing(check_id="path_shadowing"):
    title = "PATH shadowing among common dev executables"
    anchor = "path-collisions"

    path_dirs = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    is_windows = (sys.platform == "win32")

    if is_windows:
        pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        extensions = [e.lower() for e in pathext.split(os.pathsep) if e]
    else:
        extensions = []

    duplicates_found = False
    shim_or_store_found = False
    observed = []

    for name in PATH_SHADOW_NAMES:
        matches = []
        seen = set()
        for d in path_dirs:
            candidates = []
            if is_windows:
                # Only treat it as a match if it has one of PATHEXT's extensions,
                # matching how Windows/CreateProcess actually resolves bare names.
                for ext in extensions:
                    candidates.append(name + ext)
            else:
                candidates.append(name)

            for cand in candidates:
                full = os.path.join(d, cand)
                try:
                    is_match = os.path.isfile(full)
                    if is_match and not is_windows:
                        is_match = os.access(full, os.X_OK)
                except OSError:
                    is_match = False
                if is_match:
                    key = os.path.normcase(os.path.normpath(full))
                    if key not in seen:
                        seen.add(key)
                        matches.append(full)

        if len(matches) > 1:
            duplicates_found = True
        if matches:
            tags = []
            for m in matches:
                tag = ""
                lower = m.lower()
                if "appdata\\local\\microsoft\\windowsapps" in lower.replace("/", "\\"):
                    tag += " [STORE ALIAS STUB]"
                    shim_or_store_found = True
                if lower.endswith(".cmd") or lower.endswith(".bat"):
                    tag += " [SHIM %s]" % os.path.splitext(m)[1].upper()
                    shim_or_store_found = True
                tags.append(m + tag)
            marker = " (SHADOWED x%d)" % len(matches) if len(matches) > 1 else ""
            observed.append("%s%s:" % (name, marker))
            for t in tags:
                observed.append("  " + t)

    if not observed:
        observed = ["none of the tracked executable names were found on PATH"]

    if duplicates_found:
        severity = "MEDIUM"
        means = "Multiple installs of the same tool resolve on PATH; which one runs depends on PATH order and can differ between shells (cmd/PowerShell/Git Bash)."
        do = "Trim PATH to one canonical install per tool, or verify with 'where <name>' / 'which <name>' before relying on it in scripts."
    elif shim_or_store_found:
        severity = "MEDIUM"
        means = "A Windows Store alias stub or a .cmd/.bat shim is on PATH; these can behave differently from the real executable (e.g. blocking, wrapping args)."
        do = "Confirm the shim/stub forwards correctly, or replace it with a direct install."
    else:
        severity = "OK"
        means = "No PATH shadowing detected among the tracked executable names."
        do = "No action needed."

    return new_finding(check_id, title, severity, observed, means, do, anchor)


# ---------------------------------------------------------------------------
# Check 9: MSYS/Cygwin/Git-Bash environment
# ---------------------------------------------------------------------------

@safe_check
def check_msys_env(check_id="msys_env"):
    title = "MSYS2 / Git Bash / Cygwin path mangling"
    anchor = "msys-path-mangling"

    msystem = os.environ.get("MSYSTEM")
    ostype = os.environ.get("OSTYPE")
    has_usr_bin = os.path.isdir("/usr/bin")
    plat = sys.platform

    signals = []
    if msystem:
        signals.append("MSYSTEM=%s" % msystem)
    if ostype:
        signals.append("OSTYPE=%s" % ostype)
    if plat in ("cygwin", "msys"):
        signals.append("sys.platform=%s" % plat)
    if has_usr_bin and plat != "win32":
        signals.append("/usr/bin exists (POSIX-style tree)")

    detected = bool(signals)

    observed = []
    if detected:
        observed.append("MSYS/Git-Bash/Cygwin-like environment detected: " + ", ".join(signals))
    else:
        observed.append("no MSYS/Git-Bash/Cygwin signals detected (plat=%s)" % plat)

    excl = os.environ.get("MSYS2_ARG_CONV_EXCL")
    no_pathconv = os.environ.get("MSYS_NO_PATHCONV")
    observed.append("MSYS2_ARG_CONV_EXCL = %s" % (excl if excl is not None else "(unset)"))
    observed.append("MSYS_NO_PATHCONV = %s" % (no_pathconv if no_pathconv is not None else "(unset)"))

    means = ("In an MSYS/Git-Bash/Cygwin shell, POSIX-looking arguments (e.g. /c/foo or "
             "leading-slash flags like -DFOO=/bar) can be silently rewritten into Windows "
             "paths before reaching a native .exe, breaking flags that were never meant to "
             "be paths.")
    do = ("If you hit mangled arguments, set MSYS_NO_PATHCONV=1 for that command or use "
          "MSYS2_ARG_CONV_EXCL to exclude specific patterns.") if detected else \
         "Not running under MSYS/Git Bash/Cygwin right now; no action needed."

    return new_finding(check_id, title, "INFO", observed, means, do, anchor)


# ---------------------------------------------------------------------------
# Check 10: version stamp
# ---------------------------------------------------------------------------

@safe_check
def check_versions(ctx, check_id="versions"):
    title = "Environment version stamp"
    observed = []

    try:
        observed.append("platform.platform() = %s" % platform.platform())
    except Exception as exc:
        observed.append("platform.platform() error: %s" % exc)

    if sys.platform == "win32" and hasattr(sys, "getwindowsversion"):
        try:
            wv = sys.getwindowsversion()
            observed.append(
                "windows version = major=%s minor=%s build=%s platform=%s service_pack=%r"
                % (wv.major, wv.minor, wv.build, wv.platform, getattr(wv, "service_pack", ""))
            )
        except Exception as exc:
            observed.append("sys.getwindowsversion() error: %s" % exc)

    observed.append("python = %s (%s)" % (platform.python_version(), sys.executable))

    git_ver = run_cmd(["git", "--version"])
    if git_ver.ok and git_ver.returncode == 0:
        observed.append("git = %s" % git_ver.stdout.strip())
    elif git_ver.ok:
        observed.append("git --version exited %s: %s" % (git_ver.returncode, git_ver.stderr.strip()))
    else:
        observed.append("git = not available (%s)" % git_ver.error)

    observed.append("generated (UTC) = %s" % datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    return new_finding(
        check_id, title, "INFO", observed,
        means="This stamps the audit to a specific machine and toolchain state, the same way the field guide stamps each finding.",
        do="No action needed; keep this alongside any findings you report or share.",
    )


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def build_environment_block():
    """A compact environment summary reused by both text and JSON output."""
    return {
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "sys_platform": sys.platform,
    }


MAX_LINE_WIDTH = 98  # stay comfortably under the 100-char requirement


def wrap_plain(indent, text):
    """Wrap text to MAX_LINE_WIDTH, repeating `indent` on every line."""
    avail = max(20, MAX_LINE_WIDTH - len(indent))
    wrapped = textwrap.wrap(text, width=avail, break_long_words=False,
                             break_on_hyphens=False) or [""]
    return [indent + w for w in wrapped]


def wrap_labeled(indent, label, text):
    """Wrap text to MAX_LINE_WIDTH; `label` (e.g. 'Means: ') prefixes only
    the first line, continuation lines align under it."""
    avail = max(20, MAX_LINE_WIDTH - len(indent) - len(label))
    wrapped = textwrap.wrap(text, width=avail, break_long_words=False,
                             break_on_hyphens=False) or [""]
    lines = [indent + label + wrapped[0]]
    cont_indent = indent + " " * len(label)
    lines.extend(cont_indent + w for w in wrapped[1:])
    return lines


def render_text_report(target, findings, generated_utc):
    lines = []
    lines.append("%s v%s -- target: %s" % (TOOL_NAME, TOOL_VERSION, target))
    lines.append("generated (UTC): %s" % generated_utc)
    lines.append("=" * 78)
    lines.append("")

    grouped = {sev: [] for sev in SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f["severity"], []).append(f)

    for sev in SEVERITY_ORDER:
        for f in grouped.get(sev, []):
            lines.extend(wrap_plain("", "[%s] %s -- %s" % (f["severity"], f["id"], f["title"])))
            for obs in f["observed"]:
                leading = len(obs) - len(obs.lstrip(" "))
                indent = "  " + obs[:leading]
                lines.extend(wrap_plain(indent, obs.lstrip(" ")))
            lines.extend(wrap_labeled("  ", "Means: ", f["means"]))
            lines.extend(wrap_labeled("  ", "Do: ", f["do"]))
            lines.extend(wrap_plain("  ", f["url"]))
            lines.append("")

    summary = summarize(findings)
    summary_line = "Summary: " + ", ".join(
        "%s=%d" % (sev, summary.get(sev, 0)) for sev in SEVERITY_ORDER
    )
    lines.append(summary_line)
    lines.append("")
    lines.append("Read-only: this script changed nothing on this machine.")
    lines.append("")
    lines.append("Tessera -- made by an AI. https://github.com/tessera-ai21/Tessera-AI")

    return "\n".join(lines)


def summarize(findings):
    summary = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    return summary


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="winposix-audit.py",
        description="Read-only audit of Windows/POSIX boundary failure modes. "
                     "Companion to https://tessera-ai21.github.io/Tessera-AI/",
    )
    parser.add_argument(
        "path", nargs="?", default=None,
        help="path to a git repo or directory to inspect (default: current directory)",
    )
    parser.add_argument("--json", action="store_true", help="emit a single JSON object to stdout")
    parser.add_argument(
        "--no-probe", action="store_true",
        help="skip all temp-directory behavioural probes (symlink + case-sensitivity tests)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="exit code 1 if any finding has severity HIGH (default: always exit 0)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    target = args.path if args.path else os.getcwd()
    target = os.path.abspath(target)

    if not os.path.isdir(target):
        sys.stderr.write("error: path does not exist or is not a directory: %s\n" % target)
        return 2

    ctx = RepoContext(target)
    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    findings = []
    findings.append(check_autocrlf(ctx))
    findings.append(check_gitattributes(ctx))
    findings.append(check_filemode(ctx))
    findings.append(check_symlinks(ctx, args.no_probe))
    findings.append(check_developer_mode())
    findings.append(check_long_paths(ctx))
    findings.append(check_case_insensitive_fs(ctx, args.no_probe))
    findings.append(check_path_shadowing())
    findings.append(check_msys_env())
    findings.append(check_versions(ctx))

    summary = summarize(findings)

    if args.json:
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_utc": generated_utc,
            "target": target,
            "environment": build_environment_block(),
            "findings": findings,
            "summary": summary,
        }
        sys.stdout.write(json.dumps(payload, indent=2))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text_report(target, findings, generated_utc))
        sys.stdout.write("\n")

    if args.strict and summary.get("HIGH", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
