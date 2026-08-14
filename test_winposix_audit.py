#!/usr/bin/env python3
"""
test_winposix_audit.py -- re-runnable, read-only test suite for winposix-audit.py.

Python 3.8+ stdlib only, unittest-based. Loads the hyphenated module file via
importlib.util so it can be exercised in-process (no subprocess of the tool
itself). Every filesystem write this suite performs happens inside a fresh
tempfile.mkdtemp() directory that is always removed afterward.

Run with either:
    python -m unittest discover -s "D:/second/repo" -p "test_*.py" -v
    python "D:/second/repo/test_winposix_audit.py"
"""

import ast
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Load winposix-audit.py (hyphenated filename, so it can't be `import`ed
# normally) relative to this test file's own location -- never a hardcoded
# absolute path -- so the suite works in a fresh clone anywhere.
# ---------------------------------------------------------------------------

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(THIS_DIR, "winposix-audit.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("winposix_audit_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wpa = _load_module()

EXPECTED_CHECK_IDS = {
    "autocrlf", "gitattributes", "filemode", "symlinks", "developer_mode",
    "long_paths", "case_insensitive_fs", "path_shadowing", "msys_env", "versions",
}

MKDTEMP_PREFIX = "winposix_audit_"  # read from probe_symlink_behavior / probe_case_insensitivity


def _snapshot_tree(root):
    """Return a sorted (relpath, size, mtime_ns) list for every file and
    (relpath, None, None) for every directory under root, for before/after
    comparison of a fixture tree."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            entries.append((rel, None, None))
        for name in filenames:
            full = os.path.join(dirpath, name)
            st = os.stat(full)
            rel = os.path.relpath(full, root)
            entries.append((rel, st.st_size, st.st_mtime_ns))
    entries.sort(key=lambda t: t[0])
    return entries


# ---------------------------------------------------------------------------
# A. Pure unit tests (no subprocess)
# ---------------------------------------------------------------------------

class TestPureUnit(unittest.TestCase):

    def test_new_finding_returns_documented_seven_key_shape(self):
        """new_finding returns exactly the seven documented keys, coercing a str observed into a one-element list."""
        f = wpa.new_finding("id1", "Title", "OK", "single observed line", "means text", "do text")
        self.assertEqual(set(f.keys()), {"id", "title", "severity", "observed", "means", "do", "url"})
        self.assertEqual(f["observed"], ["single observed line"])
        self.assertEqual(f["url"], wpa.BASE_URL)

    def test_new_finding_url_anchor_appends_fragment(self):
        """new_finding's url equals BASE_URL with no anchor, and BASE_URL + '#anchor' when an anchor is supplied."""
        no_anchor = wpa.new_finding("id1", "Title", "OK", ["x"], "m", "d")
        with_anchor = wpa.new_finding("id1", "Title", "OK", ["x"], "m", "d", anchor="sect")
        self.assertEqual(no_anchor["url"], wpa.BASE_URL)
        self.assertEqual(with_anchor["url"], wpa.BASE_URL + "#sect")

    def test_unknown_finding_has_unknown_severity_and_reason_in_do(self):
        """unknown_finding always reports severity UNKNOWN and embeds the given reason text in its do field."""
        f = wpa.unknown_finding("cid", "title", "some specific reason text")
        self.assertEqual(f["severity"], "UNKNOWN")
        self.assertIn("some specific reason text", f["do"])

    def test_safe_check_converts_exception_to_unknown_and_preserves_check_id(self):
        """safe_check downgrades a raised exception to an UNKNOWN finding, naming the exception type and preserving the check_id kwarg as the finding id."""
        def boom(*args, **kwargs):
            raise ValueError("kaboom")

        wrapped = wpa.safe_check(boom)
        finding = wrapped(check_id="my_check_id")
        self.assertEqual(finding["severity"], "UNKNOWN")
        self.assertEqual(finding["id"], "my_check_id")
        self.assertIn("ValueError", finding["do"])

    def test_summarize_counts_every_severity_including_zero(self):
        """summarize returns a count for every SEVERITY_ORDER entry, including severities with zero matching findings."""
        findings = [
            wpa.new_finding("a", "t", "HIGH", "o", "m", "d"),
            wpa.new_finding("b", "t", "HIGH", "o", "m", "d"),
            wpa.new_finding("c", "t", "OK", "o", "m", "d"),
        ]
        summary = wpa.summarize(findings)
        self.assertEqual(summary["HIGH"], 2)
        self.assertEqual(summary["OK"], 1)
        self.assertEqual(summary["MEDIUM"], 0)
        for sev in wpa.SEVERITY_ORDER:
            self.assertIn(sev, summary)

    def test_severity_order_is_exact_documented_list(self):
        """SEVERITY_ORDER is exactly the five documented severities in display/grouping order."""
        self.assertEqual(wpa.SEVERITY_ORDER, ["HIGH", "MEDIUM", "INFO", "UNKNOWN", "OK"])


# ---------------------------------------------------------------------------
# B. Source-level contract tests (parse with ast; pin README promises)
# ---------------------------------------------------------------------------

class TestSourceContracts(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(MODULE_PATH, "r", encoding="utf-8") as f:
            cls.source = f.read()
        cls.tree = ast.parse(cls.source)

    def _all_import_root_names(self):
        roots = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    roots.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    roots.add(node.module.split(".")[0])
        return roots

    def test_only_stdlib_modules_from_explicit_allowlist_are_imported(self):
        """Every module imported anywhere in the source (any nesting level) has a root name in an explicit stdlib-only allowlist, so a future third-party dependency breaks this test."""
        allowlist = {
            "argparse", "json", "os", "platform", "shutil", "subprocess",
            "sys", "tempfile", "textwrap", "datetime", "winreg",
        }
        roots = self._all_import_root_names()
        self.assertTrue(roots, "expected to find at least one import in the source")
        unexpected = roots - allowlist
        self.assertEqual(unexpected, set(), "import(s) outside the explicit allowlist: %r" % (unexpected,))

    def test_no_network_modules_imported_anywhere(self):
        """None of the common networking modules are imported anywhere in the source, pinning the 'makes no network connections' claim."""
        roots = self._all_import_root_names()
        network_modules = {"socket", "urllib", "http", "ftplib", "smtplib", "requests", "httpx"}
        self.assertEqual(roots & network_modules, set())

    def test_registry_openkey_calls_always_pass_key_read(self):
        """Every OpenKey call found in the source passes winreg.KEY_READ among its arguments, pinning the 'registry keys opened strictly KEY_READ' claim."""
        openkey_calls = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Attribute) and node.func.attr == "OpenKey")
                or (isinstance(node.func, ast.Name) and node.func.id == "OpenKey")
            )
        ]
        self.assertTrue(openkey_calls, "expected to find at least one OpenKey call")
        for call in openkey_calls:
            found_key_read = False
            for sub in list(call.args) + [kw.value for kw in call.keywords]:
                for n in ast.walk(sub):
                    if isinstance(n, ast.Attribute) and n.attr == "KEY_READ":
                        found_key_read = True
                    if isinstance(n, ast.Name) and n.id == "KEY_READ":
                        found_key_read = True
            self.assertTrue(found_key_read, "OpenKey call at line %s does not pass KEY_READ" % call.lineno)

    def test_winreg_is_not_imported_at_module_top_level(self):
        """winreg never appears in the module's top-level statement list; every winreg import found anywhere is nested inside a function body (the source guards it, it does not omit it entirely)."""
        top_level_winreg = [
            node for node in self.tree.body
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "winreg" for a in node.names)
        ]
        self.assertEqual(top_level_winreg, [], "winreg must not be imported at module top level")

        nested_winreg_imports = []
        for func in ast.walk(self.tree):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(func):
                    if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "winreg" for a in node.names):
                        nested_winreg_imports.append(node)
        self.assertTrue(nested_winreg_imports, "expected winreg to be imported inside at least one function")

    def test_source_parses_as_python_3_8_syntax(self):
        """The source parses successfully under ast.parse constrained to the Python 3.8 grammar, pinning the '3.8+' promise."""
        try:
            ast.parse(self.source, feature_version=(3, 8))
        except TypeError:
            self.skipTest("this interpreter's ast.parse does not support the feature_version argument")

    def test_every_check_function_is_decorated_with_safe_check(self):
        """Every module-level function named check_* carries the @safe_check decorator; probe_* helpers are exempt since they are not checks."""
        check_funcs = [
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("check_")
        ]
        self.assertTrue(check_funcs, "expected to find at least one check_* function")
        for func in check_funcs:
            decorator_names = []
            for dec in func.decorator_list:
                if isinstance(dec, ast.Name):
                    decorator_names.append(dec.id)
                elif isinstance(dec, ast.Attribute):
                    decorator_names.append(dec.attr)
            self.assertIn("safe_check", decorator_names, "%s is missing @safe_check" % func.name)


# ---------------------------------------------------------------------------
# C. End-to-end behaviour (in-process main(), stdout/stderr captured)
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # One full run, reused by the JSON-shape and default-exit-code tests.
        cls.target_dir = tempfile.mkdtemp(prefix="wpa_test_target_")
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cls.exit_code = wpa.main(["--json", "--no-probe", cls.target_dir])
        cls.stdout_text = out.getvalue()
        cls.stderr_text = err.getvalue()
        cls.payload = json.loads(cls.stdout_text)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.target_dir, ignore_errors=True)

    def test_json_mode_emits_single_object_with_documented_top_level_keys(self):
        """main(['--json', '--no-probe', tmpdir]) writes exactly one parseable JSON object with the seven documented top-level keys."""
        self.assertEqual(
            set(self.payload.keys()),
            {"tool", "version", "generated_utc", "target", "environment", "findings", "summary"},
        )

    def test_json_mode_emits_exactly_ten_findings_with_expected_ids_and_shape(self):
        """The findings array has exactly 10 entries whose ids equal the documented set, each with all 7 finding keys and a severity from SEVERITY_ORDER."""
        findings = self.payload["findings"]
        self.assertEqual(len(findings), 10)
        self.assertEqual({f["id"] for f in findings}, EXPECTED_CHECK_IDS)
        for f in findings:
            self.assertEqual(set(f.keys()), {"id", "title", "severity", "observed", "means", "do", "url"})
            self.assertIn(f["severity"], wpa.SEVERITY_ORDER)

    def test_default_mode_exit_code_is_zero(self):
        """Without --strict, main() returns exit code 0 regardless of findings present."""
        self.assertEqual(self.exit_code, 0)

    def test_strict_mode_exits_1_only_when_strict_and_a_high_finding_are_both_present(self):
        """--strict returns exit code 1 when a HIGH finding exists (forced via a monkeypatched check_*), and the very same injected HIGH still exits 0 without --strict."""
        original = wpa.check_autocrlf

        def fake_high(ctx, check_id="autocrlf"):
            return wpa.new_finding(check_id, "fake high for test", "HIGH", ["injected for test"], "m", "d")

        wpa.check_autocrlf = fake_high
        self.addCleanup(setattr, wpa, "check_autocrlf", original)

        tmp = tempfile.mkdtemp(prefix="wpa_test_strict_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        out_strict = io.StringIO()
        with contextlib.redirect_stdout(out_strict), contextlib.redirect_stderr(io.StringIO()):
            rc_strict = wpa.main(["--json", "--no-probe", "--strict", tmp])
        self.assertEqual(rc_strict, 1)

        out_nonstrict = io.StringIO()
        with contextlib.redirect_stdout(out_nonstrict), contextlib.redirect_stderr(io.StringIO()):
            rc_nonstrict = wpa.main(["--json", "--no-probe", tmp])
        self.assertEqual(rc_nonstrict, 0)

    def test_nonexistent_path_returns_exit_code_2_and_writes_stderr_message(self):
        """A target path that does not exist returns exit code 2 and writes an error message to stderr."""
        missing = os.path.join(tempfile.gettempdir(), "wpa_test_does_not_exist_%d" % os.getpid())
        self.assertFalse(os.path.exists(missing))
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = wpa.main(["--json", missing])
        self.assertEqual(rc, 2)
        self.assertTrue(err.getvalue().strip())

    def test_text_mode_output_is_nonempty_and_mentions_all_check_ids(self):
        """Text (non-JSON) mode produces non-empty output mentioning every one of the ten check ids, without raising."""
        tmp = tempfile.mkdtemp(prefix="wpa_test_text_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = wpa.main(["--no-probe", tmp])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertTrue(text.strip())
        for cid in EXPECTED_CHECK_IDS:
            self.assertIn(cid, text)


# ---------------------------------------------------------------------------
# D. The read-only guarantee
# ---------------------------------------------------------------------------

class TestReadOnlyGuaranteeNoProbe(unittest.TestCase):

    def setUp(self):
        self.fixture_dir = tempfile.mkdtemp(prefix="wpa_test_fixture_")
        self.addCleanup(shutil.rmtree, self.fixture_dir, ignore_errors=True)
        with open(os.path.join(self.fixture_dir, "alpha.txt"), "w", encoding="utf-8") as f:
            f.write("alpha\n")
        os.mkdir(os.path.join(self.fixture_dir, "subdir"))
        with open(os.path.join(self.fixture_dir, "subdir", "beta.txt"), "w", encoding="utf-8") as f:
            f.write("beta\n")

    def test_no_probe_run_does_not_modify_system_temp_dir_listing(self):
        """With --no-probe, neither probe helper is invoked at all, no entry appears under the tool's mkdtemp prefix, and no pre-existing temp entry is removed.

        Deliberately NOT a byte-identical diff of the whole temp listing: that
        directory is shared with every other process on the machine, so an exact
        comparison flakes on unrelated churn. These two assertions are the part
        the tool is actually answerable for.
        """
        temp_root = tempfile.gettempdir()
        before = set(os.listdir(temp_root))

        # The strongest form of the claim: with --no-probe the probe helpers are
        # never entered at all, so there is no window in which anything is
        # written. Checking only for leftover directories would let a probe that
        # writes and then tidies up pass.
        called = []
        for probe_name in ("probe_symlink_behavior", "probe_case_insensitivity"):
            original = getattr(wpa, probe_name)
            self.addCleanup(setattr, wpa, probe_name, original)
            setattr(wpa, probe_name,
                    lambda *a, _n=probe_name, **k: called.append(_n))

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = wpa.main(["--json", "--no-probe", self.fixture_dir])
        self.assertEqual(rc, 0)
        self.assertEqual(called, [], "--no-probe still invoked a probe helper")
        after = set(os.listdir(temp_root))
        self.assertEqual(
            [n for n in sorted(after - before) if n.startswith(MKDTEMP_PREFIX)], [],
            "--no-probe still created a probe directory in the system temp dir",
        )
        self.assertEqual(
            sorted(before - after), [],
            "the run removed pre-existing entries from the system temp dir",
        )

    def test_no_probe_run_does_not_modify_fixture_tree(self):
        """With --no-probe, a fixture directory tree's relative paths, sizes, and mtimes are unchanged after a full run."""
        before = _snapshot_tree(self.fixture_dir)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = wpa.main(["--json", "--no-probe", self.fixture_dir])
        self.assertEqual(rc, 0)
        after = _snapshot_tree(self.fixture_dir)
        self.assertEqual(before, after)


class TestReadOnlyGuaranteeWithProbes(unittest.TestCase):

    def setUp(self):
        self.fixture_dir = tempfile.mkdtemp(prefix="wpa_test_fixture_probes_")
        self.addCleanup(shutil.rmtree, self.fixture_dir, ignore_errors=True)
        with open(os.path.join(self.fixture_dir, "alpha.txt"), "w", encoding="utf-8") as f:
            f.write("alpha\n")
        os.mkdir(os.path.join(self.fixture_dir, "subdir"))
        with open(os.path.join(self.fixture_dir, "subdir", "beta.txt"), "w", encoding="utf-8") as f:
            f.write("beta\n")

    def test_probes_enabled_run_does_not_modify_fixture_tree(self):
        """With probes enabled (no --no-probe), a fixture directory tree's relative paths, sizes, and mtimes are unchanged after a full run."""
        before = _snapshot_tree(self.fixture_dir)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = wpa.main(["--json", self.fixture_dir])
        self.assertEqual(rc, 0)
        after = _snapshot_tree(self.fixture_dir)
        self.assertEqual(before, after)

    def test_probes_enabled_run_leaves_no_surviving_mkdtemp_entries(self):
        """With probes enabled, no OS-temp entry created under the tool's own mkdtemp prefix survives after a full run (probe dirs are cleaned up)."""
        temp_root = tempfile.gettempdir()
        before = set(os.listdir(temp_root))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = wpa.main(["--json", self.fixture_dir])
        self.assertEqual(rc, 0)
        after = set(os.listdir(temp_root))
        new_entries = after - before
        surviving = [e for e in new_entries if e.startswith(MKDTEMP_PREFIX)]
        self.assertEqual(surviving, [], "leftover probe temp entries: %r" % (surviving,))


if __name__ == "__main__":
    unittest.main()
