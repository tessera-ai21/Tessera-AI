# Windows/POSIX boundary failure modes — verification results

Date: 2026-08-08
Machine: Windows 11 (10.0.26200)

Tool versions gathered at run time:
- `git --version` → git version 2.53.0.windows.2
- `bash --version | head -1` → GNU bash, version 5.2.37(1)-release (x86_64-pc-msys)
- `python --version` → Python 3.14.3
- `node --version` → v24.15.0
- `docker --version` → Docker version 29.6.2, build dfc4efb
- Docker daemon status: **NOT RUNNING** — `docker info` returned:
  ```
  Server:
  failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; check if the path is correct and if the daemon is running: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
  ```
  All docker-dependent sub-tests below are marked UNTESTABLE. Per instructions, no attempt was made to start Docker Desktop (out of scope / not a "daemon is running" state).

All work done under `D:\second\draft\tests\`. No global/system git config touched (only repo-local `git config user.name/email` inside test repos). No network access. No files modified outside `D:\second\draft`.

---

## Test 1 — MSYS path mangling with `docker run -v` and general `/`-prefixed args

**Docker sub-part: UNTESTABLE** — daemon not running (see above).

**Non-docker path-mangling test** (Git Bash → `cmd.exe`), in `D:\second\draft\tests\test1_pathmangle`:

Commands and verbatim output:

```
$ cmd /c echo /test
Microsoft Windows [Version 10.0.26200.8875]
(c) Microsoft Corporation. All rights reserved.

D:\second\draft\tests\test1_pathmangle>
```
(cmd opened an interactive shell instead of running the command — see mechanism below — and immediately exited on EOF)

```
$ cmd //c echo /test
"C:/Program Files/Git/test"
```

```
$ MSYS_NO_PATHCONV=1 cmd /c echo /test
/test
```

```
$ cmd /c echo /c/some/path
Microsoft Windows [Version 10.0.26200.8875]
(c) Microsoft Corporation. All rights reserved.

D:\second\draft\tests\test1_pathmangle>
```
(same interactive-shell derailment as above)

```
$ cmd //c echo /c/some/path
C:/some/path
```

```
$ cmd //c echo /data
"C:/Program Files/Git/data"
```

```
$ cmd //c echo //data
/data
```

```
$ MSYS_NO_PATHCONV=1 cmd //c echo /data
Microsoft Windows [Version 10.0.26200.8875]
(c) Microsoft Corporation. All rights reserved.

D:\second\draft\tests\test1_pathmangle>
```
(interactive shell again — `//c` is not recognized as the `/c` switch when path conversion is fully disabled)

**Verdict: REPRODUCED.**

**Mechanism:** MSYS's bash runtime rewrites any bare argument that looks like a POSIX absolute path (`/foo`) into a Windows path before exec'ing a native (non-MSYS) binary. `/c` alone collides with this heuristic and gets rewritten to a drive-root-like path, so `cmd.exe` never sees its `/c` switch and instead falls into an interactive session. `/test` similarly gets resolved against the MSYS root (`/` = `C:\Program Files\Git`) producing `C:/Program Files/Git/test`. The classic docker workaround of doubling the leading slash (`//data`) works because MSYS's rule for a *doubled* leading slash is "strip one slash and pass through literally" rather than "treat as POSIX path and convert" — this is exactly the mechanism `-v //c/some/path:/data` workarounds rely on. `MSYS_NO_PATHCONV=1` disables the conversion heuristic entirely, which fixes `/c` + single-slash args together, but breaks the double-slash trick (since `//c` is then passed through literally and `cmd.exe` doesn't recognize a double-slash switch). The two workarounds are therefore mutually exclusive, not stackable.

---

## Test 2 — npm/node shebang + `.cmd`/`.ps1` shim resolution

Directory: `D:\second\draft\tests\test2_npm`

**Shebang script run directly in Git Bash:**
```
$ printf '#!/usr/bin/env node\nconsole.log("hello from script");\n' > script
$ chmod +x script
$ ./script
hello from script
```
Works — Git Bash's exec honors the shebang line for a chmod+x extensionless file.

**Command resolution, same name, two shells:**

Git Bash:
```
$ which npm
/c/Program Files/nodejs/npm
$ file "/c/Program Files/nodejs/npm"
/c/Program Files/nodejs/npm: Bourne-Again shell script, ASCII text executable
#!/usr/bin/env bash
```
→ Git Bash resolves bare `npm` to the extensionless **POSIX bash shim** shipped alongside `npm.cmd`/`npm.ps1`.

PowerShell:
```
PS> Get-Command npm | Format-List Name,CommandType,Source
Name        : npm.ps1
CommandType : ExternalScript
Source      : C:\Program Files\nodejs\npm.ps1
```
→ PowerShell resolves the identical bare `npm` to the **`.ps1` script**, a different file entirely.

Both run correctly (`npm --version` → `11.12.1` in each), but they are genuinely different interpreters/files being silently selected for the same typed command name, depending only on which shell you're in.

**Local shim pair experiment** (hand-built npm-style `.bin` shims, no network install):
```
node_modules/.bin/mytool      (POSIX #!/bin/sh shim)
node_modules/.bin/mytool.cmd  (Windows batch shim)
```

From Git Bash: `node_modules/.bin/mytool foo bar` → runs the POSIX shim directly → `mytool ran, args: foo,bar`. `node_modules/.bin/mytool.cmd foo bar` also runs fine from Bash (MSYS hands `.cmd`/`.exe` files to Windows CreateProcess transparently).

From PowerShell, with **both** `mytool` and `mytool.cmd` present: `.\node_modules\.bin\mytool foo bar` → runs `mytool ran, args: foo,bar`. This is *not* PowerShell interpreting the POSIX shim — verified by removing `mytool.cmd` and re-running the identical command:

```
PS> & ".\node_modules\.bin\mytool" baz
(no output, no error, no exception, $LASTEXITCODE empty)

PS> & ".\node_modules\.bin\mytool" baz 2>&1 | ForEach-Object { ... }
Cannot run a document in the middle of a pipeline: D:\...\mytool
    + FullyQualifiedErrorId : CantActivateDocumentInPipeline
```

**Verdict: REPRODUCED** (silent divergence in shim selection; PowerShell fails opaquely on the extensionless POSIX shim).

**Mechanism:** Windows command resolution is extension-driven (`PATHEXT`), not shebang-driven. When PowerShell/cmd resolve a bare name like `mytool` and an exact-match executable extension isn't present, they transparently append PATHEXT candidates (`.cmd` wins), which is *why npm ships both files* — the `.cmd`/`.ps1` exist purely for Windows shells, the extensionless file purely for POSIX shells. If only the extensionless POSIX shim exists, PowerShell can't recognize it as executable at all: it's treated as a data "document" with no associated handler. Outside a pipeline this fails **silently** (no output, no thrown exception, no exit code) — a genuinely dangerous failure mode for scripting, since `if ($LASTEXITCODE -eq 0)` checks would be misleading (empty, not 0). Inside a pipeline it fails loudly instead (`CantActivateDocumentInPipeline`). Git Bash has no such ambiguity: it reads the shebang directly for extensionless executable files, and separately, MSYS transparently marshals `.cmd`/`.exe` files to `CreateProcess` when run from Bash.

---

## Test 3 — File locking on open handles

Directory: `D:\second\draft\tests\test3_locking`

**Exclusive lock** (PowerShell background process): `[System.IO.File]::Open(path, Open, ReadWrite, FileShare.None)`, held for 60s.

From Git Bash while held:
```
$ rm locked.txt
rm: cannot remove 'locked.txt': Device or resource busy
$ mv locked.txt locked2.txt
mv: cannot move 'locked.txt' to 'locked2.txt': Device or resource busy
$ echo "new content" > locked.txt
/usr/bin/bash: line 25: locked.txt: Device or resource busy
$ cp src.txt locked.txt
cp: cannot create regular file 'locked.txt': Device or resource busy
```
All four operations fail with `Device or resource busy` (errno EBUSY, mapped from Win32 `ERROR_SHARING_VIOLATION`).

**Soft case — file open for reading with a genuinely shared read mode**: `[System.IO.File]::Open(path, Open, Read, FileShare.Read)` (note: the naive 3-argument `File.Open(path, mode, access)` overload actually defaults to `FileShare.None` regardless of access — verified empirically: with that overload, even `cat` failed with EBUSY. Retested with explicit `FileShare.Read` for the true "soft" case.)

With explicit `FileShare.Read` held elsewhere:
```
$ cat readshared2b.txt
content for soft read test          # succeeds — reading is allowed
$ rm readshared2b.txt
rm: cannot remove 'readshared2b.txt': Device or resource busy
$ mv readshared2b.txt renamed.txt
mv: cannot move 'readshared2b.txt' to 'renamed.txt': Device or resource busy
```
Reading succeeds, but delete/rename still fail.

After releasing all locks, `rm locked.txt readshared.txt readshared2b.txt` succeeded cleanly.

**Verdict: REPRODUCED.**

**Mechanism:** Windows file sharing is opt-in and granted at open time via `FileShare` flags (`Read`/`Write`/`Delete`), unlike POSIX where `unlink()` only removes a directory entry and never touches an already-open file's inode/data until the last handle closes. `.NET`'s `FileShare.Read` (what a "read-only viewer" typically uses) permits concurrent reads but **not** `FILE_SHARE_DELETE`, so any attempt to delete, rename, or truncate/overwrite the path fails with `ERROR_SHARING_VIOLATION` (surfaced by MSYS/Git Bash tools as `EBUSY` / "Device or resource busy") until every handle with non-delete-sharing is closed. This is a fundamentally different failure surface than Linux, where `rm` on an open file always succeeds and just unlinks the name.

---

## Test 4 — PATH / command resolution: Git Bash vs PowerShell

Commands run in both shells; verbatim key lines:

| name | Git Bash resolves to | PowerShell resolves to | Same program? |
|---|---|---|---|
| `python` | `/c/Python314/python` (first of 3 candidates: Python314, WindowsApps stub, Python38) | `C:\Python314\python.exe` (also first of same 3, via `Get-Command -All`) | Yes, by luck of PATH order |
| `python3` | `/c/Users/cdyks/AppData/Local/Microsoft/WindowsApps/python3` (Store alias stub only) | `C:\...\WindowsApps\python3.exe` (Store alias stub only) | Yes — but note: neither shell finds the real Python 3.14 under this name, only the Microsoft Store app-execution-alias stub |
| `node` | `/c/Program Files/nodejs/node` | `C:\Program Files\nodejs\node.exe` | Yes |
| `git` | `/mingw64/bin/git` | `C:\Program Files\Git\cmd\git.exe` | Functionally yes (both are "real" git, different front-end wrapper) |
| `sort` | `/usr/bin/sort` (GNU coreutils) | **Alias → `Sort-Object` cmdlet** (confirmed: `"banana","apple","cherry" \| sort` → alphabetized object sort, not text-line sort of `sort.exe`) | **NO — different program entirely** |
| `find` | `/usr/bin/find` (GNU find, tree search) | `C:\Windows\system32\find.exe` (DOS-era substring-in-file search; `echo "hello world" \| find "hello"` → `FIND: Parameter format not correct`, exit code 2) | **NO — different program, different syntax, different purpose** |
| `where` (bash) | `/c/Windows/system32/where` | n/a (native `where.exe`) | n/a |

**Verdict: REPRODUCED** (for `sort` and `find`; NOT REPRODUCED / non-issue for `python`, `node`, `git` on this machine's current PATH ordering).

**Mechanism:** Git Bash's `PATH` is MSYS-flavored (`/usr/bin` first, containing GNU coreutils) plus the inherited Windows `PATH`; `which`/`type` walk it left to right and GNU tools shadow same-named Windows tools. PowerShell has its own resolution order — aliases first, then functions, then cmdlets, then external executables found via `PATHEXT`-extended `PATH` search — so `sort` never reaches `sort.exe` at all (the built-in alias to `Sort-Object` wins first), and `find` reaches the ancient Win32 `find.exe` (no PowerShell alias shadows it) rather than any GNU find, since PowerShell's `PATH` doesn't include MSYS's `/usr/bin` equivalent. `python`/`node`/`git` happen to agree here only because both shells' search paths list the same real install first — this is PATH-order coincidence, not a guarantee, and the `python3` case shows the failure mode plainly: neither shell's `python3` reaches the real interpreter, only the Microsoft Store stub.

---

## Test 5 — git clone: case-collision and symlink

Directory: `D:\second\draft\tests\test5_source`, `test5_source_symlink`, and clones.

### Case collision

Setup: single blob added to the index under both `readme.md` and `README.md` via `git update-index --add --cacheinfo 100644 <sha> <path>`, committed.

```
$ git clone -q ./test5_source ./test5_clone_case
warning: the following paths have collided (e.g. case-sensitive paths
on a case-insensitive filesystem) and only one from the same
colliding group is in the working tree:

  'README.md'
  'readme.md'
```
Clone exit code 0 (warning only, not fatal). Resulting working tree: only **`readme.md`** (lowercase) materialized on disk — i.e. the *last*-processed entry in checkout order wins, not the alphabetically-first one (`git ls-files` lists `README.md` before `readme.md` due to byte-value sort, but lowercase won the collision). `git status` reports clean; reading either `readme.md` or `README.md` returns the same content (filesystem case-insensitivity resolves both names to the one file on disk).

**Verdict: REPRODUCED.**

**Mechanism:** Git's object model is fully case-sensitive (two distinct index entries, potentially different blobs), but NTFS defaults to case-insensitive path lookup. Checkout writes files in index order; each subsequent colliding name overwrites/reuses the same on-disk file the previous one created, so silently only one blob's content survives on disk even though the index and history still contain both entries. Git detects this since ~2.x and emits a warning but does not fail the clone — a repo authored (accidentally or via case-sensitive collaborators/CI) with such a collision degrades silently on Windows checkouts.

### Symlink

Setup: `target.txt` added normally; `link` added via `git update-index --add --cacheinfo 120000 <sha-of-"target.txt"-blob> link` (a real git symlink mode entry), committed.

```
$ git clone -q ./test5_source_symlink ./test5_clone_symlink_default
$ git config core.symlinks
true
$ ls -la link
lrwxrwxrwx 1 cdyks 197609 10 Aug  8 18:31 link -> target.txt
$ file link
link: symbolic link to target.txt
```
Confirmed via PowerShell this is a genuine NTFS reparse point, not an MSYS emulation:
```
PS> Get-Item link | Format-List Name,LinkType,Target,Attributes
LinkType   : SymbolicLink
Target     : {target.txt}
Attributes : Archive, ReparsePoint
PS> fsutil reparsepoint query link
Tag value: Symbolic Link
```
Explicit `git clone -c core.symlinks=true` gave an identical result (redundant here, since `core.symlinks=true` is already the effective system-config default on this machine).

**Verdict: NOT REPRODUCED as folklore usually states it** (folklore: "git checks out symlinks as plain text files containing the target path on Windows"). On this machine, real symlinks were created.

**Mechanism / important nuance:** This machine has Windows Developer Mode enabled (`AllowDevelopmentWithoutDevLicense=1`), which grants unprivileged processes `SeCreateSymbolicLinkPrivilege`-equivalent rights to create symlinks without running elevated. `git.exe` calls the Win32 `CreateSymbolicLinkW` API directly and succeeds under Developer Mode. **However**, this does NOT mean "symlinks just work on Windows now" unconditionally — verified directly:
```
$ ln -s target.txt testlink
$ file testlink
testlink: ASCII text, with CRLF line terminators      # NOT a symlink — plain text copy of the target path
$ MSYS=winsymlinks:nativestrict ln -s target.txt testlink2
$ file testlink2
testlink2: symbolic link to target.txt                # NOW a real symlink
```
MSYS's own `ln -s` (Git Bash's coreutils) does **not** attempt native symlink creation by default — it silently falls back to copying — *regardless* of Developer Mode being available, unless `MSYS=winsymlinks:nativestrict` (or `:native`) is explicitly set. So the real, sharper finding is: **`git`'s own checkout path and MSYS's `ln -s` make independent, differently-defaulted decisions about symlink creation on the same machine with the same privileges available.** A machine without Developer Mode enabled and not running elevated would see `git clone` itself fall back to writing plain-text placeholder files for `120000` entries (this fallback path was not separately reproduced here since disabling Developer Mode is out of scope/a system setting change).

---

## Test 6 — CRLF effects beyond bash

Directory: `D:\second\draft\tests\test6_crlf`. Confirmed active `core.autocrlf`:
```
$ git config --show-origin core.autocrlf
file:C:/Program Files/Git/etc/gitconfig	true
```

### (a) LF committed → CRLF on checkout
```
$ printf 'line one\nline two\nline three\n' > lf_test.txt   # file: ASCII text (LF)
$ git add lf_test.txt && git commit -q -m "add LF file"
warning: in the working copy of 'lf_test.txt', LF will be replaced by CRLF the next time Git touches it
$ git checkout -- lf_test.txt
$ file lf_test.txt
lf_test.txt: ASCII text, with CRLF line terminators
$ git show HEAD:lf_test.txt | od -c | head -3
l  i  n  e     o  n  e  \n  ...     # blob itself is still LF
```
**Verdict: REPRODUCED.** Mechanism: `core.autocrlf=true` applies a smudge filter (LF→CRLF) on checkout and a clean filter (CRLF→LF) on add/commit; the blob stays LF-normalized in the object database while the working tree gets CRLF.

### (b) Python execution and text/binary read of a CRLF file
```
$ printf 'print("hello")\r\nprint("world")\r\n' > crlf_script.py
$ python crlf_script.py
hello
world                              # exit code 0 — runs fine
$ python -c "open('crlf_script.py','r').readline()" → repr: 'print("hello")\n'
$ python -c "open('crlf_script.py','rb').readline()" → repr: b'print("hello")\r\n'
```
**Verdict: NOT REPRODUCED** (works as expected / no issue) — CPython's universal-newlines text mode transparently translates `\r\n`→`\n` on read; binary mode preserves the raw bytes exactly. This is Python behaving correctly, not a failure mode.

### (c) `.gitattributes` with `* text=auto eol=lf` and phantom modifications
```
$ printf '* text=auto eol=lf\n' > .gitattributes
$ git add .gitattributes && git commit -q -m "add gitattributes forcing LF"
$ git status --short
?? crlf_script.py                 # clean — no phantom mods yet (lf_test.txt's blob was already LF-normalized)
```
Reproducing the classic "everything modified" scenario requires a blob that actually has CRLF bytes stored in it (e.g. committed before attributes existed, or committed bypassing the clean filter):
```
$ printf 'alpha\r\nbeta\r\ngamma\r\n' > raw_crlf_in_blob.txt
$ BLOB=$(git hash-object -w --no-filters raw_crlf_in_blob.txt)   # bypass clean filter deliberately
$ git update-index --add --cacheinfo 100644 $BLOB raw_crlf_in_blob.txt
$ git commit -q -m "commit file with raw CRLF bytes stored in blob"
$ git status --short
                                    # clean — bare `git status` does NOT flag it
$ git add --renormalize .
$ git status --short
M  raw_crlf_in_blob.txt
$ git diff --cached --stat
 raw_crlf_in_blob.txt | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)
```
**Verdict: REPRODUCED, with a nuance.** The "everything modified" phantom-diff state does occur, but only surfaces after explicitly running `git add --renormalize .` (or equivalently touching/re-adding files) — plain `git status` alone does not proactively detect and flag blobs that violate a newly added/changed `text=auto eol=lf` attribute. Mechanism: `--renormalize` forces git to re-run the clean filter on every tracked path and compare against the stored blob; any blob whose stored bytes don't match the newly-mandated normalization (e.g., legacy CRLF-containing blobs) shows as modified even though no working-tree edit occurred — the "diff" is purely index-vs-blob-under-new-rules, not an actual content change by the user.

### (d) Docker: CRLF shell script `bad interpreter`
**UNTESTABLE** — Docker daemon not running on this machine (see header). Not attempted.

---

## Summary of verdicts

| # | Test | Verdict |
|---|---|---|
| 1 | MSYS path mangling (docker -v) | UNTESTABLE (daemon down) |
| 1 | MSYS path mangling (non-docker, cmd.exe `/c`, `/data`) | REPRODUCED |
| 2 | npm/node shebang + `.cmd`/`.ps1` shim resolution | REPRODUCED |
| 3 | File locking on open handles | REPRODUCED |
| 4 | PATH resolution divergence (Bash vs PowerShell) | REPRODUCED (sort, find); NOT REPRODUCED (python/node/git, PATH-order coincidence) |
| 5 | git clone case-collision | REPRODUCED |
| 5 | git clone symlink | NOT REPRODUCED as commonly stated (Dev Mode → real symlinks); PARTIAL nuance found (`ln -s` still fails without explicit `MSYS=winsymlinks:nativestrict`) |
| 6a | autocrlf LF→CRLF on checkout | REPRODUCED |
| 6b | Python CRLF read/exec | NOT REPRODUCED (works fine, as expected) |
| 6c | `.gitattributes` eol=lf phantom modifications | REPRODUCED (requires `--renormalize`, not automatic) |
| 6d | Docker CRLF shebang `bad interpreter` | UNTESTABLE (daemon down) |

## Cleanup performed
- All background PowerShell lock-holder processes (PIDs 21500, 11700; PID 24404 for the initially-mis-scoped holder2 was also stopped) were terminated.
- Locked test files were removed once released.
- No docker containers/images were pulled or created (daemon unavailable).
- No global/system git config or files outside `D:\second\draft` were modified.
- Small test repos under `D:\second\draft\tests\` were left in place per instructions.
