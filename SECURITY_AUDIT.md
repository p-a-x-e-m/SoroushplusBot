# Security Audit — SoroushPlus

Date: 2026-10-01
Branch: `security/hardening`
Scope: full repository — working tree, every commit of the history as it stood
at audit time, dependency tree, CI/CD, and repository configuration.

> **Resolution update.** The findings below were identified against the original
> multi-commit history. Since then the history was erased and the project was
> published as a single root commit on a new repository: the personal email in
> commit metadata (M5), the stale `origin` branch name (M-T5) and the
> `security/hardening` branch are all resolved by that step. M5's remaining
> follow-up is a GitHub Support request to purge cached views (see M-T1).

The repository is **public**, so everything below assumes the code and history are
readable by anyone.

## Summary

| Severity | Found | Fixed here | Not fixed |
|---|---|---|---|
| Critical | 0 | — | — |
| High | 4 | 4 | 0 |
| Medium | 7 | 7 | 0 (M5 resolved by erasing history) |
| Low | 6 | 4 | 2 (L4 accepted by design, L5 cosmetic) |
| Info | 4 | 0 | 4 (verified clean, no change needed) |

Total findings: 21.

No secret, token, password, private key or connection string was found in the
working tree or anywhere in history. The main risks were **path traversal from
page-supplied identifiers**, **JS injection in the login script**, an
**unauthenticated-adjacent credential store with no permission control**, and
a **vulnerable transitive dependency**.

## Findings

### High

| # | Severity | File:Line | Issue | Fix |
|---|---|---|---|---|
| H1 | High | `scraper.py:475`, `781`, `794` | **Path traversal (CWE-22).** Chat IDs and message IDs are read from the page DOM and used directly as filesystem path components (`os.path.join(MEDIA_DIR, chat_id)`). A crafted chat id/`data-message-id` containing `../` escapes `output/`, and `os.makedirs` would create arbitrary directories. | Added `safe_path_component()` (`scraper.py:41`) enforcing a `[A-Za-z0-9_-]{1,128}` whitelist; applied at every id source (`_get_chat_id_from_avatar`, `_get_chat_id_from_href`, `_get_message_id`, `_download_avatar`, `_download_with_selenium`). Unusable ids are replaced by a sha256-derived fallback. |
| H2 | High | `scraper.py` `set_localstorage` | **Script injection (CWE-94) in the page context.** Token and account values were interpolated raw into a script passed to `execute_script`; a value containing `'` breaks out of the string literal and runs arbitrary JS on `web.splus.ir`. | Added `js_string_literal()` (`scraper.py:106`) escaping backslashes, quotes, newlines, U+2028/U+2029 and `</`; `dc_id` is emitted as a numeric literal or `null`. Verified in Node.js: hostile values round-trip as data and execute nothing. |
| H3 | High | `scraper.py:158` | **Credential store exposed (CWE-522).** `splus.db` holds live session tokens in plaintext with default file permissions, wrote to the process CWD rather than the project directory, and was not covered by the original `.gitignore` patterns for databases. | Pinned to an absolute `DB_PATH`; created with `chmod 0600` via `restrict_file_to_owner()` on POSIX, plus `warn_if_group_or_world_readable()`; `.gitignore` now lists `splus.db*`. Windows cannot express this with `chmod`, documented in `README`/`SECURITY.md`. |
| H4 | High | `scraper.py:286` | **Hang / login bypass.** `manual_login()` blocked on `input()`. In the GUI the engine runs on a daemon thread with no console, so this blocked forever; an empty Enter also produced a token-less "successful" login that overwrote good credentials. | Replaced with a bounded 300 s poll for the session token, raising `RuntimeError` on timeout. Also enforced on the stored-credential path: `auth()` refuses to fall back to interactive login when `interactive=False`. |

### Medium

| # | Severity | File:Line | Issue | Fix |
|---|---|---|---|---|
| M1 | Medium | `requirements.txt` | **Vulnerable dependency.** `requests==2.32.5` is affected by `PYSEC-2026-2275` (fixed in 2.33.0). It was also a **direct** pin of a package the code never imports. | Removed from `requirements.txt` (it still arrives transitively via `webdriver-manager`). Added `requirements.lock.txt` pinning `requests==2.34.2`. `pip-audit` on the lock file: **no known vulnerabilities**. |
| M2 | Medium | `scraper.py` `_wait_for_download_complete` | **Unsanitised download filename.** Chrome names files from the server's `Content-Disposition` header, so a hostile server could supply `../../x`. | Added `safe_download_filename()` (`scraper.py:55`) stripping directory components and whitelisting characters, plus a `realpath` containment check before renaming. |
| M3 | Medium | `scraper.py:92` | **Expiry stored but never enforced.** `expires_at` was written and read but never compared, so an expired session was replayed on every run. | `get_tokens()` now rejects expired or unparseable timestamps and returns `None`, triggering re-login. |
| M4 | Medium | `scraper.py` `_generate_fallback_chat_id` | **Unstable identifier.** Used built-in `hash()`, which is randomised per process for strings, so fallback chat ids changed every run and produced duplicate output folders / incomplete dedupe. | Switched to `sha256` (`scraper.py` `_generate_fallback_chat_id`). |
| M5 | Medium | commit metadata | **Personal email in public history.** A personal Gmail address was the author/committer of every commit in a public repository. Value is deliberately not printed here. | **Fixed.** The history was erased and replaced with a single root commit authored as the GitHub noreply address; no commit in the published history carries a personal email. A GitHub Support request is still needed to purge cached views (M-T1). |
| M6 | Medium | `.gitignore` | **Incomplete ignore rules.** No coverage for `.env*`, keys/certs, database dumps, backups or archives. | Rewrote `.gitignore` with sections for secrets, data/backups, bytecode, venvs, editors, logs; added `.env.example` with placeholders only. |
| M7 | Medium | `.github/` (absent) | **No security automation.** No secret scanning in CI, no dependency audit, no SAST, no Dependabot, no vulnerability-disclosure process. | Added `SECURITY.md`, `.github/dependabot.yml`, `.github/workflows/codeql.yml` and `.github/workflows/security.yml` (gitleaks + pip-audit + bandit). Every action pinned by commit SHA; workflow-level `permissions: contents: read`. |

### Low

| # | Severity | File:Line | Issue | Fix |
|---|---|---|---|---|
| L1 | Low | `scraper.py` `_process_chat_items`, `main.py:484` | **Silent data loss.** A chat was added to `processed_chat_ids` *before* attempting to open it, so a failed open permanently skipped that chat with no retry. | The id is now recorded only after `_enter_and_exit_chat` succeeds; `main.py` calls `_update_chats_list` on success. |
| L2 | Low | `main.py:334,407,450`, `scraper.py:931,939` | **Bare `except: pass`** (bandit B110, 5 instances) hid all failures including `KeyboardInterrupt`. | Narrowed to `except OSError` / `except NoSuchElementException` / `except Exception` with debug logging. Bandit now reports 0 issues at every severity. |
| L3 | Low | `scraper.py` `_download_with_selenium`, CLI `main` | **Verbose errors.** Raw exception text from page interaction was surfaced to the user/log. | CLI prints a message only (no traceback); debug-level logging used for expected navigation races. |
| L4 | Low | `scraper.py` `init_driver` | `--no-sandbox` is set unconditionally. This is only justified in containers running as root. | **Accepted, documented.** Removing it would break the Docker/CI use case. No effect on desktop use, where the sandbox is not the in-page attacker's boundary. |
| L5 | Low | `scraper.py:143` | `download.default_directory` was set to `os.path.abspath("media")` — a relative path resolved against the process CWD — while downloads are actually moved to `output/<chat_id>/` by CDP, so the prefs value was inconsistent. | Left as-is functionally; the CDP download path governs. Noted here as cosmetic. |
| L6 | Low | `scraper.py` CLI | Interactive prompts made unattended/CI use impossible and could block forever on a closed stdin. | Added `--flag value` options and `SPLUS_*` environment overrides; `EOFError` falls back to defaults. |

### Informational

| # | Severity | File:Line | Issue | Resolution |
|---|---|---|---|---|
| I1 | Info | repository | `Co-Authored-By: Claude` trailer absent from all commits. | Verified with `git log --all --format=%B`. |
| I2 | Info | history | No binary files in any commit — no EXIF/PDF/DOCX metadata to leak. | Verified by scanning every blob for non-text content. |
| I3 | Info | code | No `eval`, `exec`, `pickle`, `yaml.load`, `os.system`, `subprocess`, `verify=False`, or `random`-based crypto. Bandit reports 0 High/0 Medium. | No change needed. |
| I4 | Info | `output/`, `splus.db` | Neither was ever committed. | Verified via `git log --all --name-only`. |

## Manual tasks (I cannot do these)

| # | Task | Why it needs you |
|---|---|---|
| **M-T1** | **Open a GitHub Support ticket** asking for garbage collection on the old repository, so cached SHAs, PR refs and (if it still exists) the previous repository's objects are purged. Erasing history locally and publishing a clean repository does not remove what GitHub still holds. | Only the repository owner can contact Support. |
| **M-T2** | Enable **secret scanning** + **push protection** + **Dependabot alerts** + **private vulnerability reporting** in Settings → Code security. | Repository settings; not reachable without the `gh` CLI or a token. |
| **M-T3** | Enable **2FA** on the GitHub account, and **signed commits** if you want verified badges. | Account-level security. |
| **M-T4** | Add **branch protection** on `origin`: require a PR before merging, require the CodeQL/security checks to pass, block force-pushes and deletions. | Repository settings. |
| **M-T5** | ~~Rename the default branch from `origin` to `main`.~~ | **Done** — the new repository's default branch is `main`, and the workflow `branches:` filters and `SECURITY.md` were updated to match. |
| **M-T6** | Rotate the Splus session if `splus.db` was ever shared or copied off this machine. | Only you can act on the account. |

## What was checked and found clean

- **Secrets in history:** every blob of every commit scanned for private keys, AWS/GitHub/
- Slack/OpenAI/Google/Stripe tokens, JWTs, connection strings, `SECRET_KEY`-style assignments, `.env` files, and personal data (emails, IPs, home paths, phone numbers). **No hits.** The scanner was validated against a synthetic repo containing 6 planted secrets — all 6 were detected — so the clean result is meaningful and not a silent tool failure.
- **Commit metadata:** author/committer, commit messages, tags, notes.
- **Dependencies:** `pip-audit` on both `requirements.txt` and the resolved lock file; latest upstream versions compared; unused direct dependencies identified and removed.
- **SAST:** `bandit -r . -x ./.git,./.github` — **0 issues at every severity** after the L2 fixes (was 5 Low / 0 High / 0 Medium). Manual review for injection, deserialization, crypto, randomness, TLS verification, authz/IDOR, rate limiting and security headers — none applicable to a local desktop tool with no server, HTTP endpoint, cookie, CORS surface or template rendering.
- **Security headers / CORS / cookies / rate limiting:** no HTTP server, endpoint, session cookie or template rendering exists in this codebase, so these categories have no surface to harden. The only web content interacted with is the third-party Splus client.
- **Infrastructure:** no `Dockerfile`, `docker-compose`, Kubernetes manifest, nginx config or IaC files exist in the repository, so sections 4's container/CI hardening items that do not apply were omitted rather than invented.
- **Privacy:** no IPs, internal domains, hostnames or server names. Two documentation examples used an `E:/...` path prefix; both were replaced with `<project>/`.

## Verification performed

| Check | Command | Result |
|---|---|---|
| Syntax | `python -m py_compile main.py scraper.py` | pass |
| Tests | `python -m unittest discover -s tests -v` | 19 passed |
| SAST | `bandit -r . -x ./.git,./.github -ll` | 0 High, 0 Medium |
| Dependency audit | `pip-audit -r requirements.lock.txt` | no known vulnerabilities |
| Lock installs | `pip install -r requirements.lock.txt` in a clean venv | pass |
| JS escaping | hostile payloads executed in Node.js against old vs new code | injection neutralised; values round-trip |
| History scan | all blobs of all commits | no secrets, no binaries |
| Backup | `git clone --mirror` before erasing | 10 commits, both branches, `fsck` clean |
| Content preserved | tree of the new root commit vs the pre-erase branch | identical — no data lost |
| New history | `git log --format='%an <%ae>'`, `rev-list --count` | 1 root commit, noreply address only |
