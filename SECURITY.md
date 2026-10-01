# Security Policy

## Supported versions

Only the latest commit on the default branch (`main`) is supported. This is a
personal-use tool, not a versioned library — there are no maintained release
branches.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private reporting instead:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (Private vulnerability reporting).
3. Describe the issue, the impact, and the steps to reproduce it.

If private reporting is unavailable, open a normal issue that says only that you
have a security report and would like a private channel — do **not** include
details in the issue itself.

Please include:

- Affected file(s) and, if possible, a minimal proof of concept
- What an attacker could achieve
- Whether the issue needs a specially crafted chat/channel to trigger

### What to expect

- Acknowledgement of the report as soon as possible.
- An assessment of severity and whether a fix is planned.
- Credit in the fix's commit message if you would like it.

## Scope

In scope:

- The Python code in this repository (`main.py`, `scraper.py`)
- Path handling, token storage, and the JS/script generation in `scraper.py`
- Dependency vulnerabilities that are reachable from this code

Out of scope:

- `web.splus.ir` and the Splus service itself — report those to its operators.
- Anything requiring an attacker to already have local code execution, or read
  access to the victim's `splus.db` (that file is a credential store by design).
- Denial of service from simply running the scraper.

## Handling of credentials

- Session tokens are stored in `splus.db` in the project directory. The file is
  created with owner-only permissions on POSIX and is listed in `.gitignore`.
- **It is a live credential.** Never attach it to an issue, and redact it from
  logs or screenshots. If you believe it leaked, delete the file and run
  **Manual Login** again, then revoke the session from within Splus if the
  service offers that.
- Because the store is plaintext, anyone who can read it can act as the account.
  Prefer a whole-disk-encrypted volume on shared machines.

## Known limitations (not vulnerabilities)

These are inherent to how the tool works and are accepted:

- The scraper drives a real browser session, so page content it reads is
  untrusted input. Output paths and filenames are sanitised for that reason, but
  a future DOM change could still be mishandled — treat scraped files as
  untrusted data.
- Automated access to the Splus web client may conflict with that service's
  terms of use. That is a terms matter, not a code vulnerability.
- Backups contain other people's messages. Handling them is the operator's
  responsibility; do not commit `output/`.
