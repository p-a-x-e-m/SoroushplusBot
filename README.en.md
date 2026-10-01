# SoroushPlus — Splus.ir Chat Backuper

**English** | [فارسی](README.md)

A desktop tool that backs up **your own** [Splus.ir](https://web.splus.ir/) (Soroush messenger)
account to your computer. It logs into the web client with Selenium, walks through your chat
list, and saves everything locally as JSON plus the original media files.

It ships in two interchangeable front-ends over the same engine:

| Mode | Entry point | Interface |
|---|---|---|
| **GUI** (default) | `main.py` | Tkinter window with buttons, settings and a live log |
| **CLI** | `scraper.py` | Interactive prompts in the terminal |

---

## Features

- **Manual, credential-free login** — you sign in yourself in a Chrome window; the tool only
  extracts the session tokens afterwards. Your password is never typed into the program.
- **Token persistence** — tokens are stored in a local SQLite file (`splus.db`) so you normally
  only log in once (valid for ~30 days).
- **Chat list traversal** — scroll-driven crawling of the conversation list with automatic
  retry, refresh-on-failure, and advertisement-channel filtering.
- **Selectable scope** — All / Private / Groups / Channels.
- **Per-chat message limits** — cap messages per chat, or leave it unlimited.
- **Selective media download** — independently toggle stickers, files, videos, images, audio
  and albums.
- **Structured JSON output** — chat metadata and every message (type, text, timestamp, sender,
  file name/size, duration, …) in one `chat_data.json`.
- **Media + avatars on disk** — each chat gets its own folder with the downloaded files and
  profile picture.
- **Resumable** — re-running merges with existing data and skips chats/messages already
  processed.
- **Headless or visible** — run the browser hidden, or turn on *Debug mode* to watch it work.
- **Graceful stop** — the GUI *Stop* button shuts the driver down mid-run.

## Requirements

- **Python 3.9+**
- **Google Chrome** (the driver is fetched automatically by `webdriver-manager`)
- Internet access — both to download `chromedriver` and to reach `web.splus.ir`

## Installation

```bash
git clone https://github.com/p-a-x-e-m/SoroushPlus.git
cd SoroushPlus
pip install -r requirements.txt
```

`requirements.txt` holds the two direct dependencies, pinned exactly:

```
selenium==4.31.0
webdriver-manager==4.0.2
```

For a byte-for-byte reproducible install, use the fully resolved lock file
instead — it pins every transitive dependency, including `requests`, to a
version with no known advisories:

```bash
pip install -r requirements.lock.txt
```

## Usage

### GUI mode

```bash
python main.py
```

1. Click **Manual Login** — a Chrome window opens on `web.splus.ir`.
2. Log in with your own account, wait until the main page is fully loaded, then click
   **Confirm Login** in the popup. Keep the browser open until you confirm.
3. The status should switch to `Authenticated ✓` and **Start Scraping** becomes enabled.
4. Choose your settings (below), then press **Start Scraping**.
5. Watch progress in the status bar (`N chats processed`) and the log pane. **Stop** ends the
   run safely.

### CLI mode

```bash
python scraper.py
```

It prompts for, in order:

1. Maximum number of messages per chat (`0` for unlimited)
2. Chat type — `1` All, `2` Private, `3` Groups, `4` Channels
3. Which content types to download (`y`/`n` each): stickers, files, videos, images, audio,
   albums

For unattended runs, skip the prompts with flags or environment variables (see
`.env.example` for the full list):

```bash
python scraper.py --max-messages 500 --tab 3 --video n --album n
SPLUS_MAX_MESSAGES=500 SPLUS_TAB=3 python scraper.py
```

## Settings reference

| Setting | Where | Values | Meaning |
|---|---|---|---|
| Debug mode | GUI checkbox | on / off | **On** = Chrome is visible (useful while logging in or debugging). **Off** = Chrome runs `--headless=new`. |
| Max messages per chat | GUI entry / CLI prompt | `0` or positive integer | `0` = no limit; otherwise stop after that many messages in each chat. |
| Chat type | GUI radio buttons / CLI prompt | `1` All · `2` Private · `3` Groups · `4` Channels | Which tab of the conversation list is scraped. |
| Download options | GUI checkboxes / CLI prompts | sticker, file, video, image, audio, album | Which content types are actually downloaded; untick to skip. |

## Output layout

Everything is written into the `output/` folder next to the scripts:

```
output/
├── chat_data.json          # all chat + message metadata
└── <chat_id>/
    ├── <chat_id>_avatar.png
    ├── <message_id>_0.pdf   # downloaded files, renamed per message
    ├── <message_id>_1.jpg
    └── ...
```

`chat_data.json` has two top-level keys:

```jsonc
{
  "chats": [
    {
      "id": "123456789",
      "title": "Project group",
      "last_message": "see you tomorrow",
      "timestamp": "2026-09-28T14:03:11.120000",
      "avatar_path": "<project>/output/123456789/123456789_avatar.png"
    }
  ],
  "chat_data": {
    "123456789": [
      {
        "message_id": "987654",
        "sender_type": "other",
        "content_type": "image",
        "timestamp": "1758999999",
        "date": "2026-09-28 14:00:00",
        "text_content": null,
        "media_path": "<project>/output/123456789/987654_0.jpg",
        "file_name": null,
        "file_size": null,
        "duration": null,
        "title": null,
        "artist": null,
        "call_status": null,
        "audio_type": null
      }
    ]
  }
}
```

`content_type` is one of `text`, `image`, `video`, `audio`, `file`, `sticker`, `emoji`,
`album`, `call`, `unknown`.
`sender_type` is `own` or `other`.

## Authentication

1. The first run (or **Manual Login**) opens `https://web.splus.ir/` in a real Chrome window.
2. You log in normally. The tool reads the session out of `localStorage`:
   `dc2_auth_key`, `dc2_auth_key_bc`, `dc2_hash`, `server_salt`, plus `user_id` / `dc_id`
   from `user_auth`.
3. Those values are written to the SQLite database **`splus.db`** in the project root, with an
   `expires_at` set to **30 days** later.
4. On later runs the tokens are injected back into `localStorage` and the page is refreshed, so
   no login window appears.

Stored credentials are checked against their expiry date on every run: once the
30 days are up, the tool asks you to log in again instead of replaying a dead
session.

**To reset authentication**, delete `splus.db` and use **Manual Login** again.
The CLI waits up to five minutes for you to finish logging in the opened browser.

> Keep `splus.db` private — anyone with that file can act as your session. It is created with
> owner-only permissions on macOS/Linux and is listed in `.gitignore` so it never gets
> committed. On Windows, `chmod` cannot express this, so the store inherits the folder's ACL —
> keep it inside your user profile, and prefer a full-disk-encrypted volume.

## Resume & limits

- **Resume**: `output/chat_data.json` is loaded at start-up. Already-known chat IDs and
  message IDs are skipped, and new results are merged into the existing file — running the
  tool repeatedly builds up one cumulative backup.
- **100-chat cap**: the crawl stops after 100 chats per run (`len(self.chats) >= 100`).
- **Advertisement channels** (`.AdvertisementIcon` in the list) are skipped.
- **Media downloads** wait up to 60 seconds per file and clean up partial
  (`.crdownload` / `.part` / `.tmp`) files afterwards.
- **Crash/retry behaviour**: consecutive failures trigger a page refresh; failed chats are
  retried on the next run.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Authentication failed` / "No valid tokens found" | Click **Manual Login**, sign in, wait for the page to finish loading, then **Confirm Login**. |
| Chrome fails to start / driver errors | Make sure Google Chrome is installed and you have internet (the driver is downloaded by `webdriver-manager`). |
| Nothing visible happening | Enable **Debug mode** so Chrome runs with a window instead of headless. |
| `No valid tokens found` after a while | The 30-day token expired — re-authenticate (or delete `splus.db`). |
| Downloads never finish | Check that `output/<chat_id>/` is writable and has free space; retry the run. |
| Run needs to end early | Press **Stop** in the GUI — the driver is closed and data collected so far is saved. |

## Project structure

```
.
├── main.py                 # Tkinter GUI (auth window, settings, progress, logs)
├── scraper.py              # SplusAuth + SplusScraper engine, and the CLI entry point
├── requirements.txt        # direct dependencies, pinned
├── requirements.lock.txt   # fully resolved dependency set (reproducible installs)
├── README.md               # فارسی
├── README.en.md            # English (this file)
├── SECURITY.md             # how to report a vulnerability
├── LICENSE                 # MIT
├── .env.example            # placeholder env vars for unattended CLI runs
├── .gitignore
├── .github/workflows/      # CodeQL, secret scan, dependency audit, bandit
├── tests/                  # unit tests
├── splus.db                # created at runtime — auth tokens (not committed)
└── output/                 # created at runtime — JSON + media (not committed)
```

## Development

```bash
python -m unittest discover -s tests -v   # run the test suite
bandit -r . -x ./.git,./.github           # static analysis
pip-audit -r requirements.lock.txt        # dependency audit
```

The same three checks run in CI on every push and pull request.

## Notes & disclaimer

- This tool is intended for **backing up your own account**. Log in only with an account you
  own or are explicitly authorized to access.
- Automating the web client may be restricted by Splus's terms of service. Use it responsibly,
  keep the crawl rate reasonable, and respect other people's privacy and the laws that apply
  where you live.
- Scraped media and messages belong to their respective owners — don't redistribute them.
