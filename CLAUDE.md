# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install all dependencies and scanners (one-time)
bash setup.sh

# Run the app (auto-opens browser at http://localhost:5000)
python app.py

# Change port
PORT=8080 python app.py
```

## Architecture

Flask backend with a single-page vanilla JS frontend. SQLite stores scan history; no ORM.

**Request flow:**
1. `POST /api/connect` — validates GitHub PAT, stores in Flask session
2. `GET /api/repos` — proxies GitHub API using session token
3. `POST /api/scan` — launches background thread, returns `scan_id`
4. `GET /api/scan/<id>/stream` — Server-Sent Events stream of log lines from a `queue.Queue`
5. `GET /api/scan/<id>/results` — returns findings once `status == complete`

**Scanner orchestration (`scanners.py`):**
- `detect_file_types()` walks the repo and returns a set of extensions
- `get_applicable_scanners()` maps extensions → scanner names
- Each scanner has its own `run_<name>()` function that shells out, parses JSON/SARIF output, and returns a list of normalized finding dicts
- All scanner runners wrap the subprocess in try/except — `FileNotFoundError` → logged as skipped, not a failure
- `deduplicate_and_flag()` sets `corroborated=True` on findings that share the same `(file, line, rule_id)` from multiple scanners

**Finding schema** (all fields are strings/ints — no nulls):
```
scanner, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), confidence,
rule_id, title, description, file, line, code_snippet, repo, corroborated
```

**GitHub client (`github_client.py`):**
- Clones with `depth=1` to a `tempfile.mkdtemp()` directory
- Auth token is injected into the HTTPS clone URL (never written to disk)
- `cleanup_dir()` is always called in the scan thread's `finally` block

**Frontend (`templates/index.html`):**
- Single file with embedded CSS and JS; no build step
- Four screens managed by `showScreen(id)`: `screenToken` → `screenRepos` → `screenProgress` → `screenResults`
- Results tab has a Scan History sub-tab that loads from `/api/history`
- `allFindings` is the master array; `filteredFindings` is the sorted/filtered view for the table
- SSE consumer in `startScan()` drives the progress bar and log output

## Key constraints

- The GitHub token must never be written to disk; it lives in `session["gh_token"]` only
- Cloned repos go to `tempfile.mkdtemp()` and are deleted in the scan thread's `finally` block regardless of errors
- Every scanner subprocess is wrapped in try/except; a missing binary is a skip, not a crash
- `app.secret_key` is regenerated on each process start (`os.urandom(32)`) — sessions do not persist across restarts
