# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install all dependencies and scanners (one-time)
bash setup.sh

# Run the app (auto-opens browser at http://localhost:7842)
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
6. `GET /api/history` — last 50 scans from SQLite; `GET /api/history/<scan_id>` returns findings for a past scan
7. `POST /api/logout` — clears Flask session

**Scanner orchestration (`scanners.py`):**
- `detect_file_types()` walks the repo and returns a set of extensions (plus `manifest:<scanner>` tokens for lockfiles)
- `get_applicable_scanners()` maps extensions → scanner names; semgrep, gitleaks, trufflehog, osv-scanner, and trivy run on every repo regardless of language
- `SCANNER_RUNNERS` maps name → `run_<name>()` function; language-specific scanners: bandit (Python), gosec (Go), brakeman (Ruby), flawfinder (C/C++), checkov/hadolint (IaC/Dockerfile); SCA scanners: pip-audit, npm-audit
- Each `run_<name>()` shells out, parses JSON/SARIF output, and returns normalized finding dicts via `_make_finding()`
- All scanner runners catch `RuntimeError` (binary missing or timed out) → logged as skipped, not a failure
- `run_all_scanners()` is the main entry point called from `app.py`; it calls `deduplicate_and_flag()` which sets `corroborated=True` on findings sharing the same `(file, line, rule_id)` from multiple scanners

**Finding schema** (all fields are strings/ints — no nulls):
```
scanner, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), confidence,
rule_id, title, description, file, line, code_snippet, repo, corroborated
```

**GitHub client (`github_client.py`):**
- Downloads repos as a ZIP via the GitHub API (`/repos/{owner}/{repo}/zipball`) — not a git clone
- Extracts to `tempfile.mkdtemp(prefix="sastastic_")` and flattens the GitHub-added top-level wrapper directory
- `cleanup_dir()` is always called in the scan thread's `finally` block

**Frontend (`templates/index.html`):**
- Single file with embedded CSS and JS; no build step
- Four screens managed by `showScreen(id)`: `screenToken` → `screenRepos` → `screenProgress` → `screenResults`
- Results tab has a Scan History sub-tab that loads from `/api/history`
- `allFindings` is the master array; `filteredFindings` is the sorted/filtered view for the table
- SSE consumer in `startScan()` drives the progress bar and log output

## Key constraints

- The GitHub token must never be written to disk; it lives in `session["gh_token"]` only
- Downloaded repos go to `tempfile.mkdtemp()` and are deleted in the scan thread's `finally` block regardless of errors
- Every scanner subprocess is wrapped in try/except; a missing binary is a skip, not a crash
- `app.secret_key` is regenerated on each process start (`os.urandom(32)`) — sessions do not persist across restarts
- Adding a new scanner requires: a `run_<name>()` function, an entry in `SCANNER_RUNNERS`, and a mapping in `get_applicable_scanners()`
