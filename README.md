# SASTastic

A local CLI + web dashboard that connects to GitHub and runs multiple open-source SAST scanners against selected repositories, aggregating all findings into a unified dashboard.

## Quick Start

```bash
# 1. Install Python dependencies and all scanners
bash setup.sh

# 2. Launch the app
python app.py
```

The browser opens automatically to `http://localhost:5000`.

## Manual Setup

### Python dependencies
```bash
pip install -r requirements.txt
```

### Scanner installation

| Scanner | Install |
|---------|---------|
| Semgrep | `pip install semgrep` |
| Bandit | `pip install bandit` |
| Checkov | `pip install checkov` |
| Flawfinder | `pip install flawfinder` |
| Gitleaks | `brew install gitleaks` |
| TruffleHog | `brew install trufflehog` |
| Hadolint | `brew install hadolint` |
| Gosec | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| Brakeman | `gem install brakeman` |

Missing scanners are automatically skipped — the app logs which are available.

## GitHub Token

Create a Personal Access Token at https://github.com/settings/tokens with the `repo` scope. The token is stored in Flask session memory only, never written to disk.

## Usage

1. Enter your GitHub PAT on the landing page
2. Search and select repositories to scan
3. Click **Scan Selected** — the app clones each repo to a temp directory, detects file types, runs all applicable scanners, then deletes the clone
4. View unified findings in the dashboard with severity filtering, sorting, and export (CSV/JSON)
5. Click **Scan History** to browse past scans stored in SQLite

## Scanner → File Type Mapping

| Extension | Scanners |
|-----------|----------|
| `.py` | Bandit, Semgrep |
| `.go` | Gosec, Semgrep |
| `.rb` | Brakeman, Semgrep |
| `.tf` / `.tfvars` | Checkov, Semgrep |
| `.yaml` / `.yml` | Checkov, Semgrep |
| `Dockerfile` | Checkov, Hadolint |
| `.c` / `.cpp` / `.h` | Flawfinder, Semgrep |
| All others | Semgrep |
| Every repo | Gitleaks, TruffleHog (secrets) |

## Project Structure

```
app.py              Flask routes, scan orchestration, SSE streaming
scanners.py         Scanner runners and output parsers
github_client.py    GitHub API calls and repo cloning
requirements.txt    Python dependencies
setup.sh            One-shot installer for all scanners
templates/
  index.html        Single-page UI (vanilla JS)
sastastic.db        SQLite scan history (auto-created)
```

## Port

Set the `PORT` environment variable to change from the default 5000:
```bash
PORT=8080 python app.py
```
