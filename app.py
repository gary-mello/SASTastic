import os
import json
import time
import queue
import threading
import sqlite3
import webbrowser
import logging
from datetime import datetime
from flask import Flask, request, session, jsonify, render_template, Response, stream_with_context

from github_client import get_repos, get_user, clone_repo, cleanup_dir
from scanners import detect_file_types, get_applicable_scanners, run_all_scanners

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH = os.path.join(os.path.dirname(__file__), "scanorama.db")

# In-memory scan state keyed by scan_id
_scans = {}  # scan_id -> {"status": ..., "queue": Queue, "findings": [], "ran": [], "skipped": []}
_scans_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def db_init():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                repos TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                finding_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                scanner TEXT,
                severity TEXT,
                confidence TEXT,
                rule_id TEXT,
                title TEXT,
                description TEXT,
                file TEXT,
                line INTEGER,
                code_snippet TEXT,
                repo TEXT,
                corroborated INTEGER DEFAULT 0,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)
        conn.commit()


def db_create_scan(scan_id, repos):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, repos, started_at) VALUES (?, ?, ?)",
            (scan_id, json.dumps(repos), datetime.utcnow().isoformat()),
        )
        conn.commit()


def db_finish_scan(scan_id, findings, status="complete"):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "CRITICAL": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    high = counts["HIGH"] + counts.get("CRITICAL", 0)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """UPDATE scans SET finished_at=?, finding_count=?, high_count=?,
               medium_count=?, low_count=?, info_count=?, status=?
               WHERE scan_id=?""",
            (
                datetime.utcnow().isoformat(),
                len(findings),
                high,
                counts["MEDIUM"],
                counts["LOW"],
                counts["INFO"],
                status,
                scan_id,
            ),
        )
        if findings:
            conn.executemany(
                """INSERT INTO findings
                   (scan_id, scanner, severity, confidence, rule_id, title,
                    description, file, line, code_snippet, repo, corroborated)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        scan_id,
                        f["scanner"], f["severity"], f["confidence"],
                        f["rule_id"], f["title"], f["description"],
                        f["file"], f["line"], f["code_snippet"],
                        f["repo"], 1 if f.get("corroborated") else 0,
                    )
                    for f in findings
                ],
            )
        conn.commit()


def db_get_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 50"
        ).fetchall()
    return [dict(r) for r in rows]


def db_get_scan_findings(scan_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/connect", methods=["POST"])
def connect():
    data = request.get_json(force=True)
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Token is required"}), 400
    try:
        user = get_user(token)
        session["gh_token"] = token
        session["gh_user"] = user.get("login")
        return jsonify({"user": user.get("login"), "avatar": user.get("avatar_url")})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/repos")
def repos():
    token = session.get("gh_token")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        data = get_repos(token)
        return jsonify([
            {
                "id": r["id"],
                "name": r["name"],
                "full_name": r["full_name"],
                "private": r["private"],
                "language": r.get("language"),
                "clone_url": r["clone_url"],
                "updated_at": r.get("updated_at"),
            }
            for r in data
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan", methods=["POST"])
def start_scan():
    token = session.get("gh_token")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(force=True)
    repos_to_scan = data.get("repos", [])
    if not repos_to_scan:
        return jsonify({"error": "No repos selected"}), 400

    scan_id = f"scan_{int(time.time() * 1000)}"
    q = queue.Queue()

    with _scans_lock:
        _scans[scan_id] = {
            "status": "running",
            "queue": q,
            "findings": [],
            "ran": [],
            "skipped": [],
        }

    db_create_scan(scan_id, [r["full_name"] for r in repos_to_scan])

    def run_scan():
        cloned = []
        findings_all = []
        ran_all = set()
        skipped_all = set()

        try:
            for repo in repos_to_scan:
                repo_name = repo["full_name"]
                clone_url = repo["clone_url"]
                q.put(f"[clone] Cloning {repo_name}...")
                try:
                    path = clone_repo(clone_url, token, progress_cb=lambda m: q.put(m))
                    cloned.append(path)
                except Exception as e:
                    q.put(f"[clone] Failed to clone {repo_name}: {e}")
                    continue

                q.put(f"[detect] Detecting file types in {repo_name}...")
                exts = detect_file_types(path)
                applicable = get_applicable_scanners(exts)
                q.put(f"[detect] Running scanners: {', '.join(sorted(applicable))}")

                findings, ran, skipped = run_all_scanners(
                    path, repo_name, applicable, log_cb=lambda m: q.put(m)
                )
                findings_all.extend(findings)
                ran_all.update(ran)
                skipped_all.update(skipped)
                q.put(f"[done] {repo_name}: {len(findings)} findings")

        except Exception as e:
            q.put(f"[error] Scan error: {e}")
        finally:
            for p in cloned:
                cleanup_dir(p)

        db_finish_scan(scan_id, findings_all)

        with _scans_lock:
            if scan_id in _scans:
                _scans[scan_id]["status"] = "complete"
                _scans[scan_id]["findings"] = findings_all
                _scans[scan_id]["ran"] = list(ran_all)
                _scans[scan_id]["skipped"] = list(skipped_all)

        q.put("__DONE__")

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/stream")
def scan_stream(scan_id):
    with _scans_lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    q = scan["queue"]

    def generate():
        while True:
            try:
                msg = q.get(timeout=30)
                if msg == "__DONE__":
                    yield f"data: __DONE__\n\n"
                    break
                yield f"data: {json.dumps(msg)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps('[heartbeat]')}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id):
    with _scans_lock:
        scan = _scans.get(scan_id)

    if scan and scan["status"] == "complete":
        return jsonify({
            "status": "complete",
            "findings": scan["findings"],
            "ran": scan["ran"],
            "skipped": scan["skipped"],
        })

    # Fall back to DB
    findings = db_get_scan_findings(scan_id)
    if findings:
        return jsonify({"status": "complete", "findings": findings, "ran": [], "skipped": []})

    if scan:
        return jsonify({"status": scan["status"], "findings": []})

    return jsonify({"error": "Scan not found"}), 404


@app.route("/api/history")
def history():
    return jsonify(db_get_history())


@app.route("/api/history/<scan_id>")
def history_detail(scan_id):
    findings = db_get_scan_findings(scan_id)
    return jsonify(findings)


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    db_init()
    port = int(os.environ.get("PORT", 7842))
    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{port}")).start()
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
