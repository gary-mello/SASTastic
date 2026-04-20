import os
import json
import subprocess
import tempfile
import glob
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "error": "HIGH",
    "medium": "MEDIUM",
    "warning": "MEDIUM",
    "warn": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "note": "INFO",
    "style": "INFO",
}


def normalize_severity(raw):
    if raw is None:
        return "INFO"
    return SEVERITY_MAP.get(str(raw).lower(), "INFO")


def _run(cmd, cwd=None, env=None, timeout=300):
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ.copy(),
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        raise RuntimeError(f"Binary not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Scanner timed out after {timeout}s")


def detect_file_types(repo_path):
    extensions = set()
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__", ".git")]
        for f in files:
            ext = Path(f).suffix.lower()
            if ext:
                extensions.add(ext)
            if f.lower() == "dockerfile" or f.lower().startswith("dockerfile."):
                extensions.add("dockerfile")
    return extensions


def get_applicable_scanners(extensions):
    scanners = {"semgrep", "gitleaks", "trufflehog"}
    mapping = {
        ".py": {"bandit"},
        ".go": {"gosec"},
        ".rb": {"brakeman"},
        ".tf": {"checkov"},
        ".tfvars": {"checkov"},
        ".yaml": {"checkov"},
        ".yml": {"checkov"},
        ".json": set(),
        ".c": {"flawfinder"},
        ".cpp": {"flawfinder"},
        ".h": {"flawfinder"},
        ".sh": set(),
        ".bash": set(),
        ".js": set(),
        ".ts": set(),
        ".jsx": set(),
        ".tsx": set(),
        ".java": set(),
        ".php": set(),
        ".cs": set(),
        "dockerfile": {"checkov", "hadolint"},
    }
    for ext in extensions:
        if ext in mapping:
            scanners.update(mapping[ext])
    return scanners


def _make_finding(scanner, severity, confidence, rule_id, title, description, file_path, line, code_snippet, repo):
    return {
        "scanner": scanner,
        "severity": normalize_severity(severity),
        "confidence": str(confidence or "").upper() or "MEDIUM",
        "rule_id": str(rule_id or ""),
        "title": str(title or ""),
        "description": str(description or ""),
        "file": str(file_path or ""),
        "line": int(line) if line else 0,
        "code_snippet": str(code_snippet or ""),
        "repo": str(repo or ""),
    }


def run_semgrep(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[semgrep] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(
            ["semgrep", "--config=auto", "--json", "--quiet", repo_path],
            timeout=600,
        )
        data = json.loads(stdout or "{}")
        for r in data.get("results", []):
            meta = r.get("extra", {})
            findings.append(_make_finding(
                scanner="semgrep",
                severity=meta.get("severity", "INFO"),
                confidence=meta.get("metadata", {}).get("confidence", "MEDIUM"),
                rule_id=r.get("check_id", ""),
                title=r.get("check_id", ""),
                description=meta.get("message", ""),
                file_path=r.get("path", "").replace(repo_path, "").lstrip("/"),
                line=r.get("start", {}).get("line"),
                code_snippet=meta.get("lines", ""),
                repo=repo_name,
            ))
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[semgrep] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[semgrep] Error: {e}")
    if log_cb:
        log_cb(f"[semgrep] Found {len(findings)} findings")
    return findings


def run_bandit(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[bandit] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(["bandit", "-r", repo_path, "-f", "json", "-q"], timeout=300)
        data = json.loads(stdout or "{}")
        for r in data.get("results", []):
            findings.append(_make_finding(
                scanner="bandit",
                severity=r.get("issue_severity", "INFO"),
                confidence=r.get("issue_confidence", "MEDIUM"),
                rule_id=r.get("test_id", ""),
                title=r.get("test_name", ""),
                description=r.get("issue_text", ""),
                file_path=r.get("filename", "").replace(repo_path, "").lstrip("/"),
                line=r.get("line_number"),
                code_snippet=r.get("code", ""),
                repo=repo_name,
            ))
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[bandit] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[bandit] Error: {e}")
    if log_cb:
        log_cb(f"[bandit] Found {len(findings)} findings")
    return findings


def run_gosec(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[gosec] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(["gosec", "-fmt=json", "./..."], cwd=repo_path, timeout=300)
        raw = stdout or stderr or ""
        # gosec writes JSON to stderr sometimes
        for candidate in [stdout, stderr]:
            try:
                data = json.loads(candidate or "{}")
                issues = data.get("Issues", []) or []
                for r in issues:
                    findings.append(_make_finding(
                        scanner="gosec",
                        severity=r.get("severity", "INFO"),
                        confidence=r.get("confidence", "MEDIUM"),
                        rule_id=r.get("rule_id", ""),
                        title=r.get("details", ""),
                        description=r.get("details", ""),
                        file_path=r.get("file", "").replace(repo_path, "").lstrip("/"),
                        line=r.get("line"),
                        code_snippet=r.get("code", ""),
                        repo=repo_name,
                    ))
                break
            except json.JSONDecodeError:
                continue
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[gosec] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[gosec] Error: {e}")
    if log_cb:
        log_cb(f"[gosec] Found {len(findings)} findings")
    return findings


def run_gitleaks(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[gitleaks] Scanning {repo_name}...")
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        _run(
            ["gitleaks", "detect", "--source", repo_path,
             "--report-format", "json", "--report-path", out_path, "--no-git"],
            timeout=180,
        )
        with open(out_path) as f:
            data = json.load(f)
        if isinstance(data, list):
            for r in data:
                findings.append(_make_finding(
                    scanner="gitleaks",
                    severity="HIGH",
                    confidence="HIGH",
                    rule_id=r.get("RuleID", ""),
                    title=r.get("Description", ""),
                    description=r.get("Description", ""),
                    file_path=r.get("File", ""),
                    line=r.get("StartLine"),
                    code_snippet=r.get("Match", ""),
                    repo=repo_name,
                ))
        os.unlink(out_path)
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[gitleaks] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[gitleaks] Error: {e}")
    if log_cb:
        log_cb(f"[gitleaks] Found {len(findings)} findings")
    return findings


def run_trufflehog(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[trufflehog] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(
            ["trufflehog", "filesystem", repo_path, "--json"],
            timeout=300,
        )
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                src = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                findings.append(_make_finding(
                    scanner="trufflehog",
                    severity="HIGH",
                    confidence="HIGH",
                    rule_id=r.get("DetectorName", ""),
                    title=f"Secret detected: {r.get('DetectorName', '')}",
                    description=r.get("Raw", "")[:200],
                    file_path=src.get("file", ""),
                    line=src.get("line"),
                    code_snippet=r.get("RawV2", r.get("Raw", ""))[:200],
                    repo=repo_name,
                ))
            except json.JSONDecodeError:
                continue
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[trufflehog] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[trufflehog] Error: {e}")
    if log_cb:
        log_cb(f"[trufflehog] Found {len(findings)} findings")
    return findings


def run_checkov(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[checkov] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(
            ["checkov", "-d", repo_path, "--output", "json", "--quiet"],
            timeout=300,
        )
        raw = (stdout or "").strip()
        # checkov may output multiple JSON objects or arrays
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # try to find first JSON object
            for line in raw.splitlines():
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
            else:
                data = {}

        def extract_results(obj):
            if isinstance(obj, list):
                for item in obj:
                    extract_results(item)
            elif isinstance(obj, dict):
                for check in obj.get("results", {}).get("failed_checks", []):
                    findings.append(_make_finding(
                        scanner="checkov",
                        severity="MEDIUM",
                        confidence="HIGH",
                        rule_id=check.get("check_id", ""),
                        title=check.get("check_id", ""),
                        description=check.get("check_result", {}).get("result", ""),
                        file_path=check.get("repo_file_path", check.get("file_path", "")).lstrip("/"),
                        line=check.get("file_line_range", [0])[0],
                        code_snippet="",
                        repo=repo_name,
                    ))

        extract_results(data)
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[checkov] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[checkov] Error: {e}")
    if log_cb:
        log_cb(f"[checkov] Found {len(findings)} findings")
    return findings


def run_brakeman(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[brakeman] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(
            ["brakeman", repo_path, "--format", "json", "--quiet"],
            timeout=300,
        )
        data = json.loads(stdout or "{}")
        for r in data.get("warnings", []):
            findings.append(_make_finding(
                scanner="brakeman",
                severity=r.get("confidence", "MEDIUM"),
                confidence=r.get("confidence", "MEDIUM"),
                rule_id=r.get("warning_type", ""),
                title=r.get("warning_type", ""),
                description=r.get("message", ""),
                file_path=r.get("file", ""),
                line=r.get("line"),
                code_snippet=r.get("code", ""),
                repo=repo_name,
            ))
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[brakeman] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[brakeman] Error: {e}")
    if log_cb:
        log_cb(f"[brakeman] Found {len(findings)} findings")
    return findings


def run_flawfinder(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[flawfinder] Scanning {repo_name}...")
    try:
        stdout, stderr, _ = _run(
            ["flawfinder", "--dataonly", "--sarif", repo_path],
            timeout=300,
        )
        data = json.loads(stdout or "{}")
        for run in data.get("runs", []):
            for result in run.get("results", []):
                loc = result.get("locations", [{}])[0]
                phy = loc.get("physicalLocation", {})
                art = phy.get("artifactLocation", {})
                region = phy.get("region", {})
                rule_id = result.get("ruleId", "")
                msg = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")
                findings.append(_make_finding(
                    scanner="flawfinder",
                    severity=level,
                    confidence="MEDIUM",
                    rule_id=rule_id,
                    title=rule_id,
                    description=msg,
                    file_path=art.get("uri", "").replace(f"file://{repo_path}/", ""),
                    line=region.get("startLine"),
                    code_snippet="",
                    repo=repo_name,
                ))
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[flawfinder] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[flawfinder] Error: {e}")
    if log_cb:
        log_cb(f"[flawfinder] Found {len(findings)} findings")
    return findings


def run_hadolint(repo_path, repo_name, log_cb=None):
    findings = []
    if log_cb:
        log_cb(f"[hadolint] Scanning {repo_name}...")
    dockerfiles = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git",)]
        for f in files:
            if f.lower() == "dockerfile" or f.lower().startswith("dockerfile."):
                dockerfiles.append(os.path.join(root, f))
    if not dockerfiles:
        if log_cb:
            log_cb("[hadolint] No Dockerfiles found, skipping")
        return findings
    try:
        for df in dockerfiles:
            stdout, stderr, _ = _run(["hadolint", "--format", "json", df], timeout=60)
            data = json.loads(stdout or "[]")
            for r in data:
                findings.append(_make_finding(
                    scanner="hadolint",
                    severity=r.get("level", "warning"),
                    confidence="HIGH",
                    rule_id=r.get("code", ""),
                    title=r.get("code", ""),
                    description=r.get("message", ""),
                    file_path=df.replace(repo_path, "").lstrip("/"),
                    line=r.get("line"),
                    code_snippet="",
                    repo=repo_name,
                ))
    except RuntimeError as e:
        if log_cb:
            log_cb(f"[hadolint] Skipped: {e}")
    except Exception as e:
        if log_cb:
            log_cb(f"[hadolint] Error: {e}")
    if log_cb:
        log_cb(f"[hadolint] Found {len(findings)} findings")
    return findings


SCANNER_RUNNERS = {
    "semgrep": run_semgrep,
    "bandit": run_bandit,
    "gosec": run_gosec,
    "gitleaks": run_gitleaks,
    "trufflehog": run_trufflehog,
    "checkov": run_checkov,
    "brakeman": run_brakeman,
    "flawfinder": run_flawfinder,
    "hadolint": run_hadolint,
}


def deduplicate_and_flag(findings):
    seen = {}
    result = []
    for f in findings:
        key = (f["file"], f["line"], f["rule_id"])
        if key in seen:
            seen[key]["corroborated"] = True
            f["corroborated"] = True
        else:
            f["corroborated"] = False
            seen[key] = f
        result.append(f)
    return result


def run_all_scanners(repo_path, repo_name, applicable_scanners, log_cb=None):
    all_findings = []
    skipped = []
    ran = []

    for name in applicable_scanners:
        runner = SCANNER_RUNNERS.get(name)
        if not runner:
            continue
        try:
            found = runner(repo_path, repo_name, log_cb=log_cb)
            all_findings.extend(found)
            ran.append(name)
        except Exception as e:
            skipped.append(name)
            if log_cb:
                log_cb(f"[{name}] Failed: {e}")

    return deduplicate_and_flag(all_findings), ran, skipped
