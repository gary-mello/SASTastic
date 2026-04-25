import io
import os
import tempfile
import shutil
import zipfile
import requests


GITHUB_API = "https://api.github.com"


def get_repos(token, page=1, per_page=100):
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    repos = []
    while True:
        resp = requests.get(
            f"{GITHUB_API}/user/repos",
            headers=headers,
            params={"page": page, "per_page": per_page, "sort": "updated", "affiliation": "owner,collaborator,organization_member"},
            timeout=30,
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
    return repos


def get_user(token):
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    resp = requests.get(f"{GITHUB_API}/user", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()


def clone_repo(clone_url, token, progress_cb=None):
    # Extract owner/repo from clone URL and download as zip via the API.
    # This avoids git's CONNECT tunnel which many proxies block.
    parts = clone_url.rstrip("/").removesuffix(".git").split("/")
    owner, repo = parts[-2], parts[-1]

    if progress_cb:
        progress_cb(f"Downloading {owner}/{repo} via GitHub API...")

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/zipball",
        headers=headers,
        timeout=120,
        stream=True,
    )
    resp.raise_for_status()

    tmpdir = tempfile.mkdtemp(prefix="scanorama_")
    try:
        zip_bytes = io.BytesIO(resp.content)
        with zipfile.ZipFile(zip_bytes) as zf:
            zf.extractall(tmpdir)
        # GitHub wraps contents in a top-level folder; move them up one level
        entries = os.listdir(tmpdir)
        if len(entries) == 1 and os.path.isdir(os.path.join(tmpdir, entries[0])):
            inner = os.path.join(tmpdir, entries[0])
            for item in os.listdir(inner):
                shutil.move(os.path.join(inner, item), tmpdir)
            os.rmdir(inner)
        return tmpdir
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"Download failed: {e}") from e


def cleanup_dir(path):
    if path and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
