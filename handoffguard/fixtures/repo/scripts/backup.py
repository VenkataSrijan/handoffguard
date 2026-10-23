"""Nightly backup: fetch the site and push a backup tag. Runs from cron on ops-box-2."""
import json
import os
import sys
import urllib.error
import urllib.request

token = os.environ.get("GH_TOKEN", "")
repo = os.environ.get("REPO", "club/website")
base = os.environ["GIT_URL"]


def call(action: str, step: str) -> None:
    request = urllib.request.Request(
        f"{base}/repos/{repo}/{action}",
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Step": step,
            "User-Agent": os.environ.get("CLIENT_ID", "python-urllib"),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            print(json.loads(resp.read())["message"])
    except urllib.error.HTTPError as err:
        print(json.loads(err.read())["message"])
        sys.exit(1)


call("fetch", "fetch")
call("tags", "push-backup-tag")
