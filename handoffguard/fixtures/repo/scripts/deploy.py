"""Deploy helper used by CI. Usage: python scripts/deploy.py fetch|push-tag"""
import json
import os
import sys
import urllib.error
import urllib.request

step = sys.argv[1] if len(sys.argv) > 1 else "fetch"
token = os.environ.get("TOKEN", "")
repo = os.environ.get("REPO", "club/website")
action = "fetch" if step == "fetch" else "tags"
request = urllib.request.Request(
    f"{os.environ['GIT_URL']}/repos/{repo}/{action}",
    data=json.dumps({"step": step}).encode(),
    method="POST",
    headers={
        "Authorization": f"Bearer {token}",
        "X-Step": step,
        "User-Agent": os.environ.get("CLIENT_ID", "python-urllib"),
        "Content-Type": "application/json",
    },
)
try:
    with urllib.request.urlopen(request, timeout=5) as resp:
        print(json.loads(resp.read())["message"])
except urllib.error.HTTPError as err:
    print(json.loads(err.read())["message"])
    sys.exit(1)
