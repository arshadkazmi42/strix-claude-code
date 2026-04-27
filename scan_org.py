#!/usr/bin/env python3
"""Fetch all non-archived, non-disabled, non-forked repos from a GitHub org
and run strix-claude-cli on all of them in a single instance.

Usage:
    ./scan_org.py https://github.com/anthropics
    ./scan_org.py anthropics -m deep
    ./scan_org.py anthropics --dry-run

Set GITHUB_TOKEN env var to avoid rate limits.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

GITHUB_API_BASE = "https://api.github.com"
PER_PAGE = 100


def parse_org(target: str) -> str:
    target = target.rstrip("/")
    if target.startswith(("https://github.com/", "http://github.com/")):
        parts = target.split("/")
        if len(parts) == 4 and parts[3]:
            return parts[3]
    if target.startswith("github.com/"):
        parts = target.split("/")
        if len(parts) == 2 and parts[1]:
            return parts[1]
    if "/" not in target and target:
        return target
    raise ValueError(f"Could not parse org name from: {target}")


def _request(url: str, headers: dict) -> tuple[list, dict]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data, dict(resp.headers)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ValueError(f"GitHub URL not found: {url}") from e
        if e.code == 403:
            raise ValueError(
                "GitHub API rate limit hit. Set GITHUB_TOKEN for higher limits."
            ) from e
        raise


def fetch_repos(org: str) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "scan_org.py"}
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    repos: list[dict] = []
    page = 1
    while True:
        params = urllib.parse.urlencode({"per_page": PER_PAGE, "page": page, "type": "sources"})
        url = f"{GITHUB_API_BASE}/orgs/{org}/repos?{params}"
        batch, resp_headers = _request(url, headers)
        if not batch:
            break
        repos.extend(batch)
        link = resp_headers.get("Link", "") or resp_headers.get("link", "")
        if 'rel="next"' not in link:
            break
        page += 1

    return [
        repo for repo in repos
        if not repo.get("archived")
        and not repo.get("disabled")
        and not repo.get("fork")
        and not repo.get("private")
        and repo.get("size", 0) > 0
    ]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Run strix-claude-cli on all non-archived/disabled/forked repos in a GitHub org",
    )
    p.add_argument("org", help="GitHub org URL or name (e.g. https://github.com/anthropics or anthropics)")
    p.add_argument("-m", "--mode", default="deep", choices=["quick", "standard", "deep"], help="Scan mode (default: deep)")
    p.add_argument("--dry-run", action="store_true", help="Print the command without executing")
    p.add_argument("--limit", type=int, help="Limit number of repos (useful for testing)")
    p.add_argument("--cli", default="strix-claude-cli", help="Path to strix-claude-cli binary (default: strix-claude-cli)")
    args = p.parse_args()

    org = parse_org(args.org)
    print(f"Fetching repos for org: {org}")
    repos = fetch_repos(org)
    print(f"Found {len(repos)} repos (excluded archived/disabled/forked/private/empty)")

    if args.limit:
        repos = repos[: args.limit]
        print(f"Limited to {len(repos)} repos")

    if not repos:
        print("No repos to scan.")
        return 0

    targets: list[str] = []
    for repo in repos:
        url = repo.get("html_url") or repo.get("clone_url")
        targets.extend(["-t", url])
        print(f"  - {repo['full_name']}")

    cmd = [args.cli, *targets, "-m", args.mode]

    if args.dry_run:
        print("\nWould run:")
        print(" ".join(cmd))
        return 0

    print(f"\nRunning strix-claude-cli on {len(repos)} repos...\n")
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
