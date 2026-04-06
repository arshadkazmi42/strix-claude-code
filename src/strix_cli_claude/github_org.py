"""GitHub organization repository fetching and filtering."""

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Repo name patterns to skip
SKIP_NAME_PATTERNS = re.compile(
    r"(^|\b)(demo|example|sample|test|template|tutorial|starter|boilerplate)s?($|\b)",
    re.IGNORECASE,
)

GITHUB_API_BASE = "https://api.github.com"
PER_PAGE = 100


def _get_headers() -> dict[str, str]:
    """Build GitHub API headers, using GITHUB_TOKEN if available."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_org_repos(
    org: str,
    *,
    min_stars: int = 0,
    include_private: bool = False,
) -> list[dict[str, Any]]:
    """Fetch all non-archived, non-forked, non-disabled repos from a GitHub org.

    Args:
        org: GitHub organization name.
        min_stars: Minimum stargazer count to include (default 0 = all).
        include_private: Whether to include private repos (requires token with scope).

    Returns:
        List of repo dicts with keys: name, full_name, clone_url, ssh_url,
        html_url, stars, language, description, default_branch.
    """
    headers = _get_headers()
    all_repos: list[dict[str, Any]] = []
    page = 1

    with httpx.Client(headers=headers, timeout=30.0, trust_env=False) as client:
        while True:
            url = f"{GITHUB_API_BASE}/orgs/{org}/repos"
            params: dict[str, Any] = {
                "per_page": PER_PAGE,
                "page": page,
                "type": "sources",  # excludes forks
            }

            response = client.get(url, params=params)

            if response.status_code == 404:
                raise ValueError(f"GitHub organization '{org}' not found")
            if response.status_code == 403:
                raise ValueError(
                    "GitHub API rate limit exceeded. Set GITHUB_TOKEN env var for higher limits."
                )
            response.raise_for_status()

            repos = response.json()
            if not repos:
                break

            all_repos.extend(repos)
            page += 1

            # Check if there are more pages via Link header
            link = response.headers.get("Link", "")
            if 'rel="next"' not in link:
                break

    logger.info(f"Fetched {len(all_repos)} source repos from {org}")

    # Filter
    filtered = []
    for repo in all_repos:
        name = repo.get("name", "")
        full_name = repo.get("full_name", "")

        # Skip archived
        if repo.get("archived"):
            logger.debug(f"Skipping archived: {full_name}")
            continue

        # Skip disabled
        if repo.get("disabled"):
            logger.debug(f"Skipping disabled: {full_name}")
            continue

        # Skip private unless requested
        if repo.get("private") and not include_private:
            logger.debug(f"Skipping private: {full_name}")
            continue

        # Skip repos matching demo/example/sample/test patterns
        if SKIP_NAME_PATTERNS.search(name):
            logger.debug(f"Skipping by name pattern: {full_name}")
            continue

        # Skip below star threshold
        stars = repo.get("stargazers_count", 0)
        if stars < min_stars:
            logger.debug(f"Skipping low stars ({stars}): {full_name}")
            continue

        # Skip empty repos
        if repo.get("size", 0) == 0:
            logger.debug(f"Skipping empty: {full_name}")
            continue

        filtered.append({
            "name": name,
            "full_name": full_name,
            "clone_url": repo.get("clone_url", ""),
            "ssh_url": repo.get("ssh_url", ""),
            "html_url": repo.get("html_url", ""),
            "stars": stars,
            "language": repo.get("language"),
            "description": repo.get("description", ""),
            "default_branch": repo.get("default_branch", "main"),
        })

    # Sort by stars descending (scan most important repos first)
    filtered.sort(key=lambda r: r["stars"], reverse=True)

    logger.info(
        f"Filtered to {len(filtered)} repos "
        f"(skipped {len(all_repos) - len(filtered)}: "
        f"archived/disabled/forked/demo/example/sample/test/empty)"
    )

    return filtered


def parse_org_from_url(target: str) -> str | None:
    """Extract org name from a GitHub org URL.

    Returns the org name if the target is an org URL, None otherwise.

    Recognized formats:
        https://github.com/orgname
        http://github.com/orgname
        github.com/orgname
        orgname  (single word, no slash — only if explicitly requested)
    """
    target = target.rstrip("/")

    # https://github.com/orgname (exactly 4 parts = no repo)
    if target.startswith(("https://github.com/", "http://github.com/")):
        parts = target.split("/")
        # https://github.com/org = 4 parts, https://github.com/org/repo = 5+
        if len(parts) == 4 and parts[3]:
            return parts[3]
        return None

    # github.com/orgname (no scheme)
    if target.startswith("github.com/"):
        parts = target.split("/")
        if len(parts) == 2 and parts[1]:
            return parts[1]
        return None

    return None
