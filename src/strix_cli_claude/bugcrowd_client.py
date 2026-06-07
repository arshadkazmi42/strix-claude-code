"""Minimal read-only Bugcrowd program source.

Programs come from the PUBLIC engagements feed (no auth):
  GET https://bugcrowd.com/engagements.json?category=bug_bounty&page=N   (1-indexed)
      → {"engagements": [...], "paginationMeta": {"limit": 24, "totalCount": 226}}

Each engagement: name, briefUrl ("/engagements/<handle>"), accessStatus,
rewardSummary (dict), productEngagementType (dict), isPrivate, isDemo, isBanned.

Per-program scope (target_groups) is ONLY behind the authenticated Hacker Portal;
the public target_groups URL 301-redirects to an HTML SPA. So:
  * Unauthenticated sync = programs only (targets stay empty).
  * Optional scope import is gated behind a BUGCROWD_TOKEN (Bearer) or
    BUGCROWD_SESSION (session cookie) env var — mirrors how IntigritiClient reads
    INTIGRITI_TOKEN. If absent, sync programs only and skip scope.

No write/submission endpoints — submission stays manual on bugcrowd.com.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

API_BASE = "https://bugcrowd.com"
ENGAGEMENTS_PATH = "/engagements.json"
DEFAULT_PAGE_LIMIT = 24
MAX_RETRIES = 3
PAGE_SLEEP_SECONDS = 1.0  # polite delay between pages


class BugcrowdError(Exception):
    """Raised for any Bugcrowd failure. Never contains the credential."""


def normalize_asset_type(raw: str | None) -> str:
    """Map Bugcrowd target category strings to our standard taxonomy."""
    if not raw:
        return "OTHER"
    r = raw.strip().lower()
    if "wildcard" in r:
        return "WILDCARD"
    if "api" in r:
        return "API"
    if "website" in r or "url" in r or "web" in r:
        return "URL"
    if "domain" in r:
        return "DOMAIN"
    if "source" in r or "github" in r or "code" in r:
        return "SOURCE_CODE"
    if "android" in r:
        return "MOBILE_ANDROID"
    if "ios" in r or "iphone" in r or "apple" in r:
        return "MOBILE_IOS"
    if "mobile" in r:
        return "MOBILE_OTHER"
    if "ip" in r:
        return "IP_ADDRESS"
    if "hardware" in r or "device" in r or "iot" in r:
        return "HARDWARE"
    if "executable" in r or "binary" in r:
        return "EXECUTABLE"
    return raw.upper().replace(" ", "_")[:64]


def _handle_from_brief(brief_url: str | None) -> str | None:
    """basename of briefUrl ('/engagements/<handle>') -> '<handle>'."""
    if not brief_url:
        return None
    handle = brief_url.rstrip("/").rsplit("/", 1)[-1]
    return handle or None


def _offers_bounty(reward_summary: Any) -> bool:
    """True if rewardSummary advertises a monetary reward (defensive across shapes)."""
    if not isinstance(reward_summary, dict):
        return False
    for k in ("hasMonetaryReward", "monetary", "hasReward", "paysCash", "isMonetary"):
        if reward_summary.get(k) is True:
            return True
    for k in ("max", "min", "maxReward", "minReward", "amount", "top",
              "rewardRangeMax", "maxRewardAmount"):
        v = reward_summary.get(k)
        if isinstance(v, (int, float)) and v > 0:
            return True
    rng = reward_summary.get("rewardRangeSummary")
    if isinstance(rng, list):
        for item in rng:
            if isinstance(item, dict):
                for k in ("max", "min", "amount", "maxReward"):
                    v = item.get(k)
                    if isinstance(v, (int, float)) and v > 0:
                        return True
    # Real Bugcrowd shape: reward fields are STRINGS, e.g.
    #   {"summary": "$150 - $7,500", "minReward": "$150", "maxReward": "$7,500"}
    # Treat a currency symbol + a digit as a monetary reward (points/VDP have neither).
    currency_chars = "$€£₹¥₩"
    for k in ("summary", "maxReward", "minReward", "compensationSummary", "rewardRange", "range"):
        v = reward_summary.get(k)
        if isinstance(v, str) and any(c in v for c in currency_chars) and any(ch.isdigit() for ch in v):
            return True
    # A currency code on the summary almost always implies a cash reward.
    if reward_summary.get("currency"):
        return True
    return False


def _transform_engagement(eng: dict[str, Any]) -> dict[str, Any] | None:
    """Map one engagement to a program dict, or None to skip it."""
    if eng.get("isPrivate") or eng.get("isDemo") or eng.get("isBanned"):
        return None
    brief = eng.get("briefUrl")
    handle = _handle_from_brief(brief)
    if not handle:
        return None
    return {
        "id": handle,  # bugcrowd is keyed by handle (used by get_program_scope)
        "handle": handle,
        "name": eng.get("name") or handle,
        "policy_url": f"{API_BASE}{brief}" if brief else None,
        "offers_bounty": _offers_bounty(eng.get("rewardSummary")),
        "submission_state": eng.get("accessStatus"),
        "brief_url": brief,
    }


class BugcrowdClient:
    def __init__(self, timeout: float = 30.0, page_sleep: float = PAGE_SLEEP_SECONDS) -> None:
        token = (os.environ.get("BUGCROWD_TOKEN") or "").strip()
        session = (os.environ.get("BUGCROWD_SESSION") or "").strip()
        self.authenticated = bool(token or session)
        self._page_sleep = page_sleep

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "strix-claude-code/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if session:
            # Accept either a bare cookie value or a full "k=v; k2=v2" cookie string.
            headers["Cookie"] = session if "=" in session else f"_bugcrowd_session={session}"

        self._client = httpx.Client(headers=headers, timeout=timeout, follow_redirects=True)

    def __enter__(self) -> "BugcrowdClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    # -------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{API_BASE}{path}"
        last_status: int | None = None
        for attempt in range(MAX_RETRIES):
            try:
                r = self._client.get(url, params=params)
            except httpx.HTTPError as e:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(1.0 + attempt)
                    continue
                raise BugcrowdError(f"Bugcrowd request failed on {path}: {e}") from e
            last_status = r.status_code

            if r.status_code == 401:
                raise BugcrowdError(
                    "Bugcrowd auth failed (HTTP 401). Verify BUGCROWD_TOKEN / BUGCROWD_SESSION."
                )
            if r.status_code == 403:
                raise BugcrowdError(f"Bugcrowd access denied (HTTP 403) for {path}")
            if r.status_code == 404:
                raise BugcrowdError(f"Bugcrowd endpoint not found: {path}")
            if r.status_code == 429:
                retry_after = int(r.headers.get("Retry-After") or "5")
                time.sleep(min(retry_after, 60))
                continue
            if 500 <= r.status_code < 600:
                time.sleep(1.0 + attempt)
                continue
            if r.status_code >= 400:
                snippet = (r.text or "")[:300]
                raise BugcrowdError(f"Bugcrowd error {r.status_code} on {path}: {snippet}")

            try:
                return r.json()
            except ValueError as e:
                # A 200 with HTML (e.g. an SPA redirect target) is not machine-readable.
                raise BugcrowdError(f"Bugcrowd returned non-JSON for {path}") from e

        raise BugcrowdError(
            f"Bugcrowd failed after {MAX_RETRIES} attempts (last status: {last_status}) on {path}"
        )

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def list_programs(self) -> list[dict[str, Any]]:
        """Return all public bug-bounty programs from the engagements feed.

        Skips private/demo/banned entries. Paginates politely (1-indexed).
        """
        results: list[dict[str, Any]] = []
        page = 1
        total: int | None = None
        limit: int | None = None

        while True:
            data = self._get(ENGAGEMENTS_PATH, params={"category": "bug_bounty", "page": page})
            meta = data.get("paginationMeta") or {}
            if total is None:
                total = int(meta.get("totalCount") or 0)
            if limit is None:
                limit = int(meta.get("limit") or DEFAULT_PAGE_LIMIT)

            engagements = data.get("engagements") or []
            if not engagements:
                break

            for eng in engagements:
                transformed = _transform_engagement(eng)
                if transformed:
                    results.append(transformed)

            if len(engagements) < limit:
                break
            if total and page * limit >= total:
                break
            page += 1
            if page > 1000:  # hard safety
                break
            if self._page_sleep:
                time.sleep(self._page_sleep)

        return results

    def get_program_scope(self, handle: str) -> list[dict[str, Any]]:
        """Best-effort authenticated scope import for one program.

        Requires BUGCROWD_TOKEN / BUGCROWD_SESSION. Bugcrowd's machine-readable
        scope lives behind the Hacker Portal and its exact shape varies; this
        parses defensively and returns [] when it can't extract assets. Shape
        mirrors IntigritiClient.get_program_scope().
        """
        if not self.authenticated:
            raise BugcrowdError(
                "Bugcrowd scope import requires BUGCROWD_TOKEN or BUGCROWD_SESSION"
            )
        data = self._get(f"/engagements/{handle}/target_groups.json")
        groups = (
            data.get("groups")
            or data.get("target_groups")
            or data.get("targetGroups")
            or []
        )
        results: list[dict[str, Any]] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            in_scope = group.get("in_scope", group.get("inScope", True))
            for tgt in (group.get("targets") or []):
                if not isinstance(tgt, dict):
                    continue
                identifier = tgt.get("uri") or tgt.get("name") or tgt.get("identifier")
                if not identifier:
                    continue
                category = tgt.get("category") or tgt.get("type")
                results.append({
                    "asset_type": normalize_asset_type(category),
                    "asset_identifier": identifier,
                    "instruction": tgt.get("description") or group.get("name") or "",
                    "max_severity": None,
                    "eligible_for_bounty": bool(in_scope),
                    "eligible_for_submission": bool(in_scope),
                    "raw_category": category,
                })
        return results
