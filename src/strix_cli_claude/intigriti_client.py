"""Minimal read-only Intigriti researcher API client.

API docs (beta v1):
  https://kb.intigriti.com/en/articles/8529303-intigriti-researcher-api
  https://api.intigriti.com/external/researcher/swagger/index.html

Auth: Bearer token from INTIGRITI_TOKEN env. Mint one in the Intigriti
researcher portal → Integrations / API.

Endpoint shape:
  GET /external/researcher/v1/programs?limit=N&offset=M
      → {"maxCount": N, "records": [...]}
  GET /external/researcher/v1/programs/{id}
      → {..., "domains": {"content": [...]} , ...}

No write endpoints exposed — submission stays manual on intigriti.com.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

API_BASE = "https://api.intigriti.com/external/researcher/v1"
PAGE_SIZE = 500
MAX_RETRIES = 3

# Status IDs we keep (per Intigriti's enum). 3 = Open, 4 = Suspended (paused, still active).
ACTIVE_STATUS_IDS = {3, 4}

# Tier ID = 5 means "Out of scope".
OUT_OF_SCOPE_TIER_ID = 5


class IntigritiError(Exception):
    """Raised for any Intigriti API failure. Never contains the token."""


def normalize_asset_type(raw: str | None) -> str:
    """Map Intigriti `type.value` strings to our standard taxonomy."""
    if not raw:
        return "OTHER"
    r = raw.strip().lower()
    if "url" in r or "web" in r:
        return "URL"
    if "wildcard" in r:
        return "WILDCARD"
    if "domain" in r:
        return "DOMAIN"
    if "source" in r or "github" in r or "code" in r:
        return "SOURCE_CODE"
    if "android" in r:
        return "MOBILE_ANDROID"
    if "ios" in r or "iphone" in r:
        return "MOBILE_IOS"
    if "mobile" in r:
        return "MOBILE_OTHER"
    if "ip" in r:
        return "IP_ADDRESS"
    if "device" in r or "hardware" in r:
        return "HARDWARE"
    if "executable" in r or "binary" in r:
        return "EXECUTABLE"
    if "api" in r:
        return "API"
    # Unknown — uppercase + safe-ish
    return raw.upper().replace(" ", "_")[:64]


class IntigritiClient:
    def __init__(self, timeout: float = 30.0) -> None:
        token = (os.environ.get("INTIGRITI_TOKEN") or "").strip()
        if not token:
            raise IntigritiError(
                "INTIGRITI_TOKEN must be set in environment "
                "(export it in your shell rc)"
            )
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "strix-claude-code/1.0",
            },
            timeout=timeout,
            follow_redirects=True,
        )

    def __enter__(self) -> "IntigritiClient":
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
            r = self._client.get(url, params=params)
            last_status = r.status_code

            if r.status_code == 401:
                raise IntigritiError(
                    "Intigriti API auth failed (HTTP 401). Verify INTIGRITI_TOKEN."
                )
            if r.status_code == 403:
                raise IntigritiError(
                    f"Intigriti API access denied (HTTP 403) for {path}"
                )
            if r.status_code == 404:
                raise IntigritiError(f"Intigriti API endpoint not found: {path}")
            if r.status_code == 429:
                retry_after = int(r.headers.get("Retry-After") or "5")
                time.sleep(min(retry_after, 60))
                continue
            if 500 <= r.status_code < 600:
                time.sleep(1.0 + attempt)
                continue
            if r.status_code >= 400:
                snippet = (r.text or "")[:300]
                raise IntigritiError(
                    f"Intigriti API error {r.status_code} on {path}: {snippet}"
                )

            # Soft rate-limit indicated in body
            if "Request blocked" in (r.text or ""):
                time.sleep(2.0)
                continue

            return r.json()

        raise IntigritiError(
            f"Intigriti API failed after {MAX_RETRIES} attempts "
            f"(last status: {last_status}) on {path}"
        )

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def list_programs(self) -> list[dict[str, Any]]:
        """Return all programs visible to the authenticated researcher.

        Filters to active programs (status.id in {3, 4}).
        Synthesizes a stable handle from the program's web URL path
        (so users can refer to programs by 'company/program' just like H1).
        """
        results: list[dict[str, Any]] = []
        offset = 0
        total: int | None = None

        while True:
            data = self._get(
                "/programs",
                params={"limit": PAGE_SIZE, "offset": offset},
            )
            if total is None:
                total = int(data.get("maxCount") or 0)
            records = data.get("records") or []
            if not records:
                break

            for rec in records:
                status_id = (rec.get("status") or {}).get("id")
                if status_id not in ACTIVE_STATUS_IDS:
                    continue

                program_id = rec.get("id")
                if not program_id:
                    continue

                # Derive handle from webLinks.detail like ".../researcher?id=company/program"
                detail = ((rec.get("webLinks") or {}).get("detail")) or ""
                handle = _derive_handle(detail) or program_id

                max_bounty = ((rec.get("maxBounty") or {}).get("value")) or 0
                conf = ((rec.get("confidentialityLevel") or {}).get("id"))

                results.append({
                    "id": program_id,
                    "handle": handle,
                    "name": rec.get("name") or handle,
                    "policy_url": (
                        f"https://app.intigriti.com/researcher{_handle_path(detail)}"
                        if detail else None
                    ),
                    "offers_bounty": bool(max_bounty and max_bounty > 0),
                    "private": conf == 4,
                    "submission_state": None,
                    "raw_status_id": status_id,
                })

            offset += len(records)
            if total and offset >= total:
                break
            if not records:
                break
            if offset > 100_000:  # hard safety
                break

        return results

    def get_program_scope(self, program_id: str) -> list[dict[str, Any]]:
        """Return scope assets for a single program by ID.

        Mirrors the H1 client's get_structured_scopes() shape.
        """
        data = self._get(f"/programs/{program_id}")
        content = ((data.get("domains") or {}).get("content")) or []
        results: list[dict[str, Any]] = []

        for item in content:
            endpoint = item.get("endpoint")
            if not endpoint:
                continue
            tier_id = (item.get("tier") or {}).get("id")
            tier_value = (item.get("tier") or {}).get("value") or ""
            type_value = (item.get("type") or {}).get("value")
            description = item.get("description") or ""

            in_scope = tier_id != OUT_OF_SCOPE_TIER_ID
            eligible_for_bounty = in_scope and tier_value.lower() != "no bounty"

            results.append({
                "asset_type": normalize_asset_type(type_value),
                "asset_identifier": endpoint,
                "instruction": description,
                "max_severity": None,
                "eligible_for_bounty": eligible_for_bounty,
                "eligible_for_submission": in_scope,
                "raw_type_value": type_value,
                "raw_tier_value": tier_value,
            })

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _handle_path(detail_url: str) -> str:
    """Extract '/.../company/program/detail' path from a webLinks.detail URL."""
    if "?id=" in detail_url:
        return "/" + detail_url.split("?id=", 1)[1].lstrip("/")
    return ""


def _derive_handle(detail_url: str) -> str | None:
    """Pull 'company/program' from the detail URL. Returns None if not parseable."""
    path = _handle_path(detail_url)
    parts = [p for p in path.strip("/").split("/") if p and p != "detail"]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return None
