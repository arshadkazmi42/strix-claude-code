"""VS Code Marketplace and Chrome Web Store extension downloader.

Detects extension URLs, downloads the package (.vsix or .crx — both are zip
archives), and extracts the source into a workspace directory. The existing
local-source / whitebox flow then scans the extracted code unchanged.

VSIX: a regular zip from the Marketplace asset endpoint.
CRX: a zip with a Chrome-specific header prefix. Python's zipfile reads the
End-of-Central-Directory record from the END of the file, so it tolerates
the prefix bytes and extracts cleanly.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

USER_AGENT = "strix-claude-cli/1.0"
_CHROME_EXT_ID_RE = re.compile(r"^[a-p]{32}$")


def parse_extension_url(url: str) -> dict[str, Any] | None:
    """Detect VS Code Marketplace and Chrome Web Store URLs.

    Returns a dict describing the extension, or None if `url` is not a
    recognized extension URL.

    VS Code: https://marketplace.visualstudio.com/items?itemName=publisher.extension
    Chrome (new): https://chromewebstore.google.com/detail/<slug>/<ext_id>
    Chrome (old): https://chrome.google.com/webstore/detail/<slug>/<ext_id>
    """
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None

    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()

    if host == "marketplace.visualstudio.com":
        qs = urllib.parse.parse_qs(parsed.query)
        item_name = (qs.get("itemName") or [""])[0].strip()
        if not item_name or "." not in item_name:
            return None
        publisher, _, extension = item_name.partition(".")
        publisher = publisher.strip()
        extension = extension.strip()
        if not publisher or not extension:
            return None
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", f"{publisher}_{extension}")
        return {
            "kind": "vscode",
            "publisher": publisher,
            "extension": extension,
            "name": f"vscode_{safe}",
            "url": url,
        }

    is_chrome_new = host == "chromewebstore.google.com" and parsed.path.startswith("/detail/")
    is_chrome_old = host == "chrome.google.com" and parsed.path.startswith("/webstore/detail/")
    if is_chrome_new or is_chrome_old:
        path_parts = [p for p in parsed.path.split("/") if p]
        ext_id: str | None = None
        for part in reversed(path_parts):
            if _CHROME_EXT_ID_RE.match(part):
                ext_id = part
                break
        if not ext_id:
            return None
        slug_source = path_parts[-2] if len(path_parts) >= 2 else "ext"
        slug = re.sub(r"[^a-z0-9_-]+", "_", slug_source.lower()).strip("_") or "ext"
        return {
            "kind": "chrome",
            "ext_id": ext_id,
            "name": f"chrome_{slug}_{ext_id[:8]}",
            "url": url,
        }

    return None


def _vsix_url(publisher: str, extension: str) -> str:
    return (
        f"https://{publisher}.gallery.vsassets.io/_apis/public/gallery/"
        f"publisher/{publisher}/extension/{extension}/latest/"
        "assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    )


def _crx_url(ext_id: str) -> str:
    return (
        "https://clients2.google.com/service/update2/crx?"
        "response=redirect"
        "&os=linux&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64"
        "&prod=chromecrx&prodchannel=unknown"
        "&prodversion=120.0.6099.224&lang=en-US"
        "&acceptformat=crx2,crx3"
        f"&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
    )


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        if status == 204:
            raise RuntimeError(
                "Marketplace returned 204 No Content. The extension may be "
                "restricted (MV3-only, geo-limited, region-locked, removed, "
                "or only distributed via the Web Store install flow)."
            )
        with dest.open("wb") as out:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                out.write(chunk)


def download_extension(info: dict[str, Any], target_dir: Path) -> Path:
    """Download and extract an extension into target_dir/<name>.

    Returns the extracted source directory path.
    """
    kind = info["kind"]
    target_dir.mkdir(parents=True, exist_ok=True)
    extract_dir = target_dir / info["name"]
    extract_dir.mkdir(parents=True, exist_ok=True)

    if kind == "vscode":
        url = _vsix_url(info["publisher"], info["extension"])
        archive_name = f"{info['name']}.vsix"
    elif kind == "chrome":
        url = _crx_url(info["ext_id"])
        archive_name = f"{info['name']}.crx"
    else:
        raise ValueError(f"Unknown extension kind: {kind!r}")

    archive_path = target_dir / archive_name
    logger.info("Downloading %s extension from %s", kind, url)
    _download(url, archive_path)

    size = archive_path.stat().st_size
    if size < 256:
        raise RuntimeError(
            f"Extension archive at {archive_path} is only {size} bytes — "
            "the download likely returned an error page rather than a package."
        )

    if not zipfile.is_zipfile(archive_path):
        raise RuntimeError(
            f"Downloaded file at {archive_path} is not a recognized zip archive "
            "(VSIX/CRX). The marketplace may have rejected the request or the "
            "extension URL is wrong."
        )

    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(extract_dir)

    return extract_dir
