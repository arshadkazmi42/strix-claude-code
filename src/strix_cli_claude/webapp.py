"""Mobile-first PWA dashboard for Strix hunter sessions.

Self-contained, additive module. It only *reads from* and *calls into* the
existing CLI code (``db`` and ``scan_manager``) plus ``screen`` — it does not
modify any CLI behaviour. Running it has zero effect on the CLI.

Design priorities (per use):
  - Running screen sessions are the source of truth via ``screen -list``,
    NOT the scan-metadata DB (hunters started manually have no metadata).
  - Latest findings come from ~/.strix/strix.db.
  - "Peek" works on ANY session via ``screen -X hardcopy`` (no -L needed).

Look & feel inspired by iamarshad.me: warm cream theme, dark terminal-window
cards, violet accent, Lexend + JetBrains Mono.

Run:
    .venv/bin/python -m strix_cli_claude.webapp            # 0.0.0.0:8800

Auth (single shared password):
    env STRIX_WEB_PASSWORD  or  file ~/.strix/web_password (first line).
    Edits apply immediately (re-read per request).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles

from strix_cli_claude import db, scan_manager, verifier

STATIC_DIR = Path(__file__).parent / "web_static"
SELF_SCREEN = os.getenv("STRIX_WEB_SELF_SCREEN", "strix-app")

# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

_PW_FILE = Path.home() / ".strix" / "web_password"
_COOKIE = "strix_auth"


def _load_password() -> str:
    env = os.getenv("STRIX_WEB_PASSWORD")
    if env:
        return env
    if _PW_FILE.exists():
        lines = _PW_FILE.read_text(encoding="utf-8").splitlines()
        if lines and lines[0].strip():
            return lines[0].strip()
    _PW_FILE.parent.mkdir(mode=0o700, exist_ok=True)
    _PW_FILE.write_text("changeme\n", encoding="utf-8")
    try:
        _PW_FILE.chmod(0o600)
    except OSError:
        pass
    return "changeme"


def _token(password: str) -> str:
    return hmac.new(password.encode(), b"strix-web-authed", hashlib.sha256).hexdigest()


def _is_authed(request: Request) -> bool:
    got = request.cookies.get(_COOKIE, "")
    return bool(got) and hmac.compare_digest(got, _token(_load_password()))


# --------------------------------------------------------------------------- #
# Data: sessions (screen -list), findings, scope
# --------------------------------------------------------------------------- #

_SCREEN_RE = re.compile(r"^\s*(\d+)\.(\S+)\s+\(([^)]+)\)\s+\(([^)]+)\)\s*$")


def _age_from_dt(dt: datetime) -> str:
    secs = (datetime.now() - dt).total_seconds()
    if secs < 0:
        return ""
    if secs < 60:
        return f"{int(secs)}s"
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def _age_epoch(ts: object) -> str:
    try:
        return _age_from_dt(datetime.fromtimestamp(float(ts)))  # type: ignore[arg-type]
    except Exception:
        return ""


def list_screens() -> list[dict]:
    """Ground truth of running screen sessions, enriched with metadata if any."""
    try:
        out = subprocess.run(
            ["screen", "-list"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return []
    sessions: list[dict] = []
    for line in out.splitlines():
        m = _SCREEN_RE.match(line)
        if not m:
            continue
        pid, label, started, state = (
            m.group(1), m.group(2), m.group(3).strip(), m.group(4).strip(),
        )
        if label == SELF_SCREEN:
            continue
        target = mode = None
        if label.startswith("strix-"):
            try:
                meta = scan_manager.load_scan_metadata(label[len("strix-"):])
            except Exception:
                meta = None
            if meta:
                tg = meta.get("targets") or []
                target = ", ".join(tg) if isinstance(tg, list) else str(tg)
                mode = meta.get("scan_mode")
        age = ""
        try:
            age = _age_from_dt(datetime.strptime(started, "%m/%d/%Y %I:%M:%S %p"))
        except Exception:
            pass
        sessions.append({
            "name": f"{pid}.{label}",
            "label": label,
            "pid": pid,
            "state": state,
            "attached": "attached" in state.lower(),
            "started": started,
            "age": age,
            "target": target,
            "mode": mode,
            "is_strix": label.startswith("strix"),
        })
    sessions.sort(key=lambda s: (not s["is_strix"], s["label"]))
    return sessions


def findings_json(status: str | None = None, limit: int = 200) -> list[dict]:
    try:
        items = db.list_findings(status=status or None, limit=limit)
    except Exception:
        return []
    out = []
    for f in items:
        out.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": (f.get("severity") or "").lower(),
            "status": (f.get("status") or "").lower(),
            "program": f.get("program_handle"),
            "asset": f.get("asset") or f.get("target_identifier") or "",
            "vuln_type": f.get("vuln_type") or "",
            "asset_type": (f.get("asset_type") or "").upper(),
            "age": _age_epoch(f.get("created_at")),
            "notes": (f.get("notes") or "")[:1500],
            "verify_status": (f.get("verify_status") or "unverified"),
            "verify_verdict": f.get("verify_verdict") or "",
            "recording": bool(f.get("verify_recording")),
        })
    return out


def summary_json() -> dict:
    finds = []
    try:
        finds = db.list_findings(limit=2000)
    except Exception:
        pass
    confirmed = sum(1 for f in finds if (f.get("status") or "") == "confirmed")
    candidate = sum(1 for f in finds if (f.get("status") or "") == "candidate")
    return {
        "running": len(list_screens()),
        "findings": len(finds),
        "confirmed": confirmed,
        "candidate": candidate,
    }


def scope_json() -> dict:
    try:
        return {"counts": db.scan_status_counts(), "programs": db.scope_summary()}
    except Exception as e:
        return {"counts": {}, "programs": [], "error": str(e)}


def _screen_name_ok(name: str) -> bool:
    # "pid.label" — keep it strict to avoid shell/identifier abuse.
    return bool(re.fullmatch(r"\d+\.[\w.\-]+", name or ""))


# --------------------------------------------------------------------------- #
# PWA assets
# --------------------------------------------------------------------------- #

_MANIFEST = {
    "name": "Strix",
    "short_name": "Strix",
    "description": "Strix hunter dashboard",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "orientation": "portrait-primary",
    "background_color": "#f6f4ec",
    "theme_color": "#f6f4ec",
    "icons": [
        {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/static/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
    ],
}

_SW = """
const CACHE='strix-v3';
const SHELL=['/static/icon-192.png','/static/icon-512.png','/static/favicon-32.png'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL).catch(()=>{})));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  const req=e.request; if(req.method!=='GET') return;
  const url=new URL(req.url);
  if(url.pathname.startsWith('/api/')||url.pathname==='/login') return;       // live data: always network
  if(req.mode==='navigate'){ e.respondWith(fetch(req).catch(()=>caches.match('/'))); return; }
  if(url.pathname.startsWith('/static/')){
    e.respondWith(caches.match(req).then(r=>r||fetch(req).then(resp=>{const c=resp.clone();caches.open(CACHE).then(cc=>cc.put(req,c));return resp;})));
  }
});
"""

# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #

_HEAD = """<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover,maximum-scale=1">
<meta name=theme-color content="#f6f4ec">
<meta name=apple-mobile-web-app-capable content=yes>
<meta name=mobile-web-app-capable content=yes>
<meta name=apple-mobile-web-app-status-bar-style content=default>
<meta name=apple-mobile-web-app-title content=Strix>
<link rel=manifest href=/manifest.webmanifest>
<link rel=icon href=/static/favicon-32.png>
<link rel=apple-touch-icon href=/static/apple-touch-icon.png>
<link rel=preconnect href=https://fonts.googleapis.com>
<link rel=preconnect href=https://fonts.gstatic.com crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lexend:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel=stylesheet>"""

_LOGIN = """<!doctype html><html lang=en><head>""" + _HEAD + """
<title>Strix · login</title><style>
*{box-sizing:border-box}
body{font-family:'Lexend',system-ui,sans-serif;background:#f6f4ec;color:#1b1a17;
margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
background-image:radial-gradient(60% 40% at 50% 0%,rgba(124,92,255,.14),transparent 70%)}
form{width:100%;max-width:330px;text-align:center}
img{width:88px;height:88px;border-radius:22px;margin-bottom:16px;
box-shadow:0 14px 40px -12px rgba(124,92,255,.5)}
h1{font-size:26px;font-weight:800;letter-spacing:1px;margin:0 0 4px}
.tag{font-family:'JetBrains Mono',monospace;font-size:12px;color:#75716a;margin:0 0 22px}
input{width:100%;padding:15px;margin:8px 0;border-radius:13px;border:1px solid #e6e1d4;
background:#fff;color:#1b1a17;font-size:16px;font-family:inherit}
input:focus{outline:0;border-color:#7c5cff;box-shadow:0 0 0 3px rgba(124,92,255,.18)}
button{width:100%;padding:15px;margin-top:10px;border:0;border-radius:13px;
background:#7c5cff;color:#fff;font-size:16px;font-weight:700;font-family:inherit;cursor:pointer}
button:active{transform:scale(.98)}
.err{color:#e23744;font-size:14px;margin:6px 0}
</style></head><body><form method=post action=/login>
<img src=/static/icon-192.png alt=Strix><h1>STRIX</h1>
<p class=tag>// hunter dashboard</p>__ERR__
<input type=password name=password placeholder=Password autofocus autocomplete=current-password>
<button type=submit>Enter</button></form></body></html>"""


def login_page(error: bool = False) -> str:
    return _LOGIN.replace("__ERR__", '<p class=err>Wrong password</p>' if error else "")


_PAGE = """<!doctype html><html lang=en><head>""" + _HEAD + """
<title>Strix</title><style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{
 --bg:#f6f4ec;--bg2:#efece0;--card:#ffffff;--ink:#1b1a17;--muted:#75716a;
 --line:#e6e1d4;--pc:#7c5cff;--pc2:#6a4af0;
 --term:#0d1117;--term2:#161b22;--term-ink:#c9d1d9;--term-muted:#8b949e;--term-line:#222a35;
 --r:#ff5f57;--y:#febc2e;--g:#28c840;
 --crit:#fb7185;--high:#f26822;--med:#fbbf24;--low:#34d399;--info:#67e8f9;--blue:#5b8def;
 --sans:'Lexend',system-ui,-apple-system,sans-serif;--mono:'JetBrains Mono',ui-monospace,Menlo,monospace;
 --sh:0 1px 2px rgba(20,18,12,.04),0 10px 26px -14px rgba(20,18,12,.18)}
html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
font-size:15px;overscroll-behavior-y:contain;-webkit-font-smoothing:antialiased}
body{padding-bottom:calc(76px + env(safe-area-inset-bottom));
background-image:radial-gradient(80% 30% at 50% -5%,rgba(124,92,255,.10),transparent 60%);background-attachment:fixed}
@keyframes fu{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(40,200,64,.5)}70%{box-shadow:0 0 0 6px rgba(40,200,64,0)}}
header{position:sticky;top:0;z-index:20;background:rgba(246,244,236,.82);backdrop-filter:blur(12px);
border-bottom:1px solid var(--line);display:flex;align-items:center;gap:11px;
padding:calc(env(safe-area-inset-top) + 11px) 16px 11px}
header img{width:30px;height:30px;border-radius:9px;box-shadow:0 4px 14px -4px rgba(124,92,255,.5)}
header h1{font-size:17px;font-weight:800;letter-spacing:1.5px;margin:0;flex:1}
header .upd{font-family:var(--mono);font-size:11px;color:var(--muted)}
header button{background:#fff;border:1px solid var(--line);color:var(--muted);
border-radius:10px;width:36px;height:36px;font-size:15px}
header button:active{transform:scale(.94)}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);
border-top-color:var(--pc);border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}
main{padding:16px 13px;max-width:680px;margin:0 auto}
section[data-view]{animation:fu .28s ease}
.h2{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:1.2px;
color:var(--muted);margin:20px 4px 10px;display:flex;align-items:center;gap:8px;font-weight:600}
.h2:first-child{margin-top:2px}.h2::before{content:'//';color:var(--pc);opacity:.6}
.h2 .n{margin-left:auto;background:var(--card);border:1px solid var(--line);color:var(--ink);
border-radius:999px;padding:2px 10px;font-size:11px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin:2px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 10px;
text-align:center;box-shadow:var(--sh)}
.stat b{display:block;font-size:27px;font-weight:800;line-height:1.05;letter-spacing:-.5px}
.stat span{font-family:var(--mono);font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.stat.accent{background:linear-gradient(140deg,#7c5cff,#6a4af0);border-color:transparent}
.stat.accent b,.stat.accent span{color:#fff}.stat.accent span{opacity:.85}

/* terminal-window session card */
.term{background:var(--term);border:1px solid var(--term-line);border-radius:14px;
margin-bottom:11px;overflow:hidden;box-shadow:var(--sh)}
.termbar{display:flex;align-items:center;gap:7px;padding:9px 12px;background:var(--term2);
border-bottom:1px solid var(--term-line)}
.tl{width:11px;height:11px;border-radius:50%;flex:none}
.tl.r{background:var(--r)}.tl.y{background:var(--y)}.tl.g{background:var(--g)}
.termname{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--term-ink);
margin-left:6px;word-break:break-all}
.termbar .sp{flex:1}
.live{width:8px;height:8px;border-radius:50%;background:var(--g);animation:pulse 2s infinite}
.termbar .age{font-family:var(--mono);font-size:11px;color:var(--term-muted)}
.termbody{padding:11px 13px;font-family:var(--mono);font-size:12.5px;color:var(--term-ink);
word-break:break-word;line-height:1.5}
.termbody .pr{color:var(--low);margin-right:7px}
.termbody .meta{color:var(--term-muted)}
.term .actions{display:flex;gap:7px;padding:0 13px 13px}
.term .actions button{flex:1;padding:9px;border-radius:9px;border:1px solid rgba(255,255,255,.13);
background:rgba(255,255,255,.06);color:var(--term-ink);font-size:12.5px;font-weight:600;font-family:var(--sans)}
.term .actions button:active{transform:scale(.96)}
.term .actions .danger{color:#ff7b72;border-color:rgba(255,123,114,.3);background:rgba(255,123,114,.08)}

/* finding card */
.fcard{position:relative;background:var(--card);border:1px solid var(--line);border-radius:16px;
padding:13px 14px 13px 16px;margin-bottom:11px;box-shadow:var(--sh);overflow:hidden}
.fcard::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--muted)}
.fcard.sev-critical::before{background:var(--crit)}.fcard.sev-high::before{background:var(--high)}
.fcard.sev-medium::before{background:var(--med)}.fcard.sev-low::before{background:var(--low)}
.fcard.sev-info::before,.fcard.sev-informational::before{background:var(--info)}
.crow{display:flex;align-items:center;gap:7px;margin-bottom:7px}.crow .sp{flex:1}
.age{font-family:var(--mono);font-size:11px;color:var(--muted);flex:none}
.chip{font-family:var(--mono);font-size:10.5px;font-weight:700;border-radius:999px;
padding:3px 9px;text-transform:uppercase;letter-spacing:.4px}
.c-critical{background:var(--crit);color:#3a0011}.c-high{background:var(--high);color:#fff}
.c-medium{background:var(--med);color:#3d2c00}.c-low{background:var(--low);color:#03281a}
.c-info{background:var(--info);color:#06343a}
.s-confirmed{background:var(--low);color:#03281a}.s-candidate{background:var(--med);color:#3d2c00}
.s-rejected{background:#e7e2d5;color:#75716a}.s-submitted{background:var(--blue);color:#fff}
.s-duplicate{background:#e7e2d5;color:#75716a}.gray{background:#e7e2d5;color:#75716a}
.title{font-weight:600;font-size:15.5px;line-height:1.3;margin:1px 0 5px}
.sub{font-family:var(--mono);color:var(--muted);font-size:12px;word-break:break-word}
.fcard .actions{display:flex;gap:7px;margin-top:11px}
.fcard .actions button{flex:1;padding:9px;border-radius:10px;border:1px solid var(--line);
background:#fff;color:var(--ink);font-size:13px;font-weight:600;font-family:var(--sans)}
.fcard .actions button:active{transform:scale(.96)}
.fcard .actions .go{background:var(--pc);color:#fff;border-color:transparent}
.fcard .actions .danger{color:#e23744;border-color:#f3d4d7;background:#fff6f6}

.empty{color:var(--muted);text-align:center;padding:30px 10px;font-family:var(--mono);font-size:13px}
.empty .em{font-size:28px;display:block;margin-bottom:8px;opacity:.5}
.notes{white-space:pre-wrap;background:var(--term);color:var(--term-ink);border-radius:11px;
padding:11px;margin-top:9px;font-family:var(--mono);font-size:11.5px;max-height:240px;overflow-y:auto;
-webkit-overflow-scrolling:touch;overscroll-behavior:contain;touch-action:pan-y}

form.launch input,form.launch select{width:100%;padding:13px;margin:6px 0;border-radius:12px;
border:1px solid var(--line);background:var(--card);color:var(--ink);font-size:15px;font-family:inherit}
form.launch input:focus{outline:0;border-color:var(--pc);box-shadow:0 0 0 3px rgba(124,92,255,.16)}
form.launch button{width:100%;padding:14px;border:0;border-radius:12px;background:var(--pc);
color:#fff;font-weight:700;font-size:15px;margin-top:8px;font-family:inherit}
.seg{display:flex;gap:7px}.seg label{flex:1}.seg input{display:none}
.seg span{display:block;text-align:center;padding:11px;border-radius:11px;border:1px solid var(--line);
background:var(--card);font-size:14px;font-family:var(--mono)}
.seg input:checked+span{background:#f0ecff;border-color:var(--pc);color:var(--pc);font-weight:600}
.linkbtn{display:block;width:100%;text-align:center;padding:14px;border-radius:12px;
border:1px solid var(--line);background:var(--card);color:var(--ink);margin-top:11px;text-decoration:none;font-weight:600}

nav{position:fixed;bottom:0;left:0;right:0;z-index:20;display:flex;
background:rgba(246,244,236,.92);backdrop-filter:blur(14px);border-top:1px solid var(--line);
padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;background:none;border:0;color:var(--muted);padding:10px 0 9px;
font-family:var(--mono);font-size:10px;letter-spacing:.3px;
display:flex;flex-direction:column;align-items:center;gap:4px;transition:color .15s}
nav button .ic{font-size:20px;line-height:1}
nav button.active{color:var(--pc)}
nav button.active .ic{transform:translateY(-1px)}

#toast{position:fixed;left:50%;bottom:calc(86px + env(safe-area-inset-bottom));
transform:translateX(-50%) translateY(20px);background:#fff;border:1px solid var(--line);
border-left:4px solid var(--pc);color:var(--ink);padding:12px 16px;border-radius:13px;box-shadow:var(--sh);
font-size:13.5px;font-weight:500;opacity:0;pointer-events:none;transition:.26s;z-index:60;max-width:88vw}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
#toast.err{border-left-color:#e23744}#toast.ok{border-left-color:var(--low)}

.overlay{position:fixed;inset:0;z-index:50;background:rgba(20,18,12,.45);display:none}
.overlay.show{display:block;animation:fade .2s}@keyframes fade{from{opacity:0}to{opacity:1}}
.sheet{position:absolute;left:0;right:0;bottom:0;background:var(--card);border-radius:20px 20px 0 0;
padding:18px;padding-bottom:calc(18px + env(safe-area-inset-bottom));max-height:88vh;overflow-y:auto;
-webkit-overflow-scrolling:touch;overscroll-behavior:contain;animation:up .28s cubic-bezier(.2,.8,.2,1)}
body.locked{position:fixed;left:0;right:0;width:100%;overflow:hidden}
@keyframes up{from{transform:translateY(100%)}to{transform:none}}
.sheet.dark{background:var(--term);color:var(--term-ink)}
.sheet h3{margin:2px 0 14px;font-size:16px;font-weight:700}
.sheet.dark h3{color:var(--term-ink)}
.sheethead{position:sticky;top:0;z-index:6;display:flex;align-items:center;gap:10px;
margin:-18px -18px 12px;padding:13px 16px;border-bottom:1px solid var(--line);background:var(--card)}
.sheet.dark .sheethead{background:var(--term2);border-color:var(--term-line)}
.sheethead h3{margin:0;flex:1;font-size:16px;font-weight:700}
.sheethead .x{position:static;float:none;font-size:24px;width:42px;height:42px;flex:none;
border:1px solid var(--line);border-radius:10px;background:var(--bg2)}
.sheet.dark .sheethead .x{background:rgba(255,255,255,.06);border-color:var(--term-line);color:var(--term-ink)}
#recbox img,#recbox video{width:100%;max-height:58vh;object-fit:contain;border-radius:8px;background:#000;display:block}
.quick{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.quick button{background:#f0ecff;border:1px solid #e0d8ff;color:var(--pc2);
border-radius:999px;padding:9px 14px;font-size:13px;font-family:var(--mono);font-weight:600}
.quick button:active{transform:scale(.95)}
.sheet input{width:100%;padding:13px;border-radius:12px;border:1px solid var(--line);
background:#fbfaf6;color:var(--ink);font-size:16px;font-family:var(--mono)}
.sheet .send{width:100%;padding:13px;margin-top:10px;border:0;border-radius:12px;
background:var(--pc);color:#fff;font-weight:700;font-size:15px;font-family:var(--sans)}
#peekbox,#recbox,#verbox{white-space:pre-wrap;font-family:var(--mono);font-size:11.5px;color:var(--term-ink);
background:#06070d;border:1px solid var(--term-line);border-radius:11px;padding:11px;
max-height:64vh;overflow-y:auto;line-height:1.45;
-webkit-overflow-scrolling:touch;overscroll-behavior:contain;touch-action:pan-y}
#recbox video{width:100%;border-radius:8px;background:#000}
.sheet .x{float:right;background:none;border:0;color:var(--muted);font-size:24px;line-height:1}
.sheet.dark .x{color:var(--term-muted)}
</style></head><body>
<header><img src=/static/icon-192.png alt=""><h1>STRIX</h1>
<span class=upd id=upd></span>
<button onclick=refresh() id=refbtn>&#8635;</button></header>

<main>
 <section data-view=home>
  <div class=stats>
   <div class="stat accent"><b id=s_run>–</b><span>running</span></div>
   <div class=stat><b id=s_cand>–</b><span>candidates</span></div>
   <div class=stat><b id=s_conf>–</b><span>confirmed</span></div>
  </div>
  <div class=h2>Running sessions <span class=n id=sess_n>0</span></div>
  <div id=sessions></div>
  <div class=h2>Latest findings</div>
  <div id=home_findings></div>
 </section>

 <section data-view=findings hidden>
  <div class=h2>Findings</div>
  <div class=quick id=fpills></div>
  <div id=findings></div>
 </section>

 <section data-view=scope hidden>
  <div class=h2>Targets</div>
  <div class=stats id=scope_stats></div>
  <div class=h2>Programs</div>
  <div id=scope_progs></div>
 </section>

 <section data-view=more hidden>
  <div class=h2>Launch scan</div>
  <form class=launch onsubmit="return doLaunch(event)">
   <input name=targets placeholder="target — url / repo / path" required>
   <div class=seg>
    <label><input type=radio name=scan_mode value=deep checked><span>deep</span></label>
    <label><input type=radio name=scan_mode value=standard><span>standard</span></label>
    <label><input type=radio name=scan_mode value=quick><span>quick</span></label>
   </div>
   <input name=instruction placeholder="instruction (optional)">
   <button type=submit>Start scan</button>
  </form>
  <a class=linkbtn href=/logout>Log out</a>
  <p class=sub style="text-align:center;margin-top:16px">sessions from <code>screen -list</code> · findings from strix.db</p>
 </section>
</main>

<nav>
 <button class=navbtn data-tab=home onclick="show('home')"><span class=ic>&#9889;</span>Live</button>
 <button class=navbtn data-tab=findings onclick="show('findings')"><span class=ic>&#128027;</span>Findings</button>
 <button class=navbtn data-tab=scope onclick="show('scope')"><span class=ic>&#127919;</span>Scope</button>
 <button class=navbtn data-tab=more onclick="show('more')"><span class=ic>&#9776;</span>More</button>
</nav>

<div id=toast></div>

<div class=overlay id=sendov onclick="if(event.target===this)close_('sendov')">
 <div class=sheet><div class=sheethead><h3 id=sendtitle>Send command</h3><button class=x onclick="close_('sendov')">&times;</button></div>
  <div class=quick>
   <button onclick="qsend('work')">work</button>
   <button onclick="qsend('go')">go</button>
   <button onclick="qsend('sync h1')">sync h1</button>
   <button onclick="qsend('sync intigriti')">sync intigriti</button>
   <button onclick="qsend('status')">status</button>
   <button onclick="qsend('continue')">continue</button>
  </div>
  <input id=sendinput placeholder="custom command…" autocomplete=off>
  <button class=send onclick="sendCustom()">Send</button>
 </div>
</div>

<div class=overlay id=peekov onclick="if(event.target===this)close_('peekov')">
 <div class="sheet dark"><div class=sheethead><h3 id=peektitle>Peek</h3><button class=x onclick="close_('peekov')">&times;</button></div><div id=peekbox>loading…</div>
  <button class=send onclick=peekRefresh()>Refresh</button>
 </div>
</div>

<div class=overlay id=verov onclick="if(event.target===this)close_('verov')">
 <div class="sheet dark"><div class=sheethead><h3 id=vertitle>Verification</h3><button class=x onclick="close_('verov')">&times;</button></div>
  <div id=verstat class=sub style="margin-bottom:9px;color:var(--term-muted)">loading…</div>
  <div id=verbox>…</div>
  <div style="display:flex;gap:8px;margin-top:11px">
   <button class=send style="flex:1;background:#3a2226;color:#ff7b72" onclick="stopVer()">&#9632; Stop</button>
   <button class=send style="flex:1;background:var(--surface2)" onclick="close_('verov')">Close</button>
  </div></div>
</div>

<div class=overlay id=recov onclick="if(event.target===this)close_('recov')">
 <div class="sheet dark"><div class=sheethead><h3>PoC recording</h3><button class=x onclick="close_('recov')">&times;</button></div><div id=recbox>loading…</div>
  <div style="display:flex;gap:8px;margin-top:11px">
   <a id=recdl class=send style="flex:1;text-align:center;text-decoration:none" download>&#8681; Download</a>
   <button class=send style="flex:1;background:#3a2226;color:#ff7b72" onclick="deleteRec()">&#128465; Delete</button>
   <button class=send style="flex:1;background:var(--surface2)" onclick="close_('recov')">Close</button>
  </div>
 </div>
</div>

<script>
let activeTab='home', findingFilter='', sendTarget='', peekTarget='';
let lastHome='', lastFind='', lastScope='';
const $=id=>document.getElementById(id);
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function api(u,o){const r=await fetch(u,o);if(r.status===401){location.href='/login';throw 0;}return r;}
const getJSON=async u=>(await api(u)).json();
const post=(u,b)=>api(u,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(b).toString()});
function toast(m,k){const t=$('toast');t.textContent=m;t.className='show '+(k||'');setTimeout(()=>t.className='',2300);}
function setBusy(b){$('refbtn').innerHTML=b?'<span class=spin></span>':'&#8635;';}
function stamp(){const d=new Date();$('upd').textContent=d.toTimeString().slice(0,8);}

function sevChip(s){const k=({critical:'c-critical',high:'c-high',medium:'c-medium',low:'c-low',info:'c-info',informational:'c-info'}[s])||'c-info';return `<span class="chip ${k}">${esc(s||'?')}</span>`;}
function stChip(s){const k=({confirmed:'s-confirmed',candidate:'s-candidate',rejected:'s-rejected',submitted:'s-submitted',duplicate:'s-duplicate'}[s])||'gray';return `<span class="chip ${k}">${esc(s||'?')}</span>`;}

function sessionCard(s){
 const tgt = s.target ? esc(s.target) : (s.is_strix?'strix hunter':'manual session');
 return `<div class=term>
  <div class=termbar><span class="tl r"></span><span class="tl y"></span><span class="tl g"></span>
   <span class=termname>${esc(s.label)}</span><span class=sp></span>
   <span class=live></span><span class=age>up ${esc(s.age||'?')}</span></div>
  <div class=termbody><span class=pr>$</span>${tgt}${s.mode?(' <span class=meta>· '+esc(s.mode)+'</span>'):''}
   <span class=meta>&nbsp; (${esc(s.state)})</span></div>
  <div class=actions>
   <button onclick="peek('${esc(s.name)}','${esc(s.label)}')">Peek</button>
   <button onclick="openSend('${esc(s.name)}','${esc(s.label)}')">Send</button>
   <button class=danger onclick="stopSession('${esc(s.name)}','${esc(s.label)}')">Stop</button>
  </div></div>`;
}
function vChip(vs,verdict){
 const map={passed:'c-low',failed:'c-critical',inconclusive:'c-info',running:'c-medium',queued:'c-medium',error:'gray'};
 const cls=map[vs]||'gray';
 const label = vs==='passed'?('✓ '+(verdict||'VALID')) : vs==='failed'?(verdict||'FALSE POSITIVE') : ('verify: '+vs);
 return `<span class="chip ${cls}">${esc(label)}</span>`;
}
function findingCard(f){
 const vs=f.verify_status||'unverified';
 const busy=(vs==='queued'||vs==='running');
 const vbadge=(vs && vs!=='unverified')?`<span onclick="openVerify(${f.id})" style="cursor:pointer">${vChip(vs,f.verify_verdict)}</span>`:'';
 const atype=f.asset_type?`<span class=badge>${esc(f.asset_type)}</span>`:'';
 return `<div class="fcard sev-${esc(f.severity)}">
  <div class=crow>${sevChip(f.severity)} ${stChip(f.status)} ${vbadge}<span class=sp></span><span class=age>${esc(f.age)}</span></div>
  <div class=title>${esc(f.title)}</div>
  <div class=sub>${esc(f.program||'—')}${f.asset?(' · '+esc(f.asset)):''} ${atype}</div>
  <div class=actions>
   <button onclick="${busy?`openVerify(${f.id})`:`verifyF(${f.id})`}">${busy?'&#9203; Progress':(vs==='unverified'?'&#9889; Verify':'&#9889; Re-verify')}</button>
   ${(vs&&vs!=='unverified'&&!busy)?`<button onclick="openVerify(${f.id})">&#9432; Log</button>`:''}
   ${f.recording?`<button class=go onclick="openRec(${f.id})">&#9654; Recording</button>`:''}
   ${f.notes?`<button onclick="this.closest('.fcard').querySelector('.notes').hidden^=1">Details</button>`:''}
  </div>
  <div class=actions>
   <button class=go onclick="setF(${f.id},'confirmed')">&#10003; Confirm</button>
   <button class=danger onclick="setF(${f.id},'rejected')">&#10007; Reject</button>
  </div>
  ${f.notes?`<div class=notes hidden>${esc(f.notes)}</div>`:''}</div>`;
}

async function renderHome(){
 const d=await getJSON('/api/home');
 $('s_run').textContent=d.summary.running; $('s_cand').textContent=d.summary.candidate; $('s_conf').textContent=d.summary.confirmed;
 $('sess_n').textContent=d.sessions.length;
 const k=JSON.stringify([d.sessions,d.findings]);if(k===lastHome)return;lastHome=k;
 $('sessions').innerHTML=d.sessions.length?d.sessions.map(sessionCard).join(''):'<div class=empty><span class=em>&#128564;</span>No running sessions</div>';
 $('home_findings').innerHTML=d.findings.length?d.findings.map(findingCard).join(''):'<div class=empty><span class=em>&#128269;</span>No findings yet</div>';
}
const FILTERS=['','candidate','confirmed','rejected','submitted'];
async function renderFindings(){
 $('fpills').innerHTML=FILTERS.map(f=>`<button onclick="findingFilter='${f}';renderFindings()" style="${f===findingFilter?'background:var(--pc);color:#fff;border-color:transparent':''}">${f||'all'}</button>`).join('');
 const d=await getJSON('/api/findings?status='+encodeURIComponent(findingFilter));
 const k=findingFilter+'|'+JSON.stringify(d);if(k===lastFind)return;lastFind=k;
 $('findings').innerHTML=d.length?d.map(findingCard).join(''):'<div class=empty><span class=em>&#128269;</span>None</div>';
}
async function renderScope(){
 const d=await getJSON('/api/scope');const c=d.counts||{};
 const k=JSON.stringify(d);if(k===lastScope)return;lastScope=k;
 $('scope_stats').innerHTML=[['pending',c.pending||0],['running',c.in_progress||0],['done',c.done||0]]
   .map(([k,v])=>`<div class=stat><b>${v}</b><span>${k}</span></div>`).join('');
 $('scope_progs').innerHTML=(d.programs||[]).length?d.programs.map(p=>{
   const tot=p.total||0,done=p.done||0,pct=tot?Math.round(done/tot*100):0;
   return `<div class=fcard><div class=crow><span class=title style="margin:0;font-size:14px">${esc(p.program_handle)}</span><span class=sp></span><span class="chip gray">${esc(p.source)}</span></div>
   <div class=sub>${esc(p.asset_type)} · ${done}/${tot} done · ${p.pending||0} pending</div>
   <div style="height:7px;background:var(--bg2);border-radius:999px;margin-top:9px;overflow:hidden"><div style="height:100%;width:${pct}%;background:linear-gradient(90deg,var(--pc),var(--low));border-radius:999px;transition:width .4s"></div></div></div>`;
 }).join(''):'<div class=empty><span class=em>&#127919;</span>No programs synced</div>';
}
async function refresh(){if(document.querySelector('.overlay.show'))return;setBusy(true);const y=window.scrollY;try{
  if(activeTab==='home')await renderHome();
  else if(activeTab==='findings')await renderFindings();
  else if(activeTab==='scope')await renderScope();
 }catch(e){}finally{setBusy(false);stamp();window.scrollTo(0,y);}}
function show(t){activeTab=t;document.querySelectorAll('[data-view]').forEach(e=>e.hidden=e.dataset.view!==t);
 document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('active',b.dataset.tab===t));
 window.scrollTo(0,0);refresh();}

// actions
async function setF(id,st){try{await post('/api/finding',{id,status:st});toast(st==='confirmed'?'Confirmed ✓':'Rejected','ok');refresh();}catch(e){toast('failed','err');}}
async function verifyF(id){try{await post('/api/verify',{id});toast('verification queued — isolated repro running','ok');refresh();setTimeout(()=>openVerify(id),400);}catch(e){toast('verify failed','err');}}
let verId=0, verTimer=null;
async function openVerify(id){
 verId=id; $('vertitle').textContent='Verification · #'+id;
 $('verstat').textContent='loading…'; $('verbox').textContent='';
 $('verov').classList.add('show'); lockBody();
 await verPoll(); clearInterval(verTimer); verTimer=setInterval(verPoll,3000);
}
async function verPoll(){
 if(!$('verov').classList.contains('show')){clearInterval(verTimer);return;}
 try{
  const d=await getJSON('/api/verify-log/'+verId);
  const alive=d.container?('🟢 '+d.container):'⚪ no container running';
  let s='status: <b>'+esc(d.status)+'</b>'+(d.verdict?(' · '+esc(d.verdict)):'')+' · updated '+esc(d.updated_age)+' ago<br>'+alive;
  if(d.evidence) s+='<br><br><b>evidence:</b> '+esc(d.evidence);
  $('verstat').innerHTML=s;
  const box=$('verbox'); const bottom=box.scrollTop+box.clientHeight>=box.scrollHeight-40;
  box.textContent=d.log||'(no log yet — starting…)';
  if(bottom) box.scrollTop=box.scrollHeight;
 }catch(e){}
}
async function stopVer(){ if(!confirm('Force-stop this verification? (destroys its sandbox)'))return;
 try{await post('/api/verify-stop',{id:verId});toast('stopping…','ok');verPoll();refresh();}catch(e){toast('stop failed','err');}}
let recId=0;
async function deleteRec(){
 if(!recId||!confirm('Delete this recording? The verdict stays; only the file is removed.'))return;
 try{await post('/api/recording/delete',{id:recId});toast('recording deleted','ok');close_('recov');refresh();}
 catch(e){toast('delete failed','err');}
}
async function openRec(id){
 recId=id;
 const box=$('recbox'); $('recdl').href='/recordings/'+id+'?download=1';
 box.textContent='loading…'; $('recov').classList.add('show'); lockBody();
 try{
  const r=await api('/recordings/'+id);
  const ct=(r.headers.get('content-type')||'').toLowerCase();
  if(ct.indexOf('video')===0){
   box.innerHTML='<video controls autoplay playsinline><source src="/recordings/'+id+'"></video>';
  }else if(ct.indexOf('image')===0){
   box.innerHTML='<img src="/recordings/'+id+'" alt="PoC recording">';
  }else{
   const t=await r.text(); box.textContent=t||'(empty recording)';
  }
 }catch(e){ box.textContent='could not load recording'; }
}
let _sy=0;
function lockBody(){_sy=window.scrollY;document.body.style.top=(-_sy)+'px';document.body.classList.add('locked');}
function unlockBody(){document.body.classList.remove('locked');document.body.style.top='';window.scrollTo(0,_sy);}
function openSend(name,label){sendTarget=name;$('sendtitle').textContent='Send → '+label;$('sendinput').value='';$('sendov').classList.add('show');lockBody();}
function close_(id){$(id).classList.remove('show');if(!document.querySelector('.overlay.show'))unlockBody();}
async function qsend(c){await doSend(c);}
async function sendCustom(){const c=$('sendinput').value.trim();if(c)await doSend(c);}
async function doSend(cmd){try{await post('/api/send',{name:sendTarget,cmd});toast('sent: '+cmd,'ok');close_('sendov');}catch(e){toast('send failed','err');}}
async function stopSession(name,label){if(!confirm('Stop session '+label+'?'))return;
 try{await post('/api/stop',{name});toast('stopped '+label,'ok');refresh();}catch(e){toast('stop failed','err');}}
async function peek(name,label){peekTarget=name;$('peektitle').textContent='Peek · '+label;$('peekbox').textContent='loading…';$('peekov').classList.add('show');lockBody();peekRefresh();}
async function peekRefresh(){try{const r=await api('/api/peek?name='+encodeURIComponent(peekTarget));const t=await r.text();
 const b=$('peekbox');b.textContent=t||'(empty)';b.scrollTop=b.scrollHeight;}catch(e){$('peekbox').textContent='peek failed';}}
async function doLaunch(ev){ev.preventDefault();const f=ev.target;
 try{await post('/api/launch',Object.fromEntries(new FormData(f)));toast('scan started','ok');f.reset();show('home');}
 catch(e){toast('launch failed','err');}return false;}

setInterval(()=>{if(!document.hidden)refresh();},5000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});
show('home');
</script></body></html>"""


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

app = FastAPI(title="Strix Dashboard")

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
def _startup() -> None:
    try:
        db.init_db()
    except Exception:
        pass


async def _form(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


_PUBLIC = ("/login", "/sw.js", "/manifest.webmanifest")


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    path = request.url.path
    if path in _PUBLIC or path.startswith("/static") or _is_authed(request):
        return await call_next(request)
    if path.startswith("/api") or path.startswith("/screens"):
        return PlainTextResponse("unauthorized", status_code=401)
    return RedirectResponse("/login", status_code=303)


# ---- PWA assets ----------------------------------------------------------- #

@app.get("/manifest.webmanifest")
async def manifest():
    return JSONResponse(_MANIFEST, media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker():
    return Response(_SW, media_type="application/javascript")


# ---- auth ----------------------------------------------------------------- #

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    if _is_authed(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(login_page())


@app.post("/login")
async def login_post(request: Request):
    form = await _form(request)
    if hmac.compare_digest(form.get("password", ""), _load_password()):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_COOKIE, _token(_load_password()),
                        httponly=True, samesite="lax", max_age=30 * 24 * 3600)
        return resp
    return HTMLResponse(login_page(error=True), status_code=401)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(_COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(_PAGE)


# ---- JSON APIs ------------------------------------------------------------ #

@app.get("/api/home")
async def api_home():
    return JSONResponse({
        "summary": summary_json(),
        "sessions": list_screens(),
        "findings": findings_json(limit=8),
    })


@app.get("/api/findings")
async def api_findings(status: str | None = None):
    return JSONResponse(findings_json(status=status, limit=200))


@app.get("/api/scope")
async def api_scope():
    return JSONResponse(scope_json())


# ---- session actions (by screen name) ------------------------------------- #

@app.get("/api/peek", response_class=PlainTextResponse)
def api_peek(name: str):
    if not _screen_name_ok(name):
        return PlainTextResponse("bad name", status_code=400)
    path = f"/tmp/strix_peek_{os.getpid()}_{int(time.time() * 1000)}.txt"
    try:
        subprocess.run(["screen", "-S", name, "-X", "hardcopy", "-h", path],
                       capture_output=True, timeout=10)
        for _ in range(10):
            if os.path.exists(path):
                break
            time.sleep(0.05)
        data = Path(path).read_bytes()[-40000:] if os.path.exists(path) else b"(no output)"
    except Exception as e:
        data = f"(peek error: {e})".encode()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return PlainTextResponse(data.decode("utf-8", "replace"))


@app.post("/api/send")
async def api_send(request: Request):
    form = await _form(request)
    name, cmd = form.get("name", ""), form.get("cmd", "")
    if not _screen_name_ok(name) or not cmd:
        return PlainTextResponse("bad request", status_code=400)
    try:
        subprocess.run(["screen", "-S", name, "-X", "stuff", cmd + "\n"],
                       capture_output=True, timeout=10)
    except Exception as e:
        return PlainTextResponse(f"send failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.post("/api/stop")
async def api_stop(request: Request):
    form = await _form(request)
    name = form.get("name", "")
    if not _screen_name_ok(name):
        return PlainTextResponse("bad name", status_code=400)
    try:
        subprocess.run(["screen", "-S", name, "-X", "quit"], capture_output=True, timeout=10)
    except Exception as e:
        return PlainTextResponse(f"stop failed: {e}", status_code=500)
    return PlainTextResponse("ok")


# ---- findings + launch ---------------------------------------------------- #

@app.post("/api/finding")
async def api_finding(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    status = form.get("status", "")
    if status not in ("candidate", "confirmed", "rejected", "submitted", "duplicate"):
        return PlainTextResponse("bad status", status_code=400)
    try:
        db.update_finding_status(fid, status)
    except Exception as e:
        return PlainTextResponse(f"failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.post("/api/verify")
async def api_verify(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    if not db.get_finding(fid):
        return PlainTextResponse("no such finding", status_code=404)
    try:
        verifier.launch_verification(fid)
    except Exception as e:
        return PlainTextResponse(f"launch failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.get("/recordings/{finding_id}")
def api_recording(finding_id: int, download: bool = False):
    f = db.get_finding(finding_id)
    rec = f.get("verify_recording") if f else None
    if not rec or not Path(rec).exists():
        return PlainTextResponse("no recording", status_code=404)
    if download:
        return FileResponse(rec, filename=Path(rec).name, content_disposition_type="attachment")
    # Serve INLINE (no attachment) so it renders in the sheet — video plays,
    # text/cast transcripts display.
    return FileResponse(rec, content_disposition_type="inline")


@app.get("/api/verify-log/{finding_id}")
def api_verify_log(finding_id: int):
    f = db.get_finding(finding_id)
    if not f:
        return JSONResponse({"error": "no finding"}, status_code=404)
    log = ""
    p = verifier.verify_log_path(finding_id)
    if p.exists():
        try:
            log = p.read_text(errors="replace")[-16000:]
        except Exception:
            pass
    container = ""
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Status}}"],
                             capture_output=True, text=True, timeout=8).stdout
        pref = verifier.verify_container_prefix(finding_id)
        for ln in out.splitlines():
            if ln.startswith(pref):
                container = ln.strip()
                break
    except Exception:
        pass
    return JSONResponse({
        "status": f.get("verify_status") or "unverified",
        "verdict": f.get("verify_verdict") or "",
        "evidence": (f.get("verify_evidence") or "")[:2000],
        "updated_age": _age_epoch(f.get("updated_at")),
        "container": container,
        "recording": bool(f.get("verify_recording")),
        "log": log,
    })


@app.post("/api/verify-stop")
async def api_verify_stop(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    try:
        verifier.stop_verification(fid)
    except Exception as e:
        return PlainTextResponse(f"stop failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.post("/api/recording/delete")
async def api_recording_delete(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    f = db.get_finding(fid)
    rec = f.get("verify_recording") if f else None
    if rec:
        try:
            Path(rec).unlink(missing_ok=True)
        except Exception:
            pass
    db.clear_recording(fid)
    return PlainTextResponse("ok")


@app.post("/api/launch")
async def api_launch(request: Request):
    form = await _form(request)
    targets = [t.strip() for t in form.get("targets", "").split(",") if t.strip()]
    if not targets:
        return PlainTextResponse("no target", status_code=400)
    try:
        scan_manager.start_scan(
            targets=targets,
            scan_mode=form.get("scan_mode", "deep"),
            instruction=form.get("instruction") or None,
        )
    except Exception as e:
        return PlainTextResponse(f"start failed: {e}", status_code=500)
    return PlainTextResponse("ok")


def main() -> None:
    import uvicorn

    host = os.getenv("STRIX_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("STRIX_WEB_PORT", "8800"))
    print(f"Strix dashboard on http://{host}:{port}  (password file: {_PW_FILE})")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
