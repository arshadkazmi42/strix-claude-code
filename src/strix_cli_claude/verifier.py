"""Standalone, isolated PoC verifier for findings.

Given a finding id, this spins up a FRESH, isolated sandbox and runs a headless
Strix session whose ONLY job is to reproduce ONE finding the way a skeptical
human triager would — then write back a strict verdict + a screen recording.

The verifier session must:
  1. Clone the target PRISTINE at the recorded commit and prove `git diff` is
     empty (so a bug can't be faked by editing the source).
  2. Stand the environment up from the target's OWN recipe
     (docker-compose / Dockerfile / .devcontainer / CI workflow / README).
  3. Re-run the recorded repro against the UNMODIFIED app and SCREEN-RECORD it.
  4. Return a strict verdict: VALID / FALSE_POSITIVE / INCONCLUSIVE.

It reuses the existing Sandbox + Claude CLI infra and runs in a background
thread, so the web request that triggers it returns immediately. Status,
verdict, evidence and the recording path are written back to the findings DB.

NOTE: the heavy path (isolated build + live PoC + recording) needs a real
target, Docker, and Claude auth to exercise fully end-to-end. The orchestration,
DB transitions, prompt assembly and recording extraction are self-contained and
testable; the actual reproduction quality depends on the target.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from strix_cli_claude import db

logger = logging.getLogger(__name__)

RECORDINGS_DIR = Path.home() / ".strix" / "recordings"
# Where the verifier session is told to drop its recording inside the sandbox.
_REC_BASENAME = "poc_recording"
_REC_EXTS = (".mp4", ".webm", ".cast", ".gif", ".txt")

_VERDICTS = ("VALID", "FALSE_POSITIVE", "INCONCLUSIVE")


# --------------------------------------------------------------------------- #
# Prompt assembly (asset-type drivers)
# --------------------------------------------------------------------------- #

def _driver_steps(asset_type: str, source_ref: str, commit_ref: str | None) -> str:
    """Asset-type-specific setup + recording recipe."""
    at = (asset_type or "SOURCE_CODE").upper()
    commit = commit_ref or "(HEAD — record the exact SHA you land on)"

    if at == "CHROME_EXTENSION":
        return f"""ASSET TYPE: Chrome extension.
1. Fetch the extension source / .crx for: {source_ref}  (commit/version: {commit}).
   Prove integrity: for a repo, `git diff` must be empty; for a published .crx,
   note its exact version/hash. Do NOT edit the extension.
2. Launch a REAL Chromium with the extension loaded, headed, via Playwright:
     chromium.launchPersistentContext(..., args=[
       f"--disable-extensions-except={{ext_dir}}",
       f"--load-extension={{ext_dir}}"], record_video_dir="/workspace/rec")
3. Build the clickjacking / attack page from the repro, open it, and perform the
   exact hijacked action. The Playwright video IS the PoC recording.
4. Save the recording to /workspace/{_REC_BASENAME}.webm (rename Playwright's file)."""

    if at == "VSCODE_EXTENSION":
        return f"""ASSET TYPE: VS Code extension.
1. Clone {source_ref} at {commit}; prove `git diff` is empty. Do NOT modify it.
2. Run it in a real Extension Host using @vscode/test-electron (or `code
   --extensionDevelopmentPath=. --new-window`) under Xvfb, recording the screen
   (ffmpeg x11grab to /workspace/{_REC_BASENAME}.mp4).
3. Trigger the exact repro (malicious workspace file / command / webview) and
   capture the impact on video."""

    if at in ("URL", "DOMAIN"):
        return f"""ASSET TYPE: live {at}.
NOTE: you cannot prove "pristine source" for a live target — verify against the
live endpoint instead, and say so in the evidence.
1. Target: {source_ref}.
2. Drive a headed browser via Playwright with record_video_dir="/workspace/rec"
   (for web UI bugs) OR capture the raw request/response with curl (for API bugs).
3. Run the exact repro and capture the impact. Save recording to
   /workspace/{_REC_BASENAME}.webm (browser) or the request/response transcript to
   /workspace/{_REC_BASENAME}.txt (API)."""

    if at == "NPM":
        return f"""ASSET TYPE: npm package.
1. In a clean dir, install the EXACT published version under test ({source_ref}
   @ {commit}). Do NOT patch node_modules.
2. Write the minimal attacker script that drives the public API to trigger the
   bug, run it with `script -c '...' /workspace/{_REC_BASENAME}.txt` (or asciinema
   to /workspace/{_REC_BASENAME}.cast) to record the terminal.
3. The output must show the impact (RCE marker file, prototype pollution, etc.)."""

    # Default: source code (web app / service / CLI)
    return f"""ASSET TYPE: source code.
1. Fresh clone {source_ref} at commit {commit} into /workspace/target.
   Run `git -C /workspace/target diff --quiet && echo PRISTINE_OK` — it MUST print
   PRISTINE_OK. NEVER edit the source/tests/config to make the bug appear.
2. Stand the app up using ITS OWN recipe, in priority order:
     a) docker-compose.yml  -> `docker compose up -d`
     b) .devcontainer / Dockerfile -> build & run
     c) the CI workflow under .github/workflows (it lists the exact working steps)
     d) README run instructions
   Install whatever the project's manifests declare; iterate on build errors.
3. Reproduce the bug against the RUNNING, unmodified app:
     - web UI  -> headed Playwright with record_video_dir="/workspace/rec"
     - HTTP API -> curl, saving request+response to /workspace/{_REC_BASENAME}.txt
     - CLI      -> `script -c '<cmd>' /workspace/{_REC_BASENAME}.txt`
4. Save the screen recording / transcript to /workspace/{_REC_BASENAME}.* """


def build_verifier_prompt(finding: dict) -> str:
    source_ref = finding.get("source_ref") or finding.get("target_identifier") or ""
    commit_ref = finding.get("commit_ref")
    asset_type = finding.get("asset_type") or finding.get("target_asset_type") or "SOURCE_CODE"
    program = finding.get("program_handle") or ""
    instruction = finding.get("target_instruction") or ""

    return f"""You are STRIX-VERIFY, a SKEPTICAL bug-bounty triager. You are NOT here to find
new bugs. You verify EXACTLY ONE finding and decide, like a human would, whether it
is genuinely real and exploitable — or a false positive. Be adversarial: try to
BREAK the claim. Default to FALSE_POSITIVE unless you can make the impact actually happen.

THE FINDING UNDER TEST
  Title    : {finding.get('title')}
  Severity : {finding.get('severity')}
  Type     : {finding.get('vuln_type')}
  Asset    : {finding.get('asset')}
  Program  : {program}
  Source   : {source_ref}
  Commit   : {commit_ref}
  Claimed repro:
{finding.get('repro') or '(none provided — that itself is grounds for INCONCLUSIVE)'}

NON-NEGOTIABLE RULES (this is the whole point):
  - PRISTINE ONLY. Reproduce against UNMODIFIED upstream. If `git diff` is not empty
    after setup, or you had to edit code/tests/config to make it work, the finding is
    FALSE_POSITIVE (tampered).
  - NO "ifs". A real finding triggers concrete impact you can show. "Could be
    exploitable" = FALSE_POSITIVE.
  - REAL EXECUTION, not code reading. A request/response or command/output that
    demonstrates impact — not "the code looks vulnerable".
  - SCOPE. If the program policy forbids this vuln class (e.g. DoS) or the asset is
    out of scope, verdict = INCONCLUSIVE with reason "out of scope". RoE: {instruction or '(none)'}

{_driver_steps(asset_type, source_ref, commit_ref)}

DELIVERABLES (do these, in order):
  1. Stand it up pristine and reproduce (or fail to).
  2. Make sure the recording is at /workspace/{_REC_BASENAME}.<ext> (mp4/webm/cast/txt).
  3. End your FINAL message with EXACTLY these lines and nothing after:

     VERDICT: <VALID|FALSE_POSITIVE|INCONCLUSIVE>
     RECORDING: /workspace/{_REC_BASENAME}.<ext>
     EVIDENCE: <one or two lines: pristine proof + the concrete impact you observed,
               or precisely why it failed>

Work autonomously. Do not ask the user anything."""


# --------------------------------------------------------------------------- #
# Verdict / recording extraction
# --------------------------------------------------------------------------- #

def parse_verdict(text: str) -> tuple[str, str]:
    """Return (verdict, evidence) parsed from the session's final output."""
    verdict, evidence = "INCONCLUSIVE", ""
    for line in text.splitlines():
        s = line.strip()
        up = s.upper()
        if up.startswith("VERDICT:"):
            val = s.split(":", 1)[1].strip().upper().replace("-", "_")
            for v in _VERDICTS:
                if v in val:
                    verdict = v
                    break
        elif up.startswith("EVIDENCE:"):
            evidence = s.split(":", 1)[1].strip()
    return verdict, evidence


def _extract_recording(container_name: str, finding_id: int) -> str | None:
    """docker cp the recording out of the sandbox to RECORDINGS_DIR."""
    RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
    for ext in _REC_EXTS:
        src = f"{container_name}:/workspace/{_REC_BASENAME}{ext}"
        dst = RECORDINGS_DIR / f"finding_{finding_id}{ext}"
        try:
            r = subprocess.run(
                ["docker", "cp", src, str(dst)],
                capture_output=True, timeout=60,
            )
            if r.returncode == 0 and dst.exists() and dst.stat().st_size > 0:
                return str(dst)
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def launch_verification(finding_id: int) -> None:
    """Queue verification of a finding; runs in a daemon thread."""
    db.set_verify_status(finding_id, "queued", log_append="queued for verification")
    t = threading.Thread(target=_run_verification, args=(finding_id,), daemon=True)
    t.start()


def _run_verification(finding_id: int) -> None:
    # Imported lazily so importing this module never drags in docker/main.
    import secrets
    from strix_cli_claude.main import create_mcp_config, check_claude_cli
    from strix_cli_claude.sandbox import Sandbox, SandboxError

    finding = db.get_finding(finding_id)
    if not finding:
        return
    if not check_claude_cli():
        db.set_verify_status(finding_id, "error", log_append="claude CLI not found on host")
        return

    scan_id = f"verify-{finding_id}-{secrets.token_hex(3)}"
    container_name = f"strix-cli-{scan_id}"
    sandbox: Sandbox | None = None
    temp_dir: str | None = None
    try:
        db.set_verify_status(finding_id, "running", log_append="starting isolated sandbox")
        # Docker socket mounted so the verifier can stand the target up with compose.
        sandbox = Sandbox(scan_id=scan_id, mount_docker_socket=True)
        info = sandbox.start()

        report_file = str(RECORDINGS_DIR / f"finding_{finding_id}_verify.md")
        mcp_config = create_mcp_config(
            info["tool_server_url"], info["tool_server_token"], info["scan_id"],
            report_file, extra_env={"STRIX_SCAN_KIND": "verify"},
        )
        temp_dir = tempfile.mkdtemp(prefix=f"strix-verify-{finding_id}-")
        cfg_path = Path(temp_dir) / "mcp.json"
        cfg_path.write_text(json.dumps(mcp_config, indent=2))

        prompt = build_verifier_prompt(finding)
        db.set_verify_status(finding_id, "running", log_append="reproducing on pristine source")

        env = {**os.environ, "CLAUDE_CODE_SKIP_TRUST_DIALOG": "1"}
        result = subprocess.run(
            ["claude", "--mcp-config", str(cfg_path),
             "--append-system-prompt", prompt,
             "--permission-mode", "bypassPermissions",
             "--dangerously-skip-permissions",
             "--print", "Verify the finding now. Follow the deliverables exactly."],
            cwd=temp_dir, env=env, capture_output=True, text=True,
            timeout=int(os.getenv("STRIX_VERIFY_TIMEOUT", "5400")),  # 90 min default
        )
        out = (result.stdout or "") + "\n" + (result.stderr or "")
        verdict, evidence = parse_verdict(out)
        recording = _extract_recording(container_name, finding_id)

        status = "passed" if verdict == "VALID" else "failed"
        if verdict == "INCONCLUSIVE":
            status = "inconclusive"
        db.set_verify_result(
            finding_id, verdict, status=status,
            recording=recording,
            evidence=evidence or out[-1500:],
        )
        db.set_verify_status(
            finding_id, status,
            log_append=f"verdict={verdict} recording={'yes' if recording else 'none'}",
        )
    except SandboxError as e:
        db.set_verify_status(finding_id, "error", log_append=f"sandbox error: {e}")
    except subprocess.TimeoutExpired:
        db.set_verify_status(finding_id, "error", log_append="verification timed out")
    except Exception as e:  # noqa: BLE001
        logger.exception("verification failed")
        db.set_verify_status(finding_id, "error", log_append=f"error: {e}")
    finally:
        if sandbox is not None:
            try:
                sandbox.stop()
            except Exception:
                pass
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
