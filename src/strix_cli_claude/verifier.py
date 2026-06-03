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
_REC_EXTS = (".mp4", ".webm", ".gif", ".png", ".cast", ".txt")

_VERDICTS = ("VALID", "FALSE_POSITIVE", "INCONCLUSIVE")


# --------------------------------------------------------------------------- #
# Prompt assembly (asset-type drivers)
# --------------------------------------------------------------------------- #

def _driver_steps(asset_type: str, source_ref: str, commit_ref: str | None) -> str:
    """Asset-type-specific setup + recording recipe."""
    at = (asset_type or "SOURCE_CODE").upper()
    commit = commit_ref or "(HEAD — record the exact SHA you land on)"
    rec = f"/workspace/{_REC_BASENAME}"

    # Reusable: set up a headed browser + screen recording to MP4 video.
    browser_setup = f"""   ENV SETUP (do this, install whatever is missing — server's time, not the user's):
     - apt-get update && apt-get install -y xvfb ffmpeg x11-utils >/dev/null
     - install Playwright + Chromium:
         (python) pip install playwright && playwright install --with-deps chromium
         (or node) npm i -D playwright && npx playwright install --with-deps chromium
     - start a virtual display:  Xvfb :99 -screen 0 1280x800x24 & ; export DISPLAY=:99
     - start screen capture to VIDEO:
         ffmpeg -y -f x11grab -video_size 1280x800 -framerate 12 -i :99 \\
                -pix_fmt yuv420p {rec}.mp4 &   # kill it after the PoC: pkill -INT ffmpeg
     PREFER recording real on-screen video to {rec}.mp4. If x11grab is impossible,
     fall back to Playwright's built-in record_video_dir, then move the file to {rec}.webm."""

    if at == "CHROME_EXTENSION":
        return f"""ASSET TYPE: Chrome extension — must be shown in a REAL browser, on VIDEO.
1. Fetch the extension for: {source_ref} (version/commit: {commit}). For a repo,
   `git diff` MUST be empty; for a published .crx, note exact version+hash. Do NOT edit it.
{browser_setup}
2. Launch a HEADED Chromium with the extension loaded (headless cannot load MV3 UI):
     chromium.launchPersistentContext(userDataDir, headless=False, args=[
       f"--disable-extensions-except={{ext_dir}}", f"--load-extension={{ext_dir}}"])
3. Build the EXACT attack page from the repro (e.g. the clickjacking iframe), open it,
   and perform the hijacked action SLOWLY and visibly so the video clearly shows:
   the extension UI, the overlay/iframe, and the unintended action firing.
4. Stop ffmpeg. The MP4 at {rec}.mp4 must clearly show the attack working."""

    if at == "VSCODE_EXTENSION":
        return f"""ASSET TYPE: VS Code extension — shown in a REAL VS Code window, on VIDEO.
1. Clone {source_ref} at {commit}; `git diff` MUST be empty. Do NOT modify it. Install deps.
{browser_setup}
2. Launch the extension in a real Extension Development Host under the virtual display:
     download VS Code (or use `code`/code-server), then
     code --extensionDevelopmentPath=$PWD --disable-workspace-trust <malicious-workspace>
   (or @vscode/test-electron). Make sure the VS Code window renders on :99.
3. Trigger the EXACT repro (malicious .vscode/ file, command, or webview) and let the
   video show the impact (e.g. command execution marker, exfil, rogue webview).
4. Stop ffmpeg. {rec}.mp4 must clearly show the bug firing inside VS Code."""

    if at in ("URL", "DOMAIN"):
        return f"""ASSET TYPE: live {at} (cannot prove pristine source — verify against the live target; say so).
1. Target: {source_ref}.
2. For a web-UI bug: {browser_setup}
   then drive a HEADED browser to the page and perform the repro on video ({rec}.mp4).
   For an API bug: capture the exact request+response with curl -v into {rec}.txt.
3. The recording must clearly demonstrate the impact."""

    if at == "NPM":
        return f"""ASSET TYPE: npm package (terminal PoC).
1. In a clean dir, install the EXACT published version ({source_ref} @ {commit}).
   Do NOT patch node_modules.
2. Write a MINIMAL, readable attacker script (/workspace/poc.js) that drives only the
   public API to trigger the bug.
3. Record a CLEAN labelled terminal transcript:
     script -q -c 'bash /workspace/poc.sh' {rec}.txt
   where poc.sh echoes a banner before each step (see RECORDING QUALITY) and ends by
   printing the concrete impact (RCE marker file contents, polluted prototype, etc.)."""

    # Default: source code (web app / service / CLI)
    return f"""ASSET TYPE: source code.
1. Fresh clone {source_ref} at commit {commit} into /workspace/target.
   Run `git -C /workspace/target diff --quiet && echo PRISTINE_OK` — it MUST print
   PRISTINE_OK. NEVER edit the source/tests/config to make the bug appear.
2. Stand the app up using ITS OWN recipe, in priority order:
     a) docker-compose.yml  -> `docker compose up -d`
     b) .devcontainer / Dockerfile -> build & run
     c) the CI workflow under .github/workflows (the exact working steps)
     d) README run instructions
   Install whatever the project's manifests declare; iterate on build errors.
3. Reproduce against the RUNNING, unmodified app and record CLEANLY:
     - web UI -> {browser_setup}
                 then drive a HEADED browser through the repro on video ({rec}.mp4).
     - HTTP API / CLI -> write /workspace/poc.sh with a labelled banner per step and
                 record:  script -q -c 'bash /workspace/poc.sh' {rec}.txt
4. The recording must end by clearly showing the impact."""


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

RECORDING QUALITY (the recording is what the human reviews INSTEAD of redoing your work — make it CLEAN):
  TWO PHASES — this is the whole trick to a clean recording:
    PHASE A — PREPARE, and DO NOT RECORD: clone, install, build, and START the target. ALL the
      noisy setup (apt, npm, pip, docker compose up, build logs) happens here, OFF-camera.
      Confirm the target is fully up BEFORE you start any recording.
    PHASE B — DEMO, record ONLY this: a tiny run that assumes everything is already up and does
      nothing but SHOW the attack. NEVER put installs/builds/`docker compose up` inside the recording.
  - Prefer real VIDEO (.mp4) for ANYTHING with a UI. Use a .txt transcript only for pure CLI/API bugs.
  - For a terminal demo, write /workspace/poc.sh that is SHORT and QUIET — banner, one command, result:
        set +x
        echo "===== STEP 1: prove pristine ====="; git -C /workspace/target diff --quiet && echo PRISTINE_OK
        echo "===== STEP 2: fire the PoC =====";   <the single attack command>
        echo "===== RESULT: <impact in one line> ====="; <print ONLY the line that proves impact>
      Suppress every command's noise (append 2>/dev/null, grep to the key line). The script must be
      ~5-15 lines of OUTPUT total. Then record JUST this script:
        script -q -c 'bash /workspace/poc.sh' /workspace/{_REC_BASENAME}.txt
  - For VIDEO, start ffmpeg only AFTER setup is finished; perform each action slowly/visibly; then stop
    ffmpeg. The recording must be SECONDS of clear demo, never minutes of setup scrolling by.

DELIVERABLES (do these, in order):
  1. Stand it up pristine and reproduce (or fail to).
  2. Produce ONE clean recording at /workspace/{_REC_BASENAME}.<ext> — .mp4 (video, preferred for UI)
     or .txt (labelled transcript for CLI/API).
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
