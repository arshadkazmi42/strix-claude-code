"""Post-scan validator.

After the main scan finishes, parse the findings out of the markdown report
and re-validate each one with a *fresh* Claude CLI subprocess (no shared
context with the scan agent). The validator reuses the same live sandbox via
the same MCP config, so it can re-run the PoC, read source under /workspace,
and hit live endpoints. False positives are removed from the main report and
moved to a sibling `<report>.false_positives.md` file.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

VERDICT_BEGIN = "===VALIDATION_VERDICT_BEGIN==="
VERDICT_END = "===VALIDATION_VERDICT_END==="

_FINDING_HEADER_RE = re.compile(r"^### (?P<title>.+?)\s*$", re.MULTILINE)
_NEXT_TOP_SECTION_RE = re.compile(r"^## (?!Findings\b)", re.MULTILINE)

_STRIX_GUIDELINES_PATH = Path(__file__).parent.parent.parent / ".claude" / "CLAUDE.md"


def _load_strix_guidelines() -> str | None:
    if _STRIX_GUIDELINES_PATH.is_file():
        try:
            return _STRIX_GUIDELINES_PATH.read_text(encoding="utf-8").strip()
        except OSError:
            return None
    return None


def _validator_system_prompt(target_info: str, scan_mode: str, cpu_count: int) -> str:
    guidelines = _load_strix_guidelines()
    guidelines_block = ""
    if guidelines:
        guidelines_block = f"""
==============================================================================
STRIX TRIAGE & REPORTING GUIDELINES (MANDATORY)
==============================================================================
{guidelines}
"""

    return f"""You are a senior HackerOne triager performing INDEPENDENT validation of a single security finding produced by a previous scan agent. You have NO access to that agent's reasoning. Verify the finding from scratch.

You have the SAME sandbox tools the scan agent had (terminal_execute, browser_action, str_replace_editor, list_files, list_requests, view_request, send_request, repeat_request, python_action, etc.) attached to the same live sandbox. Source code is at /workspace. You may re-run the PoC, hit live endpoints, read code, etc.

TARGETS (for context):
{target_info}

SCAN MODE: {scan_mode}
AVAILABLE CPUs: {cpu_count}

TRIAGE STANDARDS (apply strictly):
- Assume the attacker is EXTERNAL, unauthenticated, with no internal network access, no source-code access (unless the repo is public), no admin/privileged sessions, and no insider permissions.
- REJECT findings that require internal access, repo write access, CI workflow_dispatch, host loopback, or already-privileged sessions.
- REJECT findings against archived / demo / example / single-tenant code where there is no real victim.
- REJECT findings whose PoC is a unit test, mock, or simulated harness rather than a real exploit against the running app.
- REJECT findings whose PoC fails to reproduce when re-run.
- REJECT findings that are best-practice / defense-in-depth recommendations with no real impact.
- ACCEPT findings only when (a) you reproduce a working external-attacker exploit, OR (b) you confirm the bug exists in actively maintained code with realistic external impact.

VALIDATION PROCESS (do all of these):
1. Read the finding details given to you.
2. If a PoC exists, RE-RUN IT against the sandbox / live target. Capture the actual response.
3. If the finding is whitebox/code-level, open the cited file at the cited line and confirm the vulnerable pattern actually exists.
4. Check repo status (archived, demo, example) before accepting code-level findings.
5. Test edge cases: does the bug require unrealistic preconditions?
6. Apply the H1 triage standards above.

REQUIRED OUTPUT FORMAT:
At the END of your response — and ONLY at the end — output the verdict between these EXACT markers, with NOTHING else inside:

{VERDICT_BEGIN}
{{"verdict": "valid" | "false_positive", "reasoning": "<2-4 sentences explaining the call>", "severity_change": "keep" | "raise" | "lower", "evidence": "<one-line summary of what you observed when you re-ran the PoC or read the code>"}}
{VERDICT_END}

Rules:
- The verdict block MUST be valid JSON.
- "verdict" MUST be exactly "valid" or "false_positive".
- If you cannot re-run the PoC AND the code-level evidence is weak, return "false_positive" with reasoning="unverifiable".
- DO NOT call finish_scan. DO NOT call create_vulnerability_report. DO NOT modify the report file. Only output the verdict block.
{guidelines_block}"""


def _validator_initial_prompt(finding_md: str, target_info: str) -> str:
    return f"""You are validating ONE finding from a previous security scan. Below is the finding markdown. Re-verify it independently using the sandbox tools, apply H1 triage standards, and output your verdict.

TARGETS:
{target_info}

FINDING UNDER REVIEW:
---BEGIN FINDING---
{finding_md}
---END FINDING---

Begin validation now. Re-run the PoC if possible. End your response with the {VERDICT_BEGIN} ... {VERDICT_END} block exactly as instructed.
"""


def parse_findings_from_report(report_file: str) -> list[dict[str, Any]]:
    """Extract `### {title}` finding blocks from the report.

    Preferred path: bounds findings by the `## Findings` section. Fallback:
    if no `## Findings` heading exists (the existing finish_scan handler can
    drop it when splitting on `---`), each `### ` block in the document is
    treated as a finding, bounded by the next `### ` or `## ` heading or EOF.

    Returns a list of dicts: title, body, abs_start, abs_end. `body` strips
    the trailing `---` separator. `abs_start`/`abs_end` cover the full block
    including the trailing `---` so callers can splice cleanly.
    """
    path = Path(report_file)
    if not path.exists():
        return []

    text = path.read_text()

    findings_marker = "## Findings"
    if text.startswith(findings_marker):
        findings_idx = 0
    else:
        idx = text.find("\n" + findings_marker)
        findings_idx = idx + 1 if idx != -1 else -1

    if findings_idx != -1:
        nl = text.find("\n", findings_idx)
        section_start = nl + 1 if nl != -1 else len(text)
        next_match = _NEXT_TOP_SECTION_RE.search(text, section_start)
        section_end = next_match.start() if next_match else len(text)
    else:
        section_start = 0
        section_end = len(text)

    headers = [
        m for m in _FINDING_HEADER_RE.finditer(text, section_start, section_end)
    ]
    chunks: list[dict[str, Any]] = []
    for i, m in enumerate(headers):
        chunk_start = m.start()
        if i + 1 < len(headers):
            chunk_end = headers[i + 1].start()
        else:
            next_top = re.search(r"^## ", text[m.end():section_end], re.MULTILINE)
            chunk_end = m.end() + next_top.start() if next_top else section_end
        raw = text[chunk_start:chunk_end]
        body = raw.rstrip()
        body = re.sub(r"\n-{3,}\s*$", "", body).rstrip()
        chunks.append({
            "title": m.group("title").strip(),
            "body": body,
            "abs_start": chunk_start,
            "abs_end": chunk_end,
        })
    return chunks


def _extract_verdict(stdout: str) -> dict[str, Any] | None:
    if VERDICT_BEGIN not in stdout or VERDICT_END not in stdout:
        return None
    try:
        block = stdout.split(VERDICT_BEGIN, 1)[1].split(VERDICT_END, 1)[0].strip()
    except IndexError:
        return None

    fence_match = re.search(r"```(?:json)?\s*(.+?)```", block, re.DOTALL)
    if fence_match:
        block = fence_match.group(1).strip()
    try:
        return json.loads(block)
    except json.JSONDecodeError as e:
        logger.warning("Validator verdict JSON parse failed: %s | block=%r", e, block[:300])
        return None


def validate_finding(
    finding: dict[str, Any],
    mcp_config_path: Path,
    target_info: str,
    scan_mode: str,
    cpu_count: int,
    log_dir: Path,
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """Spawn a fresh `claude` subprocess to validate a single finding.

    Reuses the same MCP config, so the validator hits the same live sandbox
    that the scan agent used. Returns a verdict dict with keys:
    verdict ('valid' | 'false_positive' | 'unknown'), reasoning,
    severity_change, evidence, raw_output.
    """
    system_prompt = _validator_system_prompt(target_info, scan_mode, cpu_count)
    initial_prompt = _validator_initial_prompt(finding["body"], target_info)

    args = [
        "claude",
        "--model", "claude-opus-4-7",
        "--mcp-config", str(mcp_config_path),
        "--append-system-prompt", system_prompt,
        "--permission-mode", "bypassPermissions",
        "--dangerously-skip-permissions",
        "--print",
        initial_prompt,
    ]
    env = {**os.environ, "CLAUDE_CODE_SKIP_TRUST_DIALOG": "1"}

    log_dir.mkdir(parents=True, exist_ok=True)
    safe_title = re.sub(r"[^a-z0-9]+", "_", finding["title"].lower())[:60].strip("_") or "finding"
    log_file = log_dir / f"validator_{safe_title}.log"

    try:
        result = subprocess.run(
            args,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        rc = result.returncode
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or "")) or ""
        stderr = (e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, (bytes, bytearray)) else (e.stderr or "")) or ""
        log_file.write_text(f"TIMEOUT after {timeout_seconds}s\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
        return {
            "verdict": "unknown",
            "reasoning": f"validator timed out after {timeout_seconds}s",
            "severity_change": "keep",
            "evidence": "",
            "raw_output": stdout,
        }
    except Exception as e:
        log_file.write_text(f"EXCEPTION launching validator: {e}")
        return {
            "verdict": "unknown",
            "reasoning": f"validator subprocess failed: {e}",
            "severity_change": "keep",
            "evidence": "",
            "raw_output": "",
        }

    log_file.write_text(f"RC: {rc}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")

    parsed = _extract_verdict(stdout)
    if not parsed:
        return {
            "verdict": "unknown",
            "reasoning": "validator did not return a parseable verdict block",
            "severity_change": "keep",
            "evidence": "",
            "raw_output": stdout,
        }

    verdict = parsed.get("verdict")
    if verdict not in ("valid", "false_positive"):
        verdict = "unknown"

    return {
        "verdict": verdict,
        "reasoning": str(parsed.get("reasoning", "")),
        "severity_change": str(parsed.get("severity_change", "keep")),
        "evidence": str(parsed.get("evidence", "")),
        "raw_output": stdout,
    }


def _annotate_finding_body(body: str, verdict: dict[str, Any]) -> str:
    return (
        body.rstrip()
        + "\n\n"
        + f"**Validator Verdict:** {verdict['verdict'].upper()}\n"
        + f"**Validator Reasoning:** {verdict.get('reasoning', '')}\n"
        + f"**Validator Evidence:** {verdict.get('evidence', '')}\n"
        + f"**Severity Suggestion:** {verdict.get('severity_change', 'keep')}\n"
        + "\n---\n"
    )


def apply_validation_results(
    report_file: str,
    findings: list[dict[str, Any]],
    verdicts: list[dict[str, Any]],
) -> tuple[int, int, int, str | None]:
    """Rewrite the report: keep `valid` and `unknown` findings (with validator
    annotation), drop `false_positive` findings entirely, and write rejected
    findings to a sibling `<report-stem>.false_positives.md` file.

    Returns: (kept, rejected, unknown, fp_file_path or None).
    """
    path = Path(report_file)
    if not path.exists():
        return (0, 0, 0, None)

    text = path.read_text()

    paired = sorted(
        zip(findings, verdicts),
        key=lambda p: p[0]["abs_start"],
    )

    new_parts: list[str] = []
    rejected_blocks: list[str] = []
    cursor = 0
    kept = rejected = unknown = 0

    for finding, v in paired:
        new_parts.append(text[cursor:finding["abs_start"]])
        annotated = _annotate_finding_body(finding["body"], v)
        if v["verdict"] == "valid":
            new_parts.append(annotated + "\n")
            kept += 1
        elif v["verdict"] == "false_positive":
            rejected_blocks.append(annotated + "\n")
            rejected += 1
        else:
            new_parts.append(annotated + "\n")
            unknown += 1
        cursor = finding["abs_end"]

    new_parts.append(text[cursor:])
    new_text = "".join(new_parts).rstrip() + "\n"

    summary = (
        f"\n---\n\n"
        f"_Validator pass: {kept} kept, {rejected} false positives removed, "
        f"{unknown} unable to verify (kept and flagged). "
        f"Run at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}._\n"
    )
    new_text = new_text + summary
    path.write_text(new_text)

    fp_path: str | None = None
    if rejected_blocks:
        fp_file = path.parent / f"{path.stem}.false_positives.md"
        header = (
            f"# False Positives — {path.name}\n\n"
            f"_Generated by validator pass at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}._\n\n"
            "These findings were re-reviewed by an independent validator agent (fresh context, "
            "same sandbox) and judged to be false positives or unverifiable. They were removed "
            "from the main report and preserved here for audit.\n\n"
            "---\n\n"
        )
        fp_file.write_text(header + "\n".join(rejected_blocks))
        fp_path = str(fp_file)

    return (kept, rejected, unknown, fp_path)


def run_validation_pass(
    report_file: str,
    mcp_config_path: Path,
    target_info: str,
    scan_mode: str,
    cpu_count: int,
    log_dir: Path,
    console: Any | None = None,
) -> dict[str, Any]:
    """High-level entry point. Parses the report, validates each finding
    sequentially, and rewrites the report with the verdicts applied.
    """
    findings = parse_findings_from_report(report_file)
    if not findings:
        if console:
            console.print("[yellow]Validator pass skipped — no findings in report.[/yellow]")
        return {"total": 0, "kept": 0, "rejected": 0, "unknown": 0, "fp_file": None}

    if console:
        console.print(
            f"\n[bold cyan]Validator pass:[/bold cyan] re-checking "
            f"{len(findings)} finding(s) sequentially with a fresh agent per finding."
        )

    verdicts: list[dict[str, Any]] = []
    for i, finding in enumerate(findings, 1):
        if console:
            console.print(f"  [{i}/{len(findings)}] [bold]{finding['title']}[/bold] — validating…")
        v = validate_finding(
            finding=finding,
            mcp_config_path=mcp_config_path,
            target_info=target_info,
            scan_mode=scan_mode,
            cpu_count=cpu_count,
            log_dir=log_dir,
        )
        verdicts.append(v)
        if console:
            color = {"valid": "green", "false_positive": "red", "unknown": "yellow"}.get(v["verdict"], "white")
            reason_excerpt = (v.get("reasoning") or "").strip().replace("\n", " ")
            if len(reason_excerpt) > 140:
                reason_excerpt = reason_excerpt[:140] + "…"
            console.print(f"      → [{color}]{v['verdict'].upper()}[/{color}]: {reason_excerpt}")

    kept, rejected, unknown, fp_file = apply_validation_results(report_file, findings, verdicts)

    if console:
        console.print(
            f"[bold green]Validator pass complete:[/bold green] "
            f"{kept} kept · {rejected} false positives removed · {unknown} unverified."
        )
        if fp_file:
            console.print(f"  [dim]Rejected findings preserved at:[/dim] {fp_file}")
        console.print(f"  [dim]Validator logs:[/dim] {log_dir}")

    return {
        "total": len(findings),
        "kept": kept,
        "rejected": rejected,
        "unknown": unknown,
        "fp_file": fp_file,
    }
