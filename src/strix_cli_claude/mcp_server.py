"""MCP server that exposes penetration testing tools to Claude CLI."""

import asyncio
import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# The MCP server is launched as a script (`python mcp_server.py`), so relative
# imports fail. The package is installed via `pip install -e .`, so the absolute
# form works in both script and module contexts.
from strix_cli_claude import db as _h1_db
from strix_cli_claude.h1_client import H1Client, H1Error
from strix_cli_claude.intigriti_client import IntigritiClient, IntigritiError

logger = logging.getLogger(__name__)

# Tool server connection info (set by main.py before starting MCP server)
TOOL_SERVER_URL = os.getenv("STRIX_TOOL_SERVER_URL", "")
TOOL_SERVER_TOKEN = os.getenv("STRIX_TOOL_SERVER_TOKEN", "")
AGENT_ID = os.getenv("STRIX_AGENT_ID", "claude-cli-agent")
REPORT_FILE = os.getenv("STRIX_REPORT_FILE", "")


class ToolServerClient:
    """Client to communicate with the sandbox tool server."""

    MAX_RETRIES = 3
    RETRY_DELAY = 2.0  # seconds

    def __init__(self, base_url: str, token: str, agent_id: str):
        self.base_url = base_url
        self.token = token
        self.agent_id = agent_id
        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=300.0,
        )

    async def call_tool(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Call a tool on the sandbox tool server with retry logic."""
        last_error = None

        for attempt in range(self.MAX_RETRIES):
            try:
                response = await self.client.post(
                    "/execute",
                    json={
                        "tool_name": tool_name,
                        "kwargs": params,
                        "agent_id": self.agent_id,
                    },
                )
                response.raise_for_status()
                result = response.json()

                # Validate response structure
                if not isinstance(result, dict):
                    last_error = f"Invalid response from tool server: expected dict, got {type(result).__name__}"
                    continue

                # Check for empty error response (tool server bug)
                if "error" in result and "result" not in result:
                    error_msg = result.get("error", "")
                    if not error_msg:
                        last_error = "Tool server returned empty error (no result)"
                        if attempt < self.MAX_RETRIES - 1:
                            await asyncio.sleep(self.RETRY_DELAY)
                        continue

                return result

            except httpx.ConnectError as e:
                last_error = f"Cannot connect to tool server at {self.base_url}. Is the Docker container running? Details: {e}"
            except httpx.TimeoutException as e:
                last_error = f"Tool server request timed out. The command may still be running. Details: {e}"
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP error {e.response.status_code}: {e.response.text[:500] if e.response.text else 'No response body'}"
            except Exception as e:
                last_error = f"Tool server error ({type(e).__name__}): {str(e) or 'Unknown error'}"

            # Wait before retry (except on last attempt)
            if attempt < self.MAX_RETRIES - 1:
                await asyncio.sleep(self.RETRY_DELAY)

        # All retries failed
        return {
            "error": f"TOOL FAILURE after {self.MAX_RETRIES} attempts: {last_error}\n\n"
                     f"The sandbox tools are not responding. Please check:\n"
                     f"1. Is the Docker container still running? (docker ps)\n"
                     f"2. Check container logs: docker logs <container_name>\n"
                     f"3. The tool server may need to be restarted\n\n"
                     f"IMPORTANT: Please inform the user about this issue and wait for guidance before continuing."
        }

    async def close(self):
        await self.client.aclose()


# Define the tools available for pen testing
PENTEST_TOOLS = [
    Tool(
        name="terminal_execute",
        description="""Execute shell commands in the Kali Linux sandbox.

Available tools include:
- Reconnaissance: nmap, subfinder, httpx, gospider, katana
- Vulnerability scanning: nuclei, sqlmap, zaproxy, wapiti
- Fuzzing: ffuf, dirsearch, arjun
- Code analysis: semgrep, bandit, trufflehog
- JWT: jwt_tool
- WAF detection: wafw00f

The /workspace directory is shared and persistent.""",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute",
                },
                "terminal_id": {
                    "type": "string",
                    "description": "Terminal session ID (default: 'main')",
                    "default": "main",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Command timeout in seconds (default: 300)",
                    "default": 300,
                },
            },
            "required": ["command"],
        },
    ),
    Tool(
        name="python_action",
        description="""Execute Python code in the sandbox.

Pre-imported libraries:
- requests, httpx, aiohttp for HTTP
- bs4 (BeautifulSoup) for HTML parsing
- json, base64, hashlib for encoding
- re for regex
- asyncio for async operations

Use for:
- Custom exploit scripts
- Payload generation
- Automated testing loops
- Data processing

Actions: "execute" (run code), "new_session" (create session), "list_sessions", "close" """,
        inputSchema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["execute", "new_session", "list_sessions", "close"],
                    "description": "Action to perform (use 'execute' to run code)",
                },
                "code": {
                    "type": "string",
                    "description": "Python code to execute",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 30)",
                    "default": 30,
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID for persistent sessions",
                },
            },
            "required": ["action"],
        },
    ),
    Tool(
        name="browser_action",
        description="""Control a Playwright browser for web testing.

Actions:
- launch: Start browser (headless)
- goto: Navigate to URL
- click: Click element by selector
- type: Type text into element
- scroll: Scroll page (up/down/to element)
- screenshot: Take screenshot
- execute_js: Run JavaScript
- get_html: Get page HTML
- close: Close browser

The browser uses the Caido proxy automatically.""",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["launch", "goto", "click", "type", "scroll", "screenshot", "execute_js", "get_html", "close"],
                    "description": "Browser action to perform",
                },
                "url": {"type": "string", "description": "URL for goto action"},
                "selector": {"type": "string", "description": "CSS selector for click/type actions"},
                "text": {"type": "string", "description": "Text for type action"},
                "script": {"type": "string", "description": "JavaScript for execute_js action"},
                "direction": {"type": "string", "description": "Scroll direction: up, down, or selector"},
            },
            "required": ["action"],
        },
    ),
    Tool(
        name="list_requests",
        description="""List HTTP requests captured by the Caido proxy.

Filter by:
- host: Filter by hostname
- method: GET, POST, PUT, DELETE, etc.
- path: URL path pattern
- status_code: Response status

Returns request/response summary for analysis.""",
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Filter by hostname"},
                "method": {"type": "string", "description": "Filter by HTTP method"},
                "path": {"type": "string", "description": "Filter by path pattern"},
                "status_code": {"type": "integer", "description": "Filter by status code"},
                "limit": {"type": "integer", "description": "Max results (default: 50)", "default": 50},
            },
        },
    ),
    Tool(
        name="view_request",
        description="""View detailed request/response from proxy history.

Returns full headers and body for both request and response.""",
        inputSchema={
            "type": "object",
            "properties": {
                "request_id": {
                    "type": "string",
                    "description": "Request ID from list_requests",
                },
            },
            "required": ["request_id"],
        },
    ),
    Tool(
        name="send_request",
        description="""Send an HTTP request through the proxy.

For manual testing and exploitation.
Supports all HTTP methods and custom headers.""",
        inputSchema={
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP method"},
                "url": {"type": "string", "description": "Full URL"},
                "headers": {"type": "object", "description": "Request headers"},
                "body": {"type": "string", "description": "Request body"},
            },
            "required": ["method", "url"],
        },
    ),
    Tool(
        name="repeat_request",
        description="""Modify and replay a captured request.

Useful for testing parameter variations and payloads.""",
        inputSchema={
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Original request ID"},
                "modifications": {
                    "type": "object",
                    "description": "Modifications: {headers: {}, params: {}, body: string}",
                },
            },
            "required": ["request_id"],
        },
    ),
    Tool(
        name="str_replace_editor",
        description="""View, create, or edit files in the sandbox.

Commands:
- view: Read file contents (use view_range for specific lines)
- create: Create a new file with file_text content
- str_replace: Replace old_str with new_str in file
- insert: Insert new_str at insert_line

All paths relative to /workspace.""",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["view", "create", "str_replace", "insert"],
                    "description": "File operation command",
                },
                "path": {"type": "string", "description": "File path"},
                "file_text": {"type": "string", "description": "Content for create command"},
                "view_range": {"type": "array", "items": {"type": "integer"}, "description": "[start_line, end_line] for view"},
                "old_str": {"type": "string", "description": "String to replace (str_replace)"},
                "new_str": {"type": "string", "description": "Replacement string (str_replace/insert)"},
                "insert_line": {"type": "integer", "description": "Line number for insert"},
            },
            "required": ["command", "path"],
        },
    ),
    Tool(
        name="list_files",
        description="""List files in a directory in the sandbox.""",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path"},
                "recursive": {"type": "boolean", "description": "List recursively", "default": False},
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="create_vulnerability_report",
        description="""Create a formal vulnerability report. REQUIRED for every confirmed vulnerability.

This writes a detailed finding to the markdown report file with CVSS scoring.
Include complete technical details and proof-of-concept code.""",
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Vulnerability title"},
                "description": {"type": "string", "description": "What the vulnerability is"},
                "impact": {"type": "string", "description": "Business/security impact"},
                "target": {"type": "string", "description": "Affected endpoint/component"},
                "technical_analysis": {"type": "string", "description": "Technical details of how it works"},
                "poc_description": {"type": "string", "description": "PoC explanation"},
                "poc_script_code": {"type": "string", "description": "Actual exploit/PoC code"},
                "remediation_steps": {"type": "string", "description": "How to fix"},
                "attack_vector": {
                    "type": "string",
                    "enum": ["N", "A", "L", "P"],
                    "description": "CVSS Attack Vector: N=Network, A=Adjacent, L=Local, P=Physical",
                },
                "attack_complexity": {
                    "type": "string",
                    "enum": ["L", "H"],
                    "description": "CVSS Attack Complexity: L=Low, H=High",
                },
                "privileges_required": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Privileges Required: N=None, L=Low, H=High",
                },
                "user_interaction": {
                    "type": "string",
                    "enum": ["N", "R"],
                    "description": "CVSS User Interaction: N=None, R=Required",
                },
                "scope": {
                    "type": "string",
                    "enum": ["U", "C"],
                    "description": "CVSS Scope: U=Unchanged, C=Changed",
                },
                "confidentiality": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Confidentiality Impact: N=None, L=Low, H=High",
                },
                "integrity": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Integrity Impact: N=None, L=Low, H=High",
                },
                "availability": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Availability Impact: N=None, L=Low, H=High",
                },
                "endpoint": {"type": "string", "description": "Specific endpoint/URL affected"},
                "method": {"type": "string", "description": "HTTP method if applicable"},
            },
            "required": ["title", "description", "impact", "target", "technical_analysis", "poc_description", "poc_script_code", "remediation_steps", "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope", "confidentiality", "integrity", "availability"],
        },
    ),
    Tool(
        name="write_report",
        description="""Write findings to the markdown report file on the host machine.

Use this to document all findings, vulnerabilities, and scan results.
The report is saved to the location specified when starting the scan.

Call this tool to:
- Add a new finding/vulnerability
- Update the executive summary
- Add reconnaissance results
- Document the methodology used

Content should be valid markdown.""",
        inputSchema={
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Markdown content to append to the report",
                },
                "section": {
                    "type": "string",
                    "enum": ["header", "executive_summary", "findings", "reconnaissance", "methodology", "appendix"],
                    "description": "Report section (findings is default)",
                    "default": "findings",
                },
                "overwrite": {
                    "type": "boolean",
                    "description": "If true, overwrite the entire report instead of appending",
                    "default": False,
                },
            },
            "required": ["content"],
        },
    ),
    Tool(
        name="read_report",
        description="""Read the current contents of the security report file.

Use this to review what has been documented so far.""",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    Tool(
        name="create_note",
        description="""Create a note to save information during the assessment.

Use for:
- Saving interesting findings for later investigation
- Recording observations and hypotheses
- Tracking attack paths to explore
- Documenting methodology decisions""",
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Note title"},
                "content": {"type": "string", "description": "Note content"},
                "category": {
                    "type": "string",
                    "enum": ["general", "findings", "methodology", "questions", "plan"],
                    "description": "Note category",
                    "default": "general",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags for organization",
                },
            },
            "required": ["title", "content"],
        },
    ),
    Tool(
        name="list_notes",
        description="""List saved notes, optionally filtered by category or search.""",
        inputSchema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["general", "findings", "methodology", "questions", "plan"],
                    "description": "Filter by category",
                },
                "search": {"type": "string", "description": "Search in title/content"},
            },
        },
    ),
    Tool(
        name="think",
        description="""Use this tool for complex reasoning, planning, and analysis.

Call this when you need to:
- Plan your attack strategy
- Analyze findings before reporting
- Work through complex logic
- Reason about potential vulnerabilities

Your thought will be logged to the report for documentation.""",
        inputSchema={
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "Your reasoning, analysis, or planning thoughts",
                },
            },
            "required": ["thought"],
        },
    ),
    Tool(
        name="finish_scan",
        description="""Finalize the security assessment and write the complete report.

Call this when you have completed all testing and want to finalize the report.
This writes the executive summary, methodology, analysis, and recommendations.

ONLY call this when you are completely done with the assessment.""",
        inputSchema={
            "type": "object",
            "properties": {
                "executive_summary": {
                    "type": "string",
                    "description": "High-level summary of findings for executives (2-3 paragraphs)",
                },
                "methodology": {
                    "type": "string",
                    "description": "Testing methodology used (tools, techniques, approach)",
                },
                "technical_analysis": {
                    "type": "string",
                    "description": "Detailed technical analysis of the security posture",
                },
                "recommendations": {
                    "type": "string",
                    "description": "Prioritized recommendations for remediation",
                },
            },
            "required": ["executive_summary", "methodology", "technical_analysis", "recommendations"],
        },
    ),
    Tool(
        name="fetch_github_org_repos",
        description="""Fetch all scannable repositories from a GitHub organization.

Returns a filtered list of repos (skips archived, disabled, forked, demo/example/sample/test repos, and repos exceeding max_size_kb).
Each repo includes: name, full_name, clone_url, html_url, stars, language, description, default_branch, size_kb.

Use this tool when scanning a GitHub org to get the list of repos to clone and scan.
After getting the list, clone repos inside the sandbox using terminal_execute with git clone.""",
        inputSchema={
            "type": "object",
            "properties": {
                "org": {
                    "type": "string",
                    "description": "GitHub organization name (e.g. 'facebook', 'google')",
                },
                "include_private": {
                    "type": "boolean",
                    "description": "Include private repos (requires token with appropriate scope)",
                    "default": False,
                },
                "max_size_kb": {
                    "type": "integer",
                    "description": "Maximum repo size in KB. Repos larger than this are skipped. Default: 2097152 (2 GB)",
                    "default": 2097152,
                },
            },
            "required": ["org"],
        },
    ),
    Tool(
        name="download_extension",
        description="""Download a VS Code Marketplace or Chrome Web Store extension and extract its source into /workspace inside the sandbox for whitebox review.

Pass the public marketplace listing URL. Supported URL shapes:
- VS Code: https://marketplace.visualstudio.com/items?itemName=publisher.extension
- Chrome (new): https://chromewebstore.google.com/detail/<slug>/<32-char-id>
- Chrome (old): https://chrome.google.com/webstore/detail/<slug>/<32-char-id>

The tool resolves the direct package URL (.vsix or .crx — both are zip archives), curls it inside the sandbox, and unzips it to /workspace/<auto-generated-name>. Returns the extracted path on success.

After it returns, list_files /workspace/<name> and start your whitebox review. Do NOT probe the marketplace listing URL itself — it is just the delivery channel.""",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Public marketplace listing URL for the extension",
                },
                "name": {
                    "type": "string",
                    "description": "Optional override for the /workspace subdirectory name. Defaults to an auto-generated name like 'vscode_<publisher>_<extension>' or 'chrome_<slug>_<id-prefix>'.",
                },
            },
            "required": ["url"],
        },
    ),
]


# ---------------------------------------------------------------------------
# Bounty tools — HackerOne + Intigriti + scan queue + findings ledger.
# Backed by SQLite at ~/.strix/strix.db. All tools run in-process; the
# sandbox is not required to call any of them.
# ---------------------------------------------------------------------------

BOUNTY_TOOLS = [
    Tool(
        name="h1_sync_programs",
        description=(
            "Pull all programs and their structured scopes from the HackerOne "
            "API and upsert into local SQLite. Use once at the start of a "
            "session (or to refresh). Reads H1_USERNAME and H1_TOKEN from the "
            "MCP server's environment. Returns counts of programs and targets "
            "synced."
        ),
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    Tool(
        name="h1_list_programs",
        description=(
            "List HackerOne programs currently stored in the local DB (after "
            "sync). Optionally filter by substring of the program handle."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "handle_filter": {
                    "type": "string",
                    "description": "Case-insensitive substring of the program handle",
                },
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="h1_get_scope",
        description=(
            "Return all in-scope assets for a single program from the local "
            "DB (after sync). Each row gives asset_type, identifier, "
            "max_severity, eligible_for_bounty, and the maintainer's free-text "
            "instruction."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "program_handle": {
                    "type": "string",
                    "description": "HackerOne program handle, e.g. 'shopify'",
                },
            },
            "required": ["program_handle"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="scope_summary",
        description=(
            "Return counts grouped by (source, program, asset_type). If "
            "program_handle is given, returns per-asset-type totals plus a "
            "scan-status breakdown for that program only. Use to render the "
            "scope picker. Optional `source` narrows to 'h1' or 'intigriti'."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "program_handle": {"type": "string"},
                "source": {
                    "type": "string",
                    "enum": ["h1", "intigriti"],
                    "description": "Limit to one platform",
                },
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="scan_claim_next",
        description=(
            "Atomically claim the next pending target. Marks it 'in_progress' "
            "and returns its row, or returns {target: null} if nothing is "
            "available. Stale claims (in_progress > 4h) are automatically "
            "reclaimable. Optional filters narrow the queue."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "enum": ["h1", "intigriti"],
                    "description": "Limit to one platform",
                },
                "program_handles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Limit to these program handles",
                },
                "asset_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Limit to these asset types (e.g. SOURCE_CODE, URL, WILDCARD, DOMAIN, IP_ADDRESS)",
                },
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="scan_mark_done",
        description="Mark a target as 'done' with a short summary of what was scanned.",
        inputSchema={
            "type": "object",
            "properties": {
                "target_id": {"type": "integer"},
                "summary": {"type": "string"},
            },
            "required": ["target_id"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="scan_mark_skipped",
        description=(
            "Mark a target as 'skipped' with a reason (e.g. archived, demo, "
            "out-of-scope-after-recon, oversized). Frees the slot."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target_id": {"type": "integer"},
                "reason": {"type": "string"},
            },
            "required": ["target_id", "reason"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="scan_status",
        description=(
            "Return scan-status counts (pending / in_progress / done / "
            "skipped / error). Optionally scoped to a single program and/or platform."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "program_handle": {"type": "string"},
                "source": {"type": "string", "enum": ["h1", "intigriti"]},
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="finding_create",
        description=(
            "Record a candidate finding against a target. Status is "
            "'candidate' — promote to 'confirmed' via finding_confirm only "
            "after an independent validator subagent agrees."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target_id": {"type": "integer"},
                "title": {"type": "string"},
                "severity": {
                    "type": "string",
                    "description": "low | medium | high | critical",
                },
                "vuln_type": {"type": "string"},
                "asset": {"type": "string", "description": "Specific URL/path/file:line"},
                "poc_path": {
                    "type": "string",
                    "description": "Path to the PoC file (markdown/curl/script)",
                },
                "notes": {"type": "string"},
            },
            "required": ["target_id", "title"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="finding_confirm",
        description="Promote a candidate finding to 'confirmed' after validator pass.",
        inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "validator_notes": {"type": "string"},
            },
            "required": ["finding_id"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="finding_reject",
        description="Mark a finding as 'rejected' (false positive / out of scope / dup-of-known).",
        inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "reason": {"type": "string"},
            },
            "required": ["finding_id", "reason"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="finding_list",
        description=(
            "List findings. Filter by status (candidate|confirmed|rejected|"
            "submitted|duplicate), program_handle, and/or source. Use this to "
            "review what's ready to submit on hackerone.com or intigriti.com."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "program_handle": {"type": "string"},
                "source": {"type": "string", "enum": ["h1", "intigriti"]},
                "limit": {"type": "integer", "default": 200},
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="intigriti_sync_programs",
        description=(
            "Pull all programs and their scopes from the Intigriti researcher "
            "API and upsert into local SQLite under source='intigriti'. Requires "
            "INTIGRITI_TOKEN in the MCP server's environment. Returns counts."
        ),
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    Tool(
        name="intigriti_list_programs",
        description=(
            "List Intigriti programs stored in the local DB (after sync). "
            "Optionally filter by substring of the program handle "
            "(handles are 'company/program' style)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "handle_filter": {"type": "string"},
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="intigriti_get_scope",
        description=(
            "Return all in-scope assets for a single Intigriti program from the "
            "local DB (after sync). Handle is 'company/program' style."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "program_handle": {"type": "string"},
            },
            "required": ["program_handle"],
            "additionalProperties": False,
        },
    ),
]

PENTEST_TOOLS = PENTEST_TOOLS + BOUNTY_TOOLS


BOUNTY_TOOL_NAMES = {t.name for t in BOUNTY_TOOLS}


def create_server() -> Server:
    """Create the MCP server with pentest tools."""
    server = Server("strix-claude-code")

    # DB is lazy-initialized; calling init_db() here is cheap and idempotent.
    try:
        _h1_db.init_db()
    except Exception as e:
        logger.warning("DB init failed (H1 tools will error individually): %s", e)

    tool_client: ToolServerClient | None = None

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return PENTEST_TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        nonlocal tool_client

        # H1 / scan-queue / findings tools (host-local, no sandbox needed)
        if name in BOUNTY_TOOL_NAMES:
            return await handle_h1_tool(name, arguments)

        # Handle local tools (write to host filesystem)
        if name == "write_report":
            return await handle_write_report(arguments)

        if name == "create_vulnerability_report":
            return await handle_create_vulnerability_report(arguments)

        if name == "think":
            return await handle_think(arguments)

        if name == "finish_scan":
            return await handle_finish_scan(arguments)

        if name == "create_note":
            return await handle_create_note(arguments)

        if name == "list_notes":
            return await handle_list_notes(arguments)

        if name == "read_report":
            return await handle_read_report()

        if name == "fetch_github_org_repos":
            return await handle_fetch_github_org_repos(arguments)

        if name == "download_extension":
            if not TOOL_SERVER_URL or not TOOL_SERVER_TOKEN:
                return [TextContent(type="text", text="Error: Tool server not configured — cannot download into sandbox.")]
            if tool_client is None:
                tool_client = ToolServerClient(TOOL_SERVER_URL, TOOL_SERVER_TOKEN, AGENT_ID)
            return await handle_download_extension(arguments, tool_client)

        if not TOOL_SERVER_URL or not TOOL_SERVER_TOKEN:
            return [TextContent(
                type="text",
                text="Error: Tool server not configured. Make sure STRIX_TOOL_SERVER_URL and STRIX_TOOL_SERVER_TOKEN are set.",
            )]

        if tool_client is None:
            tool_client = ToolServerClient(TOOL_SERVER_URL, TOOL_SERVER_TOKEN, AGENT_ID)

        result = await tool_client.call_tool(name, arguments)

        # Check for error in response (handle both non-empty errors and error-only responses)
        if "error" in result:
            error_msg = result.get("error")
            # If there's an error key with no result key, it's definitely an error
            if "result" not in result:
                if error_msg:
                    return [TextContent(type="text", text=f"Error: {error_msg}")]
                else:
                    return [TextContent(type="text", text=f"Error: Tool '{name}' failed with no error message. The tool server may not be responding correctly.")]
            # If there's both error and result, only fail if error is non-empty
            elif error_msg:
                return [TextContent(type="text", text=f"Error: {error_msg}")]

        # Extract the actual result - tool server returns {"result": {...}, "error": null}
        tool_result = result.get("result")

        # Handle missing result
        if tool_result is None:
            return [TextContent(type="text", text=f"Error: Tool '{name}' returned no result. Response: {json.dumps(result)[:200]}")]

        # Format output - look for content field first (terminal_execute, etc.)
        if isinstance(tool_result, dict):
            if "content" in tool_result:
                output = tool_result["content"]
                # Handle empty content
                if output is None or output == "":
                    output = "(empty output)"
                # Add status info if available
                if tool_result.get("status") == "error":
                    output = f"Error: {output}"
                elif tool_result.get("exit_code") is not None and tool_result.get("exit_code") != 0:
                    output = f"{output}\n[Exit code: {tool_result['exit_code']}]"
            elif "error" in tool_result and tool_result["error"]:
                output = f"Error: {tool_result['error']}"
            elif "output" in tool_result:
                # Some tools return "output" instead of "content"
                output = tool_result["output"] or "(empty output)"
            elif "data" in tool_result:
                # Some tools return "data"
                output = json.dumps(tool_result["data"], indent=2) if tool_result["data"] else "(no data)"
            else:
                output = json.dumps(tool_result, indent=2)
        elif isinstance(tool_result, str):
            output = tool_result or "(empty output)"
        elif isinstance(tool_result, list):
            output = json.dumps(tool_result, indent=2) if tool_result else "(empty list)"
        else:
            output = str(tool_result) if tool_result else "(empty result)"

        return [TextContent(type="text", text=output)]

    async def handle_write_report(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle write_report tool - writes to host filesystem."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        content = arguments.get("content", "")
        section = arguments.get("section", "findings")
        overwrite = arguments.get("overwrite", False)

        try:
            from pathlib import Path
            from datetime import datetime

            report_path = Path(REPORT_FILE)

            # Create report with header if it doesn't exist or overwriting
            if overwrite or not report_path.exists():
                header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix Claude Code

---

"""
                report_path.write_text(header + content)
                return [TextContent(type="text", text=f"Report created: {REPORT_FILE}")]

            # Append to existing report
            existing = report_path.read_text()

            # Add section header if needed
            section_headers = {
                "executive_summary": "\n## Executive Summary\n\n",
                "findings": "\n## Findings\n\n",
                "reconnaissance": "\n## Reconnaissance\n\n",
                "methodology": "\n## Methodology\n\n",
                "appendix": "\n## Appendix\n\n",
            }

            section_header = section_headers.get(section, "\n")

            # Only add section header if it's not already in the report
            if section != "header" and section_header.strip() not in existing:
                content = section_header + content
            else:
                content = "\n" + content

            report_path.write_text(existing + content)
            return [TextContent(type="text", text=f"Appended to report: {REPORT_FILE}")]

        except Exception as e:
            return [TextContent(type="text", text=f"Error writing report: {e}")]

    async def handle_create_vulnerability_report(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle create_vulnerability_report - calculates CVSS and writes to report."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        try:
            from pathlib import Path
            from datetime import datetime

            # Extract arguments
            title = arguments.get("title", "")
            description = arguments.get("description", "")
            impact = arguments.get("impact", "")
            target = arguments.get("target", "")
            technical_analysis = arguments.get("technical_analysis", "")
            poc_description = arguments.get("poc_description", "")
            poc_script_code = arguments.get("poc_script_code", "")
            remediation_steps = arguments.get("remediation_steps", "")
            endpoint = arguments.get("endpoint", "")
            method = arguments.get("method", "")

            # CVSS parameters
            av = arguments.get("attack_vector", "N")
            ac = arguments.get("attack_complexity", "L")
            pr = arguments.get("privileges_required", "N")
            ui = arguments.get("user_interaction", "N")
            s = arguments.get("scope", "U")
            c = arguments.get("confidentiality", "H")
            i = arguments.get("integrity", "H")
            a = arguments.get("availability", "N")

            # Calculate CVSS 3.1 score
            cvss_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
            cvss_score, severity = calculate_cvss(av, ac, pr, ui, s, c, i, a)

            # Format the vulnerability report
            report_content = f"""
### {title}

**Severity:** {severity.upper()} ({cvss_score:.1f})
**CVSS Vector:** `{cvss_vector}`
**Target:** {target}
{f"**Endpoint:** {endpoint}" if endpoint else ""}
{f"**Method:** {method}" if method else ""}

#### Description
{description}

#### Impact
{impact}

#### Technical Analysis
{technical_analysis}

#### Proof of Concept
{poc_description}

```
{poc_script_code}
```

#### Remediation
{remediation_steps}

---
"""

            # Write to report file
            report_path = Path(REPORT_FILE)

            if not report_path.exists():
                header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix Claude Code

---

## Findings

"""
                report_path.write_text(header + report_content)
            else:
                existing = report_path.read_text()

                # Check for duplicate vulnerability (same title)
                if f"### {title}" in existing:
                    return [TextContent(
                        type="text",
                        text=f"Vulnerability already documented: {title}\n(Skipped duplicate entry)"
                    )]

                if "## Findings" not in existing:
                    existing += "\n## Findings\n"
                report_path.write_text(existing + report_content)

            return [TextContent(
                type="text",
                text=f"Vulnerability report created: {title}\nSeverity: {severity.upper()} (CVSS {cvss_score:.1f})\nSaved to: {REPORT_FILE}"
            )]

        except Exception as e:
            return [TextContent(type="text", text=f"Error creating vulnerability report: {e}")]

    async def handle_think(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle think tool - logs reasoning to report."""
        thought = arguments.get("thought", "")

        if not thought or not thought.strip():
            return [TextContent(type="text", text="Error: Thought cannot be empty")]

        # Optionally log to report file
        if REPORT_FILE:
            try:
                from pathlib import Path
                from datetime import datetime

                report_path = Path(REPORT_FILE)

                if report_path.exists():
                    existing = report_path.read_text()
                    # Add to methodology/analysis section if exists, otherwise just append
                    log_entry = f"\n> **Analysis Note** ({datetime.now().strftime('%H:%M:%S')}): {thought[:500]}{'...' if len(thought) > 500 else ''}\n"
                    report_path.write_text(existing + log_entry)
            except Exception:
                pass  # Non-critical, just skip logging

        return [TextContent(
            type="text",
            text=f"Thought recorded ({len(thought.strip())} chars). Continue with your analysis."
        )]

    async def handle_finish_scan(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle finish_scan - writes final report sections."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        executive_summary = arguments.get("executive_summary", "")
        methodology = arguments.get("methodology", "")
        technical_analysis = arguments.get("technical_analysis", "")
        recommendations = arguments.get("recommendations", "")

        # Validate
        errors = []
        if not executive_summary.strip():
            errors.append("Executive summary cannot be empty")
        if not methodology.strip():
            errors.append("Methodology cannot be empty")
        if not technical_analysis.strip():
            errors.append("Technical analysis cannot be empty")
        if not recommendations.strip():
            errors.append("Recommendations cannot be empty")

        if errors:
            return [TextContent(type="text", text=f"Validation errors: {', '.join(errors)}")]

        try:
            from pathlib import Path
            from datetime import datetime

            report_path = Path(REPORT_FILE)

            # Build final report sections
            final_sections = f"""
## Executive Summary

{executive_summary}

## Methodology

{methodology}

## Technical Analysis

{technical_analysis}

## Recommendations

{recommendations}

---

**Report Completed:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

            if report_path.exists():
                existing = report_path.read_text()
                # Insert executive summary at the beginning (after header)
                if "## Executive Summary" not in existing:
                    # Find end of header section
                    if "---" in existing:
                        parts = existing.split("---", 2)
                        if len(parts) >= 2:
                            new_content = parts[0] + "---" + final_sections + "\n---".join(parts[2:]) if len(parts) > 2 else parts[0] + "---" + final_sections
                            report_path.write_text(new_content)
                        else:
                            report_path.write_text(existing + final_sections)
                    else:
                        report_path.write_text(existing + final_sections)
                else:
                    # Already has sections, append recommendations update
                    report_path.write_text(existing + f"\n\n---\n**Report Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            else:
                # Create new report with all sections
                header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix Claude Code

---
{final_sections}
"""
                report_path.write_text(header)

            return [TextContent(
                type="text",
                text=f"Scan completed successfully!\nReport saved to: {REPORT_FILE}\n\nThe report includes:\n- Executive Summary\n- Methodology\n- Technical Analysis\n- Recommendations\n- All vulnerability findings"
            )]

        except Exception as e:
            return [TextContent(type="text", text=f"Error finishing scan: {e}")]

    async def handle_read_report() -> list[TextContent]:
        """Handle read_report - reads the report from host filesystem."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        try:
            from pathlib import Path
            report_path = Path(REPORT_FILE)

            if not report_path.exists():
                return [TextContent(type="text", text=f"Report file does not exist yet: {REPORT_FILE}")]

            content = report_path.read_text()
            return [TextContent(type="text", text=f"**Report: {REPORT_FILE}**\n\n{content}")]

        except Exception as e:
            return [TextContent(type="text", text=f"Error reading report: {e}")]

    # In-memory notes storage
    notes_storage: dict[str, dict[str, Any]] = {}

    async def handle_create_note(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle create_note - saves notes in memory and to report."""
        import uuid
        from datetime import datetime

        title = arguments.get("title", "")
        content = arguments.get("content", "")
        category = arguments.get("category", "general")
        tags = arguments.get("tags", [])

        if not title.strip():
            return [TextContent(type="text", text="Error: Title cannot be empty")]
        if not content.strip():
            return [TextContent(type="text", text="Error: Content cannot be empty")]

        valid_categories = ["general", "findings", "methodology", "questions", "plan"]
        if category not in valid_categories:
            return [TextContent(type="text", text=f"Error: Invalid category. Must be one of: {', '.join(valid_categories)}")]

        note_id = str(uuid.uuid4())[:5]
        timestamp = datetime.now().isoformat()

        notes_storage[note_id] = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": tags,
            "created_at": timestamp,
        }

        # Also append to report file
        if REPORT_FILE:
            try:
                from pathlib import Path
                report_path = Path(REPORT_FILE)
                if report_path.exists():
                    existing = report_path.read_text()
                    note_entry = f"\n> **Note [{category}]** - {title}: {content[:200]}{'...' if len(content) > 200 else ''}\n"
                    report_path.write_text(existing + note_entry)
            except Exception:
                pass

        return [TextContent(
            type="text",
            text=f"Note created: {title} (ID: {note_id}, Category: {category})"
        )]

    async def handle_list_notes(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle list_notes - lists saved notes."""
        category = arguments.get("category")
        search = arguments.get("search", "").lower()

        filtered = []
        for note_id, note in notes_storage.items():
            if category and note.get("category") != category:
                continue
            if search:
                if search not in note.get("title", "").lower() and search not in note.get("content", "").lower():
                    continue
            filtered.append({"id": note_id, **note})

        if not filtered:
            return [TextContent(type="text", text="No notes found.")]

        output = f"Found {len(filtered)} note(s):\n\n"
        for note in filtered:
            output += f"- [{note['id']}] **{note['title']}** ({note['category']})\n  {note['content'][:100]}{'...' if len(note['content']) > 100 else ''}\n\n"

        return [TextContent(type="text", text=output)]

    async def handle_download_extension(arguments: dict[str, Any], client: ToolServerClient) -> list[TextContent]:
        """Resolve a marketplace URL to a direct package URL, then run curl+unzip
        inside the sandbox to extract the extension to /workspace/<name>.
        """
        from .extension_downloader import _crx_url, _vsix_url, parse_extension_url

        url = (arguments.get("url") or "").strip()
        if not url:
            return [TextContent(type="text", text="Error: url parameter is required")]

        info = parse_extension_url(url)
        if info is None:
            return [TextContent(
                type="text",
                text=(
                    "Error: not a recognized extension URL. Supported: "
                    "marketplace.visualstudio.com/items?itemName=publisher.ext, "
                    "chromewebstore.google.com/detail/<slug>/<id>, "
                    "chrome.google.com/webstore/detail/<slug>/<id>."
                ),
            )]

        name = (arguments.get("name") or info["name"]).strip()
        # Sanitize the name for shell safety — keep alnum, dot, dash, underscore
        import re as _re
        if not _re.fullmatch(r"[A-Za-z0-9._-]+", name):
            return [TextContent(type="text", text=f"Error: invalid name '{name}' (alnum/./_/- only)")]

        if info["kind"] == "vscode":
            download_url = _vsix_url(info["publisher"], info["extension"])
            archive_ext = "vsix"
        else:
            download_url = _crx_url(info["ext_id"])
            archive_ext = "crx"

        workspace_path = f"/workspace/{name}"
        archive_path = f"/tmp/{name}.{archive_ext}"

        # Run inside the sandbox: curl -> python zipfile (handles CRX header prefix)
        shell = (
            "set -e\n"
            f"mkdir -p {workspace_path}\n"
            f"curl -fSL --retry 2 --max-time 180 '{download_url}' -o {archive_path}\n"
            f"size=$(stat -c%s {archive_path})\n"
            'if [ "$size" -lt 256 ]; then echo "archive too small ($size bytes) — download likely failed"; exit 1; fi\n'
            f"python3 -c 'import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' {archive_path} {workspace_path}\n"
            f"rm -f {archive_path}\n"
            f"echo OK\n"
            f"ls -la {workspace_path} | head -30\n"
        )

        result = await client.call_tool("terminal_execute", {"command": shell, "timeout": 300})

        err = result.get("error")
        tool_result = result.get("result") or {}
        content = (tool_result.get("content") if isinstance(tool_result, dict) else None) or ""
        exit_code = tool_result.get("exit_code") if isinstance(tool_result, dict) else None

        if err or (exit_code not in (0, None)):
            return [TextContent(
                type="text",
                text=(
                    f"Error downloading extension into sandbox.\n"
                    f"Source URL: {url}\n"
                    f"Resolved package URL: {download_url}\n"
                    f"Exit code: {exit_code}\n"
                    f"Output:\n{content}\n"
                    f"Tool error: {err or '(none)'}"
                ),
            )]

        return [TextContent(
            type="text",
            text=(
                f"Extension downloaded.\n"
                f"  Source URL: {url}\n"
                f"  Kind: {info['kind']}\n"
                f"  Extracted at: {workspace_path}\n\n"
                f"Listing:\n{content}"
            ),
        )]

    async def handle_fetch_github_org_repos(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle fetch_github_org_repos - fetches repos from GitHub org via API."""
        org = arguments.get("org", "").strip()
        include_private = arguments.get("include_private", False)
        max_size_kb = arguments.get("max_size_kb", 2097152)

        if not org:
            return [TextContent(type="text", text="Error: org parameter is required")]

        try:
            from strix_cli_claude.github_org import fetch_org_repos
            repos = fetch_org_repos(org, include_private=include_private, max_size_kb=max_size_kb)

            if not repos:
                return [TextContent(type="text", text=f"No repos found for org '{org}' after filtering.")]

            # Format as JSON for Claude to parse
            output = json.dumps({
                "org": org,
                "total_repos": len(repos),
                "repos": repos,
            }, indent=2)

            return [TextContent(type="text", text=output)]

        except ValueError as e:
            return [TextContent(type="text", text=f"Error: {e}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error fetching repos: {e}")]

    async def handle_h1_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Dispatch for H1 / scan-queue / findings tools. All run in-process."""

        def _txt(payload: Any) -> list[TextContent]:
            if isinstance(payload, str):
                return [TextContent(type="text", text=payload)]
            return [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]

        try:
            if name == "h1_sync_programs":
                programs_synced = 0
                targets_synced = 0
                handles: list[str] = []
                with H1Client() as client:
                    programs = client.list_programs()
                    with _h1_db.get_conn() as conn:
                        for p in programs:
                            _h1_db.upsert_program(
                                conn,
                                handle=p["handle"],
                                name=p["name"],
                                policy_url=p["policy_url"],
                                offers_bounty=p["offers_bounty"],
                                submission_state=p.get("submission_state"),
                                source="h1",
                            )
                            handles.append(p["handle"])
                            programs_synced += 1

                    for p in programs:
                        try:
                            scopes = client.get_structured_scopes(p["handle"])
                        except H1Error as e:
                            logger.warning("scope fetch failed for %s: %s", p["handle"], e)
                            continue
                        with _h1_db.get_conn() as conn:
                            for s in scopes:
                                if not s.get("eligible_for_submission"):
                                    continue
                                _h1_db.upsert_target(
                                    conn,
                                    program_handle=p["handle"],
                                    asset_type=s["asset_type"],
                                    identifier=s["asset_identifier"],
                                    eligible_for_bounty=s["eligible_for_bounty"],
                                    max_severity=s.get("max_severity"),
                                    instruction=s.get("instruction"),
                                    source="h1",
                                )
                                targets_synced += 1

                _h1_db.mark_programs_archived_except(handles, source="h1")
                return _txt({
                    "source": "h1",
                    "programs_synced": programs_synced,
                    "targets_synced": targets_synced,
                })

            if name == "intigriti_sync_programs":
                programs_synced = 0
                targets_synced = 0
                handles: list[str] = []
                with IntigritiClient() as client:
                    programs = client.list_programs()
                    with _h1_db.get_conn() as conn:
                        for p in programs:
                            _h1_db.upsert_program(
                                conn,
                                handle=p["handle"],
                                name=p["name"],
                                policy_url=p.get("policy_url"),
                                offers_bounty=p["offers_bounty"],
                                submission_state=p.get("submission_state"),
                                source="intigriti",
                            )
                            handles.append(p["handle"])
                            programs_synced += 1

                    for p in programs:
                        try:
                            scopes = client.get_program_scope(p["id"])
                        except IntigritiError as e:
                            logger.warning("scope fetch failed for %s: %s", p["handle"], e)
                            continue
                        with _h1_db.get_conn() as conn:
                            for s in scopes:
                                if not s.get("eligible_for_submission"):
                                    continue
                                _h1_db.upsert_target(
                                    conn,
                                    program_handle=p["handle"],
                                    asset_type=s["asset_type"],
                                    identifier=s["asset_identifier"],
                                    eligible_for_bounty=s["eligible_for_bounty"],
                                    max_severity=s.get("max_severity"),
                                    instruction=s.get("instruction"),
                                    source="intigriti",
                                )
                                targets_synced += 1

                _h1_db.mark_programs_archived_except(handles, source="intigriti")
                return _txt({
                    "source": "intigriti",
                    "programs_synced": programs_synced,
                    "targets_synced": targets_synced,
                })

            if name == "h1_list_programs":
                return _txt(_h1_db.list_programs(
                    handle_filter=arguments.get("handle_filter"),
                    source="h1",
                ))

            if name == "intigriti_list_programs":
                return _txt(_h1_db.list_programs(
                    handle_filter=arguments.get("handle_filter"),
                    source="intigriti",
                ))

            if name == "h1_get_scope":
                handle = arguments.get("program_handle")
                if not handle:
                    return _txt("Error: program_handle is required")
                with _h1_db.get_conn() as conn:
                    rows = conn.execute(
                        "SELECT id, asset_type, identifier, eligible_for_bounty,"
                        " max_severity, instruction, scan_status, summary"
                        " FROM targets WHERE source='h1' AND program_handle=?"
                        " ORDER BY asset_type, id",
                        (handle,),
                    ).fetchall()
                return _txt([dict(r) for r in rows])

            if name == "intigriti_get_scope":
                handle = arguments.get("program_handle")
                if not handle:
                    return _txt("Error: program_handle is required")
                with _h1_db.get_conn() as conn:
                    rows = conn.execute(
                        "SELECT id, asset_type, identifier, eligible_for_bounty,"
                        " max_severity, instruction, scan_status, summary"
                        " FROM targets WHERE source='intigriti' AND program_handle=?"
                        " ORDER BY asset_type, id",
                        (handle,),
                    ).fetchall()
                return _txt([dict(r) for r in rows])

            if name == "scope_summary":
                return _txt(_h1_db.scope_summary(
                    program_handle=arguments.get("program_handle"),
                    source=arguments.get("source"),
                ))

            if name == "scan_claim_next":
                row = _h1_db.claim_next_target(
                    program_handles=arguments.get("program_handles"),
                    asset_types=arguments.get("asset_types"),
                    source=arguments.get("source"),
                )
                return _txt({"target": row})

            if name == "scan_mark_done":
                target_id = arguments.get("target_id")
                if target_id is None:
                    return _txt("Error: target_id is required")
                _h1_db.mark_target(int(target_id), "done", arguments.get("summary"))
                return _txt({"ok": True, "target_id": int(target_id), "status": "done"})

            if name == "scan_mark_skipped":
                target_id = arguments.get("target_id")
                reason = arguments.get("reason")
                if target_id is None or not reason:
                    return _txt("Error: target_id and reason are required")
                _h1_db.mark_target(int(target_id), "skipped", reason)
                return _txt({"ok": True, "target_id": int(target_id), "status": "skipped"})

            if name == "scan_status":
                return _txt(_h1_db.scan_status_counts(
                    program_handle=arguments.get("program_handle"),
                    source=arguments.get("source"),
                ))

            if name == "finding_create":
                target_id = arguments.get("target_id")
                title = arguments.get("title")
                if target_id is None or not title:
                    return _txt("Error: target_id and title are required")
                fid = _h1_db.create_finding(
                    target_id=int(target_id),
                    title=title,
                    severity=arguments.get("severity"),
                    vuln_type=arguments.get("vuln_type"),
                    asset=arguments.get("asset"),
                    poc_path=arguments.get("poc_path"),
                    notes=arguments.get("notes"),
                )
                return _txt({"ok": True, "finding_id": fid, "status": "candidate"})

            if name == "finding_confirm":
                fid = arguments.get("finding_id")
                if fid is None:
                    return _txt("Error: finding_id is required")
                _h1_db.update_finding_status(
                    int(fid), "confirmed", arguments.get("validator_notes")
                )
                return _txt({"ok": True, "finding_id": int(fid), "status": "confirmed"})

            if name == "finding_reject":
                fid = arguments.get("finding_id")
                reason = arguments.get("reason")
                if fid is None or not reason:
                    return _txt("Error: finding_id and reason are required")
                _h1_db.update_finding_status(int(fid), "rejected", reason)
                return _txt({"ok": True, "finding_id": int(fid), "status": "rejected"})

            if name == "finding_list":
                return _txt(_h1_db.list_findings(
                    status=arguments.get("status"),
                    program_handle=arguments.get("program_handle"),
                    source=arguments.get("source"),
                    limit=int(arguments.get("limit") or 200),
                ))

            return _txt(f"Error: unknown H1 tool '{name}'")

        except H1Error as e:
            return _txt(f"Error (HackerOne API): {e}")
        except IntigritiError as e:
            return _txt(f"Error (Intigriti API): {e}")
        except Exception as e:
            logger.exception("bounty tool '%s' failed", name)
            return _txt(f"Error: {type(e).__name__}: {e}")

    return server


def calculate_cvss(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> tuple[float, str]:
    """Calculate CVSS 3.1 base score and severity."""
    # Attack Vector scores
    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    # Attack Complexity scores
    ac_scores = {"L": 0.77, "H": 0.44}
    # Privileges Required scores (depends on Scope)
    pr_scores_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_scores_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    # User Interaction scores
    ui_scores = {"N": 0.85, "R": 0.62}
    # CIA Impact scores
    cia_scores = {"N": 0, "L": 0.22, "H": 0.56}

    # Get base metric scores
    av_score = av_scores.get(av, 0.85)
    ac_score = ac_scores.get(ac, 0.77)
    ui_score = ui_scores.get(ui, 0.85)

    # PR depends on scope
    if s == "C":
        pr_score = pr_scores_changed.get(pr, 0.85)
    else:
        pr_score = pr_scores_unchanged.get(pr, 0.85)

    c_score = cia_scores.get(c, 0)
    i_score = cia_scores.get(i, 0)
    a_score = cia_scores.get(a, 0)

    # Calculate ISS (Impact Sub-Score)
    iss = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))

    # Calculate Impact
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Calculate Exploitability
    exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

    # Calculate Base Score
    if impact <= 0:
        base_score = 0
    elif s == "U":
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    # Round up to 1 decimal
    import math
    base_score = math.ceil(base_score * 10) / 10

    # Determine severity
    if base_score == 0:
        severity = "none"
    elif base_score < 4.0:
        severity = "low"
    elif base_score < 7.0:
        severity = "medium"
    elif base_score < 9.0:
        severity = "high"
    else:
        severity = "critical"

    return base_score, severity


async def run_server():
    """Run the MCP server."""
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Entry point for MCP server."""
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
