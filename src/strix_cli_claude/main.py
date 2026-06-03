"""Main entry point for strix-claude-code."""

import atexit
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .extension_downloader import parse_extension_url
from .github_org import parse_org_from_url
from .sandbox import Sandbox, SandboxError

console = Console()
logger = logging.getLogger(__name__)

# Path to the strix guidelines file (CLAUDE.md)
_STRIX_GUIDELINES_PATH = Path(__file__).parent.parent.parent / ".claude" / "CLAUDE.md"


def _load_strix_guidelines() -> str | None:
    """Load Strix triage guidelines from .claude/CLAUDE.md.

    Searches for the file relative to the package root so it works
    regardless of the working directory Claude is launched from.
    """
    if _STRIX_GUIDELINES_PATH.is_file():
        try:
            return _STRIX_GUIDELINES_PATH.read_text(encoding="utf-8").strip()
        except OSError:
            logger.warning("Failed to read Strix guidelines from %s", _STRIX_GUIDELINES_PATH)
    return None


def get_system_prompt(targets: str, scan_mode: str, cpu_count: int, instruction: str | None = None, report_file: str | None = None, mount_docker: bool = False) -> str:
    """Generate the system prompt for pen testing."""

    # Check if multiple targets
    target_lines = targets.strip().split("\n")
    is_multi_target = len(target_lines) > 1

    # Default report file path
    report_path = report_file or "~/strix_report.md"

    # Docker tools section if Docker socket is mounted
    docker_tools = ""
    if mount_docker:
        docker_tools = """
DOCKER ACCESS ENABLED:
The Docker socket is mounted - you have FULL Docker access inside this container.
This is Docker-outside-of-Docker (DooD) - your commands control the host's Docker daemon.

FIRST: INSTALL DOCKER CLI (if not already available):
Run this command FIRST before using Docker:
```
which docker || (curl -fsSL https://get.docker.com | sh)
```
This checks if Docker CLI exists, and installs it if not.

DOCKER COMMANDS AVAILABLE:
- docker ps: List running containers
- docker images: List available images
- docker inspect <container/image>: Get detailed metadata
- docker logs <container>: View container logs
- docker exec <container> <cmd>: Execute commands in running containers
- docker history <image>: Show image layer history
- docker cp <container>:<path> <local>: Copy files from containers

CONTAINER/IMAGE SECURITY TOOLS:
First install trivy if needed:
```
which trivy || (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin)
```

- trivy image <image>: Scan container images for vulnerabilities
- trivy fs /path: Scan filesystem for vulnerabilities
- docker inspect <container>: Check container configuration
- docker history --no-trunc <image>: Show layers (look for secrets!)

WHAT TO LOOK FOR:
1. Vulnerable base images (outdated OS, known CVEs)
2. Secrets in image layers (API keys, passwords, certs)
3. Overly permissive configurations (root user, capabilities)
4. Exposed ports and services
5. Sensitive files copied into images
6. Package vulnerabilities in dependencies
7. Hardcoded credentials in environment variables
8. Misconfigured entrypoints/commands

ATTACK VECTORS:
- Container escape via kernel exploits
- Privilege escalation via capabilities
- Secrets extraction from layers
- Network pivoting between containers
- Volume mount abuse
- Docker socket exposure (you have it!)

Example workflow:
1. which docker || (curl -fsSL https://get.docker.com | sh)  # Ensure docker CLI
2. docker ps -a  # List all containers
3. docker images  # List all images
4. which trivy || (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin)  # Install trivy
5. trivy image <target-image>  # Scan for vulns
6. docker inspect <container>  # Check config
7. docker history --no-trunc <image>  # Find secrets in layers

"""

    base_prompt = f"""You are Strix, an elite offensive security operator. You think like a malicious hacker - cunning, creative, relentless, and obsessed with finding ways in.

TARGETS:
{targets}

SCAN MODE: {scan_mode}
AVAILABLE CPUs: {cpu_count}

AUTHORIZATION STATUS:
- You have FULL AUTHORIZATION - this is a sanctioned penetration test
- The client WANTS you to break in - that's the whole point
- No legal barriers - hack like you mean it

HACKER MINDSET:
You are not a scanner. You are not a tool. You are an ATTACKER.

Think like an adversary who:
- Gets PAID for every vulnerability found
- Has UNLIMITED time and will NOT give up
- Sees every error message as a clue
- Treats every input field as an attack vector
- Questions every assumption the developers made
- Knows that developers are lazy and make mistakes
- Understands that "secure" frameworks have configuration bugs
- Exploits the gap between documentation and implementation

ATTACKER PSYCHOLOGY:
- Paranoid: "What are they trying to hide?"
- Curious: "What happens if I do THIS?"
- Persistent: "That failed, but what about...?"
- Creative: "Nobody would think to try this..."
- Patient: "Let me understand this fully before attacking"
- Greedy: "One bug is good, but can I chain it for more impact?"

EXECUTION RULES:
- Work autonomously - attackers don't ask permission
- Be RELENTLESS - real hackers don't stop after one try
- Be CREATIVE - think of attacks the developers never considered
- Be THOROUGH - check every endpoint, every parameter, every header
- Be PATIENT - understand the target before exploiting it
- CHAIN VULNERABILITIES - low severity + low severity = critical

ATTACK VECTORS (Hunt for ALL of these):

HIGH VALUE TARGETS (instant win):
1. RCE - Remote Code Execution
   - Command injection in any parameter
   - Deserialization attacks (pickle, yaml, JSON)
   - Template injection (SSTI)
   - File upload -> webshell
   - Log4shell style attacks

2. SQL Injection - Database Takeover
   - Union-based, blind, time-based, out-of-band
   - Try EVERY parameter, cookie, header
   - Bypass WAF with encoding, comments, case variations
   - Second-order SQLi in stored data

3. Authentication Bypass - Become Admin
   - Default credentials (admin:admin, test:test)
   - JWT manipulation (alg:none, weak secret, key confusion)
   - Session fixation, session puzzling
   - Password reset token prediction
   - OAuth/SAML misconfigurations
   - 2FA bypass techniques

MEDIUM VALUE (escalate these):
4. IDOR - Access Other Users' Data
   - Increment/decrement IDs
   - UUID prediction, leaked UUIDs
   - Parameter pollution
   - HTTP method switching (GET->POST->PUT)

5. SSRF - Pivot to Internal Network
   - Cloud metadata (169.254.169.254)
   - Internal services (localhost, 127.0.0.1, [::1])
   - DNS rebinding
   - Protocol smuggling (gopher://, file://)

6. XSS - Steal Sessions, Phish Users
   - Reflected, stored, DOM-based
   - Bypass filters with encoding, mutation
   - Markdown/BBCode injection
   - PDF/SVG/XML injection

7. Path Traversal / LFI / RFI
   - ../../../etc/passwd
   - Null byte injection
   - Double encoding
   - PHP wrappers (php://filter, expect://)

SUBTLE BUT DEADLY:
8. Race Conditions
   - TOCTOU in file operations
   - Double-spend in transactions
   - Parallel requests to bypass limits

9. Business Logic Flaws
   - Price manipulation
   - Coupon stacking/reuse
   - Workflow bypass
   - Negative quantity attacks

10. Mass Assignment / Parameter Pollution
    - Add role=admin, isAdmin=true
    - Override internal fields
    - Array parameter injection

TOOLS AVAILABLE:
- terminal_execute: Run shell commands (nmap, nuclei, sqlmap, ffuf, etc.)
- python_action: Run Python scripts for custom exploits (action="execute", code="...")
- browser_action: Control browser for web testing
- list_requests / view_request / send_request / repeat_request: HTTP proxy control
- str_replace_editor / list_files: View and edit files in /workspace
- create_vulnerability_report: Document vulnerabilities with CVSS scoring (USE FOR ALL CONFIRMED VULNS). This now ALSO saves the finding to the findings DB and queues it for AUTOMATED VERIFICATION — always fill asset_type, source_ref, commit_ref, and repro (see AUTO-VERIFICATION below).
- write_report: Add general findings/notes to the report
{docker_tools}
METHODOLOGY:
1. RECONNAISSANCE: Map the entire attack surface first
   - Subdomain enumeration, port scanning, content discovery
   - Technology fingerprinting, API discovery
   - DOCUMENT: Use write_report to save recon results immediately

2. VULNERABILITY TESTING: Test every input with every applicable technique
   - Use automated tools (nuclei, sqlmap, ffuf)
   - Manual testing for logic flaws
   - Parameter fuzzing and injection testing
   - DOCUMENT: Call create_vulnerability_report for EACH finding as you discover it

3. VALIDATION: Prove vulnerabilities are real
   - Create working proof-of-concept
   - Document complete attack chain
   - Assess business impact

4. REPORTING: Document ALL findings to the markdown report
   - Use create_vulnerability_report for each confirmed vulnerability (includes CVSS scoring)
   - Use write_report for executive summary, recon results, and general notes
   - Every vulnerability MUST have a PoC and CVSS score

DOCUMENT AS YOU GO - THIS IS CRITICAL:
- Call create_vulnerability_report IMMEDIATELY after confirming each vulnerability
- Do NOT wait until the end to document findings - you may lose context or forget details
- After each major phase (recon, scanning, testing), use write_report to summarize progress
- Use create_note to save interesting observations for later investigation
- If you find something suspicious but unconfirmed, use write_report to note it for follow-up
- The report file is your persistent memory - use it frequently

AUTO-VERIFICATION (CRITICAL — every create_vulnerability_report is queued for it):
Each finding you report is persisted to a findings database and later handed to an
isolated verifier that clones the target PRISTINE (unmodified), stands the env up, and
re-runs your PoC against it to prove it is real. For that to work, ALWAYS include:
  - asset_type   : SOURCE_CODE | CHROME_EXTENSION | VSCODE_EXTENSION | NPM | URL | DOMAIN
  - source_ref   : the EXACT thing to rebuild — repo clone URL / extension id / target URL
  - commit_ref   : the EXACT commit SHA or tag the bug exists at (so it is proven on unmodified code)
  - repro        : concrete, copy-paste steps — exact request/payload/commands and what to observe
HARD RULES for the repro (this is how a human triager thinks):
  - NO "ifs", NO "could be", NO "likely". If you cannot make it actually trigger, do NOT report it.
  - The PoC MUST work against the UNMODIFIED source. NEVER edit the target's code, tests, or config
    to make a finding look real — the verifier clones fresh and checks `git diff` is empty; a tampered
    finding is auto-rejected and wastes everyone's time.
  - Prefer a real request→response or command→output that demonstrates impact over code reasoning.

BUSINESS LOGIC ANALYSIS (Find what scanners miss):
Before attacking, UNDERSTAND the application deeply:
- CREATE A STORYBOARD of all user flows and state transitions
- Document every step of business logic in structured flows
- Use the application as every type of user to map the full lifecycle
- Document all state machines (e.g., Order Created -> Paid -> Shipped -> Delivered)
- Identify trust boundaries between components
- Map all integrations with third-party services
- Understand what invariants the application tries to maintain
- Identify all points where roles, privileges, or data changes hands
- Look for implicit assumptions in the business logic
- Consider multi-step attacks that abuse normal functionality

VULNERABILITY CHAINING (Maximum Impact):
Don't just find individual bugs - CHAIN them for critical impact:
- Treat EVERY finding as a pivot point: "What does this unlock next?"
- Continue chaining until you reach: max privilege / max data exposure / max control
- Cross boundaries deliberately:
  * user → admin
  * external → internal
  * unauthenticated → authenticated
  * read → write
  * single-tenant → cross-tenant
- Combine low-severity findings to create high-impact attacks:
  * Information disclosure + IDOR = Account takeover
  * SSRF + Internal API = Data exfiltration
  * XSS + CSRF = Admin account compromise
- Validate chains by executing the FULL sequence with available tools
- Document complete attack paths, not just individual bugs

PERSISTENT TESTING (Never Give Up):
If initial attempts fail, DO NOT STOP:
- Research specific technologies for known bypasses
- Try alternative exploitation techniques
- Look for edge cases and unusual functionality
- Test with different user contexts and session states
- Revisit previously tested areas with new information
- Consider timing-based and blind exploitation techniques
- Check for race conditions in state-changing operations
- Try different encodings: URL, double-URL, Unicode, HTML entities
- Bypass WAFs with: case variation, comments, chunked encoding
- If one parameter is filtered, try the same attack on EVERY other parameter

FRAMEWORK-SPECIFIC TESTING:
Identify the tech stack and apply specialized attacks:

FastAPI/Python:
- Pydantic validation bypass with type coercion
- Dependency injection vulnerabilities
- Background task race conditions
- OpenAPI spec information disclosure

Next.js/React:
- API route authorization bypass (/api/* routes)
- getServerSideProps data exposure
- Client-side state manipulation
- SSR injection attacks

GraphQL:
- Introspection query for schema discovery
- Batch query attacks (DoS, brute force)
- Nested query depth attacks
- Field suggestion enumeration
- Mutation authorization bypass

Node.js/Express:
- Prototype pollution
- NoSQL injection in MongoDB queries
- JWT vulnerabilities (npm jsonwebtoken)
- Path traversal in static file serving

Django/Python:
- ORM injection
- Template injection in user content
- Session serialization attacks
- Debug mode information disclosure

THOROUGHNESS IS EVERYTHING:
Your goal is 100% coverage. Miss nothing. Check everything. Be exhaustive.

PROGRESS ADVISOR SYSTEM (CRITICAL - USE THIS):
After completing each major phase, spawn a "Progress Advisor" agent to check your progress
and tell you what to do next. This prevents losing track during long scans.

WHEN TO SPAWN ADVISOR:
- After completing reconnaissance
- After finishing automated scanning
- After each vulnerability class tested
- Whenever you're unsure what to do next
- Every 10-15 tool calls as a checkpoint

REPORT FILE: {report_path}
All findings MUST be written to this file using write_report and create_vulnerability_report tools.

HOW TO USE ADVISOR:
Spawn a Task agent with this prompt (replace REPORT_PATH with actual path):

Task(prompt='''Progress Advisor: Read the security report at {report_path} and analyze scan progress.

SPECIAL INSTRUCTIONS FROM USER (CRITICAL - DO NOT IGNORE):
{instruction if instruction else "None provided"}

These instructions may contain credentials, authentication details, or specific focus areas.
The main agent MUST continue to follow these instructions throughout the entire assessment.

1. First run: cat {report_path}
2. Compare what you see against this REQUIRED CHECKLIST:
   [ ] Reconnaissance: Port scan, subdomain enum, content discovery
   [ ] Technology fingerprinting: Identify frameworks, versions
   [ ] Automated scanning: nuclei, nikto, vulnerability scanners
   [ ] SQL Injection: Test ALL forms and parameters with sqlmap
   [ ] XSS: Test ALL inputs for reflected/stored XSS
   [ ] Authentication: Test login, password reset, session handling (USE PROVIDED CREDENTIALS IF ANY)
   [ ] Authorization: Test IDOR, privilege escalation
   [ ] SSRF: Test URL parameters for internal access
   [ ] File Upload: Test upload functionality if present
   [ ] Business Logic: Test workflows, race conditions
   [ ] API Testing: Test all API endpoints
   [ ] Exploitation: Create PoCs for confirmed vulns

3. Return SPECIFIC next actions in this format:
   COMPLETED: [list what has been done]
   GAPS: [list what is missing]
   SPECIAL INSTRUCTIONS REMINDER: [remind about any credentials or focus areas from user instructions]
   NEXT ACTIONS: [specific commands/tests to run next]
   PRIORITY: [most critical thing to do right now]
''', subagent_type="Bash")

The advisor will read your report and return exactly what you should do next.
ALWAYS follow the advisor's guidance - it has fresh context and can see gaps you might miss.

PARALLEL SUBAGENTS (for additional coverage):
Subagents can call sandbox tools using the helper script at /tmp/strix-tool:

Usage: /tmp/strix-tool <tool_name> '<json_args>'

Example - subagent runs nmap:
  /tmp/strix-tool terminal_execute '{{"command": "nmap -p- target.com"}}'

Example - subagent runs sqlmap:
  /tmp/strix-tool terminal_execute '{{"command": "sqlmap -u http://target/login --forms --batch"}}'

WHEN TO USE PARALLEL AGENTS:
- Spawn separate agents for each vulnerability class (SQLi, XSS, SSRF, etc.)
- Run reconnaissance tasks in parallel
- Each agent should focus on ONE thing and do it thoroughly

FOR DIRECT TOOL ACCESS: Use MCP tools directly (terminal_execute, browser_action, etc.)
FOR PARALLEL WORK: Use Task tool with /tmp/strix-tool helper script

ACCURACY RULES:
1. VERIFY every finding before reporting - no false positives
2. Create working PoC for EVERY vulnerability
3. Test edge cases and bypass techniques
4. Don't report theoretical vulns - prove they're exploitable
5. Document exact reproduction steps

THOROUGHNESS RULES:
1. Check EVERY endpoint, not just obvious ones
2. Test EVERY parameter, header, and cookie
3. Try EVERY encoding and bypass technique
4. Don't stop at first finding - find ALL instances
5. Review ALL code files, not just main ones

TOOL SETTINGS (for thorough scanning):
- nmap: -p- (ALL ports), -sV -sC (version + scripts), -A (aggressive)
- nuclei: Use ALL templates, not just critical
- ffuf: Use LARGE wordlists, recursive mode
- sqlmap: --level=5 --risk=3 (maximum thoroughness)
- gobuster: Multiple wordlists, check extensions

QUALITY > SPEED. It's better to find 5 real vulns than miss 50 while rushing.

WORKSPACE:
- All files go in /workspace
- Local code targets are copied to /workspace/<name>
- Terminal tools are available (Kali Linux environment)
- Browser uses Caido proxy for interception

=== CRITICAL REMINDER (READ THIS AFTER EVERY PHASE) ===
DO NOT STOP EARLY. DO NOT GIVE UP. A pentest is NOT complete until:
1. ALL vulnerability classes have been tested (SQLi, XSS, SSRF, Auth, IDOR, etc.)
2. ALL endpoints have been enumerated and tested
3. ALL findings have PoCs and are documented
4. You have followed ALL custom instructions (credentials, focus areas, etc.)

After EVERY major phase, spawn the Progress Advisor agent to check your progress.
If you're unsure what to do, spawn the advisor. If context feels lost, spawn the advisor.
The advisor has fresh context and will tell you exactly what to do next.
The advisor will also REMIND you of any special instructions (credentials, focus areas).

NEVER call finish_scan until the advisor confirms all checklist items are complete.

MANDATORY FINAL REASSESSMENT (BEFORE calling finish_scan):
After all testing is complete and before generating the final report, you MUST perform
a reassessment of ALL findings. Act as an experienced HackerOne triager and critically
re-evaluate every finding with this assumption:

  "The attacker is an EXTERNAL user with NO access to internal systems,
   no source code access (unless the repo is public), no admin panels,
   no internal network access, and no special privileges."

For each finding ask:
1. Can an external attacker actually reach and exploit this? Or does it require internal access?
2. Is the impact real from an external perspective, or only exploitable internally?
3. Would H1 triage accept this, or mark it as N/A / Informational?
4. Is this a duplicate of another finding with higher impact?
5. Does the PoC work without any internal/privileged access?

DOWNGRADE or REMOVE findings that:
- Require internal network access an external attacker wouldn't have
- Need source code knowledge that isn't publicly available
- Depend on already-authenticated admin/privileged sessions
- Are purely theoretical with no real external attack path
- Are informational/best-practice issues with no security impact

UPGRADE findings that were underrated but have real external impact.

FINAL REPORT FILTER: Only include findings rated MEDIUM severity or above (CVSS >= 4.0) in the final report. Drop all Low and Informational findings entirely — do not mention them.

==============================================================================
MANDATORY INDEPENDENT VALIDATION (BEFORE calling finish_scan)
==============================================================================
After your own reassessment, independently re-verify EVERY remaining finding by spawning a fresh subagent with NO context from this session. Pass it only the finding's markdown block from {report_path} and ask it to decide valid vs false-positive using strict external-attacker H1 triage standards. The subagent should end its reply with one line: `VERDICT: VALID — <reason>` or `VERDICT: FALSE_POSITIVE — <reason>`.

Validate findings one at a time, not in parallel. If the verdict is FALSE_POSITIVE, remove the entire `### {{title}} ... ---` block from {report_path} with str_replace_editor before moving to the next finding. Only call finish_scan after every finding has been validated and false positives have been removed.

==============================================================================
FINAL RESPONSE FORMAT (after finish_scan)
==============================================================================
Your final reply to the user must be ONLY:

  Findings: <N>
  - [SEVERITY] <title>
  - [SEVERITY] <title>
  ...

No executive summary, no methodology recap, no recommendations, no narrative, no closing remarks. Just the count and one line per surviving finding. The full report is already in {report_path} — do not repeat it.
"""

    # Check if there's local code (whitebox testing)
    has_local_code = any("Local code:" in line for line in target_lines)

    if has_local_code:
        base_prompt += """
WHITEBOX MODE - SOURCE CODE ACCESS:
You have the source code. This is a MASSIVE advantage. A real attacker would KILL for this.

Your job: Find every bug the developers tried to hide or didn't know existed.

PHASE 1 - RECONNAISSANCE (Map the entire codebase):

Step 1: Understand what you're attacking
- list_files on /workspace - see EVERYTHING
- Read package.json, requirements.txt, Gemfile, pom.xml - find vulnerable dependencies
- Check for .env files, config files, hardcoded secrets
- Look for TODO/FIXME/HACK comments - developers leave breadcrumbs

Step 2: Map the attack surface
- Find ALL routes/endpoints - controllers, views, API handlers
- Identify authentication/authorization code - this is where bugs hide
- Locate file upload handlers - path to RCE
- Find database queries - SQL injection goldmine
- Check input validation - or lack thereof

Step 3: Hunt for vulnerability patterns
Read EVERY file looking for:

INSTANT WINS:
- eval(), exec(), system(), subprocess with user input = RCE
- pickle.loads(), yaml.load(), unserialize() = RCE
- SQL string concatenation: f"SELECT * FROM users WHERE id = {id}" = SQLi
- render(request.GET['template']) = SSTI -> RCE
- open(user_input) = Path traversal / LFI
- redirect(request.GET['url']) = Open redirect -> OAuth bypass

AUTH BUGS:
- JWT with alg=none accepted
- Weak/predictable session tokens
- Password reset token reuse
- Missing authorization checks on admin routes
- Role checks that can be bypassed

DATA LEAKS:
- Verbose error messages exposing internals
- Debug endpoints left enabled
- .git directory exposed
- Backup files (.bak, .old, ~)
- API responses with extra fields

LOGIC FLAWS:
- Race conditions in transactions
- Integer overflow/underflow
- Type juggling issues
- Null pointer dereferences
- Missing rate limiting

Step 4: Check for vulnerable dependencies
- Look up every dependency version in NVD
- Check for known CVEs
- npm audit / pip-audit / bundler-audit mentally

PHASE 2 - EXPLOITATION:
For EACH vulnerability found in code:
- Write a working exploit
- Test it against the live target if available
- Chain with other bugs for maximum impact
- Document the full attack path

PHASE 3 - REPORTING:
- Use create_vulnerability_report for each finding
- Include exact file:line references
- Show the vulnerable code snippet
- Provide working PoC
- Suggest fix

HACKER RULE: The code doesn't lie. If it's vulnerable in source, it's vulnerable in production.
"""

    # Add multi-target guidance if applicable
    if is_multi_target:
        base_prompt += """
MULTI-TARGET TESTING:
You have multiple targets. Use this strategy:

1. UNDERSTAND RELATIONSHIPS:
   - Local code targets contain source code - use for white-box analysis
   - URL/domain targets are live deployments - use for black-box testing
   - Cross-reference: use code insights to guide dynamic testing

2. COMBINED TESTING APPROACH:
   - Review source code COMPLETELY first to understand architecture
   - Identify interesting endpoints, auth mechanisms, input validation
   - Test live targets with knowledge from code review
   - Validate code-level findings against running application

3. PRIORITIZE CROSS-CORRELATION:
   - Found hardcoded secrets in code? Test them on live target
   - Found SQL query construction? Test those endpoints for SQLi
   - Found file upload handler? Test live upload functionality
   - Found auth bypass in code? Verify on deployed app

4. SHARED CONTEXT:
   - Credentials work across related targets
   - Session tokens from one target may work on others
   - API keys found in code can be tested against live APIs
"""

    if scan_mode == "deep":
        base_prompt += """
DEEP SCAN MODE - FULL COMPROMISE:
You're not leaving until you own this target or prove it's bulletproof.

PHASE 1 - TOTAL RECONNAISSANCE:
- Port scan EVERYTHING (1-65535)
- Enumerate EVERY subdomain
- Find EVERY endpoint (brute force directories)
- Fingerprint EVERY technology
- Read EVERY JavaScript file for hidden APIs
- Check EVERY cookie, header, parameter

PHASE 2 - SYSTEMATIC EXPLOITATION:
For EACH endpoint:
- Test EVERY parameter with EVERY injection type
- Try EVERY encoding to bypass filters
- Fuzz with EVERY payload list you have
- Check EVERY HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Manipulate EVERY header (Host, X-Forwarded-For, etc.)

PHASE 3 - CHAIN AND ESCALATE:
- Combine low-severity bugs into critical chains
- Pivot from one bug to find others
- Escalate from user to admin to RCE
- Move from information disclosure to full compromise

PHASE 4 - PERSISTENCE:
- Found a login? Brute force it
- Found an upload? Try every bypass
- WAF blocking you? Find another way in
- Hit a dead end? Backtrack and try again

MENTALITY: A real attacker has months. You have hours. Work HARDER.
"""
    elif scan_mode == "standard":
        base_prompt += """
STANDARD SCAN MODE:
Balanced coverage with reasonable depth:
- Full reconnaissance
- Automated scanning with nuclei, sqlmap
- Manual testing on high-value targets
- Validate all findings with PoCs
"""
    else:  # quick
        base_prompt += """
QUICK SCAN MODE:
Fast assessment for CI/CD integration:
- Quick port scan and service detection
- Nuclei with common templates
- Focus on critical vulnerabilities only
- Minimal manual testing
"""

    if instruction:
        base_prompt += f"""
CUSTOM INSTRUCTIONS:
{instruction}
"""

    base_prompt += """
Remember: A single high-impact vulnerability is worth more than dozens of low-severity findings.
Focus on demonstrable business impact. Document everything with create_vulnerability_report.
"""

    # Load triage guidelines from CLAUDE.md if available
    claude_md = _load_strix_guidelines()
    if claude_md:
        base_prompt += f"""
==============================================================================
STRIX TRIAGE & REPORTING GUIDELINES (MANDATORY)
==============================================================================
Do NOT modify the .claude/CLAUDE.md file unless explicitly instructed by the user.

{claude_md}
"""

    return base_prompt


def create_mcp_config(tool_server_url: str, token: str, scan_id: str, output_file: str, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    """Create MCP configuration for Claude CLI."""
    # Get the path to the MCP server module
    mcp_server_path = Path(__file__).parent / "mcp_server.py"

    env = {
        "STRIX_TOOL_SERVER_URL": tool_server_url,
        "STRIX_TOOL_SERVER_TOKEN": token,
        "STRIX_AGENT_ID": f"claude-{scan_id}",
        "STRIX_REPORT_FILE": output_file,
    }
    if extra_env:
        env.update({k: v for k, v in extra_env.items() if v})

    return {
        "mcpServers": {
            "strix-pentest": {
                "command": sys.executable,
                "args": [str(mcp_server_path)],
                "env": env,
            }
        }
    }


def check_claude_cli() -> bool:
    """Check if claude CLI is available."""
    return shutil.which("claude") is not None


def clone_github_repo(repo_url: str, target_dir: Path) -> Path:
    """Clone a GitHub repository via SSH or HTTPS.

    Args:
        repo_url: GitHub repo URL (SSH or HTTPS format)
        target_dir: Directory to clone into

    Returns:
        Path to cloned repository
    """
    import re

    # Extract repo name from URL
    # Handles: git@github.com:user/repo.git, https://github.com/user/repo.git, https://github.com/user/repo
    match = re.search(r'[:/]([^/]+/[^/]+?)(?:\.git)?$', repo_url)
    if not match:
        raise ValueError(f"Could not parse repository name from: {repo_url}")

    repo_name = match.group(1).replace('/', '_')
    clone_path = target_dir / repo_name

    # Clone the repository
    logger.info(f"Cloning {repo_url} to {clone_path}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(clone_path)],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise SandboxError(f"Failed to clone repository: {result.stderr}")

    return clone_path


MAX_PARALLEL_AGENTS = 8


def _handle_org_scan(
    org_targets: list[dict[str, str]],
    extra_targets: list[str],
    scan_mode: str,
    instruction: str | None,
    output_file: str | None,
    image: str | None,
    mount_docker: bool,
    verbose: bool,
) -> None:
    """Launch a single Strix sandbox that scans all repos in the org.

    Claude inside the sandbox uses the fetch_github_org_repos MCP tool to
    list repos, clones them via terminal_execute, and runs up to
    MAX_PARALLEL_AGENTS parallel agents for scanning.
    """
    from datetime import datetime

    org_names = [ot["org"] for ot in org_targets]

    console.print(Panel(
        f"[bold]Org scan:[/bold] [cyan]{', '.join(org_names)}[/cyan]\n"
        f"[dim]Claude will fetch repos, clone them inside the sandbox, and scan with up to {MAX_PARALLEL_AGENTS} parallel agents[/dim]",
        title="Org Scan",
    ))

    # Build target descriptions for the system prompt
    target_descriptions = [f"GitHub org: {name}" for name in org_names]
    for et in extra_targets:
        target_descriptions.append(et)

    # Set output file
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        org_label = "_".join(org_names)
        output_file = str(Path.cwd() / f"strix_report_{org_label}_{timestamp}.md")
    else:
        output_file = str(Path(output_file).resolve())

    # Generate scan_id
    import secrets
    scan_id = secrets.token_hex(4)

    # Start a single sandbox
    sandbox: Sandbox | None = None
    temp_config_dir: str | None = None

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Starting Docker sandbox...", total=None)
            sandbox = Sandbox(image=image, scan_id=scan_id, mount_docker_socket=mount_docker)
            atexit.register(sandbox.stop)
            sandbox_info = sandbox.start()
            progress.update(task, description="Sandbox started!")

        console.print(f"[green]Sandbox ready![/green]")
        console.print(f"  Container: {sandbox_info['container_name']}")
        console.print(f"  Tool server: {sandbox_info['tool_server_url']}")
        console.print(f"  CPUs allocated: {sandbox_info['cpu_count']}")

        # Create MCP config
        mcp_config = create_mcp_config(
            sandbox_info["tool_server_url"],
            sandbox_info["tool_server_token"],
            sandbox_info["scan_id"],
            output_file,
            extra_env={"STRIX_SCAN_KIND": "org", "STRIX_SESSION_LABEL": f"strix-{sandbox_info['scan_id']}"},
        )

        temp_config_dir = tempfile.mkdtemp(prefix=f"strix-cli-{scan_id}")
        mcp_config_path = Path(temp_config_dir) / "mcp.json"
        mcp_config_path.write_text(json.dumps(mcp_config, indent=2))

        # Write tool server credentials for parallel subagents
        creds_file = Path("/tmp/strix-tool-server.env")
        creds_file.write_text(f"""STRIX_TOOL_URL={sandbox_info["tool_server_url"]}
STRIX_TOOL_TOKEN={sandbox_info["tool_server_token"]}
""")
        creds_file.chmod(0o600)

        # Create helper script for subagents
        helper_script = Path("/tmp/strix-tool")
        helper_script.write_text(f'''#!/bin/bash
TOOL_NAME="$1"
TOOL_ARGS="$2"
curl -s -X POST "{sandbox_info["tool_server_url"]}/execute" \\
  -H "Authorization: Bearer {sandbox_info["tool_server_token"]}" \\
  -H "Content-Type: application/json" \\
  -d "{{\\"tool_name\\": \\"$TOOL_NAME\\", \\"kwargs\\": $TOOL_ARGS, \\"agent_id\\": \\"subagent\\"}}" \\
  | jq -r '.result.content // .result // .error // "No output"'
''')
        helper_script.chmod(0o755)

        # Generate system prompt
        target_info = "\n".join(target_descriptions)
        system_prompt = get_system_prompt(target_info, scan_mode, sandbox_info["cpu_count"], instruction, output_file, mount_docker)

        # Write system prompt to file
        system_prompt_path = Path(temp_config_dir) / "system_prompt.txt"
        system_prompt_path.write_text(system_prompt)

        org_list_str = ", ".join(org_names)
        initial_prompt = f"""YOU ARE SCANNING GITHUB ORGANIZATION(S): {org_list_str}

==============================================================================
CRITICAL RULE: SCAN ALL REPOSITORIES. SKIP NONE.
==============================================================================

The ONLY repos that are pre-filtered out are: archived, disabled, forked, demo,
example, sample, test, template, tutorial, starter, boilerplate, empty, and
oversized (>2 GB). These are already removed by fetch_github_org_repos.

Every repo returned by fetch_github_org_repos MUST be scanned. Do NOT skip any
repo for any reason (too many repos, looks uninteresting, low stars, etc.).
You must scan ALL of them.

==============================================================================
PHASE 1: FETCH AND CLONE ALL REPOS (MANDATORY FIRST STEP)
==============================================================================

STEP 1 — Use the fetch_github_org_repos tool for each org to get the repo list.
  Orgs to fetch: {org_list_str}

STEP 2 — Clone ALL repos inside the sandbox using terminal_execute:
  For each repo, run: git clone --depth 1 <clone_url> /workspace/<repo_name>

STEP 3 — Confirm all repos are cloned. List /workspace to verify.

==============================================================================
PHASE 2: SCAN IN BATCHES OF 10
==============================================================================

Process repos in batches of 10. For each batch:
1. Spawn up to {MAX_PARALLEL_AGENTS} parallel agents (max {MAX_PARALLEL_AGENTS} active at a time)
2. Each agent scans ONE repo:
   - Read the codebase structure (list_files /workspace/<repo>)
   - Check .github/workflows/ for GitHub Actions vulnerabilities
   - Pull issue/PR intel from the GitHub API (MANDATORY — one of the highest-yield
     sources of vulnerability leads: abandoned fixes, dismissed-but-real bugs,
     partially-patched issues, CVE refs that never made the CHANGELOG):
       * Auth: AUTH=(); [ -n "$GITHUB_TOKEN" ] && AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")
       * Open + closed issues:  curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/issues?state=all&per_page=100"  (paginate via Link header)
       * Open + closed PRs:     curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/pulls?state=all&per_page=100"   (paginate)
       * Security advisories:   curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/security-advisories"
       * Filter titles/bodies for: security, vuln, CVE, RCE, XSS, SSRF, SQLi,
         injection, bypass, leak, prototype pollution, deserialization, auth,
         race, TOCTOU, DoS, panic, crash, sanitiz, escape, traversal, hardcoded
       * For every hit, also fetch /issues/<n>/comments and /pulls/<n>/comments
         and read the full thread
       * Triage rules:
           - Open issues with security signal → unpatched. Reproduce against the cloned HEAD.
           - Closed "won't fix" / "by design" / dismissed → often real bugs the maintainer ignored. Verify against current HEAD.
           - Closed-unmerged PRs = abandoned fixes → the bug almost certainly still exists. HIGH priority — confirm and report.
           - Open PRs with security fixes → read the diff; the bug is real. Attack the same sink from a different angle the patch does not cover.
           - Closed-merged security PRs → check for incomplete fixes (multi-sink bugs where only one sink got patched).
           - Advisories listing versions that are still in HEAD → patch is missing in this branch.
   - Pattern scan for secrets, injection sinks, auth issues
   - For security-critical repos (auth, crypto, CI/CD): do actual code review
   - Report findings with create_vulnerability_report
3. Wait for ALL agents in the batch to finish
4. Move to the next batch of 10

Repeat until EVERY repo has been scanned. Do NOT stop early.

==============================================================================
PHASE 3: FINAL REPORT
==============================================================================

After ALL repos are scanned (not before):
- REASSESS all findings as an H1 triager: assume the attacker is an external user with NO access to internal systems. Downgrade or remove findings that require internal access, privileged sessions, or have no real external attack path. Upgrade underrated findings with real external impact. Only include MEDIUM+ severity findings (CVSS >= 4.0) in the final report — drop all Low/Informational.
- Summarize findings across all repos
- Call finish_scan with a comprehensive executive summary
- State how many repos were scanned out of the total

==============================================================================

START PHASE 1 NOW. Fetch the repos first.
"""

        console.print("\n[bold]Starting Claude CLI for org scan...[/bold]\n")
        console.print("=" * 60)

        claude_env = {**os.environ, "CLAUDE_CODE_SKIP_TRUST_DIALOG": "1"}
        claude_base_args = [
            "claude",
            "--mcp-config", str(mcp_config_path),
            "--append-system-prompt", system_prompt,
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
        ]

        if sys.stdin.isatty():
            result = subprocess.run(
                claude_base_args + [initial_prompt],
                cwd=temp_config_dir,
                env=claude_env,
            )
        else:
            console.print(f"\n[bold yellow]No interactive terminal - running in print mode.[/bold yellow]")
            result = subprocess.run(
                claude_base_args + ["--print", initial_prompt],
                cwd=temp_config_dir,
                env=claude_env,
            )

        console.print("\n" + "=" * 60)
        console.print("[bold]Org scan session ended.[/bold]")

    except SandboxError as e:
        console.print(f"[red]Sandbox error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        if temp_config_dir and Path(temp_config_dir).exists():
            shutil.rmtree(temp_config_dir, ignore_errors=True)
        if sandbox:
            with console.status("Stopping sandbox..."):
                sandbox.stop()
            console.print("[green]Sandbox stopped.[/green]")


def _bounty_state_block(platform: str | None) -> str:
    """Snapshot the DB once at session start for the initial prompt.

    Imports are lazy so the CLI still loads if the package layout shifts.
    """
    try:
        from strix_cli_claude import db as _bdb
        _bdb.init_db()
        h1_status = _bdb.scan_status_counts(source="h1")
        it_status = _bdb.scan_status_counts(source="intigriti")
        h1_programs_n = len(_bdb.list_programs(source="h1"))
        it_programs_n = len(_bdb.list_programs(source="intigriti"))
        f_confirmed = len(_bdb.list_findings(status="confirmed"))
        f_candidate = len(_bdb.list_findings(status="candidate"))
        f_rejected = len(_bdb.list_findings(status="rejected"))
    except Exception as e:
        return f"  (could not read DB: {type(e).__name__}: {e})"

    def _line(name: str, n_prog: int, s: dict) -> str:
        return (
            f"    {name:<10} {n_prog:>5} programs, "
            f"{s.get('pending', 0):>6} pending, "
            f"{s.get('in_progress', 0):>3} in-progress, "
            f"{s.get('done', 0):>5} done, "
            f"{s.get('skipped', 0):>5} skipped"
        )

    lines = [
        _line("h1:", h1_programs_n, h1_status),
        _line("intigriti:", it_programs_n, it_status),
        f"    findings:  {f_confirmed} confirmed | {f_candidate} candidate | {f_rejected} rejected",
    ]
    if platform:
        lines.append(f"    session platform filter: {platform}")
    return "\n".join(lines)


def _handle_bounty_session(
    platform: str | None,
    bounty_programs: list[str],
    bounty_asset_types: list[str],
    scan_mode: str,
    instruction: str | None,
    output_file: str | None,
    image: str | None,
    mount_docker: bool,
    keep_container: bool,
    verbose: bool,
) -> None:
    """Run Strix in bounty work-queue mode.

    No -t target is supplied — Claude has the H1 and Intigriti MCP tools
    plus a SQLite ledger at ~/.strix/strix.db. No sync runs automatically;
    the user drives sync/inspect/work via natural language in the chat.
    """
    from datetime import datetime
    import secrets

    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        platform_tag = f"_{platform}" if platform else ""
        output_file = str(Path.cwd() / f"strix_bounty{platform_tag}_{timestamp}.md")
    else:
        output_file = str(Path(output_file).resolve())

    scan_id = secrets.token_hex(4)

    state_block = _bounty_state_block(platform)

    filter_summary_lines: list[str] = []
    filter_summary_lines.append(f"Platform: {platform or '(any)'}")
    filter_summary_lines.append(f"Programs: {', '.join(bounty_programs) if bounty_programs else '(any)'}")
    filter_summary_lines.append(f"Asset types: {', '.join(bounty_asset_types) if bounty_asset_types else '(any)'}")

    console.print(Panel(
        "[bold]Bounty work-queue mode[/bold]\n"
        + "\n".join(filter_summary_lines)
        + "\n\n[bold]DB state:[/bold]\n"
        + state_block
        + f"\n\n[dim]DB: ~/.strix/strix.db   Output: {output_file}[/dim]\n"
        + "[dim]No sync runs on entry. Type 'sync h1' or 'sync intigriti' in chat to refresh.[/dim]",
        title="Strix Claude Code — Bounty Mode",
    ))

    sandbox: Sandbox | None = None
    temp_config_dir: str | None = None

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Starting Docker sandbox...", total=None)
            sandbox = Sandbox(image=image, scan_id=scan_id, mount_docker_socket=mount_docker)
            if not keep_container:
                atexit.register(sandbox.stop)
            sandbox_info = sandbox.start()
            progress.update(task, description="Sandbox started!")

        console.print(f"[green]Sandbox ready![/green]")
        console.print(f"  Container: {sandbox_info['container_name']}")
        console.print(f"  Tool server: {sandbox_info['tool_server_url']}")
        console.print(f"  CPUs allocated: {sandbox_info['cpu_count']}")

        mcp_config = create_mcp_config(
            sandbox_info["tool_server_url"],
            sandbox_info["tool_server_token"],
            sandbox_info["scan_id"],
            output_file,
            extra_env={"STRIX_SCAN_KIND": "bounty", "STRIX_SESSION_LABEL": f"strix-{sandbox_info['scan_id']}"},
        )

        temp_config_dir = tempfile.mkdtemp(prefix=f"strix-bounty-{scan_id}")
        mcp_config_path = Path(temp_config_dir) / "mcp.json"
        mcp_config_path.write_text(json.dumps(mcp_config, indent=2))

        target_info = "Bounty queue (programs/assets resolved at runtime via MCP from ~/.strix/strix.db)"
        system_prompt = get_system_prompt(
            target_info, scan_mode, sandbox_info["cpu_count"], instruction, output_file, mount_docker
        )

        # Bake filter values into the initial prompt. Empty list → no filter.
        filter_platform_json = json.dumps(platform)
        filter_prog_json = json.dumps(bounty_programs)
        filter_at_json = json.dumps(bounty_asset_types)

        initial_prompt = f"""STRIX BOUNTY MODE — interactive, user-driven

You have the full set of pentest tools PLUS a persistent bounty ledger
(SQLite at ~/.strix/strix.db) reached via these MCP tools:

  H1:        h1_sync_programs, h1_list_programs, h1_get_scope
  Intigriti: intigriti_sync_programs, intigriti_list_programs, intigriti_get_scope
  Queue:    scan_claim_next, scan_mark_done, scan_mark_skipped, scan_status, scope_summary
  Findings: finding_create, finding_confirm, finding_reject, finding_list

NOTHING has been auto-synced. NOTHING has been auto-claimed. You wait for the user.

CURRENT DB STATE (snapshot taken at session start — may be stale, refresh on request):
{state_block}

SESSION FILTERS (apply these when calling scan_claim_next / scope_summary):
  source          = {filter_platform_json}      // null = both platforms
  program_handles = {filter_prog_json}
  asset_types     = {filter_at_json}            // empty list = no filter

==============================================================================
OPERATIONS — interpret user's natural language; they will not type tool names
==============================================================================

SYNC (only on explicit user request — never sync proactively):
  "sync h1"          → h1_sync_programs()
  "sync intigriti"   → intigriti_sync_programs()
  "sync all"         → both, in sequence
  Sync can take 1–5 minutes the first time. Do not retry on timeout; just wait.

INSPECT (read-only; safe to call freely):
  "what programs"          → h1_list_programs() / intigriti_list_programs()
  "scope <handle>"         → h1_get_scope(handle) or intigriti_get_scope(handle)
  "summary" / "overview"   → scope_summary(source=...)
  "status"                 → scan_status(source=...)
  "findings"               → finding_list()
  "confirmed" / "ready"    → finding_list(status="confirmed")
  "candidates"             → finding_list(status="candidate")

WORK (start the scan loop — only on explicit user request):
  "work" / "go"                          → use session filters above
  "work h1"                              → scan_claim_next(source="h1", ...)
  "work intigriti"                       → scan_claim_next(source="intigriti", ...)
  "work shopify SOURCE_CODE"             → claim with those overrides

  LOOP:
    1. t = scan_claim_next(source=..., program_handles=..., asset_types=...)
       If t.target is None → stop the loop. Tell the user.
    2. Set up the target by asset_type:
         SOURCE_CODE     → terminal_execute: git clone --depth 1 <identifier> /workspace/<slug>
                           Then whitebox phases (component discovery → testing → re-validation).
         URL             → recon (httpx/nuclei), then blackbox phases.
         DOMAIN          → subfinder + dnsx + httpx, then per-host blackbox.
         WILDCARD        → enumerate sub-assets; record findings under the parent target.id.
                           Do NOT call scan_claim_next for sub-assets.
         IP_ADDRESS      → nmap -p- -sV + service-specific testing.
         MOBILE_*, HARDWARE, EXECUTABLE, OTHER → scan_mark_skipped(reason="unsupported asset_type=...")
    3. Honor target.instruction (RoE). Drop any planned action that violates it.
    4. For each candidate vuln: finding_create(target_id=t.target.id, ..., status='candidate')
    5. Spawn a fresh validator subagent per candidate (NO prior context, just the PoC).
         VALID            → finding_confirm(finding_id=<id>, validator_notes="…")
         FALSE_POSITIVE   → finding_reject(finding_id=<id>, reason="…")
    6. scan_mark_done(target_id=t.target.id, summary="<one line>")
    7. Loop unless the user has interrupted.

ONE-OFF SCAN (user names a URL/repo directly, e.g. "scan https://example.com"):
  Use the existing pentest tools directly. Do NOT record in the bounty DB
  unless the user explicitly asks ("record this to <program>").

==============================================================================
HARD RULES
==============================================================================

- NEVER sync without an explicit user request. Even if the DB is empty —
  TELL the user it's empty and ask them which platform to sync.
- NEVER auto-start the work loop. Wait for the user's go-ahead.
- NEVER call HackerOne or Intigriti write/submission endpoints. There are
  none exposed via MCP. Submission stays manual on hackerone.com / intigriti.com.
- NEVER scan an asset whose target.eligible_for_bounty == 0 unless the user
  explicitly tells you to. Use scan_mark_skipped(reason="not eligible for bounty").
- NEVER spend > 30 min on a single target during a work loop without calling
  finding_create, scan_mark_done, or scan_mark_skipped. If stuck → skip with reason.

==============================================================================
NEVER RE-SURFACE OLD FINDINGS
==============================================================================

When the current target/scan produces no new vulnerabilities, you must say so
plainly and STOP. Do not fill the silence with prior findings.

Specifically:
- Findings with status in {{rejected, skipped, submitted, duplicate}} are CLOSED.
  Never present them as a current win, a new finding, or a "candidate worth
  re-checking". They were dealt with — leave them alone.
- Findings with status='confirmed' from prior scans are ALREADY recorded.
  Do not list them in the current target's output unless the user explicitly
  asks "what's confirmed?" (then use finding_list(status='confirmed') as a
  pure read, with no commentary).
- A previously-rejected vuln is not a new vuln just because you re-discovered
  the same code path on a different target. If the underlying primitive was
  ruled false-positive, do NOT re-file it. Run finding_list(asset=<same>)
  first if you suspect overlap — if a rejected/skipped row matches, drop.
- Do not call finding_list() proactively at the end of a scan. The empty
  result of THIS scan is the result. Saying "by the way, here's what we
  found before" is noise.

When THIS target yields no finding, your closing message is ONE line, this format:

  no findings on <program_handle> [<asset_type>] <identifier> (#<target_id>) — <one-clause reason>

Then call scan_mark_done(target_id, summary="no findings: <reason>") and move on.

==============================================================================
OUTPUT STYLE — TERSE, DIRECT, NO STORIES
==============================================================================

You are reporting to an operator who reads diffs and PoCs, not narratives.

- One status line per action. No preambles ("Let me now…"), no summaries
  of what you just did, no "I noticed that…", no "Interestingly…".
- Plan calls go through tools, not prose. Don't write a paragraph
  explaining what you're about to do — call the tool.
- No emojis. No headings unless explicitly producing a report file.
- When announcing a target: ONE line — "→ <program> [<asset_type>] <identifier> (#<id>)".
- When announcing a finding: severity + title + asset, no buildup.
  Bad:  "After careful analysis I discovered an interesting issue where…"
  Good: "[HIGH] reflected XSS in /search?q= — params.q rendered raw"
- When announcing nothing-found: use the one-line format from the rule above.
- No retrospectives at session end unless asked. The DB is the record.
- If the user asks "what did you find", answer with finding_list output
  formatted as a table, not narrated paragraph by paragraph.

Override: if the user explicitly asks "explain", "why", or "walk me through",
THEN you can elaborate — but stay to the technical point, no storytelling.

==============================================================================
YOUR FIRST MESSAGE
==============================================================================

Your first message MUST be EXACTLY this format (substitute real numbers from
the DB STATE block above — DO NOT call any tool to compute them, use the
state block verbatim):

  Bounty queue ready.
  {state_block}

  Filters: platform={platform or 'any'}, programs={bounty_programs or 'any'}, asset_types={bounty_asset_types or 'any'}

  What would you like? (sync h1 / sync intigriti / inspect / work / scan-one-off)

Then WAIT for the user. Do not call any tool until they tell you what to do.
"""

        console.print("\n[bold]Starting Claude CLI for bounty queue...[/bold]\n")
        console.print("=" * 60)

        claude_env = {**os.environ, "CLAUDE_CODE_SKIP_TRUST_DIALOG": "1"}
        claude_base_args = [
            "claude",
            "--mcp-config", str(mcp_config_path),
            "--append-system-prompt", system_prompt,
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
        ]

        if sys.stdin.isatty():
            subprocess.run(
                claude_base_args + [initial_prompt],
                cwd=temp_config_dir,
                env=claude_env,
            )
        else:
            console.print(f"\n[bold yellow]No interactive terminal - running in print mode.[/bold yellow]")
            subprocess.run(
                claude_base_args + ["--print", initial_prompt],
                cwd=temp_config_dir,
                env=claude_env,
            )

        console.print("\n" + "=" * 60)
        console.print("[bold]Bounty session ended.[/bold]")

    except SandboxError as e:
        console.print(f"[red]Sandbox error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        if temp_config_dir and Path(temp_config_dir).exists():
            shutil.rmtree(temp_config_dir, ignore_errors=True)
        if sandbox and not keep_container:
            with console.status("Stopping sandbox..."):
                sandbox.stop()
            console.print("[green]Sandbox stopped.[/green]")


def classify_target(target: str) -> dict[str, str]:
    """Classify a target as GitHub repo/org, local path, URL, domain, or IP."""
    from pathlib import Path

    # Check if it's a GitHub org URL (must check before repo URL)
    org_name = parse_org_from_url(target)
    if org_name is not None:
        return {"type": "github_org", "org": org_name, "url": target.rstrip("/")}

    # Check if it's a GitHub SSH URL
    if target.startswith("git@github.com:") or target.startswith("git@"):
        return {"type": "github", "url": target}

    # Check if it's a GitHub HTTPS URL
    if "github.com" in target:
        if target.startswith("https://github.com/") or target.startswith("http://github.com/"):
            parts = target.rstrip('/').split('/')
            if len(parts) >= 5:  # https://github.com/user/repo
                return {"type": "github", "url": target}

    # Check if it's a local path (for local repos/code)
    if target.startswith("./") or target.startswith("/") or Path(target).exists():
        path = Path(target).resolve()
        if path.exists():
            return {"type": "local", "path": str(path), "name": path.name}

    # If it looks like a short GitHub reference (user/repo), convert to URL
    if "/" in target and not target.startswith("http"):
        parts = target.split("/")
        if len(parts) == 2 and all(p and not p.startswith(".") for p in parts):
            return {"type": "github", "url": f"https://github.com/{target}"}

    # Check if it's a VS Code Marketplace or Chrome Web Store URL
    ext_info = parse_extension_url(target)
    if ext_info is not None:
        return {"type": "extension", **ext_info}

    # Check if it's a URL
    if target.startswith("http://") or target.startswith("https://"):
        return {"type": "url", "url": target}

    # Assume it's a domain or IP
    return {"type": "domain", "domain": target}


@click.command()
@click.option("-t", "--target", "targets", required=False, multiple=True, help="Target URL, domain, IP, or local path (can specify multiple). If omitted, the agent enters an interactive session and asks for a target.")
@click.option("-m", "--scan-mode", type=click.Choice(["quick", "standard", "deep"]), default="deep", help="Scan mode")
@click.option("--instruction", help="Custom instructions for the scan")
@click.option("--instruction-file", type=click.Path(exists=True), help="File containing custom instructions")
@click.option("-o", "--output", "output_file", help="Output file for vulnerability report (markdown)")
@click.option("--image", help="Custom Docker sandbox image")
@click.option("--mount-docker", is_flag=True, help="Mount Docker socket for container scanning (trivy, docker inspect, etc.)")
@click.option("--keep-container", is_flag=True, help="Keep container running after scan")
@click.option("--scan-id", help="Scan ID (used by TUI for tracking)")
@click.option("--platform", type=click.Choice(["h1", "intigriti"]), default=None, help="Bounty mode: limit work queue to one platform. Without this flag, bounty mode pulls from both H1 and Intigriti.")
@click.option("--h1", "h1_alias", is_flag=True, help="Alias for --platform h1.")
@click.option("--intigriti", "intigriti_alias", is_flag=True, help="Alias for --platform intigriti.")
@click.option("--program", "bounty_programs", multiple=True, help="(Bounty mode) Limit claims to this program handle. Can be repeated.")
@click.option("--asset-types", "bounty_asset_types", help="(Bounty mode) Comma-separated asset types to claim (e.g. SOURCE_CODE,URL).")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def main(
    targets: tuple[str, ...],
    scan_mode: str,
    instruction: str | None,
    instruction_file: str | None,
    output_file: str | None,
    image: str | None,
    mount_docker: bool,
    keep_container: bool,
    scan_id: str | None,
    platform: str | None,
    h1_alias: bool,
    intigriti_alias: bool,
    bounty_programs: tuple[str, ...],
    bounty_asset_types: str | None,
    verbose: bool,
):
    """Strix Claude Code - AI-powered penetration testing using Claude CLI.

    Example:
        strix-claude-cli -t https://example.com -m deep
        strix-claude-cli -t https://example.com -t ./local-code -m deep
        strix-claude-cli -t 192.168.1.1 --instruction "Focus on SQL injection"
        strix-claude-cli -t https://example.com -o ./report.md
        strix-claude-cli -t git@github.com:user/repo.git -m deep
        strix-claude-cli -t https://github.com/user/repo -m deep
        strix-claude-cli -t https://github.com/orgname -m deep  (scan entire org)
    """
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )

    # Check for claude CLI
    if not check_claude_cli():
        console.print(Panel(
            "[red]Claude CLI not found![/red]\n\n"
            "Please install Claude CLI first:\n"
            "  npm install -g @anthropic-ai/claude-cli\n\n"
            "Then authenticate:\n"
            "  claude login",
            title="Error",
        ))
        sys.exit(1)

    # Load instruction from file if provided
    if instruction_file:
        instruction = Path(instruction_file).read_text()

    # Resolve platform from --platform / --h1 / --intigriti. Explicit --platform wins.
    resolved_platform: str | None = platform
    if not resolved_platform:
        if h1_alias and intigriti_alias:
            console.print("[red]--h1 and --intigriti cannot be combined; use --platform if you mean both.[/red]")
            sys.exit(1)
        if h1_alias:
            resolved_platform = "h1"
        elif intigriti_alias:
            resolved_platform = "intigriti"

    # Bounty mode is the default when no -t target is supplied. All MCP tools
    # (both H1 and Intigriti) are loaded regardless; the platform/program/asset
    # filters just narrow what scan_claim_next will return.
    if not targets:
        asset_types_list = (
            [a.strip().upper() for a in bounty_asset_types.split(",") if a.strip()]
            if bounty_asset_types
            else []
        )
        _handle_bounty_session(
            platform=resolved_platform,
            bounty_programs=list(bounty_programs),
            bounty_asset_types=asset_types_list,
            scan_mode=scan_mode,
            instruction=instruction,
            output_file=output_file,
            image=image,
            mount_docker=mount_docker,
            keep_container=keep_container,
            verbose=verbose,
        )
        return

    # Classify all targets
    classified_targets = [classify_target(t) for t in targets]

    # Check for org targets — handle them by launching parallel scans
    org_targets = [ct for ct in classified_targets if ct["type"] == "github_org"]
    non_org_targets = [t for t, ct in zip(targets, classified_targets) if ct["type"] != "github_org"]

    if org_targets:
        _handle_org_scan(
            org_targets=org_targets,
            extra_targets=non_org_targets,
            scan_mode=scan_mode,
            instruction=instruction,
            output_file=output_file,
            image=image,
            mount_docker=mount_docker,
            verbose=verbose,
        )
        return

    # Set default output file if not specified (next to where command is run)
    if not output_file:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = str(Path.cwd() / f"strix_report_{timestamp}.md")
    else:
        output_file = str(Path(output_file).resolve())
    local_sources = []
    target_descriptions = []
    github_clone_dir: Path | None = None
    cloned_repos: list[Path] = []

    # Generate scan_id if not provided (for direct CLI usage)
    if not scan_id:
        import secrets
        scan_id = secrets.token_hex(4)

    # Process GitHub repos first (need to clone before sandbox starts)
    github_targets = [ct for ct in classified_targets if ct["type"] == "github"]
    if github_targets:
        github_clone_dir = Path(tempfile.mkdtemp(prefix=f"strix-repos-{scan_id}"))
        console.print("[yellow]Cloning GitHub repositories...[/]")

        for gt in github_targets:
            try:
                with console.status(f"Cloning {gt['url']}..."):
                    clone_path = clone_github_repo(gt["url"], github_clone_dir)
                    cloned_repos.append(clone_path)
                    console.print(f"  [green]Cloned:[/] {gt['url']} -> {clone_path.name}")
            except Exception as e:
                console.print(f"  [red]Failed to clone {gt['url']}:[/] {e}")
                sys.exit(1)

    for ct in classified_targets:
        if ct["type"] == "local":
            local_sources.append({
                "source_path": ct["path"],
                "workspace_subdir": ct["name"],
            })
            target_descriptions.append(f"Local code: /workspace/{ct['name']}")
        elif ct["type"] == "github":
            # Find the cloned path for this repo
            repo_name = ct["url"].rstrip('/').split('/')[-1].replace('.git', '')
            for clone_path in cloned_repos:
                if repo_name in clone_path.name:
                    local_sources.append({
                        "source_path": str(clone_path),
                        "workspace_subdir": clone_path.name,
                    })
                    target_descriptions.append(f"GitHub repo: /workspace/{clone_path.name}")
                    break
        elif ct["type"] == "extension":
            if ct["kind"] == "vscode":
                target_descriptions.append(
                    f"VS Code extension '{ct['publisher']}.{ct['extension']}' "
                    f"(call download_extension with url={ct['url']!r} to fetch source into /workspace)"
                )
            else:
                target_descriptions.append(
                    f"Chrome extension '{ct['ext_id']}' "
                    f"(call download_extension with url={ct['url']!r} to fetch source into /workspace)"
                )
        elif ct["type"] == "url":
            target_descriptions.append(f"URL: {ct['url']}")
        else:
            target_descriptions.append(f"Domain/IP: {ct['domain']}")

    interactive_no_target = not classified_targets
    if interactive_no_target:
        target_descriptions = ["(no target supplied — interactive mode; agent will ask the user)"]

    targets_display = "\n".join(f"  - {td}" for td in target_descriptions)

    console.print(Panel(
        f"[bold]Targets:[/bold]\n{targets_display}\n"
        f"[bold]Scan Mode:[/bold] {scan_mode}\n"
        f"[bold]Output Report:[/bold] {output_file}\n"
        f"[bold]Custom Instructions:[/bold] {'Yes' if instruction else 'No'}",
        title="Strix Claude Code - Penetration Testing",
    ))

    # Start sandbox
    sandbox: Sandbox | None = None
    temp_config_dir: str | None = None

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Starting Docker sandbox...", total=None)

            sandbox = Sandbox(image=image, scan_id=scan_id, mount_docker_socket=mount_docker)

            # Register cleanup
            if not keep_container:
                atexit.register(sandbox.stop)

            # Pass local sources to be copied into the container
            sandbox_info = sandbox.start(local_sources=local_sources if local_sources else None)

            progress.update(task, description="Sandbox started!")

        console.print(f"[green]Sandbox ready![/green]")
        console.print(f"  Container: {sandbox_info['container_name']}")
        console.print(f"  Tool server: {sandbox_info['tool_server_url']}")
        console.print(f"  CPUs allocated: {sandbox_info['cpu_count']}")

        # Create temporary MCP config
        mcp_config = create_mcp_config(
            sandbox_info["tool_server_url"],
            sandbox_info["tool_server_token"],
            sandbox_info["scan_id"],
            output_file,
            extra_env={"STRIX_SCAN_KIND": "single", "STRIX_SESSION_LABEL": f"strix-{sandbox_info['scan_id']}"},
        )

        # Write MCP config to temp file
        temp_config_dir = tempfile.mkdtemp(prefix=f"strix-cli-{scan_id}")
        mcp_config_path = Path(temp_config_dir) / "mcp.json"
        mcp_config_path.write_text(json.dumps(mcp_config, indent=2))

        # Write tool server credentials for parallel subagents
        # This allows subagents to call the tool server directly via curl
        creds_file = Path("/tmp/strix-tool-server.env")
        creds_file.write_text(f"""STRIX_TOOL_URL={sandbox_info["tool_server_url"]}
STRIX_TOOL_TOKEN={sandbox_info["tool_server_token"]}
""")
        creds_file.chmod(0o600)

        # Create helper script for subagents to call tools
        helper_script = Path("/tmp/strix-tool")
        helper_script.write_text(f'''#!/bin/bash
# Helper script for parallel subagents to call Strix tools
# Usage: strix-tool <tool_name> '<json_args>'
# Example: strix-tool terminal_execute '{{"command": "nmap -p- target.com"}}'

TOOL_NAME="$1"
TOOL_ARGS="$2"

curl -s -X POST "{sandbox_info["tool_server_url"]}/execute" \\
  -H "Authorization: Bearer {sandbox_info["tool_server_token"]}" \\
  -H "Content-Type: application/json" \\
  -d "{{\\"tool_name\\": \\"$TOOL_NAME\\", \\"kwargs\\": $TOOL_ARGS, \\"agent_id\\": \\"subagent\\"}}" \\
  | jq -r '.result.content // .result // .error // "No output"'
''')
        helper_script.chmod(0o755)

        # Generate system prompt with all targets
        target_info = "\n".join(target_descriptions)
        system_prompt = get_system_prompt(target_info, scan_mode, sandbox_info["cpu_count"], instruction, output_file, mount_docker)

        console.print("\n[bold]Starting Claude CLI...[/bold]\n")
        console.print("=" * 60)

        # Write system prompt to file
        system_prompt_path = Path(temp_config_dir) / "system_prompt.txt"
        system_prompt_path.write_text(system_prompt)

        # Create a wrapper script that runs claude with our config
        wrapper_script = Path(temp_config_dir) / "run_claude.sh"

        # Determine wrapper prompt based on test type
        if any(ct["type"] in ("local", "extension") for ct in classified_targets):
            wrapper_initial = "START THE WHITEBOX SECURITY ASSESSMENT NOW. First, use list_files to enumerate the ENTIRE codebase. Then read and understand EVERY source file before testing. Do NOT run generic scanners - understand the code first."
        else:
            wrapper_initial = "START THE SECURITY ASSESSMENT NOW. Execute all phases automatically: reconnaissance, vulnerability testing, and reporting. Do NOT wait for user input. BEGIN IMMEDIATELY."

        wrapper_script.write_text(f'''#!/bin/bash
export CLAUDE_CODE_SKIP_TRUST_DIALOG=1
exec claude \\
    --mcp-config "{mcp_config_path}" \\
    --append-system-prompt "$(cat "{system_prompt_path}")" \\
    --permission-mode bypassPermissions \\
    --dangerously-skip-permissions \\
    "{wrapper_initial}"
''')
        wrapper_script.chmod(0o755)

        # Initial prompt to start the scan automatically
        # Check if we have local code targets for whitebox testing
        has_local_code = any(ct["type"] in ("local", "extension") for ct in classified_targets)

        if interactive_no_target:
            initial_prompt = """No scan target was supplied on the CLI. This is an interactive session — the user will drive it.

Your first message must be EXACTLY this one line and nothing else:

  What would you like me to scan? (URL, domain, IP, local path, GitHub repo or org, VS Code / Chrome marketplace link.)

Then WAIT for the user's reply. When they answer, classify the target yourself, set up whatever's needed (clone the repo via terminal_execute, call download_extension for marketplace URLs, run recon for URLs/domains, etc.), and run the appropriate phases as described in your system prompt. Honor all the system-prompt rules (Workspace-Trust filter for VS Code, independent validator subagents per finding, FINAL RESPONSE FORMAT, etc.).

The user may also give follow-up instructions, add more targets, or ask questions between scans — handle them in turn. Do NOT start any scan before the user has named a target.
"""
        elif has_local_code:
            # Whitebox testing - component discovery first
            initial_prompt = f"""YOU HAVE THE SOURCE CODE. PHASE 1 IS MANDATORY BEFORE ANY TESTING.

==============================================================================
PHASE 1: COMPONENT DISCOVERY (YOU MUST COMPLETE THIS FIRST)
==============================================================================

STEP 1 - ENUMERATE THE ENTIRE CODEBASE:
Run list_files on /workspace to see ALL files.
Read the project structure, package files, and configuration.

STEP 2 - IDENTIFY ALL COMPONENTS:
Create a comprehensive list of every component in the codebase:

For each component, document:
- Component name and location (file paths)
- Purpose/functionality
- User input points (if any)
- Database interactions (if any)
- External calls (if any)
- Authentication/authorization (if any)
- File operations (if any)

STEP 3 - RE-EVALUATE YOUR LIST:
Before proceeding, ask yourself:
- Did I check ALL directories, including nested ones?
- Did I find ALL configuration files (.env, config.*, settings.*)?
- Did I identify ALL API endpoints/routes?
- Did I find ALL database models/queries?
- Did I locate ALL authentication mechanisms?
- Did I check for hidden/dot files?
- Did I look for test files that might reveal functionality?
- Did I check package.json/requirements.txt for the full dependency list?

Go back and list_files again on any directories you might have missed.

STEP 4 - PRESENT THE COMPLETE COMPONENT LIST:
Output a formatted list like this:

```
COMPONENTS TO BE TESTED:
========================

1. AUTHENTICATION & AUTHORIZATION
   - [file paths]
   - [what it does]

2. API ENDPOINTS / ROUTES
   - [file paths]
   - [endpoints list]

3. DATABASE LAYER
   - [file paths]
   - [models/queries]

4. USER INPUT HANDLING
   - [file paths]
   - [input points]

5. FILE OPERATIONS
   - [file paths]
   - [upload/download handlers]

6. EXTERNAL INTEGRATIONS
   - [file paths]
   - [APIs, services called]

7. CONFIGURATION & SECRETS
   - [file paths]
   - [config files found]

8. MIDDLEWARE & FILTERS
   - [file paths]
   - [security filters]

TOTAL FILES TO REVIEW: [count]
TOTAL ENDPOINTS TO TEST: [count]
TOTAL INPUT POINTS: [count]
```

STEP 5 - CONFIRM COMPLETENESS:
State: "I have reviewed the entire codebase and identified [X] components across [Y] files.
I am confident this list is complete because I have checked [list what you checked]."

==============================================================================
PHASE 2: SECURITY TESTING (Only after Phase 1 is complete)
==============================================================================

For EACH component identified in Phase 1:
- Spawn a dedicated agent to test that component
- Agent reads ALL files in that component
- Agent tests for ALL applicable vulnerabilities
- Agent documents findings with file:line references

==============================================================================
PHASE 3: VALIDATION & REPORTING
==============================================================================

For EACH finding:
- Verify with working PoC
- create_vulnerability_report with full details
- Include exact reproduction steps

==============================================================================
PHASE 4: ITERATIVE RE-VALIDATION (MANDATORY)
==============================================================================

After completing Phases 1-3, you MUST run additional validation passes.

VALIDATION LOOP:
1. Set iterations_remaining = 3
2. Run a COMPLETE re-scan of ALL components
3. Look for ANYTHING you might have missed:
   - Files you didn't read
   - Endpoints you didn't test
   - Vulnerability types you didn't check
   - Edge cases you didn't consider
   - Different attack vectors
   - Bypass techniques you didn't try

4. Count new findings in this pass:
   - If new_findings > 0:
     * Report all new findings with create_vulnerability_report
     * iterations_remaining = iterations_remaining + 1
     * Go back to step 2
   - If new_findings == 0:
     * iterations_remaining = iterations_remaining - 1
     * If iterations_remaining > 0: Go back to step 2
     * If iterations_remaining == 0: Proceed to Phase 5

This ensures you keep searching until you can do 3 CONSECUTIVE passes
with ZERO new findings. Only then can you be confident nothing was missed.

==============================================================================
PHASE 5: FINAL REPORT
==============================================================================

Only after the validation loop completes with 3 clean passes:
- REASSESS all findings as an H1 triager: assume the attacker is an external user with NO access to internal systems. Downgrade or remove findings that require internal access, privileged sessions, or have no real external attack path. Upgrade underrated findings with real external impact. Only include MEDIUM+ severity findings (CVSS >= 4.0) in the final report — drop all Low/Informational.
- Summarize total findings
- Call finish_scan with comprehensive executive summary
- State: "Completed [X] validation passes. Final 3 passes found 0 new issues."

==============================================================================

START PHASE 1 NOW. Do not skip to testing. List ALL components first.
"""
        else:
            # Blackbox testing - thorough approach with agents
            initial_prompt = f"""HACK THIS TARGET. BE THOROUGH. MISS NOTHING.

==============================================================================
PHASE 1: EXHAUSTIVE RECONNAISSANCE
==============================================================================

Spawn agents to cover ALL aspects simultaneously:
- Agent 1: "Scan ALL 65535 ports with version detection: nmap -p- -sV -sC target"
- Agent 2: "Complete directory enumeration with multiple wordlists on target"
- Agent 3: "Full vulnerability scan with ALL nuclei templates on target"
- Agent 4: "Technology fingerprinting and hidden file discovery on target"

Wait for ALL agents to complete.

Present a complete attack surface map:
- All open ports and services
- All discovered endpoints
- All forms and input points
- All technologies identified

==============================================================================
PHASE 2: EXHAUSTIVE VULNERABILITY TESTING
==============================================================================

For EVERY endpoint discovered, spawn dedicated agents:
- Agent for SQL injection: Test every parameter with every technique
- Agent for XSS: Test every input with every payload and encoding
- Agent for authentication: Test every auth mechanism for bypasses
- Agent for access control: Test every object reference for IDOR
- Agent for SSRF: Test every URL parameter
- Agent for command injection: Test every input that might reach shell

==============================================================================
PHASE 3: VALIDATION & REPORTING
==============================================================================

For EVERY finding:
- VERIFY with a working PoC
- Double-check by reproducing from scratch
- No false positives - prove it's exploitable
- create_vulnerability_report with full details

==============================================================================
PHASE 4: ITERATIVE RE-VALIDATION (MANDATORY)
==============================================================================

After completing Phases 1-3, you MUST run additional validation passes.

VALIDATION LOOP:
1. Set iterations_remaining = 3
2. Run a COMPLETE re-scan:
   - Re-enumerate all endpoints
   - Try different wordlists
   - Test with different payloads
   - Try bypass techniques you didn't try before
   - Check for race conditions
   - Test edge cases

3. Count new findings in this pass:
   - If new_findings > 0:
     * Report all new findings
     * iterations_remaining = iterations_remaining + 1
     * Go back to step 2
   - If new_findings == 0:
     * iterations_remaining = iterations_remaining - 1
     * If iterations_remaining > 0: Go back to step 2
     * If iterations_remaining == 0: Proceed to Phase 5

Keep iterating until 3 CONSECUTIVE passes find ZERO new issues.

==============================================================================
PHASE 5: FINAL REPORT
==============================================================================

Only after 3 clean passes:
- REASSESS all findings as an H1 triager: assume the attacker is an external user with NO access to internal systems. Downgrade or remove findings that require internal access, privileged sessions, or have no real external attack path. Upgrade underrated findings with real external impact. Only include MEDIUM+ severity findings (CVSS >= 4.0) in the final report — drop all Low/Informational.
- Call finish_scan with comprehensive executive summary
- State: "Completed [X] validation passes. Final 3 passes found 0 new issues."

==============================================================================

START PHASE 1 NOW. Be THOROUGH. Miss NOTHING.
"""

        # If any GitHub-origin targets are present, prepend an intel-gathering
        # preamble telling the agent to pull open/closed issues and PRs from
        # the GitHub API before reading code. The issue/PR history is one of
        # the highest-yield vulnerability sources for OSS repos.
        github_targets_present = [ct for ct in classified_targets if ct["type"] == "github"]
        if github_targets_present:
            gh_url_lines = "\n".join(f"  - {gt['url']}" for gt in github_targets_present)
            github_intel_preamble = f"""GITHUB ISSUE / PR INTEL (MANDATORY — BEFORE ANY OTHER PHASE):
GitHub repos in scope:
{gh_url_lines}

The issue and PR history is one of the highest-yield vulnerability sources for an OSS repo (abandoned fixes, dismissed-but-real bug reports, partially-patched issues, CVE refs that never made the CHANGELOG, maintainer hand-waves of real bugs). Mine it BEFORE reading code.

For each repo above, derive <owner>/<repo> from the URL and pull:
  AUTH=(); [ -n "$GITHUB_TOKEN" ] && AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/issues?state=all&per_page=100"   # paginate via Link header
  curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/pulls?state=all&per_page=100"    # paginate
  curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/security-advisories"
  # For any item with security signal, also pull the full thread:
  curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/issues/<n>/comments"
  curl -s "${{AUTH[@]}}" "https://api.github.com/repos/<owner>/<repo>/pulls/<n>/comments"

Filter titles, bodies, and comments for: security, vuln, CVE, RCE, XSS, SSRF, SQLi, injection, bypass, leak, prototype pollution, deserialization, auth, race, TOCTOU, DoS, panic, crash, sanitiz, escape, traversal, hardcoded.

Triage rules for every hit:
- Open issue with security signal → unpatched. Reproduce against the cloned HEAD.
- Closed "won't fix" / "by design" / dismissed → frequently real bugs the maintainer ignored. Verify against current HEAD before accepting the dismissal.
- Closed-unmerged PR (abandoned fix) → the bug almost certainly still exists in HEAD. HIGH priority — confirm and report.
- Open PR proposing a security fix → the bug is real. Read the diff to identify the sink, then attack it from a different angle the patch does not cover.
- Closed-merged security PR → look for incomplete fixes (multi-sink bugs where only one sink got patched, or filter-style fixes you can bypass).
- Security advisories listing versions that are still in the current branch → patch missing in HEAD.

Output a TODO list of suspected vulnerabilities derived from the intel, with the issue/PR number and the file(s) in /workspace to verify against, BEFORE proceeding to the phases below.

==============================================================================
"""
            initial_prompt = github_intel_preamble + initial_prompt

        # If any extension targets are present, prepend a short framing line
        # telling the agent to use the download_extension MCP tool to fetch
        # the source into /workspace, then run the whitebox review against
        # the extracted directory.
        extension_targets_present = [ct for ct in classified_targets if ct["type"] == "extension"]
        if extension_targets_present:
            ext_lines = [f"  - {ct['url']}" for ct in extension_targets_present]
            ext_summary = "\n".join(ext_lines)
            has_vscode_target = any(ct.get("kind") == "vscode" for ct in extension_targets_present)
            vscode_trust_rule = ""
            if has_vscode_target:
                vscode_trust_rule = r"""
==============================================================================
VS CODE EXTENSION REVIEW CHECKLIST — work through every section in order.
==============================================================================

This is the authoritative review structure. Each area lists: WHAT to check →
WHERE to look → grep PATTERN to find candidates → SECURE-vs-VULN pattern.
Do not skip sections; mark each "OK / FINDING / N/A (reason)" in your notes.

------------------------------------------------------------------------------
0. RECON & SETUP
------------------------------------------------------------------------------
WHAT: extract the .vsix (it's a zip), beautify minified bundles, separate
      first-party extension code from vendored node_modules / webpack chunks.
      Identify the publisher, the displayName, the engines.vscode constraint,
      and whether any signing/integrity metadata is present.
WHERE: /workspace/<ext>/extension.vsixmanifest, package.json, dist/, out/,
       node_modules/, .vscodeignore (negative space).
GREP:  rg -l "webpack" /workspace/<ext> ; rg -n "\"publisher\"" package.json ;
       find . -name "*.min.js" -o -name "*.bundle.js"
SECURE pattern: source maps present, no minified vendored code in first-party
                paths, no secret-looking strings in published assets, source is
                reasonably reviewable as-is.
VULN pattern: hard-coded API keys / signing keys / telemetry tokens in the
              bundle; postinstall scripts in vendored deps; binary blobs
              executed at activation with no integrity check.

Also do: rg -nE "(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}" .

------------------------------------------------------------------------------
1. MANIFEST MAP — build the attack-surface inventory FIRST
------------------------------------------------------------------------------
WHAT: enumerate every entry point and every untrusted-input boundary the
      manifest declares. You cannot review what you have not enumerated.
WHERE: package.json fields — activationEvents, main/browser, contributes.{
       commands, configuration, customEditors, viewsContainers,
       jsonValidation, languages, taskDefinitions, debuggers,
       authenticationProviders, walkthroughs, semanticTokenScopes, menus},
       capabilities.{ untrustedWorkspaces, virtualWorkspaces }, enabledApiProposals.
GREP:  jq '.activationEvents, .contributes.commands[].command, .contributes.configuration.properties, .capabilities, .enabledApiProposals' package.json
SECURE pattern: narrow activationEvents (no `*`); explicit untrustedWorkspaces
                declaration; no enabledApiProposals beyond what's used.
VULN pattern: `*` activation; missing untrustedWorkspaces; URI handler
              registered without a corresponding scheme allow-list in code;
              `contributes.menus` exposing destructive commands to webviews
              with no `when` clause.

Produce a table: { activationEvent | command | config-key } → file:line of handler.
EVERY downstream section refers back to this table.

------------------------------------------------------------------------------
2. WORKSPACE TRUST POSTURE — the trust discipline (read all of this)
------------------------------------------------------------------------------
Background — three major programs have CLOSED "RCE after trust" as out of scope:
  - Google Cloud VRP (Cody YOLO):       trusted-workspace execution is by design.
  - Shopify (theme-check `require:`):   developer-authored config in local tooling is out of scope.
  - Salesforce (salesforcedx java.home):code exec is expected behaviour of trusted IDEs.

So the easy "looks trust-gated" path is dead. BUT — do NOT drop the finding
the moment you see trust involved. The same primitive (require() of workspace
data, child_process.exec of a workspace setting, JSON.parse+eval) is often
reachable via OTHER triggers that do not require trust. The vulnerable code
is the same; only the trigger changes.

WHAT: read `capabilities.untrustedWorkspaces`. Then for every sink reachable
      only-after-trust, exhaustively interrogate the surfaces in sections
      3, 4, 5, 6, 10, 11, 12 for a NO-TRUST trigger that hits the same sink.
WHERE: package.json capabilities; every activation callback; URI handlers;
       webview message handlers; any local network bind; auto-update path.
GREP:  jq '.capabilities.untrustedWorkspaces' package.json
SECURE pattern (declaration):
   - `"supported": false`  — extension is gated to trusted workspaces; AND
     no pre-trust surface reaches the sink. Drop only after checking 3+4+5+6+10+11+12.
   - `"supported": "limited", "restrictedConfigurations": [<exhaustive list>]` —
     every setting that flows into a sink is in the list.
VULN pattern:
   - `"supported": true` and a code path in Restricted Mode reaches a sink
     (require/exec/eval/spawn/child_process) — the extension LIED. Real finding.
   - `"supported": "limited"` with a missed config key reaching a sink — in scope.
   - Activation race: extension does work BEFORE awaiting the trust prompt,
     opening an unrestricted window.

Decision rule:
- If any section 3–12 gives you a no-trust trigger reaching the same sink →
  KEEP the finding; rewrite title/PoC to use that trigger. State explicitly
  which no-trust path you confirmed.
- ONLY drop as trust-gated AFTER reading: the manifest, activation code, URI
  handlers, webview handlers, network binds, auto-update paths, and chained
  extensions. Log: "Dropped: trust required (checked URI, webview, untrust=
  false, no net bind, no chain)".

After finish_scan, append exactly: `Dropped (Workspace Trust / opt-in required): <count>`
(Print the line with `0` if none were dropped.)

------------------------------------------------------------------------------
3. PROTOCOL HANDLERS / DEEPLINKS
------------------------------------------------------------------------------
WHAT: every URI handler — `vscode://publisher.ext/<route>...` — is web-reachable.
      Clicking a link in a browser fires the handler BEFORE workspace trust.
      Routes commonly carry attacker-controlled params used in commands, file
      paths, OAuth callbacks, downloads, or vscode.commands.executeCommand.
WHERE: `window.registerUriHandler({ handleUri })`, `vscode.window.registerUriHandler`,
       `package.json` activationEvents containing `onUri:`,
       `authenticationProviders` callbacks.
GREP:  rg -nE "registerUriHandler|handleUri\s*[:(]|onUri:" .
SECURE pattern:
  - Route allow-list before dispatch.
  - Signed payload (HMAC) when the link triggers a state change.
  - OAuth: PKCE + state param verified against stored value.
  - User confirmation modal for any destructive action.
VULN pattern:
  - Switch on path with no allow-list; payload deserialized + acted on.
  - OAuth callback parses redirect/code without PKCE/state, allowing token
    injection into the wrong session.
  - URI param flows into exec / require / writeFile / openFolder / executeCommand
    without sanitization.
  - "Trusted MarkdownString" rendered from URI text without enabledCommands gate
    (see section 8).

PoC: have the attacker page do `location.href = "vscode://publisher.ext/<route>?...="`
or render `<a href>` and trigger user click. Confirm the sink fires.

------------------------------------------------------------------------------
4. WEBVIEWS
------------------------------------------------------------------------------
WHAT: webviews are full HTML in an iframe. The extension chooses CSP, sets
      webview.html, and routes postMessage via onDidReceiveMessage. Any
      sink behind the message handler is reachable from JS inside the webview,
      which is reachable from attacker HTML if CSP is weak or origins are wide.
WHERE: `vscode.window.createWebviewPanel`, `webview.html = ...`,
       `webview.onDidReceiveMessage`, `webviewOptions.enableScripts`,
       `localResourceRoots`, `webview.asWebviewUri`.
GREP:  rg -nE "createWebviewPanel|webview\.html\s*=|onDidReceiveMessage|enableScripts:\s*true|localResourceRoots|innerHTML|v-html|dangerouslySetInnerHTML"
SECURE pattern:
  - CSP: `default-src 'none'; script-src 'nonce-...' ${webview.cspSource};
    style-src ${webview.cspSource} 'unsafe-inline'; img-src ${webview.cspSource} data:`.
  - Strict nonce per render; no `'unsafe-inline'` / `'unsafe-eval'` in script-src.
  - `localResourceRoots` restricted to extension resource dirs.
  - Message handler validates `message.type` against an allow-list, then
    type-checks each field, before dispatch.
  - No `innerHTML` / `v-html` / `dangerouslySetInnerHTML` on attacker-controlled
    strings; use textContent / framework-escaped binding.
VULN pattern:
  - CSP missing, `default-src *`, or includes `unsafe-eval`/`unsafe-inline` in script-src.
  - `enableScripts: true` + wide `localResourceRoots: [Uri.file('/')]`.
  - Message handler dispatches by string without allow-list → eval/exec/writeFile.
  - HTML built with template literals interpolating untrusted data → XSS inside
    the webview, then escape to extension host via postMessage.
  - Iframe URL is a public origin reachable via DNS rebinding.

PoC: open the webview from a normal flow, then in DevTools panel paste
`acquireVsCodeApi().postMessage({type:"...",payload:"..."})` and confirm the sink.

------------------------------------------------------------------------------
5. COMMAND / PROCESS EXEC
------------------------------------------------------------------------------
WHAT: any time the extension invokes a binary, follow the receiver back to
      its source. The most common bug is `child_process.exec`/`spawn` with
      `shell: true` and an interpolated workspace value.
WHERE: `child_process.{exec,execSync,execFile,spawn,spawnSync,fork}`,
       `util.promisify(exec)`, `execa`, `cross-spawn`, `shelljs`,
       `vscode.tasks.executeTask`, `pty.spawn`, terminals via `createTerminal`+sendText.
GREP:  rg -nE "(child_process\.|require\(['\"]child_process)\.(exec|spawn|execFile|fork)\b|shell:\s*true|sendText\s*\(" .
SECURE pattern:
  - `execFile(bin, [args...])` with array args; no shell interpretation.
  - Receiver is a *fixed* string (constant or imported builtin), not user data.
  - Argument array contains only validated tokens (regex / enum check).
VULN pattern:
  - `exec(\`${userInput} ...\`)` or `spawn(cmd, { shell: true })`.
  - `execFile(userPath, ...)` where userPath comes from a config / workspace file.
  - Terminal.sendText with interpolated workspace data and no escaping.

Common FP to RULE OUT FIRST: `RegExp.prototype.exec` and protobuf message
`.fork()` are NOT child_process. Resolve the receiver before reporting.

------------------------------------------------------------------------------
6. LANGUAGE SERVER / EXTERNAL BINARIES
------------------------------------------------------------------------------
WHAT: many extensions launch an LSP, debug adapter, or vendored CLI. If the
      binary path is *configurable* and not validated, a workspace setting
      can point at an attacker-controlled binary (the classic Salesforce
      `java.home` pattern).
WHERE: `vscode-languageclient`, `LanguageClient` constructor,
       `DebugAdapterExecutable`, `vscode.workspace.getConfiguration(...).get(<binPath>)`.
GREP:  rg -nE "LanguageClient|DebugAdapterExecutable|getConfiguration.*\.get\(.*(path|home|bin)" .
SECURE pattern:
  - Fixed bundled binary path inside the extension dir.
  - If configurable: path is in `restrictedConfigurations` of the trust
    capability; AND validated to be absolute + readable + within an
    allow-listed dir.
VULN pattern:
  - Binary path read from workspace config, NOT in restrictedConfigurations.
  - Path treated as opaque string and passed to spawn — no allow-list, no
    "is this inside extension dir / system PATH" check.
  - PATH search via `which` over a workspace-controlled PATH env override.

------------------------------------------------------------------------------
7. CONFIG-DRIVEN RCE (auto-load vs approval)
------------------------------------------------------------------------------
WHAT: extensions that load JS/Python/etc. from a workspace settings key,
      a `.vscode/*.json`, or an extension-specific config file. The bug is
      auto-load on open (no user gesture) without an approval list.
WHERE: anywhere the extension does `require(p)`, `import(p)`, `vm.runInNew*`,
       `new Function(...)`, `eval(...)`, `Module._compile`, dynamic plugin
       loaders ("plugins": [...] in config).
GREP:  rg -nE "\brequire\s*\(.+\)|\bimport\s*\(.+\)|new\s+Function\b|vm\.|\beval\s*\(|Module\._compile" .
SECURE pattern:
  - Approval gate keyed on the SETTING (not just file existence); approval
    persisted per (workspace × setting value); revoked on value change.
  - Plugins resolved only from extension dir / a fixed user dir, never from
    the workspace.
VULN pattern:
  - "plugins" array auto-loaded from workspace config; approval not bound to
    the value (just first-run gate, then permanent yes).
  - Approval key omits the config value, so swapping the value bypasses approval.
  - require() of a path computed from workspace data with no allow-list.

------------------------------------------------------------------------------
8. TRUSTED MARKDOWNSTRING — isTrusted vs enabledCommands
------------------------------------------------------------------------------
WHAT: `MarkdownString` with `isTrusted: true` renders `command:` URIs as
      clickable. If the extension does not pass an `enabledCommands` allow-list,
      ANY VS Code command (including `workbench.action.terminal.sendSequence`)
      fires on click. Common 1-click RCE primitive.
WHERE: `new vscode.MarkdownString(...)`, `.isTrusted = true`, hover providers,
       status bar tooltips, walkthrough steps.
GREP:  rg -nE "MarkdownString|isTrusted\s*[:=]\s*true|appendMarkdown\s*\(" .
SECURE pattern:
  - `isTrusted: false` (default), OR
  - `isTrusted: { enabledCommands: ['ext.specificCmd1', 'ext.specificCmd2'] }`
    with a *narrow* allow-list.
VULN pattern:
  - `md.isTrusted = true` with no enabledCommands — full command palette.
  - Hover content built from workspace data → user hovers, attacker's
    `command:workbench.action.terminal.sendSequence?...` fires.

------------------------------------------------------------------------------
9. AUTH / TOKEN HANDLING
------------------------------------------------------------------------------
WHAT: extensions store API tokens (GitHub, OpenAI, internal services). Two
      common bugs: token sent to wrong host (substring match instead of exact),
      and token logged / sent to telemetry / written to workspace files.
WHERE: `vscode.authentication.getSession`, `SecretStorage.{get,store}`,
       `keytar`, axios/fetch interceptors that attach auth headers,
       telemetry hooks, log appenders.
GREP:  rg -nE "authentication\.getSession|SecretStorage|keytar|Authorization:\s*['\"]Bearer|axios\.create|interceptors\.request" .
SECURE pattern:
  - Token attached ONLY when host exactly matches a fixed allow-list.
  - SecretStorage used for persistence; never written to workspace state /
    globalState / files.
  - Telemetry strips tokens via a redact filter applied to ALL payload paths.
VULN pattern:
  - `if (url.includes('api.github.com'))` instead of `new URL(url).host === 'api.github.com'`
    — attacker controls `https://evil.com/api.github.com/...` and token leaks.
  - Token logged in console / output channel / problemMatcher.
  - Bearer added to *every* outgoing request via global interceptor.

------------------------------------------------------------------------------
10. SSRF / OUTBOUND
------------------------------------------------------------------------------
WHAT: extensions that make outbound HTTP from workspace data — model proxy
      URLs, AI provider endpoints, "fetch this docs URL", import-from-URL.
WHERE: `fetch`, `axios`, `http.request`, `https.request`, `got`, `node-fetch`,
       MCP client / language-model provider configs.
GREP:  rg -nE "\b(fetch|axios|got|http\.request|https\.request|node-fetch)\b" .
SECURE pattern:
  - Host allow-list before dispatch; rejects private/loopback ranges (10/8,
    172.16/12, 192.168/16, 127/8, ::1, link-local, metadata 169.254/16).
  - DNS pinned via `lookup` hook OR resolved + checked, then requested by IP.
  - Disallow `file:` / `data:` / scheme-not-in-(http,https).
VULN pattern:
  - URL accepted from workspace setting / chat input / webview message and
    fetched as-is — SSRF into cloud metadata, internal services, file://.
  - Allow-list checks the URL *string* (`includes('api.openai.com')`) instead
    of the parsed URL's host.

------------------------------------------------------------------------------
11. FS / PATH TRAVERSAL
------------------------------------------------------------------------------
WHAT: any file operation joining a base dir with attacker-controlled segments.
      `path.join` does NOT prevent traversal — `..` collapses past the base.
      Bug is forgetting containment check on EVERY branch (success and error).
WHERE: `fs.{readFile,writeFile,readdir,rm,unlink,createReadStream}`,
       `vscode.workspace.fs.*`, `vscode.Uri.joinPath`,
       `path.{join,resolve}` followed by fs call.
GREP:  rg -nE "(fs\.|workspace\.fs\.|Uri\.joinPath|path\.(join|resolve))" .
SECURE pattern:
  - `const target = path.resolve(base, userSeg); if (!target.startsWith(base + path.sep)) throw ...`
    BEFORE every fs call.
  - Normalize first, then containment check; never just `userSeg.includes('..')`.
VULN pattern:
  - `path.join(base, userSeg)` + fs call with no containment check.
  - Containment check on the success path only; error/cleanup path opens
    the un-checked variable.
  - `Uri.joinPath(baseUri, ...userSegs)` followed by `workspace.fs.writeFile`
    with no fsPath containment check.
  - Symlink: target inside base resolves to symlink pointing outside.

------------------------------------------------------------------------------
12. DESERIALIZATION / DYNAMIC CODE
------------------------------------------------------------------------------
WHAT: parsing untrusted YAML/TOML/XML/protobuf that supports tag-based class
      instantiation, OR running user-supplied code through vm/Function/eval.
WHERE: `js-yaml` `yaml.load` (vs `safeLoad`), `serialize-javascript` deserialize,
       `node-serialize`, XML with external entities, plist with NSKeyedUnarchiver,
       any `new Function`, `vm.runInThisContext`, `eval`.
GREP:  rg -nE "yaml\.load\b|node-serialize|deserialize|new\s+Function|vm\.runIn|eval\s*\(" .
SECURE pattern:
  - `yaml.load(s, { schema: yaml.JSON_SCHEMA })` or `yaml.safeLoad` (deprecated alias).
  - XML parser with entity expansion OFF.
  - User code runs in `vm.createContext({})` with NO globals OR not at all.
VULN pattern:
  - `yaml.load(workspaceFile)` with default schema → `!!js/function` → RCE.
  - `new Function(userString)()` from a config value or webview message.
  - protobuf reflection unmarshalling untrusted bytes into typed instances
    with side-effecting constructors.

==============================================================================
TRIAGE GATE — 6 questions every candidate finding must answer YES on
==============================================================================
Apply BEFORE writing the report. If ANY answer is NO, you do not have a finding.

  Q1. EXTERNAL REACHABILITY. Can an external, unauthenticated attacker reach
      the sink? Source-code analysis is not reachability — name the trigger
      (URI handler, webview msg, port bind, hover render, config auto-load).

  Q2. REAL DELIVERY, NOT MITM. Is the trigger deliverable without an attacker
      already on the network path? (DNS rebinding counts; "if attacker intercepts
      the response" does not unless there's no HTTPS / no pinning AND a realistic
      attacker position.)

  Q3. THE GATE — and can you actually bypass it? Identify the gate (Workspace
      Trust / user confirmation modal / approval list / signed payload).
      If you cannot describe how an external attacker bypasses it, the gate
      stands and the finding is intended-functionality.

  Q4. PoC AGAINST UNMODIFIED APP. Did you run the unmodified extension via
      `code --install-extension <vsix>` and trigger the sink with a real
      payload, OR did you only read code? Code-only is informative. PoC against
      a forked/patched build is informative.

  Q5. FIRST-PARTY vs VENDORED. Is the vulnerable code in first-party extension
      source, or inside `node_modules/<dep>/`? Vendored bugs go upstream;
      they are not a finding against this extension UNLESS the extension
      pinned a known-vulnerable version while a fix exists.

  Q6. BACKEND-DEPENDENT = UNPROVEN. If the impact requires "the backend
      server returns X", you have not proven it — that's a finding against
      the backend, not the extension. Test against the actual production
      backend or drop.

==============================================================================
COMMON FALSE POSITIVES — kill these on sight
==============================================================================

  - `someStr.match(...)` / `regex.exec(...)` — that is RegExp, NOT child_process.
    Always resolve the receiver before reporting an "exec" sink.
  - protobuf `Message.fork()` — that is the protobuf writer's fork, NOT
    child_process.fork.
  - `eval("require")` and similar shims — Webpack / bundler wrappers; the
    inner string is a literal, not attacker data.
  - `innerHTML` set from the extension's OWN JSON (e.g. localized strings
    bundled in the extension) — author-controlled, not attacker-controlled.
  - Deeplink that fires a confirmation modal before action — gated; not a
    finding unless you can bypass the modal (URI race, double-event, etc.).
  - Webview that LOOKS XSS-able but the CSP is strict (`script-src 'nonce-...'`
    only, no `unsafe-eval`/`unsafe-inline`) — injection is blocked by CSP.
    Verify the CSP actually applies (no `<meta http-equiv="Content-Security-Policy">`
    in HTML being overridden by `webview.html` outer wrapper).
  - MCP / language-model providers behind an explicit approval list AND the
    approval is keyed on the FULL config (not just "any provider once").
  - "Trusted Workspace required" with no pre-trust trigger you can name —
    see section 2 decision rule.

After section 12 + triage + FP filter is done, run the standard validator
subagents per remaining finding.
"""
            extension_preamble = f"""TASK: download and security-review the listed browser/IDE extension(s):

{ext_summary}

For each URL above, call the `download_extension` MCP tool with that URL — it will fetch the public package (.vsix / .crx) into the sandbox and extract the source under /workspace/<auto-name>. Then list_files on the extracted directory and run the whitebox source-code review against it.
{vscode_trust_rule}
"""
            initial_prompt = extension_preamble + initial_prompt

        # Common claude args
        claude_env = {**os.environ, "CLAUDE_CODE_SKIP_TRUST_DIALOG": "1"}
        claude_base_args = [
            "claude",
            "--mcp-config", str(mcp_config_path),
            "--append-system-prompt", system_prompt,
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
        ]

        if sys.stdin.isatty():
            result = subprocess.run(
                claude_base_args + [initial_prompt],
                cwd=temp_config_dir,
                env=claude_env,
            )
        else:
            console.print(f"\n[bold yellow]No interactive terminal - running in print mode.[/bold yellow]")
            result = subprocess.run(
                claude_base_args + ["--print", initial_prompt],
                cwd=temp_config_dir,
                env=claude_env,
            )

        console.print("\n" + "=" * 60)
        console.print("[bold]Scan session ended.[/bold]")

        if keep_container:
            console.print(f"\n[yellow]Container kept running:[/yellow] {sandbox_info['container_name']}")
            console.print("To stop it manually: docker stop " + sandbox_info['container_name'])

    except SandboxError as e:
        console.print(f"[red]Sandbox error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup temp files
        if temp_config_dir and Path(temp_config_dir).exists():
            shutil.rmtree(temp_config_dir, ignore_errors=True)

        # Cleanup cloned GitHub repos
        if github_clone_dir and github_clone_dir.exists():
            shutil.rmtree(github_clone_dir, ignore_errors=True)

        # Stop sandbox unless --keep-container
        if sandbox and not keep_container:
            with console.status("Stopping sandbox..."):
                sandbox.stop()
            console.print("[green]Sandbox stopped.[/green]")


if __name__ == "__main__":
    main()
