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
- create_vulnerability_report: Document vulnerabilities with CVSS scoring (USE FOR ALL CONFIRMED VULNS)
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


def create_mcp_config(tool_server_url: str, token: str, scan_id: str, output_file: str) -> dict[str, Any]:
    """Create MCP configuration for Claude CLI."""
    # Get the path to the MCP server module
    mcp_server_path = Path(__file__).parent / "mcp_server.py"

    return {
        "mcpServers": {
            "strix-pentest": {
                "command": sys.executable,
                "args": [str(mcp_server_path)],
                "env": {
                    "STRIX_TOOL_SERVER_URL": tool_server_url,
                    "STRIX_TOOL_SERVER_TOKEN": token,
                    "STRIX_AGENT_ID": f"claude-{scan_id}",
                    "STRIX_REPORT_FILE": output_file,
                },
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
            "--model", "claude-opus-4-7",
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
    --model claude-opus-4-7 \\
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
                vscode_trust_rule = """
VS CODE WORKSPACE-TRUST RULE — DO NOT SHORT-CIRCUIT, HUNT FOR BYPASSES FIRST:
Background — three major programs have closed "RCE after trust" as out of scope:
  - Google Cloud VRP (Cody YOLO): "YOLO mode... can only be used in a trusted workspace... by design."
  - Shopify (theme-check `require:`): "Code execution via developer-authored config in local development tooling is out of bounty scope... the decision to trust the source of the repository sits with the developer."
  - Salesforce (salesforcedx java.home): "If the victim trusts the workspace then this is expected behaviour for IDEs since code execution is part of its use."

So the easy "looks trust-gated" path is dead. BUT — do NOT drop the finding the moment you see trust is involved. The same primitive (e.g. `require()` of workspace data, `child_process.exec` of a workspace setting, JSON.parse + eval) is often reachable through OTHER paths that do NOT require trust. The vulnerable code is the same; only the trigger changes. Your job is to interrogate every "trust-gated" candidate for a no-trust trigger BEFORE deciding it is out of scope.

For each candidate finding that appears to need trust, exhaustively check for at least these bypass surfaces — go read the actual manifest and the actual code, do not guess:

1. activationEvents reachable without trust. A few events fire BEFORE the trust prompt or in Restricted Mode:
   - `onUri` / URI handlers — a `vscode://publisher.ext/...` link clicked in a browser can activate the extension before the user has trusted anything. Read `package.json` activationEvents and the `window.registerUriHandler` callsites.
   - `onAuthenticationRequest`, `onCustomEditor`, `onWebviewPanel` reopen — can fire from VS Code session restore.
   - `onLanguage:<id>` for a language the extension handles — an untitled buffer in that language activates it.
   - `onCommand:<cmd>` if the command is callable from a URI or another extension.
   - `*` (universal activation) — extension runs in Restricted Mode unless capabilities say otherwise.

2. `capabilities.untrustedWorkspaces` declaration. Read it carefully:
   - `"supported": true` → the extension claims it is SAFE in Restricted Mode. If any code path in Restricted Mode reaches a sink (require/exec/eval/spawn/child_process), that's a real finding: the extension lied.
   - `"supported": "limited"` with `restrictedConfigurations: [...]` → only the listed settings are blocked. Any OTHER setting that reaches a sink is in scope.
   - `"supported": false` and missing — finding fires only after trust. Still check the other bypass surfaces below before dropping.

3. Webview message handlers (`webview.onDidReceiveMessage`). Webviews can be opened pre-trust by some extensions, AND a malicious web page can frame the webview's iframe URL or postMessage to it. If the message handler ends in eval/require/exec, the trigger is web-reachable, not trust-gated.

4. Local TCP/Unix servers and IPC. Some extensions bind a port (language server, debug adapter, telemetry, devtools relay). If the bind is on `0.0.0.0` or accepts unauthenticated requests from `localhost`, an attacker on the network or a malicious page using `fetch('http://127.0.0.1:<port>')` can reach the sink without trust.

5. OAuth / authentication callback handlers. Registered via URI handlers — they fire pre-trust and often parse attacker-controlled redirect-URI params.

6. Auto-update / "download latest binary" code paths that run on activation. The download URL can be poisoned via DNS, a workspace-supplied config, or a previously-cached value.

7. Telemetry / crash-report endpoints in the extension that read workspace data and POST to a configurable URL.

8. Clipboard / notification / quickPick handlers that fire on user actions other than trust.

9. Race condition on the trust prompt. If the extension activates and starts work BEFORE the trust prompt is answered (some extensions short-circuit during startup), the sink may fire in an unrestricted window.

10. Same-publisher chained extensions. If extension A activates without trust (e.g. has correct `untrustedWorkspaces.supported: true`) and calls into vulnerable extension B's API, the bug fires from A's no-trust context.

Decision rule:
- If ANY of the above gives you a no-trust trigger that reaches the same sink → KEEP the finding, but rewrite the title/PoC to use that trigger, not the trust-gated one. State explicitly which no-trust path you confirmed.
- If you have read the manifest, the activation code, the URI handlers, the webview handlers, the network servers, and every other applicable surface, AND none of them reach the sink without trust → THEN drop it as trust-gated.

When dropping, log a one-line reason of WHAT bypasses you checked, e.g.:
  "Dropped: trust required (checked URI handler, webview msg, untrustedWorkspaces=false, no network bind)"

Apply this filter during your reassessment, BEFORE running the independent validator subagents. Keep a count of confirmed trust-gated findings you drop. After finish_scan, append exactly one extra line to your final output:

  Dropped (Workspace Trust / opt-in required): <count>

If zero were dropped, still print the line with `0`.
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
            "--model", "claude-opus-4-7",
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
