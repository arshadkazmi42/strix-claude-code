# Strix Security Scanner — Operating Guidelines

## Triage Model: H1-Style External Attacker

All findings MUST be triaged from the perspective of a HackerOne triager. Assume the attacker is:
- External, unauthenticated, no access to internal systems
- No access to CI/CD (cannot trigger workflow_dispatch, no repo write access)
- No access to container-internal networks, localhost services, or cloud metadata
- Cannot compromise third-party dependencies as a prerequisite (that's a separate report)

## What Is NOT a Vulnerability

### Archived / Unmaintained / Demo Projects
- ALWAYS check repo status FIRST before scanning: `archived` flag, README warnings, last commit date
- Archived repos, demo apps, showcase projects, example code = **Informative / N/A**
- Templates and starter kits are educational — bugs in them are not vulnerabilities in the target org

### Intended Functionality
- A sandbox executing code is doing its job, not a vulnerability
- An MCP tool querying databases is its designed purpose
- A dev tool with no auth on localhost is network-isolated by design
- Read the README and understand what the tool is FOR before calling it broken

### Single-Tenant by Design
- ALWAYS check if software is designed for single-tenant use before reporting IDOR
- Look for: how many users does the config support? Does the README mention multi-tenancy, teams, or isolation?
- A private registry with one shared password is not IDOR — it's a personal registry
- Single USERNAME/PASSWORD pair = single-tenant = no IDOR possible

### CI/CD Findings Requiring Internal Access
- workflow_dispatch injection = requires repo write access = insider threat, not external attack
- pull_request_target with actor checks (e.g., `dependabot[bot]`) = mitigated, not exploitable by forks
- Unpinned actions/deps = supply chain hygiene, not a direct vulnerability (Low at best)

### Platform-Mitigated Issues
- If the runtime platform mitigates the attack (e.g., Workers blocking private IPs), downgrade severity significantly and note the mitigation

## What IS a Vulnerability

- Bugs in actively maintained source code that are exploitable by an external attacker
- Authentication bypass, injection, XSS where an external attacker can reach the endpoint
- Security flaws in libraries/frameworks that affect users who depend on them
- Supply chain attacks against published packages (npm, PyPI, etc.)

## PoC Requirements

### PoC Must Use the Actual Application Code
- NEVER write isolated test code, mock code, or separate scripts that simulate the vulnerability
- NEVER create vitest/jest/mocha tests as a PoC — tests proving code behavior will be closed as Informative on H1
- ALWAYS run the actual application from its source code (e.g., `wrangler dev`, `npm start`, `go run`, `docker compose up`)
- ALWAYS send real HTTP requests (curl, browser, docker push/pull) against the running application
- The PoC must use the UNMODIFIED source code — do not fork, patch, or wrap the code to demonstrate the bug
- Show actual HTTP request and response from the running app, not test assertions or code analysis

### PoC Checklist Before Reporting
1. Is the actual application running from its own unmodified source code? (not a test harness, not isolated code)
2. Are you sending real HTTP requests against it? (curl/browser/docker, not vitest/jest)
3. Is the application code unmodified? (no custom test wrappers, no mocked dependencies)
4. Does the HTTP response prove the vulnerability? (actual data leaked, actual auth bypassed)
5. Could a triager clone the repo, start the app, and reproduce with your exact curl commands?

## Pre-Scan Checklist (Do This FIRST for Every Repo)

1. Check GitHub API: `archived`, `disabled`, `fork` status
2. Read the FULL README: look for "archived", "deprecated", "demo", "example", "showcase", "no longer maintained", "proof of concept", "experimental"
3. Check last commit date: >12 months stale = likely unmaintained
4. Understand the intended use case: single-tenant vs multi-tenant, dev tool vs production service, library vs app
5. Only THEN start code review

## Severity Calibration

### Critical/High — Only if:
- External attacker can exploit it
- In actively maintained source code
- With demonstrated impact (data theft, RCE, auth bypass)
- With a working PoC against the actual running application

### Medium — Design gaps in maintained OSS:
- Missing security controls that users would reasonably expect
- BUT the README doesn't claim the feature exists
- AND the project is actively maintained

### Low/Informative — Everything else:
- Best practice recommendations (PKCE should be required, iterations too low)
- Defense-in-depth suggestions (pin actions to SHA, add rate limiting)
- Archived/demo/example code issues
- Findings requiring insider access
- Platform-mitigated issues

## Report Writing

Use this exact format. Be direct. No stories, no filler, no explanations of how you found it.

```
## Title
[One line. Vulnerability type + where]

## Summary
[2-3 sentences max. What is the bug, where is it, what can an attacker do]

## Steps to Reproduce
1. [Clone repo / setup step]
2. [Start the app]
3. [Exact command to trigger the bug]
4. [What to observe]

## PoC
[Exact curl commands / HTTP requests with actual output from the running app]

## Impact
[What an attacker gains. One paragraph max]
```

Rules:
- No severity justification paragraphs — the PoC speaks for itself
- No root cause analysis unless asked — that's for the fix, not the report
- No "I noticed that..." or "Upon further investigation..." — just the facts
- Every curl command must be copy-pasteable and reproducible
