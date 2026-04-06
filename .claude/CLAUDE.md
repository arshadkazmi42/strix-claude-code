# Security Audit Instructions

## Scan Rules

### Scope
- Skip archived, disabled, forked repos
- Skip demo, example, sample, tutorial, starter, template, playground repos
- Skip test/, example/, demo/, sample/, node_modules/, vendor/, .d.ts files inside repos
- Never filter by stars or language — scan EVERYTHING
- Clone all repos, no exceptions for "small" or "non-code" repos

### Depth
- Do NOT call grep patterns a "deep scan." Be honest about scan depth.
- Quick scan = grep/regex pattern matching across files. Say "pattern scan."
- Deep scan = actually read the code, trace data flow, understand auth boundaries, follow user input from request to sink. Say "code review."
- For every repo: at minimum do pattern scan. For security-critical repos (auth, crypto, network, CI/CD): do actual code review.
- Always check .github/workflows/ — GitHub Actions vulns are the most common org-wide finding.

### GitHub Actions Scan Checklist
- Script injection: `${{ github.event.issue.title/body }}`, `${{ github.event.pull_request.title/body }}`, `${{ github.event.comment.body }}`, `${{ github.event.head_commit.message }}`, `${{ github.head_ref }}` used DIRECTLY in `run:` blocks. Env vars are safe.
- pull_request_target + checkout of PR head code (not base). Check for actor guards (dependabot[bot] etc).
- workflow_run + artifact download from untrusted workflows.
- Secrets exposed to fork PRs.
- Check AI/LLM workflows for prompt injection chains — issue body → AI → dashboard/comments.
- Unpinned third-party actions on security-sensitive workflows.
- Check .github/skills/ folders — these are AI prompts/instructions that process user-controlled input (issues, PRs, comments). Trace: what input does the skill read → what does the AI output → where does that output go → is it sanitized.

### Repo Filtering (for org-wide scans)
Skip these repos entirely — do not clone, do not scan:
- **Archived** repos (`archived: true`)
- **Disabled** repos (`disabled: true`)
- **Forked** repos (`fork: true`)
- **Demo/example/sample** repos — name contains: demo, example, sample, tutorial, starter, template, boilerplate, playground, sandbox

Skip these folders inside repos:
- test/, tests/, __tests__/, spec/, e2e/
- example/, examples/, demo/, demos/, sample/, samples/
- node_modules/, vendor/, dist/, build/
- .d.ts files (type definitions only)

Do NOT skip:
- Small repos or repos with few stars — vulns don't care about popularity
- Repos in any language — Shell, HTML, Python, Go, Rust, TypeScript all count
- .github/ folder — this is where Actions vulns live, always scan it

## Finding Analysis Rules

### H1-Style Triage
Every finding must pass these gates before reporting:
1. Is it in core code (not example/demo)?
2. Can an external attacker with zero internal access trigger it?
3. Does it affect default/shipped configuration?
4. Is the impact real and demonstrable, not theoretical?
5. Is it Medium severity or above?

If any gate fails, mark as Informative and explain why. Do NOT inflate severity.

### Common False Positives to Catch
- Sandbox containers with /exec endpoints — RCE is the feature, not a bug
- HMAC-SHA1 — still secure per RFC 2104, collision attacks don't apply to HMAC
- SHA-1 for X.509 Subject Key Identifier — mandated by RFC 5280
- Dead code (functions that exist but are never called)
- `fmt.Sprintf` with hardcoded struct field names into SQL — not user input
- `innerHTML` in debug pages behind auth — self-XSS only
- ActivityPub/federation SSRF — standard protocol behavior, all implementations have it
- `pull_request_target` guarded by `dependabot[bot]` actor check — not bypassable
- No built-in auth in a framework — design choice, not a bug (like Express.js)
- Non-timing-safe comparison of hashes (not plaintext) — can't control hash output, nanosecond delta over network

### When an Agent Flags Something
- Always manually verify before accepting. Agents produce false positives.
- Read the actual file and surrounding context.
- Check for guards, filters, and mitigations the agent may have missed.
- Count and document false positives caught — this shows rigor.

## PoC Rules

### Never Isolate Code
- PoC must work against the actual codebase, not a stripped-down reproduction.
- Reference exact file paths and line numbers.
- Show the full code path from trigger to impact: file:line → file:line → file:line.

### Prove It Works
- Every finding must have a working PoC. No PoC = not a valid finding.
- Run the PoC and show output. Screenshots or terminal output.
- For GitHub Actions injection: create a test repo with the IDENTICAL workflow pattern, trigger it, show the logs.
- For code vulns: demonstrate exploitation against the actual code, not a simplified version.

### What Counts as Proof
- Shell output showing injected command executed (e.g., `uid=1001(runner)` from `$(id)`)
- HTTP response showing leaked data
- Log output from CI/CD showing injected payload ran
- Side effect observable by attacker (callback to attacker server, DNS query, etc.)

### What Does NOT Count
- "This pattern is known to be vulnerable" — show it, don't cite it
- "If an attacker could..." — either they can or they can't, demonstrate which
- Theoretical chains with unverifiable steps — document as "additional concern," not a finding

## Report Writing Rules

### Format
```
# Title (short, specific)
# Summary (2-3 sentences max)
## Steps to Reproduce (numbered, copy-pasteable commands)
# PoC (test repo link, action run link, log output)
# Impact (what attacker gets, what attacker does NOT get)
## Fix (exact code diff)
```

### Style
- Write like a human, not AI. No filler. No stories. Everything to the point.
- Short sentences. No "it is important to note that" or "this vulnerability allows an attacker to potentially..."
- Just: "Line 38 injects `github.head_ref` into a shell command. Attacker controls the branch name."
- Include actual URLs, run IDs, log output as evidence.
- Show what the attacker CANNOT do, not just what they can — this is what separates good reports from hype.

### Severity Honesty
- If fork PRs don't get secrets, say so. Don't pretend it's Critical.
- If it requires a maintainer to approve first run, say so.
- If impact is "just" runner abuse with read-only token, say "Medium, not High" and explain why.
- Never inflate. Triage teams respect accuracy over drama.

### Before Submitting
- Check if anyone already reported it: search issues, PRs, security advisories.
- Check if the vulnerable code is still on main branch (not already fixed).
- Check the repo's SECURITY.md for reporting instructions.
- Verify the auto-approval setting: do fork PRs actually auto-run, or need approval?
- Include evidence of auto-run (show external contributor's workflow runs that completed).

## Blind/Indirect Prompt Injection

### When to Flag
- AI workflow reads attacker-controlled input (issue body, PR body, comment)
- AI output goes somewhere without sanitization (dashboard, comments, labels)
- Zero human in the loop between attacker input and AI processing

### How to Document
- If you can't verify the downstream rendering (e.g., internal dashboard), document as "additional concern" not a confirmed finding.
- Map the full chain: attacker input → AI processing → output destination → potential impact.
- Note what permissions the AI has (read-only is much lower risk than write).
- Do NOT test against production. Report the chain and let the security team verify.

## Don't Do
- Don't create dummy GitHub accounts to test against production repos
- Don't open issues/PRs on target repos to test payloads
- Don't call grep a "deep scan"
- Don't report framework design choices as vulnerabilities
- Don't store findings in CLAUDE.md — this file is for instructions only
- Don't inflate scan coverage numbers — be honest about what was grep vs what was actually read
