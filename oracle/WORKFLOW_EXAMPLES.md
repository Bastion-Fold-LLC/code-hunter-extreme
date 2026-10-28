# Oracle Mindset - Bug Bounty Workflow Examples

> These examples use the `oracle.py` prompt feeder; sample outputs are
> illustrative patterns ("Expected Output Pattern"), not captured runs.
> For the production pipeline (verified findings, reports on disk), see
> `oracle_hunter.py` flows in `README.md` and `ARCHITECTURE.md`: prescan →
> scan `--download` → queue `--execute` → hunt → verify, with outputs under
> `targets/<platform>/<slug>/{findings,reports}/`.

## Example 1: API Documentation Audit (Specification Auditing)

**Input**: API docs claim "All admin endpoints require OAuth2 Bearer tokens"

```bash
python3 oracle.py --mode spec-audit -i << 'EOF'
API Documentation states:
- All /admin/* endpoints require OAuth2 Bearer token authentication
- Tokens must be passed in Authorization header
- Invalid tokens return 401 Unauthorized
- Rate limiting applies to all authenticated endpoints
EOF
```

**Expected Output Pattern**:
```
Using SPECIFICATION AUDITING pattern:

Underspecified Terms Found:
1. "OAuth2 Bearer token" - Never specifies token validation method
   - Ambiguity: Does server validate signature? Just check presence?
   - Exploitation Vector: Test with malformed/unsigned JWT tokens

2. "Authorization header" - Never specifies case sensitivity or multiple header behavior
   - Ambiguity: What if two Authorization headers sent?
   - Exploitation Vector: Send conflicting headers, test parsing order

3. "Invalid tokens return 401" - Never defines what makes token invalid
   - Ambiguity: Expired? Wrong scope? Malformed? All treated same?
   - Exploitation Vector: Test each failure mode separately

4. "Rate limiting applies to authenticated endpoints" - Never specifies if unauthenticated are rate limited
   - Ambiguity: Can bypass rate limits by removing auth?
   - Exploitation Vector: Compare rate limits with/without token
```

---

## Example 2: Binary Conflict Isolation (The iPhone Problem)

**Scenario**: WAF claims to block SQL injection, but error messages suggest otherwise

```bash
python3 oracle.py --mode binary-conflict \
  --assertion-a "WAF policy states all SQL injection patterns are blocked at edge, returning 403 before reaching origin" \
  --assertion-b "GET /search?q=' OR '1'='1 returns 500 error with MySQL syntax error message from origin server"
```

**Expected Output**:
```
Using BINARY CONFLICT ISOLATION (The iPhone Problem):

ASSERTION A: WAF policy states all SQL injection patterns are blocked at edge, returning 403 before reaching origin
ASSERTION B: GET /search?q=' OR '1'='1 returns 500 error with MySQL syntax error message from origin server

Binary Verdict:
- If A is true, B must be false because: MySQL error proves request reached origin, WAF didn't block
- If B is true, A must be false because: Origin response confirms WAF bypass

Reproducible Check (ONE command):
```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.com/search?q=' OR '1'='1"
# Expected: 500 (proves WAF bypass) vs 403 (proves WAF working)
```

Expected Outcomes:
- Outcome 1 (A is false): HTTP 500 returned with MySQL error in body → WAF bypass confirmed
- Outcome 2 (B is false): HTTP 403 returned, no origin error → WAF working, initial observation was anomaly

Report Summary:
WAF声称的SQL注入防护与实际行为存在直接矛盾。通过发送经典SQLi payload并观察MySQL错误消息，证明请求绕过WAF到达源服务器。这是一个明确的WAF绕过漏洞，可提交为高危漏洞报告。
```

---

## Example 3: Ontological Reframing for XSS Bypass

**Problem**: "XSS filter blocks `<script>` tags but I need to execute JavaScript"

```bash
python3 oracle.py --mode reframe -p "XSS filter blocks <script> tags and event handlers like onclick, onerror. Need to execute JavaScript for PoC."
```

**Expected Output**:
```
Using ONTOLOGICAL REFRAMING pattern:

Current Problem Statement:
XSS filter blocks <script> tags and event handlers like onclick, onerror. Need to execute JavaScript for PoC.

Reframing Questions:
1. Assumption: "JavaScript execution requires <script> tags or event handlers"
   - What if JavaScript can execute WITHOUT these constructs?

2. Assumption: "Filter blocks malicious patterns"
   - What if the filter is looking for patterns, not actual execution contexts?

3. Relationship decoupling: "Input field = attack vector"
   - What if the attack vector isn't the input, but how input is PROCESSED?

Possible Reframes:
- Entity Redefinition: Don't think "script tag" → think "any context where browser evaluates code"
  - SVG <animate> with href="javascript:..."
  - <iframe src="javascript:...">
  - <object data="javascript:...">
  - CSS expression() in older IE
  - Template literal injection in JS frameworks

- Domain Translation: Move from "HTML injection" to "Context-aware injection"
  - Is output in HTML context? Attribute context? JavaScript context? URL context?
  - Each context has different valid payloads

New Problem Statement:
"Identify the output context where my input is rendered, then find the minimal syntax that triggers code evaluation in THAT specific context, regardless of whether it looks like traditional XSS."

Next Action:
Test these context-specific payloads instead of generic <script>:
- HTML context: <img src=x onerror=alert(1)>
- Attribute context: "><script>alert(1)</script><"
- JavaScript context: ';alert(1);//
- URL context: javascript:alert(1)
```

---

## Example 4: Axiom Rewriting for "Impossible" Problem

**Problem**: "Can't test for IDOR because every endpoint requires authentication"

```bash
python3 oracle.py --mode axiom -p "Impossible to test for IDOR vulnerabilities because all endpoints require authentication and I only have one user account. Cannot access other users' data to verify horizontal privilege escalation."
```

**Expected Output**:
```
Using AXIOM REWRITING pattern:

Currently "Impossible" Problem:
Cannot test IDOR because all endpoints require authentication and I only have one user account.

Current Axioms Causing Failure:
1. "Need two user accounts to test IDOR"
2. "Authentication prevents unauthorized access"
3. "IDOR requires accessing another user's resource"

Axiom Replacement Strategy:
1. Replace axiom #1: Instead of "need two accounts", use "need two resource identifiers"
2. Replace axiom #3: Instead of "access another user's resource", use "prove authorization check exists"

New Axiom Set:
- Old Axiom: "IDOR testing requires multiple user accounts"
- New Axiom: "IDOR testing requires predictable resource identifiers and observable authorization differences"
- Justification: Many systems use sequential IDs, UUIDs with patterns, or leaked identifiers from other sources

- Old Axiom: "Must successfully access other user's data to prove IDOR"
- New Axiom: "Can prove IDOR through differential responses even without full access"
- Justification: 200 vs 403, response time differences, partial data leakage all prove authorization bypass

Reformulated Problem:
"Given one user account, enumerate resource identifiers through:
(a) Sequential ID enumeration (/users/1, /users/2, /users/3...)
(b) Leaked identifiers from public endpoints, referrals, API docs
(c) Predictable patterns (timestamps, UUIDs with known prefixes)
Then test authorization by comparing responses across identifiers."

Solution Path:
1. Map all endpoints accepting resource IDs from your single account
2. Identify ID patterns (sequential, UUID, hash)
3. Generate adjacent identifiers (ID+1, ID-1, or predicted UUIDs)
4. Send requests with YOUR auth token but OTHER user's ID
5. Compare responses: 200 OK with data = IDOR confirmed
   Even partial differences (response time, error messages) indicate missing authorization checks
```

---

## Example 5: Full Workflow - From Recon to Report

### Step 1: Specification Audit of robots.txt

```bash
python3 oracle.py --mode spec-audit -i << 'EOF'
robots.txt contents:
User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /rest/cart*
Allow: /api/public/
EOF
```

### Step 2: Find Binary Conflict

```bash
python3 oracle.py --mode binary-conflict \
  --assertion-a "robots.txt disallows /rest/cart* indicating sensitive cart operations should not be publicly accessible" \
  --assertion-b "Frontend bundle CommonComponentsSiteFrontEnd.js contains hardcoded calls to /rest/cart/getCart with no authentication headers"
```

### Step 3: Generate Reproducible Check

```bash
# From oracle output, create actual test
curl -v https://target.com/rest/cart/getCart?cartId=12345
# Observe: Returns 200 OK with cart data, no auth required
```

### Step 4: Format Report (iPhone Problem Style)

```markdown
## IDOR: Cart Data Exposure via Unauthenticated Endpoint

**Binary Conflict:**
- Assertion A: robots.txt explicitly disallows `/rest/cart*` to prevent public access
- Assertion B: Frontend makes unauthenticated requests to `/rest/cart/getCart` that succeed

**Proof:**
```bash
curl -s "https://target.com/rest/cart/getCart?cartId=12345" | jq .
# Returns: {"cartId":"12345","items":[...],"total":99.99}
```

**Impact:** Any user can enumerate cart contents by incrementing cartId parameter.

**Remediation:** Enforce authentication server-side, not just robots.txt.
```

---

## Quick Reference Commands

```bash
# Start interactive session
python3 oracle.py --interactive

# Quick spec audit
echo "API requires authentication for all endpoints" | python3 oracle.py --mode spec-audit -i /dev/stdin

# Binary conflict from file
python3 oracle.py --mode binary-conflict \
  --assertion-a "$(cat assertion_a.txt)" \
  --assertion-b "$(cat assertion_b.txt)"

# Generate system prompt for Claude/Gemini
python3 oracle.py --output-system-prompt > system_prompt.txt

# Pipe to local LLM (after setup)
python3 oracle.py --mode binary-conflict --assertion-a "X" --assertion-b "Y" | \
  ollama run llama3.1:8b-instruct-q4_K_M
```
