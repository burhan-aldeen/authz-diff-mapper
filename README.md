# authz-diff-mapper

**Advanced 401/403 Authorization Behavior Analysis Tool**

Analyze authentication and authorization behavior in web APIs using differential
response analysis. Designed for **authorized bug bounty programs**, **penetration tests**,
and **security lab environments only**.

> :warning: **Legal Use Only** — This tool performs no exploitation, no credential
> brute-forcing, no token guessing, and no data modification by default. It reports
> **behavioral differences** for manual review by authorized security researchers.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Input Examples](#input-examples)
- [Output Interpretation](#output-interpretation)
- [Risk Scoring](#risk-scoring)
- [Safety Guarantees](#safety-guarantees)
- [Testing Methodology](#testing-methodology)
- [Burp Suite Integration](#burp-suite-integration)
- [BOLA / BFLA Testing Guide](#bola--bfla-testing-guide)
- [Module Reference](#module-reference)
- [FAQ](#faq)

---

## Architecture

```
authz_diff_mapper.py
├── TargetNormalizer        — URL normalization & scheme validation
├── EndpointCollector       — Gathers endpoints from file, Swagger, or discovery
├── SwaggerAnalyzer         — Parses OpenAPI 2/3, ranks high-risk endpoints
├── AuthProber              — Sends auth variants (baseline, token, context)
├── ResponseClassifier      — Classifies 401/403/200 behaviors
├── ResponseFingerprinter   — Captures hash, length, headers, snippets
├── DifferentialAnalyzer    — Compares variant vs baseline behavior
├── PathVariationModule     — Tests trailing slashes, case, versions
├── MethodBehaviorModule    — Tests GET/HEAD/OPTIONS (and POST/PUT with --dangerous-methods)
├── ContentNegotiationModule— Tests Accept, Content-Type variants
├── ResponseClustering      — Groups similar responses
├── RiskScorer              — Calculates endpoint risk scores
└── ReportGenerator         — Terminal, JSON, and Markdown reports
```

## Features

- **Zero-exploitation design** — no credential guessing, no token brute-force, no data modification
- **Safe defaults** — only GET, HEAD, OPTIONS methods; rate-limited (2 req/s default)
- **Swagger/OpenAPI analysis** — parses both Swagger 2.0 and OpenAPI 3.x
- **Auth variant probing** — 13+ baseline auth header variants per endpoint
- **Token testing** — supports user-owned Bearer tokens with custom headers & context
- **Path variation testing** — trailing slash, double slash, uppercase, encoded slash,
  dot segments, extension variants, API version prefixes
- **Content negotiation testing** — Accept, Content-Type variant behaviors
- **Response clustering** — groups by status code, body hash, classification
- **Risk scoring** — weighted scoring for high-interest authorization test candidates
- **Differential analysis** — compares every variant against baseline (no-auth)
- **Sensitive data masking** — tokens, cookies, API keys masked in reports
- **Full report output** — terminal summary, JSON, and Markdown
- **Proxy support** — Burp Suite, ZAP, or any HTTP interception proxy
- **Rate limiting** — configurable requests/second to avoid overwhelming targets

## Installation

```bash
# Clone or copy the script, then install dependencies:
pip install httpx rich pydantic PyYAML

# Verify it works:
python authz_diff_mapper.py --help
```

### Requirements

- Python 3.11+
- httpx >= 0.28.0
- rich >= 13.0.0 (recommended for terminal output)
- pydantic >= 2.0.0
- PyYAML >= 6.0

## Usage

```bash
# Basic analysis with Swagger spec, output to directory
python authz_diff_mapper.py \
    --base-url https://api.example.com \
    --swagger openapi.json \
    --output reports/

# Endpoints file + user-owned token + custom headers + proxy
python authz_diff_mapper.py \
    --base-url https://api.example.com \
    --endpoints endpoints.txt \
    --token "eyJhbGciOiJIUzI1NiIs..." \
    --header "X-Org-ID: org_123" \
    --header "X-Environment: staging" \
    --proxy http://127.0.0.1:8080 \
    --markdown

# Swagger-only analysis (no requests sent)
python authz_diff_mapper.py \
    --base-url https://api.example.com \
    --swagger https://api.example.com/openapi.json \
    --only-analyze-swagger

# Dry run with dangerous methods enabled
python authz_diff_mapper.py \
    --base-url https://api.example.com \
    --swagger swagger.json \
    --dangerous-methods \
    --dry-run

# Full analysis with context file
python authz_diff_mapper.py \
    --base-url https://api.example.com \
    --endpoints endpoints.txt \
    --token "eyJ..." \
    --context-file context.json \
    --rate 1.0 \
    --json report.json \
    --markdown report.md \
    --insecure
```

### All Options

| Flag | Description |
|------|-------------|
| `--base-url` | **(Required)** Target base URL (e.g., `https://api.example.com`) |
| `--endpoints` | File with endpoints/paths (one per line, optional `METHOD /path` format) |
| `--swagger` | Local Swagger/OpenAPI file (JSON/YAML) or URL |
| `--token` | User-owned valid Bearer token for authenticated testing |
| `--header` | Repeatable custom header (`--header "X-Org-ID: org_123"`) |
| `--context-file` | JSON file with user-owned context IDs (user_id, org_id, etc.) |
| `--methods` | HTTP methods to test (default: `GET HEAD OPTIONS`) |
| `--dangerous-methods` | Enable `POST PUT PATCH DELETE` (must be explicit) |
| `--rate` | Requests per second (default: `2.0`) |
| `--timeout` | Request timeout in seconds (default: `15.0`) |
| `--output` | Output directory for reports |
| `--json` | Export JSON report path |
| `--markdown` | Export Markdown report path |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) |
| `--insecure` | Allow invalid TLS certificates |
| `--only-analyze-swagger` | Parse and rank Swagger only — no requests sent |
| `--max-endpoints` | Safety limit on endpoints (default: `150`) |
| `--dry-run` | Show planned requests without sending |
| `--verbose`, `-v` | Enable debug logging |

## Input Examples

### Endpoints File (`example_endpoints.txt`)

```
# Comment lines are ignored
# Format: [METHOD] /path
GET /api/v1/users/me
GET /api/v1/orgs/{orgId}/members
GET /api/v1/admin/settings
```

### Context File (`example_context.json`)

```json
{
  "X-User-ID": "user_abc123",
  "X-Org-ID": "org_owned_42",
  "X-Account-ID": "acc_owned_77",
  "X-Tenant-ID": "tenant_demo_1",
  "X-Project-ID": "proj_alpha_9"
}
```

Values are sent as headers alongside the user-owned token to test context-based
authorization behavior.

## Output Interpretation

### Risk Categories

| Score | Category | Action |
|-------|----------|--------|
| 30+ | **Critical manual review** | Immediate manual testing with two owned accounts |
| 18-29 | **High manual review** | Priority manual testing |
| 10-17 | **Medium interest** | Review when critical/high done |
| 4-9 | **Low interest** | Secondary review |
| 0-3 | **Noise** | Expected behavior |

### Sample Terminal Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                 authz-diff-mapper v1.0.0              ┃
┃ Target: https://api.example.com                        ┃
┃ Tested: 45 endpoints, 680 requests                     ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

■ Critical Manual Review
┏━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃Rank┃ Method ┃ Path                          ┃ Score ┃ Key Reasons                ┃
┡━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  1 │ GET    │ /api/v1/orgs/{orgId}/members  │    31 │ orgId+members+auth changed │
│  2 │ GET    │ /api/v1/admin/roles           │    28 │ admin+role+auth bypass     │
└────┴────────┴──────────────────────────────┴───────┴────────────────────────────┘
```

### Report Fields Explained

- **Score** — Weighted risk score from multiple analysis modules
- **Baseline** — Response classification with no authentication
- **Variant** — Response classification with test auth variant
- **AUTH_STATUS_CHANGED_TO_SUCCESS** — A 401/403 changed to 200/206/302,
  indicating a potential authorization boundary gap
- **POSSIBLE_AUTH_BYPASS** — Multiple indicators suggest a condition
  where authorization may not be properly enforced
- **TOKEN_VALIDATION_DETECTED** — The endpoint distinguishes between
  missing and invalid tokens (shows token validation exists)

### False Positives

Not all interesting results are vulnerabilities. Common false positives:

1. **200 with `unauthorized` body** — The server returns 200 but the body
   denies access. This is not a bypass.
2. **Path variations returning 200** — May show a different endpoint, not
   an authorization issue.
3. **Different content types** — JSON vs HTML responses differ naturally.
4. **Rate limiting** — 429 responses can appear as behavior changes.
5. **Endpoint hidden behind different auth** — A variant might hit a public
   endpoint instead of the protected one.

## Safety Guarantees

This tool is designed with safety as a core requirement:

1. **No credential brute-force** — Only dummy/test values are sent.
2. **No token guessing** — Only `test`, `null`, `undefined` as dummy values.
3. **No password guessing** — No password fields are ever populated.
4. **No API key brute-force** — Only static test value `test`.
5. **No Basic Auth brute-force** — Only `test:test` as dummy Basic Auth.
6. **Only safe methods by default** — GET, HEAD, OPTIONS only without
   `--dangerous-methods`.
7. **No request bodies** — Dangerous methods (POST/PUT/PATCH/DELETE) are
   sent without bodies unless you explicitly add them.
8. **Rate limited** — Default 2 req/s, configurable.
9. **Sensitive value masking** — All tokens, cookies, and keys are masked
   in reports.
10. **Dry-run mode** — Plan requests before sending.

## Testing Methodology

### 401/403 Safe Testing Methodology

This tool implements the **differential response analysis** methodology:

1. **Establish baseline** — Send request with no authentication.
2. **Test dummy auth values** — Detect presence-only vs validated auth.
3. **Test valid user token** — Observe expected vs unexpected access.
4. **Test context variations** — Change org/tenant/user IDs using owned
   resources only.
5. **Test path variations** — Trailing slash, case, version prefixes.
6. **Test method variations** — HEAD vs GET, OPTIONS vs GET.
7. **Test content negotiation** — Different Accept/Content-Type.
8. **Compare, classify, cluster** — Identify behavioral anomalies.

### BOLA / BFLA Testing Guide

For testing Broken Object Level Authorization (BOLA) and Broken Function Level
Authorization (BFLA), use the tool as a reconnaissance phase:

1. Run the mapper to identify high-interest endpoints.
2. For **BOLA**: Use two user-owned accounts. Authenticate as User A, try
   to access User B's object ID (using owned resources).
3. For **BFLA**: Use a low-privilege account to attempt admin-level actions.
4. Test **tenant isolation**: Use two organizations you own, swap IDs.
5. Check **API version differences**: `/api/v1/` may behave differently
   from `/api/v2/` or `/api/internal/`.
6. Check **frontend vs backend**: What the UI blocks may still be callable
   via direct API access.

Always use resources you own for cross-account testing. Never access
third-party data.

## Burp Suite Integration

```bash
# Route traffic through Burp:
python authz_diff_mapper.py \
    --base-url https://api.example.com \
    --proxy http://127.0.0.1:8080 \
    --insecure \
    --endpoints endpoints.txt \
    --output burp_reports/
```

Burp Suite will capture all requests for manual review and modification.
Use Burp's Repeater to manually test interesting endpoints identified by
the mapper.

## Module Reference

### Target Normalizer
- Strips trailing slashes
- Adds `https://` if scheme missing
- Validates http/https scheme

### Endpoint Collector
- Reads user-provided endpoint files
- Parses Swagger/OpenAPI paths, parameters, security schemes
- Discovers safe documentation endpoints (swagger.json, openapi.json, /health, etc.)
- Enforces `--max-endpoints` safety limit

### Swagger Analyzer
- Detects OpenAPI 2 (swagger) vs OpenAPI 3 (openapi)
- Extracts security schemes (Bearer, API Key, OAuth2, etc.)
- Identifies high-risk keywords in paths and parameters
- Identifies object ID parameters for BOLA/IDOR testing
- Ranks endpoints by risk score without sending requests

### Auth Behavior Prober
Per-endpoint auth variant testing (13 variants):

| Variant | Header Value |
|---------|-------------|
| No auth | (no headers) |
| Empty Authorization | `Authorization: ` (empty) |
| Bearer test | `Authorization: Bearer test` |
| Bearer null | `Authorization: Bearer null` |
| Bearer undefined | `Authorization: Bearer undefined` |
| Basic test | `Authorization: Basic dGVzdDp0ZXN0` |
| X-Api-Key | `X-Api-Key: test` |
| X-Auth-Token | `X-Auth-Token: test` |
| X-Access-Token | `X-Access-Token: test` |
| X-User-ID | `X-User-ID: 1` |
| X-Account-ID | `X-Account-ID: 1` |
| X-Org-ID | `X-Org-ID: 1` |
| X-Tenant-ID | `X-Tenant-ID: 1` |

If `--token` provided, additional variants:
- Valid Bearer token
- Valid token + user's custom headers
- Valid token minus one custom header (privacy/context check)
- Valid token + context values

### Response Classifier

Maps each response to a classification:

| Classification | Description |
|---------------|-------------|
| `missing_auth` | 401 with "missing authorization" keywords |
| `invalid_token` | 401 with "invalid token" keywords |
| `expired_token` | 401 with "expired token" keywords |
| `insufficient_scope` | 403 with scope/permission keywords |
| `forbidden` | 403 with forbidden/denied keywords |
| `unauthenticated` | 401/403 generic auth failure |
| `unauthorized_body_with_200` | 200 response body contains denial keywords |
| `possible_success` | 200+ response without auth errors |
| `not_found` | 404 without auth indicators |
| `redirect_to_login` | Redirect to login page |
| `server_error` | 500+ errors |
| `rate_limited` | 429 responses |
| `unknown` | Unclassifiable |

### Differential Analyzer

Flags behavioral differences between baseline and variant:
- Status code changes (401/403 → 200/206/302)
- Body hash changes
- Content length changes >20%
- WWW-Authenticate header changes
- Set-Cookie header appears
- Allow header appears/changes
- CORS policy changes
- Classification changes (missing → invalid, invalid → scope)

### Path Variation Module

Tests safe path variations for high-interest endpoints:
- Trailing slash: `/path` → `/path/`
- Double slash: `/path` → `/path//`
- Uppercase: `/Path` → `path` or `/PATH`
- Encoded slash: `/path` → `/path%2f`
- Dot segment: `/path` → `/path/.`
- Dot-dot segment: `/path` → `/path/..`
- Extension: `/path` → `/path.json`
- Version prefixes: `/api/v1/`, `/api/v2/`, `/api/beta/`, `/api/internal/`,
  `/api/mobile/`, `/api/legacy/`, `/api/public/`

### Method Behavior Module

Tests alternate HTTP methods against endpoints:
- Default: GET, HEAD, OPTIONS
- With `--dangerous-methods`: POST, PUT, PATCH, DELETE (no request bodies)

### Content Negotiation Module

Tests response differences based on content negotiation headers:
- `Accept: application/json` + `Content-Type: application/json`
- `Accept: */*`
- `Accept: text/html`
- `Content-Type: application/x-www-form-urlencoded`
- `Content-Type: text/plain`

### Response Clustering

Groups all responses by classification and shows:
- Cluster label
- Count of responses
- Status codes present

### Risk Scoring

Weighted scoring system:

| Criterion | Points |
|-----------|--------|
| Sensitive keyword in path | +8 |
| Object ID parameter | +8 |
| Admin/role/permission action | +10 |
| Billing/payment/subscription keyword | +10 |
| Tenant/org/account context parameter | +8 |
| Swagger security scheme present but unexpected diff | +7 |
| 401/403 changed to 200/206/302 | +6 |
| Body changed significantly | +5 |
| Set-Cookie appeared | +5 |
| Allow header changed/appeared | +4 |
| CORS policy changed | +4 |
| Method behavior differs | +4 |
| Path normalization differs | +4 |
| Missing → invalid token | +3 |
| Invalid → insufficient scope | +3 |
| Legacy/mobile/internal version exists | +2 |

### Report Generator

Generates three output formats:
- **Terminal**: Rich-formatted tables (if `rich` installed) with risk categories
- **JSON**: Machine-readable structured report
- **Markdown**: Human-readable documentation with clusters, findings, evidence
  snippets, manual testing checklist, and recommendations

## FAQ

**Q: Is this tool a vulnerability scanner?**
A: No. It is a **behavioral analysis tool**. It does not exploit vulnerabilities,
    brute-force credentials, or modify data. It reports behavioral differences
    for manual review by authorized security researchers.

**Q: Can this tool find zero-day vulnerabilities?**
A: The tool identifies high-interest endpoints and behavioral anomalies. Whether
    those anomalies represent actual vulnerabilities requires manual verification
    by a skilled security researcher.

**Q: Does this tool send dangerous payloads?**
A: No. By default only GET, HEAD, OPTIONS are used. POST/PUT/PATCH/DELETE require
    explicit `--dangerous-methods` and even then no request bodies are sent.

**Q: How do I test BOLA/IDOR with this tool?**
A: Use the tool to identify endpoints with object IDs. Then manually test with
    two accounts you own in the same organization. Swap the object IDs between
    accounts and observe the response differences.

**Q: How do I avoid rate limiting?**
A: Use `--rate 1.0` or lower. The tool shows 429 responses in its clusters.

**Q: Can I use this without `rich`?**
A: Yes, the tool degrades gracefully to plain text terminal output.

---

## License

MIT License — Use only against targets you own or have explicit written
permission to test. Unauthorized access to computer systems is illegal
in most jurisdictions.

---

*authz-diff-mapper v1.0.0 — Authorized security testing only*
