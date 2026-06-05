#!/usr/bin/env python3
"""
authz-diff-mapper v1.0.0 — Advanced 401/403 Authorization Behavior Analysis Tool
==================================================================================
For authorized bug bounty programs and lab environments ONLY.
Do NOT use against systems you do not own or have explicit written permission to test.

License: MIT — Authorized security testing only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── Rich terminal ──────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# ── HTTP backend with fallback ─────────────────────────────────────────────────
try:
    import httpx
    HTTP_BACKEND = "httpx"
except ImportError:
    try:
        import requests  # type: ignore
        HTTP_BACKEND = "requests"
    except ImportError:
        print("[FATAL] Install httpx or requests: pip install httpx rich", file=sys.stderr)
        sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_VERSION = "1.0.0"
TOOL_UA = f"authz-diff-mapper/{TOOL_VERSION} (authorized-testing-only)"

DEFAULT_RATE = 2.0
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_ENDPOINTS = 500
DEFAULT_METHODS = ["GET", "HEAD", "OPTIONS"]
DANGEROUS_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

SAFE_DISCOVERY_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/openapi.json", "/openapi/v1.json", "/openapi/v2.json", "/openapi/v3.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/api/docs", "/swagger-ui.html", "/swagger-resources",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v3/swagger.json",
    "/health", "/status", "/api/health", "/api/status",
    "/version", "/api/version",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
]

HIGH_RISK_KEYWORDS = [
    "admin", "internal", "private", "manage", "management",
    "role", "permission", "member", "invite",
    "organization", "org", "tenant", "account",
    "billing", "invoice", "payment", "refund", "wallet",
    "coupon", "voucher", "subscription", "trial",
    "order", "document", "file", "kyc", "identity",
    "approve", "reject", "disable", "delete", "export", "import",
    "webhook", "integration", "api-key", "token", "session",
    "impersonate", "audit", "superadmin", "root",
    "elevate", "promote", "demote", "transfer", "clone",
]

OBJECT_ID_KEYWORDS = [
    "id", "userid", "accountid", "orgid", "organizationid", "tenantid",
    "projectid", "invoiceid", "orderid", "fileid", "documentid",
    "paymentid", "refundid", "memberid", "roleid", "customerid",
    "clientid", "subscriptionid", "walletid", "couponid", "voucherid",
    "teamid", "groupid", "resourceid", "objectid",
    "entityid", "itemid", "productid", "skuid",
]

BILLING_KW = {"billing", "invoice", "payment", "refund", "wallet", "coupon", "voucher", "subscription", "trial"}
ADMIN_KW = {"admin", "role", "permission", "impersonate", "superadmin", "root", "elevate", "promote", "demote"}
TENANT_KW = {"tenant", "org", "organization", "account"}

# Regex-based auth error patterns (more robust than flat keyword lists)
AUTH_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"missing\s+(authorization|auth|token|api.?key)", re.I), "missing_auth"),
    (re.compile(r"missing\s+bearer", re.I), "missing_auth"),
    (re.compile(r"no\s+(authorization|auth)\s+header", re.I), "missing_auth"),
    (re.compile(r"authorization\s+header\s+required", re.I), "missing_auth"),
    (re.compile(r"no\s+api\s*key", re.I), "missing_auth"),
    (re.compile(r"(invalid|malformed|bad)\s+token", re.I), "invalid_token"),
    (re.compile(r"token\s+(invalid|malformed|bad|rejected)", re.I), "invalid_token"),
    (re.compile(r"(expired|expiration)\s+token", re.I), "expired_token"),
    (re.compile(r"token\s+(expired|has\s+expired)", re.I), "expired_token"),
    (re.compile(r"jwt\s+expired", re.I), "expired_token"),
    (re.compile(r"insufficient\s+(scope|permissions|privilege)", re.I), "insufficient_scope"),
    (re.compile(r"scope\s+(not\s+allowed|missing|denied)", re.I), "insufficient_scope"),
    (re.compile(r"forbidden", re.I), "forbidden"),
    (re.compile(r"access\s+denied", re.I), "forbidden"),
    (re.compile(r"not\s+allowed", re.I), "forbidden"),
    (re.compile(r"permission\s+denied", re.I), "forbidden"),
    (re.compile(r"unauthorized", re.I), "unauthenticated"),
    (re.compile(r"unauthenticated", re.I), "unauthenticated"),
    (re.compile(r"(login|sign\s*in)\s+required", re.I), "unauthenticated"),
    (re.compile(r"not\s+authenticated", re.I), "unauthenticated"),
    (re.compile(r"authentication\s+required", re.I), "unauthenticated"),
]

BASELINE_PROBES: list[tuple[str, dict[str, str]]] = [
    ("no_auth",                    {}),
    ("empty_auth",                 {"Authorization": ""}),
    ("bearer_test",                {"Authorization": "Bearer test"}),
    ("bearer_null",                {"Authorization": "Bearer null"}),
    ("bearer_undefined",           {"Authorization": "Bearer undefined"}),
    ("basic_test",                 {"Authorization": "Basic dGVzdDp0ZXN0"}),
    ("x_api_key_test",             {"X-Api-Key": "test"}),
    ("x_auth_token_test",          {"X-Auth-Token": "test"}),
    ("x_access_token_test",        {"X-Access-Token": "test"}),
    ("x_user_id_1",                {"X-User-ID": "1"}),
    ("x_account_id_1",             {"X-Account-ID": "1"}),
    ("x_org_id_1",                 {"X-Org-ID": "1"}),
    ("x_tenant_id_1",              {"X-Tenant-ID": "1"}),
]

PATH_VARIATIONS: list[tuple[str, callable]] = [
    ("trailing_slash",     lambda p: p.rstrip("/") + "/"),
    ("double_slash",       lambda p: "/" if p.startswith("/") else "" + p),
    ("encoded_slash",      lambda p: p.replace("/", "%2F", 1) if p.count("/") > 1 else p),
    ("dot_segment",        lambda p: p.rstrip("/") + "/./"),
    ("dot_dot_segment",    lambda p: p.rstrip("/") + "/../"),
    ("json_extension",     lambda p: p.rstrip("/") + ".json"),
]

VERSION_ALTERNATIVES = [
    "/api/v1", "/api/v2", "/api/v3", "/api/beta",
    "/api/mobile", "/api/internal", "/api/legacy", "/api/public",
]

CONTENT_VARIANTS: list[tuple[str, dict[str, str]]] = [
    ("accept_json",       {"Accept": "application/json"}),
    ("accept_wildcard",   {"Accept": "*/*"}),
    ("accept_html",       {"Accept": "text/html"}),
    ("content_json",      {"Content-Type": "application/json"}),
    ("content_form",      {"Content-Type": "application/x-www-form-urlencoded"}),
    ("content_text",      {"Content-Type": "text/plain"}),
]

# ═══════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EndpointInfo:
    path: str
    methods: list[str] = field(default_factory=lambda: ["GET"])
    parameters: list[dict] = field(default_factory=list)
    has_object_id: bool = False
    risk_keywords: list[str] = field(default_factory=list)
    risk_score: int = 0
    source: str = "unknown"
    security_schemes: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ResponseFingerprint:
    url: str
    method: str
    probe_name: str
    status_code: int
    content_length: int
    content_type: str
    body_hash: str
    body_snippet: str
    title: str
    location: str
    has_set_cookie: bool
    www_authenticate: str
    server: str
    allow_header: str
    cors_origin: str
    cors_methods: str
    auth_classifier: str
    elapsed_ms: float
    error: str = ""


@dataclass
class DifferentialFinding:
    endpoint_path: str
    method: str
    baseline_probe: str
    variant_probe: str
    baseline_status: int
    variant_status: int
    baseline_classifier: str
    variant_classifier: str
    baseline_length: int
    variant_length: int
    delta_description: str
    risk_score: int
    notes: str
    interesting: bool = False


@dataclass
class ClusterGroup:
    key: str
    status_code: int
    classifier: str
    content_type: str
    count: int = 0
    members: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, rate: float):
        self.rate = max(0.1, rate)
        self._min_interval = 1.0 / self.rate
        self._last_call = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        sleep_time = self._min_interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
        self._last_call = time.monotonic()


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT (httpx + requests fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPClient:
    def __init__(self, timeout: float = 15.0, proxy: Optional[str] = None,
                 verify_tls: bool = True, max_retries: int = 2):
        self.timeout = timeout
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.max_retries = max_retries
        self._client = self._build()

    def _build(self):
        if HTTP_BACKEND == "httpx":
            kwargs: dict = {"timeout": self.timeout, "verify": self.verify_tls,
                            "follow_redirects": False,
                            "headers": {"User-Agent": TOOL_UA}}
            if self.proxy:
                try:
                    from httpx import URL
                    kwargs["proxy"] = self.proxy
                except ImportError:
                    kwargs["proxies"] = {"http://": self.proxy, "https://": self.proxy}
            return httpx.Client(**kwargs, limits=httpx.Limits(max_connections=10))
        else:
            import requests as req
            s = req.Session()
            s.headers["User-Agent"] = TOOL_UA
            s.verify = self.verify_tls
            if self.proxy:
                s.proxies = {"http": self.proxy, "https": self.proxy}
            return s

    def request(self, method: str, url: str, headers: Optional[dict] = None,
                allow_redirects: bool = False) -> dict:
        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                t0 = time.monotonic()
                if HTTP_BACKEND == "httpx":
                    resp = self._client.request(method, url, headers=headers or {},
                                                follow_redirects=allow_redirects)
                else:
                    resp = self._client.request(method, url, headers=headers or {},
                                                allow_redirects=allow_redirects,
                                                timeout=self.timeout)
                elapsed = (time.monotonic() - t0) * 1000
                body = resp.content[:4096]
                try:
                    body_text = body.decode("utf-8", errors="replace")
                except Exception:
                    body_text = ""
                return {"status_code": resp.status_code, "headers": dict(resp.headers),
                        "body": body_text,
                        "content_length": int(resp.headers.get("content-length", len(body))),
                        "elapsed_ms": elapsed, "error": ""}
            except Exception as exc:
                last_err = str(exc)
                if attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
        return {"status_code": 0, "headers": {}, "body": "",
                "content_length": 0, "elapsed_ms": 0.0, "error": last_err}

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# TARGET NORMALIZER
# ═══════════════════════════════════════════════════════════════════════════════

class TargetNormalizer:
    def __init__(self, base_url: str):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme '{parsed.scheme}'. Use http or https.")
        if not parsed.netloc:
            raise ValueError(f"No host in URL: {base_url}")
        path = parsed.path.rstrip("/")
        self.base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

    def join(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base + path


# ═══════════════════════════════════════════════════════════════════════════════
# SWAGGER ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class SwaggerAnalyzer:
    def __init__(self, spec: dict):
        self.spec = spec
        self.version = self._detect()
        self.security_schemes = self._extract_schemes()

    def _detect(self) -> int:
        if "openapi" in self.spec:
            try: return int(str(self.spec["openapi"]).split(".")[0])
            except: return 3
        return 2 if "swagger" in self.spec else 3

    def _extract_schemes(self) -> list[str]:
        sec = (self.spec.get("components", {}).get("securitySchemes", {})
               if self.version == 3 else self.spec.get("securityDefinitions", {}))
        return [f"{n}({s.get('type','?')})" for n, s in sec.items()]

    def _score(self, path: str, methods: list[str], params: list[dict]) -> tuple[int, list[str], bool]:
        score, matched, has_id = 0, [], False
        pl = path.lower()
        segs = set(re.split(r"[/_\-{}]", pl))
        segs.discard("")
        for kw in HIGH_RISK_KEYWORDS:
            if kw in segs or kw in pl:
                if kw in BILLING_KW: score += 10
                elif kw in ADMIN_KW: score += 10
                elif kw in TENANT_KW: score += 8
                else: score += 8
                matched.append(kw)
        for p in re.findall(r"\{([^}]+)\}", path):
            if p.lower().replace("_", "").replace("-", "") in OBJECT_ID_KEYWORDS:
                score += 8; has_id = True; matched.append(f"param:{p}")
        for p in params:
            pn = (str(p.get("name", ""))).lower().replace("_", "").replace("-", "")
            if pn in OBJECT_ID_KEYWORDS:
                score += 8; has_id = True; matched.append(f"qparam:{p.get('name')}")
        if self.security_schemes: score += 7
        for m in methods:
            if m.upper() in ("DELETE", "PUT", "PATCH"): score += 3
        for va in VERSION_ALTERNATIVES:
            if va.rstrip("/") in pl: score += 2
        return score, list(dict.fromkeys(matched)), has_id

    def extract(self) -> list[EndpointInfo]:
        endpoints = []
        for path, item in self.spec.get("paths", {}).items():
            if not isinstance(item, dict): continue
            methods, params = [], []
            params.extend(item.get("parameters", []))
            for m in ("get", "post", "put", "patch", "delete", "head", "options"):
                op = item.get(m)
                if not op: continue
                methods.append(m.upper())
                params.extend(op.get("parameters", []))
                for ct, sw in op.get("requestBody", {}).get("content", {}).items():
                    for pn in sw.get("schema", {}).get("properties", {}):
                        params.append({"name": pn, "in": "body"})
            score, kws, hid = self._score(path, methods, params)
            endpoints.append(EndpointInfo(path=path, methods=methods or ["GET"],
                             parameters=params[:20], has_object_id=hid,
                             risk_keywords=kws, risk_score=score, source="swagger",
                             security_schemes=self.security_schemes,
                             notes=", ".join(kws[:5])))
        endpoints.sort(key=lambda e: e.risk_score, reverse=True)
        return endpoints

    @staticmethod
    def load(path_or_url: str, client: HTTPClient) -> "SwaggerAnalyzer":
        if path_or_url.startswith("http"):
            resp = client.request("GET", path_or_url)
            if resp["status_code"] != 200:
                raise ValueError(f"HTTP {resp['status_code']} fetching {path_or_url}")
            spec = json.loads(resp["body"])
        else:
            with open(path_or_url, encoding="utf-8") as f:
                spec = json.load(f)
        return SwaggerAnalyzer(spec)


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class EndpointCollector:
    def __init__(self, normalizer: TargetNormalizer, client: HTTPClient):
        self.normalizer = normalizer
        self.client = client

    def from_file(self, path: str) -> list[str]:
        result = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith("/"): line = "/" + line
                    result.append(line)
        logging.info("Loaded %d endpoints from %s", len(result), path)
        return result

    def discover(self, rate_limiter: RateLimiter) -> list[str]:
        found = []
        for p in SAFE_DISCOVERY_PATHS:
            rate_limiter.wait()
            resp = self.client.request("GET", self.normalizer.join(p))
            if resp["status_code"] in (200, 401, 403):
                found.append(p)
        logging.info("Discovery: %d endpoints found", len(found))
        return found


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE CLASSIFIER (regex-based)
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseClassifier:
    @staticmethod
    def classify(status: int, body: str, headers: dict) -> str:
        if status == 0: return "connection_error"
        loc = headers.get("location", "").lower()
        if status in (301, 302, 303, 307, 308):
            return "redirect_to_login" if any(k in loc for k in ("login","signin","auth","oauth","sso")) else "redirect"
        if status == 405: return "method_not_allowed"
        if status == 404: return "not_found"
        if status == 429: return "rate_limited"
        if status >= 500: return "server_error"
        bl = body.lower()
        if 200 <= status < 300:
            for pat, _ in AUTH_ERROR_PATTERNS:
                if pat.search(bl): return "unauthorized_body_with_200"
            return "possible_success"
        if status in (401, 403):
            for pat, cls_ in AUTH_ERROR_PATTERNS:
                if pat.search(bl): return cls_
            return "unauthenticated" if status == 401 else "forbidden"
        if status == 206: return "possible_success"
        return "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# SENSITIVE DATA SCRUBBER
# ═══════════════════════════════════════════════════════════════════════════════

def scrub_sensitive(text: str) -> str:
    text = re.sub(r"(Bearer\s+)[A-Za-z0-9\-_\.\/+]+", r"\1[REDACTED]", text)
    text = re.sub(r"(api[_\-]?key[\"'\s:=]+)[A-Za-z0-9\-_]{16,}", r"\1[REDACTED]", text, flags=re.I)
    text = re.sub(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "[JWT_REDACTED]", text)
    text = re.sub(r"(token[\"'\s:=]+)[A-Za-z0-9\-_\.]{20,}", r"\1[REDACTED]", text, flags=re.I)
    return text


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE FINGERPRINTER
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseFingerprinter:
    @staticmethod
    def fingerprint(url: str, method: str, probe_name: str, resp: dict) -> ResponseFingerprint:
        hdrs = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        body = resp.get("body", "") or ""
        status = resp.get("status_code", 0)
        ct = hdrs.get("content-type", "")
        cl = resp.get("content_length", len(body.encode("utf-8")))
        bh = hashlib.sha256(body[:2048].encode("utf-8", errors="replace")).hexdigest()[:16]
        title = (m.group(1).strip()[:80] if (m := re.search(r"<title[^>]*>(.*?)</title>", body, re.I|re.S)) else "")
        snippet = scrub_sensitive(body[:200])
        return ResponseFingerprint(url=url, method=method, probe_name=probe_name,
            status_code=status, content_length=cl, content_type=ct[:80],
            body_hash=bh, body_snippet=snippet, title=title,
            location=hdrs.get("location", "")[:200],
            has_set_cookie="set-cookie" in hdrs,
            www_authenticate=hdrs.get("www-authenticate", "")[:200],
            server=hdrs.get("server", "")[:80],
            allow_header=hdrs.get("allow", "")[:100],
            cors_origin=hdrs.get("access-control-allow-origin", "")[:100],
            cors_methods=hdrs.get("access-control-allow-methods", "")[:100],
            auth_classifier=ResponseClassifier.classify(status, body, hdrs),
            elapsed_ms=resp.get("elapsed_ms", 0.0), error=resp.get("error", "")[:200])


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH BEHAVIOR PROBER
# ═══════════════════════════════════════════════════════════════════════════════

class AuthProber:
    def __init__(self, normalizer: TargetNormalizer, client: HTTPClient,
                 rate_limiter: RateLimiter, token: Optional[str] = None,
                 extra_hdrs: Optional[dict] = None, ctx: Optional[dict] = None,
                 dry_run: bool = False):
        self.normalizer = normalizer
        self.client = client
        self.rl = rate_limiter
        self.token = token
        self.extra_hdrs = extra_hdrs or {}
        self.ctx = ctx or {}
        self.dry_run = dry_run
        self._extra_probes: list[tuple[str, dict]] = []
        if token:
            base = {"Authorization": f"Bearer {token}"}
            base.update(self.extra_hdrs)
            self._extra_probes.append(("valid_token", dict(base)))
            for k in self.extra_hdrs:
                reduced = {kk: vv for kk, vv in base.items() if kk != k}
                self._extra_probes.append((f"token_no_{k.lower().replace('-','_')}", reduced))
            for ck, cv in self.ctx.items():
                ch = dict(base)
                ch[f"X-{ck.replace('_','-').title()}"] = str(cv)
                self._extra_probes.append((f"token_ctx_{ck}", ch))

    def probe(self, path: str, method: str = "GET") -> list[ResponseFingerprint]:
        url = self.normalizer.join(path)
        results = []
        for pname, phdrs in list(BASELINE_PROBES) + self._extra_probes:
            if self.dry_run:
                logging.info("[DRY-RUN] %s %s [%s]", method, url, pname)
                continue
            self.rl.wait()
            merged = {**self.extra_hdrs, **phdrs}
            resp = self.client.request(method, url, headers=merged)
            fp = ResponseFingerprinter.fingerprint(url, method, pname, resp)
            results.append(fp)
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# DIFFERENTIAL ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class DifferentialAnalyzer:
    @staticmethod
    def analyze(path: str, method: str, fps: list[ResponseFingerprint]) -> list[DifferentialFinding]:
        findings = []
        if not fps: return findings
        base = next((f for f in fps if f.probe_name == "no_auth"), fps[0])
        for fp in fps:
            if fp.probe_name == base.probe_name: continue
            parts, score, interesting = [], 0, False
            bs, vs = base.status_code, fp.status_code
            bc, vc = base.auth_classifier, fp.auth_classifier
            if bs in (401, 403) and vs in (200, 201, 206, 302):
                parts.append(f"Status {bs}->{vs} (auth bypass candidate)"); score += 6; interesting = True
            if bs != vs:
                parts.append(f"Status changed {bs}->{vs}"); score += 2
            if bc == "missing_auth" and vc == "invalid_token":
                parts.append("missing_auth->invalid_token (token detection)"); score += 3
            if bc == "invalid_token" and vc == "insufficient_scope":
                parts.append("invalid_token->insufficient_scope (scope diff)"); score += 3; interesting = True
            if bc != vc: parts.append(f"Classifier: {bc}->{vc}")
            if base.body_hash != fp.body_hash and vs == bs: parts.append("Body hash changed"); score += 5
            ld = abs(base.content_length - fp.content_length)
            if ld > 200 and base.content_length > 0: parts.append(f"Content-Length delta: {ld}B"); score += 5
            if fp.has_set_cookie and not base.has_set_cookie: parts.append("Set-Cookie appeared"); score += 5; interesting = True
            if fp.allow_header and not base.allow_header: parts.append(f"Allow: {fp.allow_header}"); score += 4
            if fp.www_authenticate != base.www_authenticate: parts.append("WWW-Auth changed"); score += 3
            if fp.cors_origin != base.cors_origin: parts.append(f"CORS: {fp.cors_origin}"); score += 4
            if not parts: continue
            findings.append(DifferentialFinding(endpoint_path=path, method=method,
                baseline_probe=base.probe_name, variant_probe=fp.probe_name,
                baseline_status=bs, variant_status=vs,
                baseline_classifier=bc, variant_classifier=vc,
                baseline_length=base.content_length, variant_length=fp.content_length,
                delta_description=" | ".join(parts), risk_score=score,
                notes="Manual review recommended", interesting=interesting))
        return sorted(findings, key=lambda f: f.risk_score, reverse=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PATH VARIATION MODULE
# ═══════════════════════════════════════════════════════════════════════════════

class PathVariationModule:
    @staticmethod
    def generate(path: str) -> list[tuple[str, str]]:
        variants = []
        for name, fn in PATH_VARIATIONS:
            try:
                v = fn(path)
                if v != path: variants.append((name, v))
            except: pass
        for va in VERSION_ALTERNATIVES:
            swapped = re.sub(r"/api/v\d+", va, path)
            if swapped != path: variants.append((f"version:{va.lstrip('/')}", swapped))
        return variants


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE CLUSTERER
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseClusterer:
    def __init__(self):
        self._clusters: dict[str, ClusterGroup] = {}
    def add(self, fp: ResponseFingerprint):
        ct = fp.content_type.split(";")[0].strip()[:30]
        key = f"{fp.status_code}|{fp.auth_classifier}|{ct}"
        if key not in self._clusters:
            self._clusters[key] = ClusterGroup(key=key, status_code=fp.status_code,
                                               classifier=fp.auth_classifier, content_type=ct)
        self._clusters[key].count += 1
        self._clusters[key].members.append(f"{fp.probe_name}|{fp.url}"[:80])
    def clusters(self) -> list[ClusterGroup]:
        return sorted(self._clusters.values(), key=lambda c: c.count, reverse=True)
    def rare(self, threshold: int = 5) -> list[ClusterGroup]:
        return [c for c in self.clusters() if c.count <= threshold]


# ═══════════════════════════════════════════════════════════════════════════════
# RISK SCORER
# ═══════════════════════════════════════════════════════════════════════════════

class RiskScorer:
    @staticmethod
    def assess(ep: EndpointInfo, findings: list[DifferentialFinding]) -> tuple[int, str]:
        total = ep.risk_score + sum(f.risk_score for f in findings[:5])
        if total >= 28: return total, "Critical manual review"
        if total >= 18: return total, "High manual review"
        if total >= 10: return total, "Medium interest"
        if total >= 4:  return total, "Low interest"
        return total, "Noise"

    @staticmethod
    def checklist(ep: EndpointInfo) -> list[str]:
        items = [
            f"Test {ep.path} with two separate user-owned accounts.",
            "Send User A's valid token, include User B's object ID.",
        ]
        if ep.has_object_id:
            items.append("Replace path parameter with IDs from second owned account.")
            items.append("Try incrementing/decrementing the ID using only owned IDs.")
        if any(k in ep.risk_keywords for k in TENANT_KW):
            items.append("Test X-Org-ID / X-Tenant-ID isolation with two owned orgs.")
            items.append("Send org_id of Org A while authenticated as Org B member.")
        if any(k in ep.risk_keywords for k in ADMIN_KW):
            items.append("Test member-role token against admin-only action.")
            items.append("Verify frontend hides button but API still responds.")
        if any(k in ep.risk_keywords for k in BILLING_KW):
            items.append("Test billing/payment with role lacking billing access.")
            items.append("Attempt reading another user's invoice by swapping ID.")
        items.append("Compare /api/v1/ vs /api/v2/ behavior if both exist.")
        items.append("Verify 200 response contains real data, not error body.")
        items.append("Do NOT test with third-party or production data.")
        return items


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    def __init__(self, base_url: str, endpoints: list[EndpointInfo],
                 findings: dict[str, list[DifferentialFinding]],
                 clusters: list[ClusterGroup], output_dir: Path):
        self.base_url = base_url
        self.endpoints = endpoints
        self.findings = findings
        self.clusters = clusters
        self.output_dir = output_dir
        self.ts = datetime.now(timezone.utc).isoformat()
        self._ranked: list[tuple[int, str, EndpointInfo, list[DifferentialFinding]]] = []

    def _rank(self):
        if not self._ranked:
            for ep in self.endpoints:
                key = f"{ep.methods[0]}:{ep.path}"
                f = self.findings.get(key, [])
                s, c = RiskScorer.assess(ep, f)
                self._ranked.append((s, c, ep, f))
            self._ranked.sort(key=lambda x: x[0], reverse=True)

    def terminal(self):
        self._rank()
        total_req = sum(len(v) for v in self.findings.values()) if hasattr(self.findings, 'values') else 0
        interesting = sum(1 for fv in self.findings.values() for f in fv if f.interesting)
        if RICH_AVAILABLE and console:
            console.print(Panel(f"[bold cyan]authz-diff-mapper[/] v{TOOL_VERSION}\n"
                          f"Target: [yellow]{self.base_url}[/]\nTime: {self.ts}", expand=False))
            console.print(f"Endpoints: {len(self.endpoints)} | Findings: {len(self.findings)} | Interesting: {interesting}\n")
            t = Table(title="Top Findings", header_style="bold magenta")
            t.add_column("#", width=3, justify="right")
            t.add_column("Method", width=7)
            t.add_column("Path", width=38)
            t.add_column("Score", width=5, justify="right")
            t.add_column("Delta", width=48)
            t.add_column("Base", width=12)
            t.add_column("Var", width=12)
            for rank, (sc, cat, ep, f) in enumerate(self._ranked[:20], 1):
                tf = f[0] if f else None
                color = "red" if sc >= 28 else "yellow" if sc >= 18 else "cyan"
                t.add_row(str(rank), f"[{color}]{ep.methods[0]}[/]", ep.path[:38],
                         f"[{color}]{sc}[/]",
                         (tf.delta_description[:46] if tf else ep.notes[:46]),
                         f"{tf.baseline_status} {tf.baseline_classifier}"[:12] if tf else "-",
                         f"{tf.variant_status} {tf.variant_classifier}"[:12] if tf else "-")
            console.print(t)
            ct = Table(title="Clusters", header_style="bold blue")
            ct.add_column("Cluster", width=8); ct.add_column("Status", width=6)
            ct.add_column("Classifier", width=22); ct.add_column("Count", width=6, justify="right")
            ct.add_column("Priority")
            for i, cl in enumerate(self.clusters[:12]):
                prio = "[red]HIGH[/]" if cl.count <= 5 else "[yellow]MED[/]" if cl.count <= 20 else "[dim]LOW[/]"
                ct.add_row(f"Cluster {chr(65+i)}", str(cl.status_code), cl.classifier, str(cl.count), prio)
            console.print(ct)
        else:
            print(f"\n=== authz-diff-mapper v{TOOL_VERSION} ===")
            print(f"Target: {self.base_url} | Endpoints: {len(self.endpoints)}")
            for rank, (sc, cat, ep, f) in enumerate(self._ranked[:20], 1):
                tf = f[0] if f else None
                d = tf.delta_description[:60] if tf else ep.notes[:60]
                print(f"  {rank:2d}. [{sc:3d}] {ep.methods[0]:6} {ep.path[:45]:45} | {d}")

    def export_json(self) -> Path:
        out = self.output_dir / "report.json"
        self._rank()
        data = {"meta": {"tool": f"authz-diff-mapper v{TOOL_VERSION}", "target": self.base_url,
                "timestamp": self.ts, "disclaimer": "Authorized testing only"},
                "endpoints": [{"path": e.path, "methods": e.methods, "risk_score": e.risk_score,
                               "risk_keywords": e.risk_keywords, "has_object_id": e.has_object_id,
                               "source": e.source, "notes": e.notes} for e in self.endpoints],
                "findings": [asdict(f) for fv in self.findings.values() for f in fv],
                "clusters": [asdict(c) for c in self.clusters]}
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logging.info("JSON report saved: %s", out)
        return out

    def export_markdown(self) -> Path:
        out = self.output_dir / "report.md"
        self._rank()
        lines = [
            f"# authz-diff-mapper Report\n",
            f"**Target:** `{self.base_url}`  \n**Timestamp:** {self.ts}  \n**Version:** {TOOL_VERSION}\n",
            f"> **LEGAL DISCLAIMER**: Authorized security testing only.\n",
            "---\n## Endpoint Ranking\n",
            "| # | Method | Path | Score | Category | Delta |",
            "|---|--------|------|-------|----------|-------|"]
        for rank, (sc, cat, ep, f) in enumerate(self._ranked[:30], 1):
            tf = f[0] if f else None
            d = (tf.delta_description[:60].replace("|","/") if tf else ep.notes[:60])
            lines.append(f"| {rank} | {ep.methods[0]} | `{ep.path}` | **{sc}** | {cat} | {d} |")
        lines.extend(["\n---\n## Response Clusters\n",
                      "| Cluster | Status | Classifier | Count | Priority |",
                      "|---------|--------|------------|-------|----------|"])
        for i, cl in enumerate(self.clusters[:15]):
            prio = "HIGH" if cl.count <= 5 else "MED" if cl.count <= 20 else "LOW"
            lines.append(f"| Cluster {chr(65+i)} | {cl.status_code} | {cl.classifier} | {cl.count} | {prio} |")
        lines.append("\n---\n## Manual Testing Checklist\n")
        for _, _, ep, _ in self._ranked[:10]:
            lines.append(f"\n### `{ep.path}`\n")
            lines.append(f"**Score:** {ep.risk_score} | **Keywords:** {', '.join(ep.risk_keywords[:5])}\n")
            for item in RiskScorer.checklist(ep):
                lines.append(f"- [ ] {item}")
        lines.append("\n---\n## Recommendations\n")
        lines.append("1. Prioritize Critical/High findings - test with two owned accounts.")
        lines.append("2. BOLA/IDOR: Swap object IDs between accounts on high-interest endpoints.")
        lines.append("3. BFLA: Test lower-privilege tokens against admin-labeled endpoints.")
        lines.append("4. Tenant isolation: Use two owned orgs for X-Org-ID testing.")
        lines.append("5. API versioning: Compare v1/v2/v3/beta on sensitive endpoints.")
        lines.append("6. Burp Suite: Replay interesting requests in Burp Repeater.")
        lines.append("7. False positives: Verify 200 response contains real data, not error JSON.")
        lines.append("8. Document: Screenshot, log timestamps, note test account IDs.")
        out.write_text("\n".join(lines), encoding="utf-8")
        return out


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    print(f"""
+---------------------------------------------------------------------+
|          authz-diff-mapper  v{TOOL_VERSION}                                   |
|      401/403 Auth/Authz Differential Analysis Tool                   |
+---------------------------------------------------------------------+
|  FOR AUTHORIZED BUG BOUNTY & LAB TESTING ONLY                       |
|  Do not use against systems without explicit permission.            |
+---------------------------------------------------------------------+
""")


def warn_dangerous():
    print("\nWARNING: --dangerous-methods enabled", file=sys.stderr)
    print("  POST, PUT, PATCH, DELETE will be tested.", file=sys.stderr)
    print("  These methods CAN MODIFY or DELETE data.", file=sys.stderr)
    print("  Consider --dry-run first.\n", file=sys.stderr)
    time.sleep(2)


def parse_headers(raw: list[str]) -> dict[str, str]:
    result = {}
    for h in raw:
        if ":" in h:
            k, _, v = h.partition(":")
            result[k.strip()] = v.strip()
    return result


def swagger_only_report(endpoints: list[EndpointInfo], output_dir: Path, args: argparse.Namespace):
    print(f"\n=== Swagger Analysis Only ===")
    print(f"Endpoints: {len(endpoints)}\n")
    print(f"{'Rank':4} {'Score':5} {'Methods':15} {'Path':50} {'Keywords'}")
    print("-" * 100)
    for rank, ep in enumerate(endpoints[:50], 1):
        print(f"{rank:4d} {ep.risk_score:5d} {','.join(ep.methods[:4]):15} {ep.path[:48]:50} "
              f"{'[ID]' if ep.has_object_id else ''} {','.join(ep.risk_keywords[:4])}")
    if args.json:
        out = output_dir / "swagger_analysis.json"
        data = {"tool": f"authz-diff-mapper v{TOOL_VERSION}", "mode": "swagger_only",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "endpoints": [{"rank": i+1, "path": ep.path, "methods": ep.methods,
                               "risk_score": ep.risk_score, "risk_keywords": ep.risk_keywords,
                               "has_object_id": ep.has_object_id,
                               "security_schemes": ep.security_schemes}
                              for i, ep in enumerate(endpoints)]}
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"\n[+] JSON: {out}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(prog="authz-diff-mapper",
        description="401/403 Auth/Authz Behavior Analyzer -- Authorized testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s --base-url https://api.example.com --swagger openapi.json\n"
               "  %(prog)s --base-url https://api.example.com --endpoints paths.txt --token TOKEN --markdown\n"
               "  %(prog)s --base-url https://api.example.com --swagger spec.json --only-analyze-swagger")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--endpoints")
    parser.add_argument("--swagger")
    parser.add_argument("--token")
    parser.add_argument("--header", action="append", dest="headers", default=[], metavar="H")
    parser.add_argument("--context-file")
    parser.add_argument("--methods", default="GET,HEAD,OPTIONS")
    parser.add_argument("--dangerous-methods", action="store_true")
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--proxy")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--max-endpoints", type=int, default=DEFAULT_MAX_ENDPOINTS)
    parser.add_argument("--only-analyze-swagger", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--safe-discovery", action="store_true")
    parser.add_argument("--path-variations", action="store_true")
    parser.add_argument("--output", default="reports")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    print_banner()

    methods = list(dict.fromkeys([m.strip().upper() for m in args.methods.split(",")]))
    if args.dangerous_methods:
        warn_dangerous()
        methods.extend(DANGEROUS_METHODS)
        methods = list(dict.fromkeys(methods))

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    extra_headers = parse_headers(args.headers)
    ctx = {}
    if args.context_file:
        try:
            raw = json.loads(Path(args.context_file).read_text(encoding="utf-8"))
            ctx = {k: str(v) for k, v in raw.items() if not k.startswith("_") and isinstance(v, (str, int, float))}
            logging.info("Context: %s", list(ctx.keys()))
        except Exception as e:
            logging.warning("Context file error: %s", e)

    try:
        normalizer = TargetNormalizer(args.base_url)
    except ValueError as e:
        logging.fatal("Invalid base URL: %s", e)
        sys.exit(1)

    client = HTTPClient(timeout=args.timeout, proxy=args.proxy, verify_tls=not args.insecure)
    rl = RateLimiter(args.rate)
    collector = EndpointCollector(normalizer, client)

    # ── Swagger ────────────────────────────────────────────────────────────────
    swagger_eps: list[EndpointInfo] = []
    if args.swagger:
        try:
            sa = SwaggerAnalyzer.load(args.swagger, client)
            swagger_eps = sa.extract()
            logging.info("Swagger: %d endpoints", len(swagger_eps))
        except Exception as e:
            logging.error("Swagger error: %s", e)

    if args.only_analyze_swagger:
        if not swagger_eps: logging.fatal("--only-analyze-swagger needs --swagger"); sys.exit(1)
        swagger_only_report(swagger_eps, output_dir, args)
        client.close(); return

    # ── Build endpoint set ─────────────────────────────────────────────────────
    path_map: dict[str, EndpointInfo] = {e.path: e for e in swagger_eps}
    if args.endpoints:
        try:
            for p in collector.from_file(args.endpoints):
                if p not in path_map: path_map[p] = EndpointInfo(path=p, source="file")
        except Exception as e: logging.error("Endpoints file: %s", e)

    if args.safe_discovery:
        for p in collector.discover(rl):
            if p not in path_map: path_map[p] = EndpointInfo(path=p, source="discovery")

    if not path_map:
        logging.warning("No endpoints collected. Use --endpoints, --swagger, or --safe-discovery.")
        if not args.dry_run: client.close(); return

    all_eps = list(path_map.values())
    if len(all_eps) > args.max_endpoints:
        logging.warning("Limiting to %d endpoints (--max-endpoints)", args.max_endpoints)
        all_eps = all_eps[:args.max_endpoints]
    logging.info("Testing %d endpoints", len(all_eps))

    # ── Probe ──────────────────────────────────────────────────────────────────
    prober = AuthProber(normalizer, client, rl, token=args.token,
                        extra_hdrs=extra_headers, ctx=ctx, dry_run=args.dry_run)
    clusterer = ResponseClusterer()
    all_findings: dict[str, list[DifferentialFinding]] = {}

    for idx, ep in enumerate(all_eps, 1):
        ep_methods = [m for m in ep.methods if m in methods] or [methods[0]]
        for method in ep_methods:
            key = f"{method}:{ep.path}"
            logging.info("[%d/%d] %s %s", idx, len(all_eps), method, ep.path)
            fps = prober.probe(ep.path, method)
            for fp in fps: clusterer.add(fp)
            findings = DifferentialAnalyzer.analyze(ep.path, method, fps)
            if findings and findings[0].interesting:
                logging.info("  Interesting: %s", findings[0].delta_description[:80])
            all_findings[key] = findings

            if args.path_variations and not args.dry_run:
                for vname, vpath in PathVariationModule.generate(ep.path)[:4]:
                    rl.wait()
                    vfps = prober.probe(vpath, method)
                    vkey = f"{method}:{vpath}"
                    for vfp in vfps: clusterer.add(vfp)
                    vf = DifferentialAnalyzer.analyze(vpath, method, vfps)
                    orig = fps[0] if fps else None
                    var_base = vfps[0] if vfps else None
                    if orig and var_base and orig.status_code != var_base.status_code:
                        vf.append(DifferentialFinding(endpoint_path=vpath, method=method,
                            baseline_probe="orig_path", variant_probe=vname,
                            baseline_status=orig.status_code, variant_status=var_base.status_code,
                            baseline_classifier=orig.auth_classifier,
                            variant_classifier=var_base.auth_classifier,
                            baseline_length=orig.content_length, variant_length=var_base.content_length,
                            delta_description=f"Path '{vname}' changed status {orig.status_code}->{var_base.status_code}",
                            risk_score=4, notes="Path normalization differs", interesting=True))
                    all_findings[vkey] = vf

    client.close()
    if args.dry_run: logging.info("DRY-RUN complete. No requests sent."); return

    # ── Report ─────────────────────────────────────────────────────────────────
    clusters = clusterer.clusters()
    reporter = ReportGenerator(args.base_url, all_eps, all_findings, clusters, output_dir)
    reporter.terminal()
    if args.json: print(f"\n[+] JSON: {reporter.export_json()}")
    if args.markdown: print(f"[+] Markdown: {reporter.export_markdown()}")


if __name__ == "__main__":
    main()
