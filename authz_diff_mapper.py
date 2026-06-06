#!/usr/bin/env python3
"""
authz-diff-mapper v1.1.0 — Smart Authorization Differential Analysis Tool
===========================================================================
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
import threading
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

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

TOOL_VERSION = "1.1.0"
TOOL_UA = f"authz-diff-mapper/{TOOL_VERSION} (authorized-testing-only)"

DEFAULT_RATE = 50.0
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_ENDPOINTS = 500
DEFAULT_METHODS = ["GET", "HEAD", "OPTIONS"]
DANGEROUS_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

BASE_PATHS = [
    "", "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/v4",
    "/swagger", "/swagger-ui", "/api-docs", "/apidocs",
    "/docs", "/doc", "/redoc",
    "/rest", "/rest-api", "/gateway", "/public",
    "/internal", "/service", "/services",
    "/developer", "/developers",
    "/graphql", "/graphiql", "/graphql-playground",
]

DOC_FILES = [
    "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "api-docs.json", "apidocs.json", "api.json",
    "api-merged.json", "doc.json", "docs.json",
    "index.json",
]

DOC_PATHS_FLAT = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/api-docs.json",
    "/apidocs", "/apidocs.json",
    "/docs", "/doc",
    "/docs/api-docs", "/docs/api-docs.json", "/docs/apidocs", "/docs/apidocs.json",
    "/docs/swagger.json", "/docs/openapi.json",
    "/api/docs/api-docs", "/api/docs/api-docs.json",
    "/api/docs/swagger.json", "/api/docs/openapi.json",
    "/swagger-resources",
    "/swagger-resources.json",
    "/swagger-ui.html",
    "/application.wadl",
    "/application.wadl?detail=true",
]

WADL_PATHS = [
    "/application.wadl",
    "/application.wadl?detail=true",
    "/application.wadl?format=xml",
    "/application.wadl.xml",
]

SWAGGER_UI_FILES = [
    "swagger-ui-bundle.html", "swagger-ui-bundle.js",
    "swagger-ui-es-bundle-core.html", "swagger-ui-es-bundle-core.js",
    "swagger-ui-es-bundle.html", "swagger-ui-es-bundle.js",
    "swagger-ui.html", "swagger-ui-init.html", "swagger-ui-init.js",
    "swagger-ui.js", "swagger-ui.json",
    "swagger-ui-layout.html", "swagger-ui-layout.js",
    "swagger-ui.min.js", "swagger-ui-plugins.html", "swagger-ui-plugins.js",
    "swagger-ui-standalone-preset.html", "swagger-ui-standalone-preset.js",
]

SWAGGER_CONFIG_FILES = [
    "swagger-config", "swagger-config.json", "swagger-config.html",
]

DOC_DIR_NAMES = [
    "swagger", "swagger-ui", "swagger-config",
    "api-docs", "apidocs", "docs", "doc",
    "openapi", "redoc",
    "v1", "v2", "v3", "v4",
]

DOC_RESOURCE_NAMES = [
    "swagger", "swagger-config", "swagger-resources",
    "api-docs", "apidocs", "docs", "doc",
    "openapi", "api", "api-merged",
    "apispec", "apispec_1",
]


def generate_discovery_paths() -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []

    def add(p: str):
        if p not in seen:
            seen.add(p)
            paths.append(p)

    # Flat / well-known paths
    for p in DOC_PATHS_FLAT:
        add(p)

    # /BASE/DOC_FILE combinations
    for base in BASE_PATHS:
        df = base.rstrip("/")
        for fname in DOC_FILES:
            add(f"/{fname}" if not base else f"{df}/{fname}")
        for ui in SWAGGER_UI_FILES:
            add(f"{df}/{ui}")
        for cf in SWAGGER_CONFIG_FILES:
            add(f"{df}/{cf}")

    # Deeper permutations: /api-docs/v1/swagger.json etc.
    for doc_dir in ["api-docs", "apidocs", "docs", "doc", "swagger", "swagger-ui"]:
        for ver in ["v1", "v2", "v3", "v4", "latest", "static"]:
            b = f"/{doc_dir}/{ver}"
            for fname in DOC_FILES + SWAGGER_UI_FILES + SWAGGER_CONFIG_FILES:
                add(f"{b}/{fname}")
            for sub in DOC_RESOURCE_NAMES:
                for fname in DOC_FILES + SWAGGER_UI_FILES + SWAGGER_CONFIG_FILES:
                    add(f"{b}/{sub}/{fname}")
                    for ver2 in ["v1", "v2", "v3"]:
                        add(f"{b}/{sub}/{ver2}/{fname}")

    # WADL paths with internal/system variants
    for w in WADL_PATHS:
        add(w)
        prefix = w.lstrip("/")
        for loc in ["api", "rest", "service", "webresources"]:
            add(f"/{loc}/{prefix}")
            for scope in ["internal", "system"]:
                add(f"/{loc}/{scope}/{prefix}")
                add(f"/{scope}/{prefix}")

    # GraphQL introspection endpoints
    gql_paths = ["/graphql", "/graphiql", "/graphql-playground",
                 "/graphql-console", "/graphql-explorer", "/graphql-browser",
                 "/graphql-dev", "/graphql-api"]
    gql_suffixes = [
        "", "/internal", "/system", "/v1", "/v2", "/v3", "/v4", "/v5",
        "/schema", "/schema/internal", "/schema/system",
        "/schema/v1", "/schema/v2",
    ]
    for gp in gql_paths:
        for gs in gql_suffixes:
            add(f"{gp}{gs}")
    # GraphQL introspection query
    add("/graphql?query=query+IntrospectionQuery{__schema{types{name,fields{name}}}}")
    add("/graphql?query={__schema{types{name}}}")

    # .well-known
    add("/.well-known/openid-configuration")
    add("/.well-known/oauth-authorization-server")
    add("/.well-known/openapi.json")
    add("/.well-known/openapi.html")
    add("/.well-known/openapi.yaml")

    # Health / status / version
    for base in ["", "/api", "/api/v1", "/api/v2", "/v1", "/v2"]:
        for suffix in ["/health", "/status", "/version", "/ping"]:
            add(f"{base}{suffix}")

    # Common API discovery hits
    add("/api")
    add("/api/")
    add("/api/v1")
    add("/v1")

    return paths


COMPREHENSIVE_DISCOVERY_PATHS = generate_discovery_paths()
logging.info("Generated %d discovery paths", len(COMPREHENSIVE_DISCOVERY_PATHS))

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
    (re.compile(r"api\s*key\s*(required|missing|invalid)", re.I), "api_key_required"),
    (re.compile(r"x-api-key", re.I), "api_key_required"),
    (re.compile(r"x-auth-token", re.I), "x_auth_token"),
    (re.compile(r"x-access-token", re.I), "x_access_token"),
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
    ("trailing_slash",     lambda p: p.rstrip("/") + "/" if p != "/" else p),
    ("double_slash",       lambda p: "/" + p.lstrip("/")),
    ("encoded_slash",      lambda p: p.replace("/", "%2F", 1) if p.count("/") > 1 else p),
    ("dot_segment",        lambda p: p.rstrip("/") + "/./"),
    ("dot_dot_segment",    lambda p: p.rstrip("/") + "/../" if p != "/" else p),
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
# SMART AUTH DETECTOR — analyzes 401/403 to infer expected auth scheme
# ═══════════════════════════════════════════════════════════════════════════════

class SmartAuthDetector:
    @staticmethod
    def detect(fp: ResponseFingerprint) -> dict[str, Any]:
        scheme: dict[str, Any] = {
            "primary_scheme": "unknown",
            "header_hint": "",
            "body_hint": "",
            "expected_header": "",
            "expected_prefix": "",
            "confidence": 0.0,
        }
        if fp.status_code not in (401, 403):
            return scheme

        www_auth = fp.www_authenticate.lower()
        body_lower = fp.body_snippet.lower() if fp.body_snippet else ""

        # WWW-Authenticate header analysis
        if "bearer" in www_auth:
            scheme["primary_scheme"] = "bearer_token"
            scheme["header_hint"] = "WWW-Authenticate: Bearer"
            scheme["expected_header"] = "Authorization"
            scheme["expected_prefix"] = "Bearer"
            scheme["confidence"] = 0.9
        elif "basic" in www_auth:
            scheme["primary_scheme"] = "basic_auth"
            scheme["header_hint"] = "WWW-Authenticate: Basic"
            scheme["expected_header"] = "Authorization"
            scheme["expected_prefix"] = "Basic"
            scheme["confidence"] = 0.9
        elif "digest" in www_auth:
            scheme["primary_scheme"] = "digest_auth"
            scheme["header_hint"] = "WWW-Authenticate: Digest"
            scheme["expected_header"] = "Authorization"
            scheme["expected_prefix"] = "Digest"
            scheme["confidence"] = 0.8
        elif "negotiate" in www_auth or "ntlm" in www_auth:
            scheme["primary_scheme"] = "negotiate_auth"
            scheme["header_hint"] = www_auth[:50]
            scheme["confidence"] = 0.7
        elif www_auth:
            scheme["primary_scheme"] = f"custom({fp.www_authenticate[:60]})"
            scheme["header_hint"] = fp.www_authenticate[:80]
            scheme["confidence"] = 0.5

        # Body content analysis
        if scheme["confidence"] < 0.5:
            if re.search(r"bearer\s+token", body_lower):
                scheme["primary_scheme"] = "bearer_token"
                scheme["expected_header"] = "Authorization"
                scheme["expected_prefix"] = "Bearer"
                scheme["body_hint"] = "body mentions bearer token"
                scheme["confidence"] = 0.7
            elif re.search(r"api\s*key", body_lower):
                scheme["primary_scheme"] = "api_key"
                scheme["body_hint"] = "body mentions api key"
                scheme["expected_header"] = "X-Api-Key"
                scheme["confidence"] = 0.7
            elif re.search(r"(access|auth)\s*token", body_lower):
                scheme["primary_scheme"] = "access_token"
                scheme["expected_header"] = "Authorization"
                scheme["expected_prefix"] = "Bearer"
                scheme["body_hint"] = "body mentions access/auth token"
                scheme["confidence"] = 0.6
            elif re.search(r"x-api-key", body_lower):
                scheme["primary_scheme"] = "api_key"
                scheme["expected_header"] = "X-Api-Key"
                scheme["body_hint"] = "body references X-Api-Key"
                scheme["confidence"] = 0.8
            elif re.search(r"x-auth-token", body_lower):
                scheme["primary_scheme"] = "x_auth_token"
                scheme["expected_header"] = "X-Auth-Token"
                scheme["body_hint"] = "body references X-Auth-Token"
                scheme["confidence"] = 0.7
            elif re.search(r"(jwt|json web token)", body_lower):
                scheme["primary_scheme"] = "jwt"
                scheme["expected_header"] = "Authorization"
                scheme["expected_prefix"] = "Bearer"
                scheme["body_hint"] = "body mentions JWT"
                scheme["confidence"] = 0.7
            elif re.search(r"(session.*(timed? out|invalid|expire))", body_lower):
                scheme["primary_scheme"] = "session_cookie"
                scheme["expected_header"] = "Cookie"
                scheme["body_hint"] = "body mentions expired/invalid session"
                scheme["confidence"] = 0.7
            elif re.search(r"(login|signin|password)", body_lower):
                scheme["primary_scheme"] = "form_login"
                scheme["body_hint"] = "body mentions login/signin"
                scheme["confidence"] = 0.4

        # If still unknown, check status code
        if scheme["confidence"] < 0.3:
            if fp.status_code == 401:
                scheme["primary_scheme"] = "generic_bearer"
                scheme["expected_header"] = "Authorization"
                scheme["expected_prefix"] = "Bearer"
                scheme["confidence"] = 0.3

        return scheme

    @staticmethod
    def generate_probes(scheme: dict[str, Any]) -> list[tuple[str, dict[str, str]]]:
        probes: list[tuple[str, dict[str, str]]] = []
        s = scheme.get("primary_scheme", "unknown")
        hdr = scheme.get("expected_header", "")
        prefix = scheme.get("expected_prefix", "")

        if s == "bearer_token":
            for val in ["test", "null", "undefined", "0", "1", "true", "false",
                        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test",
                        "admin", "guest", "invalid"]:
                probes.append((f"smart_bearer_{val}", {"Authorization": f"Bearer {val}"}))
        elif s in ("session_cookie", "form_login"):
            # Session/cookie-based auth: try empty session, common values, and Bearer as fallback
            for val in ["", "null", "undefined", "guest", "admin", "test", "1"]:
                probes.append((f"smart_cookie_{val or 'empty'}", {"Cookie": f"session={val}"}))
            for val in ["", "null", "undefined"]:
                probes.append((f"smart_cookie2_{val or 'empty'}", {"Cookie": f"token={val}"}))
            probes.append(("smart_cookie_remove", {"Cookie": ""}))
        elif s == "basic_auth":
            for cred in ["dGVzdDp0ZXN0", "YWRtaW46YWRtaW4=", "dXNlcjpwYXNz", "Z3Vlc3Q6Z3Vlc3Q="]:
                probes.append((f"smart_basic_{cred[:8]}", {"Authorization": f"Basic {cred}"}))
        elif s == "api_key":
            for val in ["test", "null", "undefined", "admin", "guest", "1", "true"]:
                probes.append((f"smart_apikey_{val}", {hdr or "X-Api-Key": val}))
        elif s == "x_auth_token":
            for val in ["test", "null", "undefined", "admin", "guest", "1"]:
                probes.append((f"smart_xauthtoken_{val}", {hdr or "X-Auth-Token": val}))
        elif s == "x_access_token":
            for val in ["test", "null", "undefined", "admin", "1"]:
                probes.append((f"smart_xaccesstoken_{val}", {hdr or "X-Access-Token": val}))
        elif hdr:
            for val in ["test", "null", "undefined", "admin", "guest", "1"]:
                probes.append((f"smart_{s}_{val}", {hdr: f"{prefix} {val}".strip() if prefix else val}))
        else:
            for val in ["test", "null", "undefined", "admin", "1"]:
                probes.append((f"smart_bearer_{val}", {"Authorization": f"Bearer {val}"}))

        return probes


# ═══════════════════════════════════════════════════════════════════════════════
# API DOC DISCOVERER — probes for Swagger/OpenAPI/WADL automatically
# ═══════════════════════════════════════════════════════════════════════════════

class ApiDocDiscoverer:
    SWAGGER_INDICATORS = [
        b'"openapi"', b'"swagger"', b'"paths"', b'"info"', b'"swaggerVersion"',
        b'"apiVersion"', b'"definitions"', b'"components"',
    ]
    WADL_INDICATORS = [b'<application', b'<resources', b'<resource', b'<method']
    GRAPHQL_INDICATORS = [b'"data"', b'"__schema"', b'"__typename"', b'"queryType"']

    def __init__(self, client: HTTPClient, normalizer: TargetNormalizer,
                 rate_limiter: RateLimiter):
        self.client = client
        self.normalizer = normalizer
        self.rl = rate_limiter
        self.discovered_docs: list[dict[str, Any]] = []

    def discover(self, max_paths: int = 2000) -> list[dict[str, Any]]:
        paths = COMPREHENSIVE_DISCOVERY_PATHS[:max_paths]
        logging.info("Discovering API docs: probing %d paths", len(paths))
        found: list[dict[str, Any]] = []

        # Probe the base URL itself first (might be the API doc endpoint)
        self.rl.wait()
        root_resp = self.client.request("GET", self.normalizer.join(""))
        root_body = (root_resp.get("body", "") or "").encode("utf-8", errors="replace")
        root_ct = (root_resp.get("headers", {}) or {}).get("content-type", "").lower()
        if root_resp["status_code"] == 200:
            root_type = self._detect_doc_type(root_body, root_ct, "")
            if root_type:
                found.append({
                    "path": "", "status": 200, "content_type": root_ct,
                    "type": root_type, "body": root_resp.get("body", "") or "",
                    "headers": root_resp.get("headers", {}) or {},
                })
                logging.info("  [%s] (base URL itself)", root_type)
                if root_type in ("openapi", "swagger"):
                    self.discovered_docs.append(found[-1])
                    return found  # Found it at root, no need to probe more

        for p in paths:
            self.rl.wait()
            resp = self.client.request("GET", self.normalizer.join(p))
            status = resp["status_code"]
            body = resp.get("body", "") or ""
            ct = (resp.get("headers", {}) or {}).get("content-type", "").lower()
            raw_body = body.encode("utf-8", errors="replace")
            headers = resp.get("headers", {}) or {}

            if status not in (200, 401, 403, 206):
                continue

            doc_type = self._detect_doc_type(raw_body, ct, p)
            if doc_type:
                entry = {
                    "path": p,
                    "status": status,
                    "content_type": ct,
                    "type": doc_type,
                    "body": body if status == 200 else "",
                    "headers": headers,
                }
                found.append(entry)
                logging.info("  [%s] %s (status=%d)", doc_type, p, status)
                if doc_type in ("openapi", "swagger") and status == 200:
                    self.discovered_docs.append(entry)

        logging.info("Discovery complete: %d docs found", len(found))
        return found

    def _detect_doc_type(self, raw_body: bytes, content_type: str, path: str) -> str:
        pl = path.lower()
        if any(indicator in raw_body for indicator in self.SWAGGER_INDICATORS):
            if b'"openapi"' in raw_body:
                return "openapi"
            return "swagger"
        if any(indicator in raw_body for indicator in self.WADL_INDICATORS):
            return "wadl"
        if any(indicator in raw_body for indicator in self.GRAPHQL_INDICATORS) or \
           "graphql" in path.lower():
            return "graphql"
        if "json" in content_type and pl.endswith(".json"):
            return "json_doc"
        if "yaml" in content_type or pl.endswith((".yaml", ".yml")):
            return "yaml_doc"
        if "wadl" in content_type or pl.endswith(".wadl"):
            return "wadl"
        if "html" in content_type and (
            "swagger" in pl or "api-doc" in pl or "redoc" in pl or "doc" in pl
        ):
            return "html_doc"
        return ""

    def parse_swagger(self, entry: dict) -> Optional["SwaggerAnalyzer"]:
        try:
            body = entry.get("body", "")
            if not body:
                return None
            spec = json.loads(body)
            sa = SwaggerAnalyzer(spec)
            logging.info("Parsed swagger: %d paths, %d schemes",
                         len(spec.get("paths", {})), len(sa.security_schemes))
            return sa
        except Exception as e:
            logging.debug("Swagger parse failed for %s: %s", entry.get("path", ""), e)
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, rate: float, adaptive: bool = True):
        self._base_rate = max(0.5, rate)
        self._min_interval = 1.0 / self._base_rate
        self._current_interval = self._min_interval
        self._last_call: float = 0.0
        self._lock = threading.Lock()
        self._adaptive = adaptive
        self._errors: list[float] = []
        self._window = 10.0  # seconds

    def wait(self, ok: bool = True) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            sleep_time = self._current_interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            self._last_call = time.monotonic()

            if not self._adaptive:
                return

            # Adaptive: track errors in sliding window
            cutoff = now - self._window
            self._errors = [t for t in self._errors if t > cutoff]
            if not ok:
                self._errors.append(now)

            err_ratio = len(self._errors) / max(1, self._window / self._current_interval)
            if err_ratio > 0.3:
                self._current_interval = min(self._current_interval * 1.5, 10.0)
            elif err_ratio < 0.05 and self._current_interval > self._min_interval:
                self._current_interval = max(self._current_interval * 0.9, self._min_interval)

    def report(self, status_code: int) -> None:
        self.wait(ok=status_code not in (0, 429, 503, 502, 504))


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT (httpx + requests fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPClient:
    def __init__(self, timeout: float = 15.0, proxy: Optional[str] = None,
                 verify_tls: bool = True, max_retries: int = 2,
                 rate_limiter: Optional[RateLimiter] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.max_retries = max_retries
        self.rl = rate_limiter
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
                # Full body for swagger parsing; truncated copy for fingerprinting
                body = resp.content[:2097152]
                try:
                    body_text = body.decode("utf-8", errors="replace")
                except Exception:
                    body_text = ""
                if self.rl:
                    self.rl.report(resp.status_code)
                return {"status_code": resp.status_code, "headers": dict(resp.headers),
                        "body": body_text,
                        "content_length": int(resp.headers.get("content-length", len(body))),
                        "elapsed_ms": elapsed, "error": ""}
            except Exception as exc:
                last_err = str(exc)
                if self.rl:
                    self.rl.report(0)
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
            try:
                return int(str(self.spec["openapi"]).split(".")[0])
            except Exception:
                return 3
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
                if kw in BILLING_KW:
                    score += 10
                elif kw in ADMIN_KW:
                    score += 10
                elif kw in TENANT_KW:
                    score += 8
                else:
                    score += 8
                matched.append(kw)
        for p in re.findall(r"\{([^}]+)\}", path):
            if p.lower().replace("_", "").replace("-", "") in OBJECT_ID_KEYWORDS:
                score += 8
                has_id = True
                matched.append(f"param:{p}")
        for p in params:
            pn = (str(p.get("name", ""))).lower().replace("_", "").replace("-", "")
            if pn in OBJECT_ID_KEYWORDS:
                score += 8
                has_id = True
                matched.append(f"qparam:{p.get('name')}")
        if self.security_schemes:
            score += 7
        for m in methods:
            if m.upper() in ("DELETE", "PUT", "PATCH"):
                score += 3
        for va in VERSION_ALTERNATIVES:
            if va.rstrip("/") in pl:
                score += 2
        return score, list(dict.fromkeys(matched)), has_id

    def extract(self) -> list[EndpointInfo]:
        endpoints = []
        for path, item in self.spec.get("paths", {}).items():
            if not isinstance(item, dict):
                continue
            methods, params = [], []
            params.extend(item.get("parameters", []))
            for m in ("get", "post", "put", "patch", "delete", "head", "options"):
                op = item.get(m)
                if not op:
                    continue
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
                    if not line.startswith("/"):
                        line = "/" + line
                    result.append(line)
        logging.info("Loaded %d endpoints from %s", len(result), path)
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE CLASSIFIER (regex-based)
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseClassifier:
    @staticmethod
    def classify(status: int, body: str, headers: dict) -> str:
        if status == 0:
            return "connection_error"
        loc = headers.get("location", "").lower()
        if status in (301, 302, 303, 307, 308):
            return "redirect_to_login" if any(k in loc for k in ("login", "signin", "auth", "oauth", "sso")) else "redirect"
        if status == 405:
            return "method_not_allowed"
        if status == 404:
            return "not_found"
        if status == 429:
            return "rate_limited"
        if status >= 500:
            return "server_error"
        bl = body.lower()
        if 200 <= status < 300:
            for pat, _ in AUTH_ERROR_PATTERNS:
                if pat.search(bl):
                    return "unauthorized_body_with_200"
            return "possible_success"
        if status in (401, 403):
            for pat, cls_ in AUTH_ERROR_PATTERNS:
                if pat.search(bl):
                    return cls_
            return "unauthenticated" if status == 401 else "forbidden"
        if status == 206:
            return "possible_success"
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
        title = (m.group(1).strip()[:80] if (m := re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)) else "")
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
                 dry_run: bool = False, smart_detect: bool = False):
        self.normalizer = normalizer
        self.client = client
        self.rl = rate_limiter
        self.token = token
        self.extra_hdrs = extra_hdrs or {}
        self.ctx = ctx or {}
        self.dry_run = dry_run
        self.smart_detect = smart_detect
        self._extra_probes: list[tuple[str, dict]] = []
        if token:
            base_d = {"Authorization": f"Bearer {token}"}
            base_d.update(self.extra_hdrs)
            self._extra_probes.append(("valid_token", dict(base_d)))
            for k in self.extra_hdrs:
                reduced = {kk: vv for kk, vv in base_d.items() if kk != k}
                self._extra_probes.append((f"token_no_{k.lower().replace('-','_')}", reduced))
            for ck, cv in self.ctx.items():
                ch = dict(base_d)
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

    def probe_smart(self, path: str, method: str = "GET",
                    first_pass_fps: Optional[list[ResponseFingerprint]] = None) -> list[ResponseFingerprint]:
        if not self.smart_detect:
            return self.probe(path, method)

        url = self.normalizer.join(path)
        results = list(first_pass_fps) if first_pass_fps else []

        if not results:
            # Do a minimal first probe to detect auth scheme
            for pname, phdrs in [("no_auth", {}), ("bearer_test", {"Authorization": "Bearer test"})]:
                self.rl.wait()
                merged = {**self.extra_hdrs, **phdrs}
                resp = self.client.request(method, url, headers=merged)
                fp = ResponseFingerprinter.fingerprint(url, method, pname, resp)
                results.append(fp)
            first_pass_fps = results

        # Use the first probe's response to detect auth scheme
        probe_fp = first_pass_fps[0] if first_pass_fps else results[0] if results else None
        if not probe_fp or probe_fp.status_code not in (401, 403):
            if not first_pass_fps:
                for pname, phdrs in BASELINE_PROBES:
                    if self.dry_run:
                        continue
                    self.rl.wait()
                    merged = {**self.extra_hdrs, **phdrs}
                    resp = self.client.request(method, url, headers=merged)
                    fp = ResponseFingerprinter.fingerprint(url, method, pname, resp)
                    results.append(fp)
            return results

        scheme = SmartAuthDetector.detect(probe_fp)
        logging.debug("Smart auth detected for %s %s: %s (confidence=%.1f)",
                      method, path, scheme["primary_scheme"], scheme["confidence"])

        smart_probes = SmartAuthDetector.generate_probes(scheme)
        seen_names = {r.probe_name for r in results}
        for pname, phdrs in smart_probes:
            if pname in seen_names:
                continue
            seen_names.add(pname)
            if self.dry_run:
                logging.info("[DRY-RUN] %s %s [%s]", method, url, pname)
                continue
            self.rl.wait()
            merged = {**self.extra_hdrs, **phdrs}
            resp = self.client.request(method, url, headers=merged)
            fp = ResponseFingerprinter.fingerprint(url, method, pname, resp)
            results.append(fp)

        # Also add standard probes that weren't in first_pass
        for pname, phdrs in list(BASELINE_PROBES) + self._extra_probes:
            if pname in seen_names:
                continue
            seen_names.add(pname)
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
    SUCCESS_STATUSES = {200, 201, 204}
    PROTECTED_CLASSIFIERS = {"unauthenticated", "missing_auth", "invalid_token", "forbidden"}

    @staticmethod
    def analyze(path: str, method: str, fps: list[ResponseFingerprint]) -> list[DifferentialFinding]:
        findings = []
        if not fps:
            return findings
        base = next((f for f in fps if f.probe_name == "no_auth"), fps[0])

        # Check if the endpoint is completely unprotected (no auth needed)
        if base.status_code in DifferentialAnalyzer.SUCCESS_STATUSES:
            auth_words = ["login", "signin", "session", "password", "token", "auth"]
            body_lower = (base.body_snippet or "").lower()
            if not any(w in body_lower for w in auth_words):
                findings.append(DifferentialFinding(
                    endpoint_path=path, method=method,
                    baseline_probe=base.probe_name, variant_probe="",
                    baseline_status=base.status_code, variant_status=base.status_code,
                    baseline_classifier=base.auth_classifier or "", variant_classifier="",
                    baseline_length=base.content_length, variant_length=base.content_length,
                    delta_description="Baseline returns success without auth",
                    risk_score=8,
                    notes="Endpoint accessible without authentication",
                    interesting=True
                ))

        for fp in fps:
            if fp.probe_name == base.probe_name:
                continue
            parts, score, interesting = [], 0, False
            bs, vs = base.status_code, fp.status_code
            bc, vc = base.auth_classifier, fp.auth_classifier
            if bs in (401, 403) and vs in (200, 201, 206, 302):
                parts.append(f"Status {bs}->{vs} (auth bypass candidate)")
                score += 6
                interesting = True
            if bs != vs:
                parts.append(f"Status changed {bs}->{vs}")
                score += 2
            if bc == "missing_auth" and vc == "invalid_token":
                parts.append("missing_auth->invalid_token (token detection)")
                score += 3
            if bc == "invalid_token" and vc == "insufficient_scope":
                parts.append("invalid_token->insufficient_scope (scope diff)")
                score += 3
                interesting = True
            if bc != vc:
                parts.append(f"Classifier: {bc}->{vc}")
            if base.body_hash != fp.body_hash and vs == bs:
                parts.append("Body hash changed")
                score += 5
            ld = abs(base.content_length - fp.content_length)
            if ld > 200 and base.content_length > 0:
                parts.append(f"Content-Length delta: {ld}B")
                score += 5
            if fp.has_set_cookie and not base.has_set_cookie:
                parts.append("Set-Cookie appeared")
                score += 5
                interesting = True
            if fp.allow_header and not base.allow_header:
                parts.append(f"Allow: {fp.allow_header}")
                score += 4
            if fp.www_authenticate != base.www_authenticate:
                parts.append("WWW-Auth changed")
                score += 3
            if fp.cors_origin != base.cors_origin:
                parts.append(f"CORS: {fp.cors_origin}")
                score += 4
            if not parts:
                continue
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
                if v != path:
                    variants.append((name, v))
            except Exception:
                pass
        for va in VERSION_ALTERNATIVES:
            swapped = re.sub(r"/api/v\d+", va, path)
            if swapped != path:
                variants.append((f"version:{va.lstrip('/')}", swapped))
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
        if total >= 28:
            return total, "Critical manual review"
        if total >= 18:
            return total, "High manual review"
        if total >= 10:
            return total, "Medium interest"
        if total >= 4:
            return total, "Low interest"
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
            ct.add_column("Cluster", width=8)
            ct.add_column("Status", width=6)
            ct.add_column("Classifier", width=22)
            ct.add_column("Count", width=6, justify="right")
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
            d = (tf.delta_description[:60].replace("|", "/") if tf else ep.notes[:60])
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
|      Smart Auth Differential Analysis Tool                            |
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
                "endpoints": [{"rank": i + 1, "path": ep.path, "methods": ep.methods,
                               "risk_score": ep.risk_score, "risk_keywords": ep.risk_keywords,
                               "has_object_id": ep.has_object_id,
                               "security_schemes": ep.security_schemes}
                              for i, ep in enumerate(endpoints)]}
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"\n[+] JSON: {out}")


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHZDIFFMAPPER — Main orchestrator class
# ═══════════════════════════════════════════════════════════════════════════════

class AuthzDiffMapper:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.base_url = args.base_url
        self.normalizer = TargetNormalizer(self.base_url)
        self.rl = RateLimiter(args.rate)
        self.client = HTTPClient(timeout=args.timeout, proxy=args.proxy,
                                  verify_tls=not getattr(args, 'insecure', False),
                                  rate_limiter=self.rl)
        self.collector = EndpointCollector(self.normalizer, self.client)
        self.endpoints: list[EndpointInfo] = []
        self.clusters: list[ClusterGroup] = []
        self.all_findings: dict = {}
        self.total_requests = 0

    def run(self):
        args = self.args
        methods = list(dict.fromkeys([m.strip().upper() for m in args.methods.split(",")]))
        if getattr(args, 'dangerous_methods', False):
            warn_dangerous()
            methods.extend(DANGEROUS_METHODS)
            methods = list(dict.fromkeys(methods))

        output_dir = Path(getattr(args, 'output', 'reports'))
        output_dir.mkdir(parents=True, exist_ok=True)

        extra_headers = parse_headers(getattr(args, 'header', []))

        # Quick connectivity check before heavy discovery
        logging.info("Checking target connectivity...")
        probe_paths = ["/", "/api", "/health", "/swagger.json"]
        reachable = 0
        blocked = 0
        for pp in probe_paths:
            self.rl.wait()
            pr = self.client.request("GET", self.normalizer.join(pp), headers={"User-Agent": "curl/8.0"})
            sc = pr.get("status_code", 0)
            if sc == 0:
                pass  # connection error
            elif sc == 403:
                blocked += 1
            else:
                reachable += 1
        if reachable == 0 and blocked >= 3:
            logging.error("Target unreachable or blocking all requests (%d/4 403). Exiting.", blocked)
            print("\n[!] Target is not responding or is blocking this IP.")
            print("[!] Try: --proxy http://... or verify the target is accessible from this machine.\n")
            self.client.close()
            return
        if blocked >= 3:
            logging.warning("Target appears to be blocking requests (%d/4 probes returned 403).", blocked)
            logging.warning("The server may have WAF/IP restrictions. Probes may all fail.")

        # Discovery phase
        swagger_eps: list[EndpointInfo] = []
        swagger_path = getattr(args, 'swagger', None)
        if swagger_path:
            try:
                sa = SwaggerAnalyzer.load(swagger_path, self.client)
                swagger_eps = sa.extract()
                logging.info("Swagger: %d endpoints", len(swagger_eps))
            except Exception as e:
                logging.error("Swagger error: %s", e)

        only_swagger = getattr(args, 'only_analyze_swagger', False)
        if only_swagger and swagger_eps:
            swagger_only_report(swagger_eps, output_dir, args)
            self.endpoints = swagger_eps
            return

        # Auto-discover API docs if no endpoints provided
        endpoints_file = getattr(args, 'endpoints', None)
        path_map: dict[str, EndpointInfo] = {e.path: e for e in swagger_eps}

        if endpoints_file:
            try:
                for p in self.collector.from_file(endpoints_file):
                    if p not in path_map:
                        path_map[p] = EndpointInfo(path=p, source="file")
            except Exception as e:
                logging.error("Endpoints file: %s", e)

        if not swagger_eps and not endpoints_file:
            logging.info("No swagger/endpoints provided — auto-discovering API docs...")
            discoverer = ApiDocDiscoverer(self.client, self.normalizer, self.rl)
            docs = discoverer.discover(max_paths=500)

            for doc in docs:
                if doc["type"] in ("openapi", "swagger") and doc["status"] == 200:
                    logging.info("Parsing discovered doc: %s", doc["path"])
                    sa = discoverer.parse_swagger(doc)
                    if sa:
                        for ep in sa.extract():
                            if ep.path not in path_map:
                                path_map[ep.path] = ep
                    break

            # If still no paths, try happy discovery on common API patterns
            if not path_map:
                logging.info("No API docs found — probing common API paths...")
                for p in ["/api", "/api/v1", "/v1", "/health", "/status"]:
                    resp = self.client.request("GET", self.normalizer.join(p))
                    if resp["status_code"] in (200, 401, 403):
                        if p not in path_map:
                            path_map[p] = EndpointInfo(path=p, source="discovery")

        if not path_map:
            logging.warning("No endpoints collected. Target may be unreachable or non-API.")
            self.endpoints = []
            return

        all_eps = list(path_map.values())
        max_eps = getattr(args, 'max_endpoints', 500)
        if len(all_eps) > max_eps:
            logging.warning("Limiting to %d endpoints (--max-endpoints)", max_eps)
            all_eps = all_eps[:max_eps]
        logging.info("Testing %d endpoints", len(all_eps))

        # Probing phase
        ctx = {}
        if getattr(args, 'context_file', None):
            try:
                raw = json.loads(Path(args.context_file).read_text(encoding="utf-8"))
                ctx = {k: str(v) for k, v in raw.items() if not k.startswith("_") and isinstance(v, (str, int, float))}
            except Exception as e:
                logging.warning("Context file error: %s", e)

        smart = getattr(args, 'smart', True)
        prober = AuthProber(self.normalizer, self.client, self.rl,
                            token=getattr(args, 'token', None),
                            extra_hdrs=extra_headers, ctx=ctx,
                            dry_run=getattr(args, 'dry_run', False),
                            smart_detect=smart)
        clusterer = ResponseClusterer()
        all_findings: dict[str, list[DifferentialFinding]] = {}
        self.total_requests = 0

        concurrency = getattr(args, 'concurrency', 1)
        tasks = []
        for ep in all_eps:
            ep_methods = [m for m in ep.methods if m in methods] or [methods[0]]
            for method in ep_methods:
                tasks.append((ep, method))

        def _probe_one(ep: EndpointInfo, method: str) -> tuple[str, list[DifferentialFinding], list[ResponseFingerprint]]:
            local_client = self.client
            if concurrency > 1:
                local_client = HTTPClient(timeout=args.timeout, proxy=args.proxy,
                                          verify_tls=not getattr(args, 'insecure', False),
                                          rate_limiter=self.rl)
            local_prober = AuthProber(self.normalizer, local_client, self.rl,
                                       token=getattr(args, 'token', None),
                                       extra_hdrs=extra_headers, ctx=ctx,
                                       dry_run=getattr(args, 'dry_run', False),
                                       smart_detect=smart)
            key = f"{method}:{ep.path}"
            fps = local_prober.probe_smart(ep.path, method)
            findings = DifferentialAnalyzer.analyze(ep.path, method, fps)
            if concurrency > 1:
                local_client.close()
            return key, findings, fps

        results: list[tuple[str, list[DifferentialFinding], list[ResponseFingerprint]]] = []
        if concurrency > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_probe_one, ep, method) for ep, method in tasks]
                for f in as_completed(futures):
                    key, findings, fps = f.result()
                    results.append((key, findings, fps))
        else:
            for ep, method in tasks:
                key, findings, fps = _probe_one(ep, method)
                results.append((key, findings, fps))
            self.client.close()

        for key, findings, fps in results:
            self.total_requests += len(fps)
            for fp in fps:
                clusterer.add(fp)
            if findings and findings[0].interesting:
                logging.info("  Interesting: %s", findings[0].delta_description[:80])
            all_findings[key] = findings
        if getattr(args, 'dry_run', False):
            logging.info("DRY-RUN complete. No requests sent.")
            return

        self.endpoints = all_eps
        self.clusters = clusterer.clusters()
        self.all_findings = all_findings

        # Report
        reporter = ReportGenerator(self.base_url, all_eps, all_findings,
                                    self.clusters, output_dir)
        reporter.terminal()
        if getattr(args, 'json', None):
            print(f"\n[+] JSON: {reporter.export_json()}")
        if getattr(args, 'markdown', None):
            print(f"[+] Markdown: {reporter.export_markdown()}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(prog="authz-diff-mapper",
        description="401/403 Auth/Authz Behavior Analyzer — Smart Auto-Discovery Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s --base-url https://api.example.com\n"
               "  %(prog)s --base-url https://api.example.com --swagger openapi.json\n"
               "  %(prog)s --base-url https://api.example.com --endpoints paths.txt --token TOKEN --markdown\n"
               "  %(prog)s --base-url https://api.example.com --swagger spec.json --only-analyze-swagger")
    parser.add_argument("--base-url", required=True,
                        help="Target base URL (e.g. https://api.example.com/api)")
    parser.add_argument("--endpoints", help="File with one path per line")
    parser.add_argument("--swagger", help="Local or remote Swagger/OpenAPI spec file")
    parser.add_argument("--token", help="Valid Bearer token for differential comparison")
    parser.add_argument("--header", action="append", dest="headers", default=[], metavar="H",
                        help="Extra headers (e.g. 'X-Org-ID: org_42')")
    parser.add_argument("--context-file", help="JSON file with context values (tenant IDs etc.)")
    parser.add_argument("--methods", default="GET,HEAD,OPTIONS",
                        help="HTTP methods to test (default: GET,HEAD,OPTIONS)")
    parser.add_argument("--dangerous-methods", action="store_true",
                        help="Enable POST/PUT/PATCH/DELETE (may modify data)")
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE,
                        help="Requests per second (default: %.1f)" % DEFAULT_RATE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Request timeout in seconds (default: %.1f)" % DEFAULT_TIMEOUT)
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--max-endpoints", type=int, default=DEFAULT_MAX_ENDPOINTS,
                        help="Max endpoints to test (default: %d)" % DEFAULT_MAX_ENDPOINTS)
    parser.add_argument("--only-analyze-swagger", action="store_true",
                        help="Only analyze swagger, don't probe")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log what would be done, don't send requests")
    parser.add_argument("--path-variations", action="store_true",
                        help="Test path normalization variants")
    parser.add_argument("--output", default="reports", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Export JSON report")
    parser.add_argument("--markdown", action="store_true", help="Export Markdown report")
    parser.add_argument("--concurrency", type=int, default=1,
                        help="Parallel endpoint probes (default: 1, no concurrency)")
    parser.add_argument("--no-smart", action="store_true",
                        help="Disable smart auth detection (use standard probes only)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    print_banner()
    print("[i] Smart mode: %s" % ("ON" if not args.no_smart else "OFF"))
    print("[i] Auto-discovering API docs: %s" % ("YES" if not args.swagger and not args.endpoints else "from input"))

    mapper = AuthzDiffMapper(args)
    mapper.run()


if __name__ == "__main__":
    main()
