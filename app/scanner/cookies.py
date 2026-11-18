"""Cookie security analysis.

analyze_cookies() takes the raw Set-Cookie header strings collected by the HTTP
client and returns (findings, notes). It makes no network requests.

Scope and limits:
  - Only cookies set while loading the pages we fetched. Login cookies are
    normally set after signing in, which this scan never does.
  - "Session-like" is guessed from the cookie NAME only.
  - Cookie VALUES are never stored, analyzed or shown.
  - We do not record which redirect hop set a cookie.
"""

import re
from dataclasses import dataclass

from app.scanner.models import Finding, Severity

CHECK_NAME = "Cookie security"
COVERS = ("A02:2025",)  # OWASP categories this check contributes to

SESSION_HINTS = ("sess", "token", "auth", "login", "jwt")
SESSION_EXACT_TOKENS = {"sid", "remember"}
VALID_SAMESITE = {"strict", "lax", "none"}
MAX_NAMES_SHOWN = 10


@dataclass
class ParsedCookie:
    """A cookie's name and attributes. The value is deliberately NOT kept."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None  # lowercase text, or None if the attribute is absent
    path: str | None
    domain: str | None
    persistent: bool      # has Max-Age or Expires
    kind: str             # "session", "csrf" or "other"


def classify_cookie(name: str) -> str:
    """Guess what a cookie is for, from its name only."""
    lowered = name.lower()
    if "csrf" in lowered or "xsrf" in lowered:
        return "csrf"
    for token in re.split(r"[^a-z0-9]+", lowered):
        if not token:
            continue
        if token in SESSION_EXACT_TOKENS or any(h in token for h in SESSION_HINTS):
            return "session"
    return "other"


def parse_set_cookie(header: str):
    """Parse one Set-Cookie header. Returns None if it is not a valid cookie."""
    parts = header.split(";")
    name, separator, _value = parts[0].strip().partition("=")
    name = name.strip()
    if not separator or not name:
        return None

    attributes = {}
    for part in parts[1:]:
        key, _, value = part.strip().partition("=")
        key = key.strip().lower()
        if key:
            attributes[key] = value.strip().strip('"')  # the last occurrence wins

    samesite = attributes["samesite"].lower() if "samesite" in attributes else None
    return ParsedCookie(
        name=name,
        secure="secure" in attributes,
        httponly="httponly" in attributes,
        samesite=samesite,
        path=attributes.get("path"),
        domain=attributes.get("domain"),
        persistent=("max-age" in attributes) or ("expires" in attributes),
        kind=classify_cookie(name),
    )


# ------------------------------------------------------------------- helpers
def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _names(cookies) -> str:
    names = [_clip(c.name, 60) for c in cookies]
    shown = ", ".join(names[:MAX_NAMES_SHOWN])
    if len(names) > MAX_NAMES_SHOWN:
        shown += f" and {len(names) - MAX_NAMES_SHOWN} more"
    return shown


def _group_finding(
    check_id, title, affected, session_severity, other_severity, description, remediation
):
    """One finding for a group of cookies. Severity depends on whether any
    affected cookie looks like a session cookie. Returns None if nothing to report."""
    session = [c for c in affected if c.kind == "session"]
    others = [c for c in affected if c.kind != "session"]

    if session:
        severity = session_severity
    elif others and other_severity is not None:
        severity = other_severity
    else:
        return None

    evidence_parts = []
    if session:
        evidence_parts.append(f"Session-like cookies: {_names(session)}.")
    if others:
        evidence_parts.append(f"Other cookies: {_names(others)}.")

    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        owasp_category="A02:2025",
        description=description,
        remediation=remediation,
        evidence=" ".join(evidence_parts),
    )


def _prefix_violations(cookies):
    bad = []
    for c in cookies:
        lowered = c.name.lower()
        if lowered.startswith("__secure-") and not c.secure:
            bad.append(c)
        elif lowered.startswith("__host-") and (not c.secure or c.path != "/" or c.domain):
            bad.append(c)
    return bad


# --------------------------------------------------------------- entry points
def analyze_cookies(set_cookie_headers):
    """Analyze raw Set-Cookie header strings. Returns (findings, notes)."""
    notes: list[str] = []
    cookies: dict = {}
    unreadable = 0

    for header in set_cookie_headers:
        cookie = parse_set_cookie(header)
        if cookie is None:
            unreadable += 1
            continue
        # The same cookie set twice: the later one replaces the earlier one.
        key = (cookie.name, (cookie.domain or "").lower(), cookie.path or "")
        cookies[key] = cookie

    if unreadable:
        notes.append(f"{unreadable} Set-Cookie header(s) could not be read and were skipped.")

    if not cookies:
        notes.append(
            "No cookies were set by the pages visited. Login cookies are usually "
            "set only after signing in, which this scan never does."
        )
        return [], notes

    cookie_list = list(cookies.values())
    candidates = [
        _group_finding(
            "cookie-missing-secure",
            "Cookies are set without the Secure flag",
            [c for c in cookie_list if not c.secure],
            Severity.MEDIUM,
            Severity.LOW,
            "Cookies without the Secure flag can be sent over plain HTTP, where "
            "anyone on the network path could read them. For a session cookie, "
            "that can mean account takeover.",
            "Add the Secure attribute to every cookie, for example: "
            "Set-Cookie: sessionid=...; Secure; HttpOnly; SameSite=Lax. "
            "Framework settings: Django SESSION_COOKIE_SECURE = True, Flask "
            "SESSION_COOKIE_SECURE = True, Express cookie option secure: true, "
            "PHP session.cookie_secure = 1.",
        ),
        _group_finding(
            "cookie-missing-httponly",
            "Cookies are set without the HttpOnly flag",
            [c for c in cookie_list if not c.httponly and c.kind != "csrf"],
            Severity.MEDIUM,
            Severity.INFORMATIONAL,
            "Without HttpOnly, JavaScript running on the page can read the cookie. "
            "If an attacker injects a script (XSS), they can steal session cookies.",
            "Add the HttpOnly attribute to every cookie that scripts do not need "
            "to read, especially session cookies. Framework settings: Django "
            "SESSION_COOKIE_HTTPONLY = True, Flask SESSION_COOKIE_HTTPONLY = True, "
            "Express cookie option httpOnly: true, PHP session.cookie_httponly = 1.",
        ),
        _group_finding(
            "cookie-missing-samesite",
            "Cookies have no valid SameSite attribute",
            [c for c in cookie_list if c.samesite not in VALID_SAMESITE],
            Severity.LOW,
            Severity.INFORMATIONAL,
            "SameSite tells the browser not to send the cookie with requests started "
            "by other websites, which helps against cross-site request forgery "
            "(CSRF). Some browsers apply a safe default, but not all do.",
            "Set SameSite=Lax (or Strict) on every cookie unless it must be sent "
            "in cross-site contexts. Framework settings: Django "
            "SESSION_COOKIE_SAMESITE = 'Lax', Flask SESSION_COOKIE_SAMESITE = 'Lax', "
            "Express cookie option sameSite: 'lax'.",
        ),
        _group_finding(
            "cookie-samesite-none-insecure",
            "Cookies use SameSite=None without the Secure flag",
            [c for c in cookie_list if c.samesite == "none" and not c.secure],
            Severity.LOW,
            Severity.LOW,
            "SameSite=None is only allowed together with Secure. Modern browsers "
            "reject such cookies, which can silently break logins.",
            "Add the Secure attribute, or use SameSite=Lax if the cookie does not "
            "need to be sent in cross-site contexts.",
        ),
        _group_finding(
            "cookie-samesite-none",
            "Session-like cookies are sent on cross-site requests (SameSite=None)",
            [c for c in cookie_list if c.samesite == "none" and c.secure and c.kind == "session"],
            Severity.INFORMATIONAL,
            None,
            "These cookies are sent with requests started by other websites. That "
            "is sometimes intended (embedded content, single sign-on), but it means "
            "CSRF protection must come from other measures such as CSRF tokens.",
            "If cross-site use is not needed, change to SameSite=Lax. Otherwise, "
            "make sure every state-changing request requires a CSRF token.",
        ),
        _group_finding(
            "cookie-prefix-violation",
            "Cookie name prefix rules are not followed",
            _prefix_violations(cookie_list),
            Severity.LOW,
            Severity.LOW,
            "Cookie names starting with __Secure- or __Host- promise extra "
            "protection: __Secure- requires the Secure flag; __Host- also requires "
            "Path=/ and no Domain attribute. Browsers reject cookies that break "
            "these rules, so they may not work at all.",
            "Make the attributes match the prefix (Secure; Path=/; no Domain for "
            "__Host-), or remove the prefix from the cookie name.",
        ),
    ]
    findings = [f for f in candidates if f is not None]

    count = len(cookie_list)
    notes.append(
        f"{count} cookie{'s' if count != 1 else ''} checked "
        "(names and attributes only; values are never stored)."
    )
    if any(c.kind == "session" for c in cookie_list):
        notes.append(
            "'Session-like' is guessed from cookie names only (for example "
            "sessionid, token, auth). The scan cannot see how the site really "
            "uses each cookie."
        )
    return findings, notes


def run_cookie_checks(fetch_result):
    """Run the cookie checks on a FetchResult. Returns (findings, notes)."""
    return analyze_cookies(fetch_result.set_cookie_headers)