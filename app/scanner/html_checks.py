"""HTML page content checks.

analyze_html() looks at the HTML text of ONE page and returns (findings, notes).
It makes no network requests.

Scope and limits:
  - Only the page we fetched (up to ~1 MB). Content added later by JavaScript
    is not seen.
  - Library versions are reported as DISCLOSURE only. There is no vulnerability
    database here, so we never claim that a version is vulnerable.
  - "Third-party" is decided by comparing host names (www. is ignored).
  - For error messages we record WHICH pattern matched, never the matched text.
"""

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from app.scanner.models import Finding, Severity

CHECK_NAME = "HTML page content"
# Contributes to these categories (A03 and A08 only in a very limited way).
COVERS = ("A02:2025", "A03:2025", "A04:2025", "A08:2025", "A10:2025")

MAX_ITEMS = 2000
MAX_SHOWN = 5
SRI_EXEMPT_HOSTS = {"fonts.googleapis.com"}  # their CSS differs per browser, so SRI cannot be used
VERSION_PATTERN = re.compile(r"\d+\.\d+")
TAG_PATTERN = re.compile(r"<[^>]{0,500}>")
DIRECTORY_LISTING = re.compile(
    r"<title>\s*Index of\s+/|<h1>\s*Index of\s+/|\[To Parent Directory\]", re.IGNORECASE
)
LIBRARY_PATTERN = re.compile(
    r"(?<![a-z0-9])(jquery|jquery-ui|bootstrap|angular|angularjs|react|react-dom|"
    r"vue|lodash|moment|backbone|underscore)[-.@/_]v?(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

DEBUG_LABEL = "Framework debug mode page"
ERROR_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"\bat\s+[\w$.]+\([\w$]+\.java:\d+\)")),
    (
        ".NET stack trace or error page",
        re.compile(r"Server Error in '[^']{1,60}' Application|\bat System\.[\w.]{1,80}\("),
    ),
    (
        "PHP error message with file path",
        re.compile(
            r"(?:Fatal error|Parse error|Warning|Notice|Uncaught \w+)[^\n]{0,200}?"
            r"\bin\s+(?:/|[A-Za-z]:\\)[^\n]{0,200}?\bon line\s+\d+",
            re.IGNORECASE,
        ),
    ),
    (
        "Node.js stack trace",
        re.compile(r"\bat\s+[^\n(]{1,80}\((?:/|[A-Za-z]:\\)[^\n)]{1,200}:\d+:\d+\)"),
    ),
    (
        "SQL error message",
        re.compile(
            r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[\w+\]|"
            r"Unclosed quotation mark after the character string|pg_query\(\)|"
            r"sqlite3\.OperationalError",
            re.IGNORECASE,
        ),
    ),
    (
        DEBUG_LABEL,
        re.compile(
            r"The debugger caught an exception in your WSGI application|Werkzeug Debugger|"
            r"seeing this error because you have\s*(?:<code>)?\s*DEBUG\s*=\s*True|"
            r"Whoops! There was an error",
            re.IGNORECASE,
        ),
    ),
]


# ------------------------------------------------------------------- parsing
@dataclass
class Resource:
    tag: str            # html tag name, e.g. "script"
    kind: str           # script, stylesheet, frame, object or media
    url: str
    active: bool        # active content can change the page (scripts, styles, frames)
    has_integrity: bool


@dataclass
class Form:
    action: str
    method: str
    has_password: bool = False


class PageParser(HTMLParser):
    """Collects the parts of the page that the checks need."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources: list[Resource] = []
        self.forms: list[Form] = []
        self.passwords_outside_forms = 0
        self.generator = ""
        self.capped = False
        self._current_form = None

    def _add_resource(self, tag, kind, url, active, integrity=""):
        if not url or not url.strip():
            return
        if len(self.resources) >= MAX_ITEMS:
            self.capped = True
            return
        self.resources.append(Resource(tag, kind, url.strip(), active, bool(integrity.strip())))

    def handle_starttag(self, tag, attrs):
        a = {name.lower(): (value or "") for name, value in attrs}

        if tag == "script":
            self._add_resource(tag, "script", a.get("src", ""), True, a.get("integrity", ""))
        elif tag == "link":
            if "stylesheet" in a.get("rel", "").lower().split():
                self._add_resource(
                    tag, "stylesheet", a.get("href", ""), True, a.get("integrity", "")
                )
        elif tag in ("iframe", "embed"):
            self._add_resource(tag, "frame", a.get("src", ""), True)
        elif tag == "object":
            self._add_resource(tag, "object", a.get("data", ""), True)
        elif tag in ("img", "audio", "video", "source"):
            self._add_resource(tag, "media", a.get("src", ""), False)
        elif tag == "form":
            method = a.get("method", "get").strip().lower() or "get"
            self._current_form = Form(action=a.get("action", "").strip(), method=method)
            if len(self.forms) < MAX_ITEMS:
                self.forms.append(self._current_form)
        elif tag == "input":
            if a.get("type", "").strip().lower() == "password":
                if self._current_form is not None:
                    self._current_form.has_password = True
                else:
                    self.passwords_outside_forms += 1
        elif tag == "meta":
            if a.get("name", "").strip().lower() == "generator" and not self.generator:
                self.generator = a.get("content", "").strip()

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


# ------------------------------------------------------------------- helpers
def _clip(text: str, limit: int = 100) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _display_url(url: str, limit: int = 100) -> str:
    """URL for evidence text: query string and fragment removed (they may hold tokens)."""
    return _clip(url.strip().split("?", 1)[0].split("#", 1)[0], limit)


def _summarize(resources) -> str:
    shown = [f"{_display_url(r.url)} ({r.tag})" for r in resources[:MAX_SHOWN]]
    text = ", ".join(shown)
    if len(resources) > MAX_SHOWN:
        text += f" and {len(resources) - MAX_SHOWN} more"
    return text


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _same_site(host_a: str, host_b: str) -> bool:
    a = host_a[4:] if host_a.startswith("www.") else host_a
    b = host_b[4:] if host_b.startswith("www.") else host_b
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _third_party_host(page_url: str, resource_url: str) -> str | None:
    """Host name of the resource if it is loaded from another site, else None."""
    try:
        parsed = urlparse(urljoin(page_url, resource_url))
        host = (parsed.hostname or "").lower()
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host:
        return None
    return None if _same_site(_hostname(page_url), host) else host


def _finding(check_id, title, severity, owasp, description, remediation, evidence) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        owasp_category=owasp,
        description=description,
        remediation=remediation,
        evidence=evidence,
    )


# -------------------------------------------------------------------- checks
def _check_mixed_content(resources, page_is_https) -> list[Finding]:
    if not page_is_https:
        return []
    insecure = [r for r in resources if r.url.lower().startswith("http://")]
    active = [r for r in insecure if r.active]
    passive = [r for r in insecure if not r.active]
    findings = []

    if active:
        findings.append(
            _finding(
                "mixed-content-active",
                "HTTPS page loads scripts, styles or frames over HTTP",
                Severity.MEDIUM,
                "A04:2025",
                "The page is delivered over HTTPS but loads active content over plain "
                "HTTP. Someone on the network can change those files and take control "
                "of the page. Browsers usually block this content, which can also "
                "break the page.",
                "Change every resource address to https:// (or to a relative address). "
                "If a resource is not available over HTTPS, host it yourself or remove "
                "it. The header Content-Security-Policy: upgrade-insecure-requests "
                "can help while you clean up.",
                f"Insecure resources: {_summarize(active)}.",
            )
        )
    if passive:
        findings.append(
            _finding(
                "mixed-content-passive",
                "HTTPS page loads images or media over HTTP",
                Severity.LOW,
                "A04:2025",
                "The page is delivered over HTTPS but loads images, audio or video "
                "over plain HTTP. These can be observed or swapped by someone on the "
                "network, and browsers may show a 'not fully secure' warning.",
                "Change the addresses of images and media to https:// (or relative "
                "addresses).",
                f"Insecure resources: {_summarize(passive)}.",
            )
        )
    return findings


def _check_subresource_integrity(resources, page_url) -> list[Finding]:
    scripts, styles = [], []
    for r in resources:
        if r.has_integrity or r.kind not in ("script", "stylesheet"):
            continue
        host = _third_party_host(page_url, r.url)
        if host is None:
            continue
        if r.kind == "script":
            scripts.append(r)
        elif host not in SRI_EXEMPT_HOSTS:
            styles.append(r)

    fix = (
        "Add integrity and crossorigin attributes, for example: "
        '<script src="https://cdn.example.net/lib-1.2.3.min.js" '
        'integrity="sha384-..." crossorigin="anonymous"></script>. '
        "Use fixed version numbers in the address, or host the file yourself. "
        "Tools such as srihash.org can create the hash."
    )
    findings = []
    if scripts:
        findings.append(
            _finding(
                "external-script-no-sri",
                "Scripts from other websites have no integrity check",
                Severity.LOW,
                "A08:2025",
                "The page runs JavaScript from other hosts without Subresource "
                "Integrity. If one of those hosts is hacked or serves changed files, "
                "that code runs on your page with full access to it.",
                fix,
                f"Scripts without an integrity attribute: {_summarize(scripts)}.",
            )
        )
    if styles:
        findings.append(
            _finding(
                "external-stylesheet-no-sri",
                "Stylesheets from other websites have no integrity check",
                Severity.INFORMATIONAL,
                "A08:2025",
                "The page loads stylesheets from other hosts without Subresource "
                "Integrity. A changed stylesheet is less dangerous than a changed "
                "script, but it can still alter or hide parts of the page.",
                fix,
                f"Stylesheets without an integrity attribute: {_summarize(styles)}.",
            )
        )
    return findings


def _check_forms(parser, page_is_https) -> list[Finding]:
    findings = []
    has_password = parser.passwords_outside_forms > 0 or any(
        f.has_password for f in parser.forms
    )

    if has_password and not page_is_https:
        findings.append(
            _finding(
                "password-form-over-http",
                "Password field on a page served over HTTP",
                Severity.HIGH,
                "A04:2025",
                "The page contains a password field but is delivered over plain HTTP. "
                "Passwords typed into it can be read by anyone on the network path.",
                "Serve every page that asks for a password over HTTPS only, and "
                "redirect HTTP to HTTPS.",
                "A password input field was found on a page loaded over HTTP.",
            )
        )

    get_password_forms = [f for f in parser.forms if f.has_password and f.method == "get"]
    if get_password_forms:
        findings.append(
            _finding(
                "password-form-uses-get",
                "Password form sends data in the web address (GET)",
                Severity.MEDIUM,
                "A02:2025",
                "A form with a password field uses the GET method (the default when no "
                "method is given). The password then appears in the web address, which "
                "ends up in browser history, server logs and referrer headers.",
                'Add method="post" to the form, and make sure the server only accepts '
                "the login data from POST requests.",
                f"Forms with a password field that use GET: {len(get_password_forms)}.",
            )
        )

    if page_is_https:
        insecure = [f for f in parser.forms if f.action.lower().startswith("http://")]
        if insecure:
            severity = Severity.HIGH if any(f.has_password for f in insecure) else Severity.MEDIUM
            shown = ", ".join(_display_url(f.action) for f in insecure[:MAX_SHOWN])
            findings.append(
                _finding(
                    "form-posts-to-http",
                    "Form on an HTTPS page submits over HTTP",
                    severity,
                    "A04:2025",
                    "A form on an HTTPS page sends its data to an http:// address, so "
                    "whatever visitors type can be read or changed on the network.",
                    "Change the form's action to an https:// address (or a relative "
                    "address) and make sure the server supports HTTPS for it.",
                    f"Form actions: {shown}.",
                )
            )
    return findings


def _check_directory_listing(body: str) -> list[Finding]:
    if not DIRECTORY_LISTING.search(body):
        return []
    return [
        _finding(
            "directory-listing",
            "Directory listing is enabled",
            Severity.MEDIUM,
            "A02:2025",
            "The page lists the files of a folder. Visitors can browse and download "
            "files that were never meant to be public, such as backups or "
            "configuration files.",
            "Disable directory listing ('autoindex off;' in nginx, 'Options -Indexes' "
            "in Apache) and remove files that should not be on the web server.",
            "The page looks like an automatic 'Index of /' file listing.",
        )
    ]


def _check_generator(generator: str) -> list[Finding]:
    if not generator or not VERSION_PATTERN.search(generator):
        return []
    return [
        _finding(
            "generator-version-disclosure",
            "Page reveals the website software and version",
            Severity.LOW,
            "A02:2025",
            "A meta tag announces which software (and version) builds this site. This "
            "does not break anything by itself, but it helps attackers look for "
            "known weaknesses of that exact version.",
            "Remove the generator meta tag (many CMS settings or plugins can do this) "
            "and keep the software updated.",
            f"Generator meta tag: {_clip(generator)}",
        )
    ]


def _check_library_versions(resources) -> list[Finding]:
    found = set()
    for r in resources:
        if r.kind not in ("script", "stylesheet"):
            continue
        try:
            path = urlparse(r.url).path
        except ValueError:
            continue
        for name, version in LIBRARY_PATTERN.findall(path):
            found.add((name.lower(), version))
    if not found:
        return []
    listing = ", ".join(f"{name} {version}" for name, version in sorted(found))
    return [
        _finding(
            "library-versions-detected",
            "Software library versions are visible in the page",
            Severity.INFORMATIONAL,
            "A03:2025",
            "The file names of scripts or stylesheets show which library versions "
            "the page uses. This scan does not check these versions against a "
            "vulnerability database, so it cannot tell whether they are vulnerable. "
            "Old versions deserve a manual review.",
            "Check each library's release notes or a tool such as retire.js or "
            "'npm audit', and update libraries that are outdated or have known "
            "vulnerabilities.",
            f"Detected: {listing}.",
        )
    ]


def _check_error_leaks(body: str) -> list[Finding]:
    text = TAG_PATTERN.sub(" ", body)
    labels = [label for label, pattern in ERROR_SIGNATURES if pattern.search(text)]
    if not labels:
        return []
    severity = Severity.HIGH if DEBUG_LABEL in labels else Severity.MEDIUM
    return [
        _finding(
            "error-details-exposed",
            "Page exposes technical error details",
            severity,
            "A10:2025",
            "The response contains error messages, stack traces or debug output. "
            "These show file paths, code structure or database details that help "
            "attackers, and a debug mode left on can expose much more.",
            "Turn off debug mode in production, show visitors a generic error page, "
            "and write the detailed errors to a private log instead.",
            "Matched patterns: " + ", ".join(labels) + ". (The matched text is not shown.)",
        )
    ]


# --------------------------------------------------------------- entry points
def analyze_html(body: str, final_url: str, content_type: str = "", truncated: bool = False):
    """Analyze a page's text. Returns (findings, notes)."""
    findings: list[Finding] = []
    notes: list[str] = []
    content_type = (content_type or "").lower()

    if not body or not body.strip():
        notes.append("The page body was empty, so page content checks were skipped.")
        return findings, notes

    is_html = "html" in content_type or (not content_type and body.lstrip().startswith("<"))
    is_text = is_html or not content_type or any(
        t in content_type for t in ("text/", "json", "xml")
    )
    if not is_text:
        notes.append("Page content checks were skipped because the response is not text or HTML.")
        return findings, notes

    if truncated:
        notes.append("Only the first part of a very large page was analyzed.")

    page_is_https = final_url.lower().startswith("https://")

    if is_html:
        parser = PageParser()
        try:
            parser.feed(body)
            parser.close()
        except Exception:
            notes.append(
                "The page's HTML could not be fully parsed; some checks may be incomplete."
            )
        if parser.capped:
            notes.append(f"The page has a very large number of resources; only the first {MAX_ITEMS} were analyzed.")

        findings.extend(_check_mixed_content(parser.resources, page_is_https))
        findings.extend(_check_subresource_integrity(parser.resources, final_url))
        findings.extend(_check_forms(parser, page_is_https))
        findings.extend(_check_directory_listing(body))
        findings.extend(_check_generator(parser.generator))
        findings.extend(_check_library_versions(parser.resources))
    else:
        notes.append(
            "HTML structure checks (mixed content, forms, script integrity) were "
            "skipped because the response is not HTML."
        )

    findings.extend(_check_error_leaks(body))
    return findings, notes


def run_html_checks(fetch_result):
    """Run the HTML checks on a FetchResult. Returns (findings, notes)."""
    return analyze_html(
        fetch_result.body_text,
        fetch_result.final_url,
        fetch_result.headers.get("content-type", ""),
        fetch_result.body_truncated,
    )