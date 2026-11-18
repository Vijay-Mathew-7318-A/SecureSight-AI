"""Safe HTTP client for SecureSight AI.

Safety measures:
  - The starting URL and EVERY redirect target go through validate_target_url()
    (blocks localhost, private IPs, odd schemes and ports).
  - Redirects are followed manually, up to a limit.
  - Timeouts on every request, plus a total time limit for reading the body.
  - The response body is capped in size.
  - Environment proxy settings are ignored (trust_env = False).
  - Only GET requests are sent. Nothing is submitted, guessed or exploited.

Known limits (we do not claim more than this):
  - DNS rebinding: a hostname could resolve to a different IP between our
    check and the real connection. We re-check the connected IP after the
    connection is made, but this detects the problem after the connection
    instead of preventing it, and it works only where the library exposes
    the socket. Treat it as defense in depth, not a guarantee.
"""

import time
import warnings
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from urllib3.exceptions import InsecureRequestWarning

from app.core.config import get_settings
from app.core.url_validator import (
    UnsafeURLError,
    ValidatedTarget,
    is_blocked_ip,
    validate_target_url,
)

MAX_BODY_BYTES = 1_000_000  # read at most ~1 MB of the page
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
USER_AGENT = "SecureSightAI/0.1 (passive security assessment)"


class FetchError(Exception):
    """Raised when the website cannot be fetched (timeout, connection error...)."""


@dataclass
class RedirectHop:
    """One step in a redirect chain."""

    url: str
    status_code: int
    location: str


@dataclass
class FetchResult:
    """What we learned by fetching the target page."""

    requested_url: str
    final_url: str
    status_code: int
    headers: dict            # final response headers, names in lowercase
    body_text: str
    body_truncated: bool
    set_cookie_headers: list[str]   # every Set-Cookie header from every hop
    redirect_chain: list[RedirectHop]
    final_target: ValidatedTarget
    tls_verified: bool | None = None  # None = site was not reached over HTTPS
    tls_error: str = ""


def extract_set_cookie_headers(response) -> list[str]:
    """Return every Set-Cookie header (requests merges duplicates, so use raw)."""
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
        if values:
            return list(values)
    single = response.headers.get("Set-Cookie")
    return [single] if single else []


class SafeHttpClient:
    """Fetches a page safely. Use: SafeHttpClient().fetch("example.com")"""

    def __init__(self, timeout=None, max_redirects=None, max_body_bytes=MAX_BODY_BYTES):
        settings = get_settings()
        self.timeout = timeout if timeout is not None else settings.request_timeout
        self.max_redirects = (
            max_redirects if max_redirects is not None else settings.max_redirects
        )
        self.max_body_bytes = max_body_bytes

        self.session = requests.Session()
        self.session.trust_env = False  # ignore HTTP(S)_PROXY environment variables
        self.session.headers.update(
            {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
        )

    # ------------------------------------------------------------------ public
    def fetch(self, raw_url: str) -> FetchResult:
        """Validate the URL, fetch it, follow redirects safely, return the result."""
        target = validate_target_url(raw_url)  # raises UnsafeURLError if unsafe
        requested_url = target.url
        current_url = target.url

        redirect_chain: list[RedirectHop] = []
        cookies: list[str] = []
        tls_verified = None
        tls_error = ""

        for _ in range(self.max_redirects + 1):
            response, verified, error = self._send_with_tls_fallback(current_url)
            try:
                if target.scheme == "https":
                    if not verified:
                        tls_verified = False
                        tls_error = tls_error or error
                    elif tls_verified is None:
                        tls_verified = True

                self._check_peer_ip(response)
                cookies.extend(extract_set_cookie_headers(response))

                location = response.headers.get("Location")
                if response.status_code in REDIRECT_STATUSES and location:
                    next_url = urljoin(current_url, location)
                    redirect_chain.append(
                        RedirectHop(current_url, response.status_code, next_url)
                    )
                    target = self._validate_redirect(next_url)
                    current_url = target.url
                    continue

                body, truncated = self._read_body(response)
                return FetchResult(
                    requested_url=requested_url,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body_text=self._decode(body, response),
                    body_truncated=truncated,
                    set_cookie_headers=cookies,
                    redirect_chain=redirect_chain,
                    final_target=target,
                    tls_verified=tls_verified,
                    tls_error=tls_error,
                )
            finally:
                response.close()

        raise FetchError(f"Too many redirects (more than {self.max_redirects}).")

    # ----------------------------------------------------------------- private
    def _send(self, url: str, verify: bool):
        """Send ONE GET request. No automatic redirects. (Tests replace this.)"""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            return self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
                verify=verify,
            )

    def _send_with_tls_fallback(self, url: str):
        """Try with certificate verification. If the certificate is bad, retry
        WITHOUT verification so we can still read headers and report the problem.
        Returns (response, tls_verified, tls_error_text)."""
        try:
            return self._send(url, verify=True), True, ""
        except requests.exceptions.SSLError as exc:
            if not url.lower().startswith("https://"):
                raise self._to_fetch_error(exc) from exc
            error_text = str(exc)[:300]
            try:
                return self._send(url, verify=False), False, error_text
            except requests.exceptions.RequestException as retry_exc:
                raise self._to_fetch_error(retry_exc) from retry_exc
        except requests.exceptions.RequestException as exc:
            raise self._to_fetch_error(exc) from exc

    def _to_fetch_error(self, exc: Exception) -> FetchError:
        if isinstance(exc, requests.exceptions.Timeout):
            return FetchError(f"The website did not respond within {self.timeout} seconds.")
        if isinstance(exc, requests.exceptions.SSLError):
            return FetchError("The secure (TLS) connection to the website failed.")
        if isinstance(exc, requests.exceptions.ConnectionError):
            return FetchError("Could not connect to the website.")
        return FetchError("The request to the website failed.")

    @staticmethod
    def _validate_redirect(next_url: str) -> ValidatedTarget:
        try:
            return validate_target_url(next_url)
        except UnsafeURLError as exc:
            raise UnsafeURLError(f"Blocked redirect to {next_url[:200]}: {exc}") from exc

    @staticmethod
    def _get_peer_ip(response):
        """Best effort: the IP address we are actually connected to."""
        try:
            return response.raw._connection.sock.getpeername()[0].split("%")[0]
        except Exception:
            return None

    def _check_peer_ip(self, response) -> None:
        peer_ip = self._get_peer_ip(response)
        if peer_ip and is_blocked_ip(peer_ip):
            raise UnsafeURLError(
                f"Blocked: the connection went to a private or internal address ({peer_ip})."
            )

    def _read_body(self, response):
        """Read the body in chunks, stopping at the size limit or time limit."""
        chunks = []
        total = 0
        truncated = False
        deadline = time.monotonic() + self.timeout * 2

        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > self.max_body_bytes:
                keep = len(chunk) - (total - self.max_body_bytes)
                chunks.append(chunk[:keep])
                truncated = True
                break
            chunks.append(chunk)
            if time.monotonic() > deadline:
                truncated = True
                break
        return b"".join(chunks), truncated

    @staticmethod
    def _decode(body: bytes, response) -> str:
        encoding = getattr(response, "encoding", None) or "utf-8"
        try:
            return body.decode(encoding, errors="replace")
        except LookupError:
            return body.decode("utf-8", errors="replace")