from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.resolver

from .scope import ScopeEntry, ScopeError, validate_resolved_address

CONNECT_TIMEOUT = 4.0
DNS_TIMEOUT = 2.5
REQUEST_DELAY = 0.25
MAX_DNS_RECORDS = 16
USER_AGENT = "ExternalSurfaceAuditor/0.1 (authorized staging assessment)"
SAFE_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "content-type",
    "server",
)


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host=host, port=port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        context = ssl.create_default_context()
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _resolve(host: str, allow_private: bool) -> tuple[list[str], dict[str, list[str]], list[str]]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        address = validate_resolved_address(str(literal), allow_private)
        return [str(address)], {"A" if address.version == 4 else "AAAA": [str(address)]}, []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    records: dict[str, list[str]] = {"A": [], "AAAA": [], "CNAME": [], "NS": [], "MX": []}
    errors: list[str] = []
    for record_type in records:
        try:
            answer = resolver.resolve(host, record_type, lifetime=DNS_TIMEOUT, raise_on_no_answer=False)
            if answer.rrset:
                records[record_type] = [str(record).rstrip(".")[:180] for record in list(answer)[:MAX_DNS_RECORDS]]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as exc:
            errors.append(f"{record_type}: {type(exc).__name__}")
        except (dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            continue
        except dns.exception.DNSException as exc:
            errors.append(f"{record_type}: {type(exc).__name__}")

    addresses = list(dict.fromkeys(records["A"] + records["AAAA"]))
    if not addresses:
        return [], records, errors
    validated = [str(validate_resolved_address(address, allow_private)) for address in addresses]
    return validated, records, errors


def _format_host_header(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if address.version == 6 else host


def _request_head(host: str, address: str, path: str, use_tls: bool) -> dict[str, Any]:
    port = 443 if use_tls else 80
    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    if use_tls:
        connection = PinnedHTTPSConnection(host, address, port, CONNECT_TIMEOUT)
    else:
        connection = PinnedHTTPConnection(host, address, port, CONNECT_TIMEOUT)

    try:
        connection.request(
            "HEAD",
            path,
            headers={
                "Host": _format_host_header(host),
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers: dict[str, str] = {}
        for key, value in response.getheaders():
            lower_key = key.lower()
            if lower_key in SAFE_HEADERS:
                headers[lower_key] = value[:256]
        location = response.getheader("Location")
        redirect_scheme = None
        redirect_host = None
        if location:
            try:
                redirect = urlsplit(location)
                redirect_scheme = redirect.scheme.lower() or None
                redirect_host = redirect.hostname.lower().rstrip(".") if redirect.hostname else None
            except ValueError:
                pass
        normalized_redirect_host = None
        if redirect_host:
            try:
                normalized_redirect_host = ipaddress.ip_address(redirect_host).compressed.lower()
            except ValueError:
                try:
                    normalized_redirect_host = redirect_host.encode("idna").decode("ascii")
                except UnicodeError:
                    normalized_redirect_host = None
        tls_info: dict[str, Any] | None = None
        if use_tls and connection.sock:
            certificate = connection.sock.getpeercert()
            not_after = certificate.get("notAfter") if certificate else None
            expiry = None
            days_remaining = None
            if not_after:
                expiry_dt = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
                expiry = expiry_dt.isoformat()
                days_remaining = (expiry_dt - datetime.now(UTC)).days
            tls_info = {
                "version": connection.sock.version(),
                "certificate_expires_at": expiry,
                "certificate_days_remaining": days_remaining,
                "certificate_verified": True,
            }
        return {
            "scheme": "https" if use_tls else "http",
            "path": path,
            "status": response.status,
            "reason": response.reason[:80],
            "headers": headers,
            "redirect_scheme": redirect_scheme,
            "redirect_host": normalized_redirect_host,
            "tls": tls_info,
            "error": None,
        }
    except ssl.SSLCertVerificationError as exc:
        return {
            "scheme": "https" if use_tls else "http",
            "path": path,
            "status": None,
            "reason": None,
            "headers": {},
            "redirect_scheme": None,
            "redirect_host": None,
            "tls": None,
            "tls_validation_failed": True,
            "error": f"TLS certificate validation failed ({type(exc).__name__}).",
        }
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
        return {
            "scheme": "https" if use_tls else "http",
            "path": path,
            "status": None,
            "reason": None,
            "headers": {},
            "redirect_scheme": None,
            "redirect_host": None,
            "tls": None,
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
        }
    finally:
        connection.close()


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    summary: str,
    evidence: list[str],
    remediation: str,
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "summary": summary,
        "evidence": evidence,
        "remediation": remediation,
        "confidence": confidence,
    }


def _check_http_findings(probes: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    https_root = next((p for p in probes if p["scheme"] == "https" and p["path"] == "/"), None)
    http_root = next((p for p in probes if p["scheme"] == "http" and p["path"] == "/"), None)

    if http_root and http_root["status"] is not None and http_root["status"] < 500:
        if (
            (https_root is None or https_root["status"] is None)
            and not (https_root and https_root.get("tls_validation_failed"))
        ):
            findings.append(
                _finding(
                    "http-without-https",
                    "HTTP responds without a confirmed HTTPS service",
                    "medium",
                    "transport-security",
                    "The approved target responds over HTTP and this scan did not confirm an HTTPS service or HTTPS redirect.",
                    [
                        f"HTTP status: {http_root['status']}",
                        "HTTPS could not be confirmed by this scan.",
                        "Redirect destination was not followed.",
                    ],
                    "Enable HTTPS with a valid certificate and redirect HTTP requests to the HTTPS origin.",
                    "medium",
                )
            )

    for probe in probes:
        if probe["status"] is not None and 500 <= probe["status"] <= 599:
            findings.append(
                _finding(
                    f"http-5xx-{probe['scheme']}-{probe['path']}",
                    "Endpoint returned a server error",
                    "medium",
                    "availability",
                    "A safe HEAD request to an approved staging endpoint returned an HTTP 5xx response.",
                    [f"{probe['scheme']} status: {probe['status']}", f"Path: {probe['path']}"],
                    "Review the application and upstream service logs for this endpoint, then repeat the check after remediation.",
                    "high",
                )
            )

    if https_root and https_root["status"] is not None and 200 <= https_root["status"] < 400:
        headers = https_root["headers"]
        missing: list[str] = []
        if "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        content_type = headers.get("content-type", "").lower()
        if "text/html" in content_type and "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if missing:
            findings.append(
                _finding(
                    "browser-security-headers",
                    "Recommended browser security headers are missing",
                    "low",
                    "http-configuration",
                    "The HTTPS response did not include all recommended browser security headers checked by this MVP.",
                    [f"Missing: {', '.join(missing)}"],
                    "Review whether each header is appropriate for the application and configure it at the application or reverse-proxy layer.",
                )
            )

        server_header = headers.get("server")
        if server_header:
            findings.append(
                _finding(
                    "server-header",
                    "Server response exposes implementation metadata",
                    "info",
                    "information-disclosure",
                    "The HTTPS response includes a Server header that may reveal implementation details.",
                    [f"Server header: {server_header}"],
                    "Consider removing or generalizing the Server header if it exposes unnecessary version details.",
                )
            )


def scan_target(entry: ScopeEntry) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    addresses, dns_records, dns_errors = _resolve(entry.host, entry.allow_private)
    findings: list[dict[str, Any]] = []
    if not addresses:
        findings.append(
            _finding(
                "dns-no-address",
                "No A or AAAA address was resolved",
                "medium",
                "availability",
                "The approved staging hostname did not resolve to an address during this scan.",
                dns_errors or ["No A or AAAA answer was returned."],
                "Check the staging DNS records and confirm the hostname is active in the approved test environment.",
                "medium",
            )
        )
        return {
            "target": entry.host,
            "environment": entry.environment,
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "resolved_addresses": [],
            "dns": dns_records,
            "dns_warnings": dns_errors,
            "probes": [],
            "findings": findings,
            "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
            "notes": ["No HTTP request was sent because DNS returned no address."],
        }

    pinned_address = addresses[0]
    probes: list[dict[str, Any]] = []
    time.sleep(REQUEST_DELAY)
    http_root = _request_head(entry.host, pinned_address, "/", use_tls=False)
    probes.append(http_root)

    paths = list(dict.fromkeys(["/"] + list(entry.paths)))
    for path in paths:
        time.sleep(REQUEST_DELAY)
        probes.append(_request_head(entry.host, pinned_address, path, use_tls=True))

    https_root = next((probe for probe in probes if probe["scheme"] == "https" and probe["path"] == "/"), None)
    if https_root and https_root.get("tls_validation_failed"):
        findings.append(
            _finding(
                "tls-certificate-validation-failed",
                "TLS certificate validation failed",
                "high",
                "transport-security",
                "The TLS handshake did not pass the system certificate and hostname checks.",
                [https_root["error"]],
                "Install a valid certificate for the approved hostname and verify the certificate chain and expiry date.",
            )
        )
    elif https_root and https_root.get("error"):
        findings.append(
            _finding(
                "https-request-failed",
                "HTTPS request could not be completed",
                "medium",
                "availability",
                "A safe HEAD request to the approved staging target did not complete successfully.",
                [https_root["error"]],
                "Check service availability, TLS configuration, and network policy from the scan host.",
                "medium",
            )
        )
    elif https_root and https_root.get("tls"):
        days_remaining = https_root["tls"].get("certificate_days_remaining")
        if days_remaining is not None and days_remaining < 0:
            findings.append(
                _finding(
                    "tls-certificate-expired",
                    "TLS certificate is expired",
                    "high",
                    "transport-security",
                    "The certificate presented by the approved staging target has passed its validity end date.",
                    [f"Expired {abs(days_remaining)} day(s) ago."],
                    "Renew and deploy a certificate whose subject matches the approved hostname, then retest.",
                )
            )
        elif days_remaining is not None and days_remaining <= 30:
            findings.append(
                _finding(
                    "tls-certificate-near-expiry",
                    "TLS certificate expires soon",
                    "medium",
                    "transport-security",
                    "The certificate presented by the approved staging target expires within 30 days.",
                    [f"Days remaining: {days_remaining}"],
                    "Renew the certificate before its expiry date and verify the full certificate chain.",
                )
            )
    _check_http_findings(probes, findings)

    status_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        if item["severity"] in status_counts:
            status_counts[item["severity"]] += 1

    return {
        "target": entry.host,
        "environment": entry.environment,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "resolved_addresses": addresses,
        "pinned_address": pinned_address,
        "dns": dns_records,
        "dns_warnings": dns_errors,
        "probes": probes,
        "findings": findings,
        "summary": status_counts,
        "notes": [
            "Only the exact approved target was scanned.",
            "DNS answers were pinned for HTTP connections; redirects were not followed.",
            "Only DNS queries and HEAD requests are used; response bodies, cookies, and authorization data are never read or stored.",
        ],
    }
