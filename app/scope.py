from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .paths import default_scope_file


class ScopeError(ValueError):
    """Raised when a target is invalid or is not explicitly in the approved scope."""


@dataclass(frozen=True)
class ScopeEntry:
    host: str
    environment: str
    paths: tuple[str, ...]
    allow_private: bool


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_PATHS = 10


def normalize_host(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise ScopeError("Enter one domain name or IP address.")
    if any(token in candidate for token in ("://", "/", "?", "#", "@", "\\")):
        raise ScopeError("Enter only a domain or IP address, without a URL or path.")

    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        pass

    try:
        ascii_host = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError("The domain name is not valid.") from exc

    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ScopeError("Enter a fully qualified domain name or an IP address.")
    return ascii_host


def validate_path(value: str) -> str:
    path = value.strip()
    if (
        not path.startswith("/")
        or path.startswith("//")
        or len(path) > 160
        or any(ch in path for ch in ("?", "#", "\\"))
        or any(ord(ch) < 32 or ord(ch) > 126 for ch in path)
        or any(part == ".." for part in path.split("/"))
    ):
        raise ScopeError(f"Invalid approved path: {value!r}")
    return path


def scope_file_path() -> Path:
    configured = os.environ.get("ESA_SCOPE_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    return default_scope_file()


def load_scope() -> list[ScopeEntry]:
    path = scope_file_path()
    if not path.exists():
        return []
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError("The approved target file could not be read.") from exc
    return parse_scope(raw)


def parse_scope(raw: Any) -> list[ScopeEntry]:
    if not isinstance(raw, dict) or not isinstance(raw.get("targets"), list):
        raise ScopeError("The approved target file must contain a targets list.")

    entries: list[ScopeEntry] = []
    seen: set[str] = set()
    for item in raw["targets"]:
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            raise ScopeError("Every approved target must have a host value.")
        host = normalize_host(item["host"])
        environment = item.get("environment")
        if not isinstance(environment, str) or environment not in {"staging", "lab"}:
            raise ScopeError(f"Target {host} must be marked staging or lab.")
        paths_value = item.get("paths", [])
        if not isinstance(paths_value, list) or len(paths_value) > MAX_PATHS:
            raise ScopeError(f"Target {host} may have at most {MAX_PATHS} approved paths.")
        paths = tuple(dict.fromkeys(validate_path(p) for p in paths_value if isinstance(p, str)))
        if len(paths) != len(paths_value):
            raise ScopeError(f"Target {host} has an invalid path entry.")
        if host in seen:
            raise ScopeError(f"Target {host} appears more than once in the approved target file.")
        seen.add(host)
        entries.append(
            ScopeEntry(
                host=host,
                environment=environment,
                paths=paths,
                allow_private=item.get("allow_private") is True,
            )
        )
    return entries


def find_scope_entry(host: str, entries: list[ScopeEntry]) -> ScopeEntry:
    normalized = normalize_host(host)
    for entry in entries:
        if entry.host == normalized:
            return entry
    raise ScopeError("That exact domain or IP is not in the approved target list.")


def validate_resolved_address(value: str, allow_private: bool) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ScopeError("DNS returned an invalid IP address.") from exc

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        validate_resolved_address(str(address.ipv4_mapped), allow_private)

    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ScopeError("The target resolves to a special-use address that this MVP will not scan.")
    if address.is_global:
        return address
    if address.is_private and allow_private:
        return address
    raise ScopeError("The target resolves to a private address; explicit private-target approval is required.")


_scope_write_lock = threading.Lock()

def save_scope(entries: list[dict[str, Any]]) -> list[ScopeEntry]:
    validated = parse_scope({"targets": entries})
    normalized = [{"host": e.host, "environment": e.environment, "paths": list(e.paths), "allow_private": e.allow_private} for e in validated]
    path = scope_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".scope-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"targets": normalized}, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return validated

def mutate_scope(host: str, value: dict[str, Any] | None) -> None:
    host = normalize_host(host)
    with _scope_write_lock:
        entries = [{"host": e.host, "environment": e.environment, "paths": list(e.paths), "allow_private": e.allow_private} for e in load_scope()]
        entries = [e for e in entries if e["host"] != host]
        if value is not None:
            if normalize_host(value["host"]) != host:
                raise ScopeError("The entry hostname must match the selected target.")
            entries.append(value)
        save_scope(entries)
