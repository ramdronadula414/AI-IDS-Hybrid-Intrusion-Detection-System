"""Persistent target configuration for dashboard-managed live monitoring.

This module describes *where the local AI-IDS sensor should listen*.  A domain
or IP target is converted into a passive BPF capture filter; it does not log in
to, scan, or otherwise interact with the target.
"""

from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
import os
from pathlib import Path
import socket
from typing import Any
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MONITORING_CONFIG_PATH = PROJECT_ROOT / "data" / "live" / "monitoring_config.json"

TARGET_TYPES = ["Entire Interface", "IP Address", "Domain / Website"]
PROTOCOLS = ["tcp", "udp"]

DEFAULT_MONITORING_CONFIG: dict[str, Any] = {
    "target_name": "Local Network",
    "target_type": "Entire Interface",
    "target_value": "",
    "interface": "eth0",
    "protocols": ["tcp", "udp"],
    "ports": "",
    "window_seconds": 10.0,
    "cooldown_seconds": 60.0,
    "keep_pcaps": False,
}


def _merge(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_monitoring_config(
    path: Path | str = DEFAULT_MONITORING_CONFIG_PATH,
) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return deepcopy(DEFAULT_MONITORING_CONFIG)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return deepcopy(DEFAULT_MONITORING_CONFIG)
    if not isinstance(payload, dict):
        return deepcopy(DEFAULT_MONITORING_CONFIG)
    return _merge(DEFAULT_MONITORING_CONFIG, payload)


def save_monitoring_config(
    config: dict[str, Any],
    path: Path | str = DEFAULT_MONITORING_CONFIG_PATH,
) -> Path:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    normalized = _merge(DEFAULT_MONITORING_CONFIG, config)
    tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(normalized, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    os.replace(tmp_path, config_path)
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass
    return config_path


def normalize_domain(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Domain / website is required")
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    hostname = (parsed.hostname or "").strip().rstrip(".")
    if not hostname:
        raise ValueError("Enter a valid website or domain name")
    return hostname


def parse_ports(value: str) -> list[int]:
    raw = value.strip()
    if not raw:
        return []
    ports: list[int] = []
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError as exc:
            raise ValueError(f"Invalid port: {token}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535: {port}")
        if port not in ports:
            ports.append(port)
    return ports


def resolve_target(config: dict[str, Any]) -> dict[str, Any]:
    """Validate target settings and return normalized target metadata."""
    target_type = str(config.get("target_type", "Entire Interface"))
    target_value = str(config.get("target_value", "")).strip()

    if target_type not in TARGET_TYPES:
        raise ValueError(f"Unsupported target type: {target_type}")

    if target_type == "Entire Interface":
        return {
            "target_type": target_type,
            "normalized_target": "Entire Interface",
            "addresses": [],
        }

    if target_type == "IP Address":
        if not target_value:
            raise ValueError("IP address is required")
        try:
            address = str(ipaddress.ip_address(target_value))
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 address") from exc
        return {
            "target_type": target_type,
            "normalized_target": address,
            "addresses": [address],
        }

    hostname = normalize_domain(target_value)
    try:
        info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve domain '{hostname}': {exc}") from exc

    addresses: list[str] = []
    for entry in info:
        address = entry[4][0]
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError:
            continue
        if normalized not in addresses:
            addresses.append(normalized)

    if not addresses:
        raise ValueError(f"No IP addresses were resolved for '{hostname}'")

    return {
        "target_type": target_type,
        "normalized_target": hostname,
        "addresses": addresses,
    }


def build_bpf_filter(config: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """Build a passive BPF filter from a monitoring target configuration."""
    resolved = resolve_target(config)

    protocols = [
        str(item).lower()
        for item in config.get("protocols", ["tcp", "udp"])
        if str(item).lower() in PROTOCOLS
    ]
    if not protocols:
        raise ValueError("Select at least one protocol")

    parts: list[str] = []
    if len(protocols) == 1:
        parts.append(protocols[0])
    else:
        parts.append("(" + " or ".join(protocols) + ")")

    addresses = resolved.get("addresses", [])
    if addresses:
        host_terms = [f"host {address}" for address in addresses]
        parts.append(host_terms[0] if len(host_terms) == 1 else "(" + " or ".join(host_terms) + ")")

    ports = parse_ports(str(config.get("ports", "")))
    if ports:
        port_terms = [f"port {port}" for port in ports]
        parts.append(port_terms[0] if len(port_terms) == 1 else "(" + " or ".join(port_terms) + ")")

    return (" and ".join(parts) if parts else None), resolved
