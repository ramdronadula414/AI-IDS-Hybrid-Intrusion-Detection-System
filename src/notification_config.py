"""Persistent local notification configuration for AI-IDS.

The dashboard writes this file and the live monitor reads it dynamically on
alert delivery.  The file is intentionally stored under data/live, excluded
from Git, and created with owner-only permissions where the platform supports
POSIX file modes.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "data" / "live" / "notification_config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "channels": ["console"],
    "minimum_severity": "LOW",
    "telegram": {
        "bot_token": "",
        "chat_id": "",
    },
    "discord": {
        "webhook_url": "",
    },
    "email": {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_address": "",
        "to_addresses": "",
        "use_ssl": False,
        "use_starttls": True,
    },
}


def _merge(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_notification_config(
    path: Path | str = DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return deepcopy(DEFAULT_CONFIG)

    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return deepcopy(DEFAULT_CONFIG)

    if not isinstance(payload, dict):
        return deepcopy(DEFAULT_CONFIG)
    return _merge(DEFAULT_CONFIG, payload)


def save_notification_config(
    config: dict[str, Any],
    path: Path | str = DEFAULT_CONFIG_PATH,
) -> Path:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    normalized = _merge(DEFAULT_CONFIG, config)

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
