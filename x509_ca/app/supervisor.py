"""Minimal Home Assistant Supervisor API client (restarts and notifications)."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

URL = os.environ.get("SUPERVISOR_URL", "http://supervisor").rstrip("/")
CORE = "homeassistant"  # restart target meaning "Home Assistant Core"


class SupervisorError(Exception):
    pass


def available() -> bool:
    return bool(os.environ.get("SUPERVISOR_TOKEN"))


def _call(method: str, path: str, body: dict | None = None, timeout: float = 30):
    if not available():
        raise SupervisorError("Supervisor API not available (not running inside Home Assistant).")
    req = urllib.request.Request(
        URL + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {os.environ['SUPERVISOR_TOKEN']}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        try:
            detail = json.loads(detail).get("message") or detail
        except (ValueError, AttributeError):
            pass
        raise SupervisorError(f"{method} {path} failed: HTTP {e.code} {detail}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SupervisorError(f"{method} {path} failed: {e}") from e
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return data.get("data", data) if isinstance(data, dict) else data


_self_slug: str | None = None


def self_slug() -> str:
    global _self_slug
    if _self_slug is None:
        _self_slug = _call("GET", "/addons/self/info", timeout=10).get("slug", "")
    return _self_slug


def list_apps() -> list[dict]:
    """Installed apps except this one: [{slug, name, state}]."""
    apps = _call("GET", "/addons", timeout=10).get("addons", [])
    me = self_slug()
    return sorted(
        ({"slug": a["slug"], "name": a.get("name", a["slug"]), "state": a.get("state")}
         for a in apps if a.get("slug") != me and a.get("installed", True)),
        key=lambda a: a["name"].lower(),
    )


def restart(target: str) -> str:
    """Restart Home Assistant Core or an app. Returns a short human-readable result."""
    if target == CORE:
        _call("POST", "/core/restart", timeout=600)
        return "Home Assistant restarted"
    info = _call("GET", f"/addons/{target}/info", timeout=10)
    name = info.get("name", target)
    if info.get("state") != "started":
        return f"{name} skipped (not running)"
    _call("POST", f"/addons/{target}/restart", timeout=300)
    return f"{name} restarted"


def wait_for_core(timeout: float = 600) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _call("GET", "/core/api/", timeout=10)
            return True
        except SupervisorError:
            time.sleep(10)
    return False


def notify(title: str, message: str, notification_id: str) -> None:
    _call("POST", "/core/api/services/persistent_notification/create",
          {"title": title, "message": message, "notification_id": notification_id}, timeout=15)


def dismiss(notification_id: str) -> None:
    _call("POST", "/core/api/services/persistent_notification/dismiss",
          {"notification_id": notification_id}, timeout=15)
