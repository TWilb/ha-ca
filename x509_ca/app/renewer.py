"""Periodic renewal: renew due certificates, refresh /ssl copies, restart apps, notify."""

from __future__ import annotations

import datetime as dt
import os
import threading
import time
import traceback

import pki
import supervisor

CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", str(6 * 3600)))
FIRST_CHECK_DELAY = int(os.environ.get("FIRST_CHECK_DELAY", "60"))


def log(msg: str) -> None:
    print(f"[renewal] {msg}", flush=True)


def _label(meta: dict) -> str:
    return meta.get("name") or meta.get("subject") or meta["serial"]


class Batch:
    """Collects restarts and notifications so each target restarts only once per run."""

    def __init__(self, opts: dict):
        self.notify_enabled = bool(opts.get("notifications", True))
        self.restarts: set[str] = set()
        self.notes: list[tuple[str, str, str]] = []  # (title, message, id)
        self.dismiss: list[str] = []

    def note(self, title: str, message: str, nid: str) -> None:
        log(f"{title}: {message}")
        self.notes.append((title, message, nid))

    def finish(self) -> None:
        results = []
        # Apps first, Home Assistant Core last: its restart drops notifications, so
        # notifications are sent after Core is back up.
        for target in sorted(self.restarts, key=lambda t: t == supervisor.CORE):
            try:
                results.append(supervisor.restart(target))
            except supervisor.SupervisorError as e:
                results.append(f"Restart of {target} failed: {e}")
            log(results[-1])
        if supervisor.CORE in self.restarts:
            supervisor.wait_for_core()
        if results:
            self.notes.append(("Restarts after certificate renewal",
                               "\n".join(f"- {r}" for r in results), "x509_ca_restarts"))
        if not (self.notify_enabled and supervisor.available()):
            return
        for nid in self.dismiss:
            try:
                supervisor.dismiss(nid)
            except supervisor.SupervisorError:
                pass
        for title, message, nid in self.notes:
            try:
                supervisor.notify(title, message, nid)
            except supervisor.SupervisorError as e:
                log(f"Could not send notification: {e}")


def _renew_one(meta: dict, ca: pki.CA, batch: Batch, manual: bool = False) -> str:
    old = meta["serial"]
    new, clamped = pki.renew(old, ca, require_extension=not manual)
    new_meta = pki.read_meta(new)
    lines = [f"New certificate valid until {new_meta['not_after'][:10]}."]
    if clamped:
        lines.append(f"Validity was shortened to the CA's expiry ({ca.not_after:%Y-%m-%d}). Renew your CA soon.")
    for folder in new_meta.get("export_folders", []):
        try:
            target = pki.export_to_ssl(new, folder)
            lines.append(f"Updated `{target}/`.")
        except (pki.PKIError, OSError) as e:
            lines.append(f"Could not update /ssl/{folder}: {e}")
    batch.restarts.update(new_meta.get("restart_targets", []))
    batch.dismiss += [f"x509_ca_expiring_{old}", f"x509_ca_failed_{old}"]
    batch.note(f"Certificate renewed: {_label(meta)}", "\n".join(lines), f"x509_ca_renewed_{new}")
    return new


def run_check(opts: dict, at: dt.datetime | None = None) -> Batch:
    """One renewal pass. `at` overrides the current time (for testing)."""
    at = at or pki.now()
    batch = Batch(opts)
    ca: pki.CA | None = None
    with pki.LOCK:
        for meta in pki.list_entries():
            serial = meta["serial"]
            try:
                if meta.get("superseded_by"):
                    # Old versions are kept until they expire, then cleaned up.
                    if dt.datetime.fromisoformat(meta["not_after"]) < at:
                        pki.delete_entry(serial)
                        log(f"Removed expired, superseded certificate {serial}")
                    continue
                if not pki.renewal_due(meta, int(opts.get("renew_days_before", 30)), at):
                    continue
                if meta.get("auto_renew"):
                    if ca is None:
                        ca = pki.load_ca(opts["ca_cert"], opts["ca_key"], opts.get("ca_key_password") or None)
                    _renew_one(meta, ca, batch)
                elif not meta.get("notified_expiring"):
                    expired = dt.datetime.fromisoformat(meta["not_after"]) < at
                    batch.note(
                        f"Certificate {'expired' if expired else 'expiring'}: {_label(meta)}",
                        f"{'Expired' if expired else 'Expires'} on {meta['not_after'][:10]}. "
                        "Automatic renewal is off for this certificate.",
                        f"x509_ca_expiring_{serial}")
                    pki.update_meta(serial, notified_expiring=True)
            except Exception as e:  # noqa: BLE001
                if not isinstance(e, pki.PKIError):
                    traceback.print_exc()
                err = str(e)
                if meta.get("last_error") != err:  # don't repeat the same failure every run
                    pki.update_meta(serial, last_error=err)
                    batch.note(f"Certificate renewal failed: {_label(meta)}",
                               f"{err}\n\nIt expires on {meta['not_after'][:10]}.",
                               f"x509_ca_failed_{serial}")
    batch.finish()
    return batch


def renew_now(serial: str, opts: dict) -> str:
    """Manual renewal from the UI. Restarts and notifications run in the background."""
    batch = Batch(opts)
    with pki.LOCK:
        meta = pki.read_meta(serial)
        meta["serial"] = serial
        ca = pki.load_ca(opts["ca_cert"], opts["ca_key"], opts.get("ca_key_password") or None)
        new = _renew_one(meta, ca, batch, manual=True)
    threading.Thread(target=batch.finish, daemon=True).start()
    return new


def start(get_options) -> None:
    def loop():
        time.sleep(FIRST_CHECK_DELAY)
        while True:
            try:
                run_check(get_options())
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(CHECK_INTERVAL)

    threading.Thread(target=loop, name="renewal", daemon=True).start()
    log(f"Checking every {CHECK_INTERVAL // 3600} h")
