"""Small ingress web UI for issuing certificates. Python standard library only (+ cryptography)."""

from __future__ import annotations

import datetime as dt
import html
import io
import json
import os
import re
import traceback
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import pki
import renewer
import supervisor

OPTIONS_FILE = Path(os.environ.get("OPTIONS_FILE", "/data/options.json"))
PORT = int(os.environ.get("PORT", "8099"))
# Home Assistant ingress always connects from this address. Set ALLOWED_CLIENT="" to disable.
ALLOWED_CLIENT = os.environ.get("ALLOWED_CLIENT", "172.30.32.2")
MAX_BODY = 1024 * 1024

DEFAULTS = {
    "ca_cert": "/ssl/ca/ca.crt",
    "ca_key": "/ssl/ca/ca.key",
    "ca_key_password": "",
    "default_days": 365,
    "default_key_type": "ec-p256",
    "default_profile": "server",
    "renew_days_before": 30,
    "renew_with_new_key": True,
    "notifications": True,
}


def options() -> dict:
    try:
        return {**DEFAULTS, **json.loads(OPTIONS_FILE.read_text())}
    except (OSError, ValueError):
        return dict(DEFAULTS)


def load_ca(opts: dict) -> pki.CA:
    return pki.load_ca(opts["ca_cert"], opts["ca_key"], opts.get("ca_key_password") or None)


e = html.escape

CSS = """
:root{--bg:#fafafa;--fg:#212121;--card:#fff;--muted:#6b6b6b;--border:#e0e0e0;--accent:#03a9f4;
--err-bg:#fdecea;--err:#b71c1c;--ok-bg:#e8f5e9;--ok:#1b5e20;--warn-bg:#fff8e1;--warn:#8a6d00}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#e1e1e1;--card:#1c1c1c;--muted:#9b9b9b;
--border:#333;--err-bg:#3b1414;--err:#ffb4ab;--ok-bg:#12301a;--ok:#a5d6a7;--warn-bg:#3a3000;--warn:#ffe082}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:20px}h1{font-size:22px;margin:0 0 16px}
h2{font-size:17px;margin:0 0 12px}.card{background:var(--card);border:1px solid var(--border);
border-radius:12px;padding:18px;margin-bottom:16px}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:4px}
input,select,textarea{width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:8px;
background:var(--bg);color:var(--fg);font:inherit}textarea{font-family:ui-monospace,monospace;font-size:12px}
button,.btn{display:inline-block;padding:8px 14px;border-radius:8px;border:0;background:var(--accent);
color:#fff;font:inherit;cursor:pointer;text-decoration:none}.btn.secondary,button.secondary{background:transparent;
color:var(--accent);border:1px solid var(--accent)}button.danger{background:#d32f2f}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}.mt{margin-top:12px}
.msg{padding:10px 14px;border-radius:8px;margin-bottom:16px}.err{background:var(--err-bg);color:var(--err)}
.ok{background:var(--ok-bg);color:var(--ok)}.warn{background:var(--warn-bg);color:var(--warn)}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--border);
vertical-align:top}th{font-size:13px;color:var(--muted);font-weight:500}code,.mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:260px}
details summary{cursor:pointer;color:var(--accent)}a{color:var(--accent)}
h3{font-size:14px;margin:16px 0 6px}.check{display:flex;gap:8px;align-items:center;color:var(--fg);font-size:14px}
.check input{width:auto}.checks{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:4px 12px}
button.link{background:none;border:0;color:var(--accent);padding:0 4px;text-decoration:underline;font-size:13px}
.badge{font-size:12px;padding:2px 8px;border-radius:10px}.badge.on{background:var(--ok-bg);color:var(--ok)}
.badge.bad{background:var(--err-bg);color:var(--err)}
"""


def page(base: str, title: str, body: str, msg: str = "", kind: str = "ok") -> bytes:
    banner = f'<div class="msg {kind}">{e(msg)}</div>' if msg else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<style>{CSS}</style></head><body><main>
<h1><a href="{e(base)}/" style="color:inherit;text-decoration:none">X.509 Certificate Issuer</a></h1>
{banner}{body}</main></body></html>""".encode()


def fmt_date(iso: str) -> str:
    try:
        return dt.datetime.fromisoformat(iso).strftime("%Y-%m-%d")
    except ValueError:
        return iso


def select(name: str, choices: list[str], current: str) -> str:
    opts = "".join(
        f'<option value="{e(c)}"{" selected" if c == current else ""}>{e(c)}</option>' for c in choices
    )
    return f'<select name="{name}" id="{name}">{opts}</select>'


def subject_fields(prefix: str = "") -> str:
    fields = [("CN", "Common name (CN) *", "homeassistant.local"), ("O", "Organization (O)", ""),
              ("OU", "Org. unit (OU)", ""), ("C", "Country (C)", "DE"), ("ST", "State (ST)", ""),
              ("L", "Locality (L)", "")]
    return '<div class="grid">' + "".join(
        f'<div><label for="{prefix}{k}">{e(lbl)}</label><input id="{prefix}{k}" name="{k}" '
        f'placeholder="{e(ph)}"{" required" if k == "CN" else ""}></div>'
        for k, lbl, ph in fields
    ) + "</div>"


AUTO_RENEW_BOX = """<label class="check mt"><input type="checkbox" name="auto_renew" value="1" checked>
Renew automatically before it expires</label>"""


def index_page(base: str, msg: str, kind: str) -> bytes:
    opts = options()
    try:
        ca = load_ca(opts)
        ca_err = None
    except pki.PKIError as ex:
        ca, ca_err = None, str(ex)

    if ca:
        days_left = (ca.not_after - dt.datetime.now(dt.timezone.utc)).days
        ca_html = f"""<div class="card"><h2>Certificate authority</h2>
<table><tr><th>Subject</th><td class="mono">{e(ca.subject)}</td></tr>
<tr><th>Valid until</th><td>{ca.not_after:%Y-%m-%d %H:%M} UTC ({days_left} days left)</td></tr>
<tr><th>SHA-256</th><td class="mono">{e(ca.fingerprint)}</td></tr></table>
<div class="mt"><a class="btn secondary" href="{e(base)}/ca.crt">Download CA certificate</a></div></div>"""
    else:
        ca_html = f"""<div class="msg err"><b>CA not available.</b> {e(ca_err)}<br>
Set <code>ca_cert</code> and <code>ca_key</code> in the app's Configuration tab
(current: <code>{e(opts['ca_cert'])}</code>, <code>{e(opts['ca_key'])}</code>).</div>"""

    disabled = "" if ca else " disabled"
    issue = f"""<div class="card"><h2>Issue a new certificate</h2>
<form method="post" action="{e(base)}/issue">
{subject_fields("i_")}
<div class="mt"><label for="sans">Subject alternative names: DNS names, IP addresses or e-mails, separated by commas or spaces</label>
<input id="sans" name="sans" placeholder="homeassistant.local, 192.168.1.10, *.home.lan"></div>
<div class="grid mt">
<div><label for="key_type">Key type</label>{select("key_type", pki.KEY_TYPES, opts["default_key_type"])}</div>
<div><label for="profile">Usage</label>{select("profile", pki.PROFILES, opts["default_profile"])}</div>
<div><label for="days">Validity (days)</label><input id="days" name="days" type="number" min="1" max="3650" value="{int(opts["default_days"])}"></div>
<div><label for="name">Label (optional)</label><input id="name" name="name" placeholder="defaults to CN"></div>
</div>
{AUTO_RENEW_BOX}
<div class="mt"><button type="submit"{disabled}>Issue certificate</button></div></form></div>"""

    sign = f"""<div class="card"><details><summary><b>Sign a CSR instead</b> (the private key stays with you)</summary>
<form method="post" action="{e(base)}/sign" class="mt">
<label for="csr">Certificate signing request (PEM)</label>
<textarea id="csr" name="csr" rows="8" placeholder="-----BEGIN CERTIFICATE REQUEST-----" required></textarea>
<input type="file" accept=".csr,.pem,.req,.txt" class="mt" onchange="const f=this.files[0];if(f)f.text().then(t=>document.getElementById('csr').value=t)">
<div class="mt"><label for="csr_sans">Override SANs (optional; otherwise those in the CSR are used)</label>
<input id="csr_sans" name="sans"></div>
<div class="grid mt">
<div><label for="csr_profile">Usage</label>{select("profile", pki.PROFILES, opts["default_profile"]).replace('id="profile"', 'id="csr_profile"')}</div>
<div><label for="csr_days">Validity (days)</label><input id="csr_days" name="days" type="number" min="1" max="3650" value="{int(opts["default_days"])}"></div>
<div><label for="csr_name">Label (optional)</label><input id="csr_name" name="name"></div>
</div>
{AUTO_RENEW_BOX}
<div class="mt"><button type="submit"{disabled}>Sign CSR</button></div></form></details></div>"""

    entries = [m for m in pki.list_entries() if not m.get("superseded_by")]
    now = dt.datetime.now(dt.timezone.utc)
    if entries:
        rows = []
        for m in entries:
            expired = dt.datetime.fromisoformat(m["not_after"]) < now
            rows.append(
                f'<tr><td><a href="{e(base)}/cert/{e(m["serial"])}">{e(m.get("name") or m["subject"])}</a>'
                f'<div class="muted mono">{e(", ".join(m.get("sans", [])))}</div></td>'
                f'<td>{e(m.get("profile", ""))}</td>'
                f'<td>{fmt_date(m["not_after"])}{" <b>(expired)</b>" if expired else ""}</td>'
                f'<td>{renew_badge(m)}</td></tr>'
            )
        listing = ('<div class="card"><h2>Issued certificates</h2><table><tr><th>Name / SANs</th>'
                   '<th>Usage</th><th>Expires</th><th>Renewal</th></tr>' + "".join(rows) + "</table></div>")
    else:
        listing = '<div class="card"><h2>Issued certificates</h2><p class="muted">None yet.</p></div>'

    return page(base, "Certificates", ca_html + issue + sign + listing, msg, kind)


def renew_badge(m: dict) -> str:
    if m.get("last_error"):
        return '<span class="badge bad" title="' + e(m["last_error"]) + '">failing</span>'
    if m.get("auto_renew"):
        return '<span class="badge on">auto</span>'
    return '<span class="muted">manual</span>'


def renewal_card(base: str, serial: str, m: dict) -> str:
    if m.get("superseded_by"):
        return ""
    opts = options()
    targets = set(m.get("restart_targets", []))
    try:
        apps = supervisor.list_apps()
        app_err = ""
    except supervisor.SupervisorError as ex:
        apps, app_err = [], str(ex)
    choices = [(supervisor.CORE, "Home Assistant Core", "")] + [
        (a["slug"], a["name"], "" if a["state"] == "started" else " (not running)") for a in apps]
    known = {c[0] for c in choices}
    choices += [(t, t, " (not installed)") for t in sorted(targets - known)]
    boxes = "".join(
        f'<label class="check"><input type="checkbox" name="restart" value="{e(slug)}"'
        f'{" checked" if slug in targets else ""}>{e(name)}<span class="muted">{e(note)}</span></label>'
        for slug, name, note in choices)
    if app_err:
        boxes += f'<p class="muted">Could not list apps: {e(app_err)}</p>'

    folders = m.get("export_folders", [])
    if folders:
        folder_rows = "".join(
            f'<li><code>/ssl/{e(f)}/</code> <button class="link" name="folder" value="{e(f)}" '
            f'formaction="{e(base)}/untrack/{e(serial)}">stop updating</button></li>' for f in folders)
        folder_html = f"<ul>{folder_rows}</ul>"
    else:
        folder_html = '<p class="muted">None. Use "Copy to /ssl" below to add one.</p>'

    na = dt.datetime.fromisoformat(m["not_after"])
    nb = dt.datetime.fromisoformat(m["not_before"])
    window = min(dt.timedelta(days=int(opts["renew_days_before"])), (na - nb) / 3)
    when = (na - window).strftime("%Y-%m-%d")
    status = (f"Will renew on or after <b>{when}</b>." if m.get("auto_renew")
              else "Automatic renewal is off; you'll get a notification before it expires.")
    error = (f'<div class="msg err">Last renewal attempt failed: {e(m["last_error"])}</div>'
             if m.get("last_error") else "")
    key_box = (f'<label class="check"><input type="checkbox" name="renew_new_key" value="1"'
               f'{" checked" if m.get("renew_new_key", True) else ""}>Generate a new private key on renewal '
               f'(otherwise the current key is reused)</label>' if m.get("has_key") else
               '<p class="muted">Issued from a CSR: renewals re-certify the same public key.</p>')
    return f"""<div class="card"><h2>Renewal</h2>{error}<p>{status}</p>
<form method="post" action="{e(base)}/settings/{e(serial)}">
<label class="check"><input type="checkbox" name="auto_renew" value="1"{" checked" if m.get("auto_renew") else ""}>Renew automatically</label>
{key_box}
<h3>Kept up to date in /ssl</h3>{folder_html}
<h3>Restart after renewal</h3>
<p class="muted">So they load the new certificate. Apps that aren't running are skipped.</p>
<div class="checks">{boxes}</div>
<div class="row mt"><button type="submit">Save</button>
<button type="submit" class="secondary" formaction="{e(base)}/renew/{e(serial)}"
onclick="return confirm('Issue a new certificate now and run the renewal actions (update /ssl, restarts)?')">Renew now</button></div>
</form></div>"""


def cert_page(base: str, serial: str, msg: str, kind: str) -> bytes:
    m = pki.get_entry(serial)
    b = f"{base}"
    dl = lambda n, label: f'<a class="btn secondary" href="{e(b)}/download/{e(serial)}/{n}">{label}</a>'  # noqa: E731
    downloads = [dl("cert.pem", "Certificate"), dl("fullchain.pem", "Full chain"), dl("ca.pem", "CA")]
    if m["has_key"]:
        downloads.insert(1, dl("key.pem", "Private key"))
    downloads.append(dl("bundle.zip", "All as ZIP"))

    p12 = ""
    if m["has_key"]:
        p12 = f"""<div class="card"><h2>PKCS#12 / PFX</h2>
<p class="muted">For Windows, macOS, Android, browsers and Java keystores.</p>
<form method="post" action="{e(b)}/p12/{e(serial)}" class="row">
<div style="flex:1;min-width:200px"><label for="pw">Password</label><input id="pw" name="password" type="password" autocomplete="new-password"></div>
<label style="display:flex;gap:6px;align-items:center;margin:0 0 10px"><input type="checkbox" name="legacy" value="1" style="width:auto">Legacy encryption (3DES)</label>
<button type="submit">Download .p12</button></form></div>"""

    default_folder = re.sub(r"[^A-Za-z0-9._-]", "_", m.get("name") or serial)[:64].lstrip("._-") or serial
    export = f"""<div class="card"><h2>Copy to /ssl</h2>
<p class="muted">Writes <code>fullchain.pem</code>, <code>privkey.pem</code>, <code>cert.pem</code> and <code>chain.pem</code>
to <code>/ssl/&lt;folder&gt;/</code>, where Home Assistant and other apps can use them
(e.g. <code>ssl_certificate: /ssl/{e(default_folder)}/fullchain.pem</code>). Existing files are overwritten.</p>
<form method="post" action="{e(b)}/export/{e(serial)}" class="row">
<div style="flex:1;min-width:200px"><label for="folder">Folder</label><input id="folder" name="folder" value="{e(default_folder)}" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}"></div>
<label class="check" style="margin:0 0 10px"><input type="checkbox" name="track" value="1" checked>Keep updated on renewal</label>
<button type="submit">Copy</button></form></div>"""

    key_block = (f'<details class="mt"><summary>Show private key</summary><pre>{e(m["key_pem"])}</pre></details>'
                 if m["key_pem"] else "")
    lineage = ""
    if m.get("superseded_by"):
        lineage += (f'<div class="msg warn">This certificate has been renewed. '
                    f'<a href="{e(b)}/cert/{e(m["superseded_by"])}">Go to the current one</a>.</div>')
    if m.get("renewed_from"):
        lineage += (f'<p class="muted">Renewal of <a href="{e(b)}/cert/{e(m["renewed_from"])}">'
                    f'{e(m["renewed_from"])}</a>.</p>')
    body = f"""<div class="card"><h2>{e(m.get("name") or m["subject"])}</h2>{lineage}
<table><tr><th>Subject</th><td class="mono">{e(m["subject"])}</td></tr>
<tr><th>SANs</th><td class="mono">{e(", ".join(m["sans"])) or "–"}</td></tr>
<tr><th>Usage</th><td>{e(m.get("profile", ""))}{" · " + e(m["key_type"]) if m.get("key_type") else " · from CSR"}</td></tr>
<tr><th>Valid</th><td>{fmt_date(m["not_before"])} → {fmt_date(m["not_after"])}</td></tr>
<tr><th>Serial</th><td class="mono">{e(serial)}</td></tr>
<tr><th>SHA-256</th><td class="mono">{e(m["fingerprint"])}</td></tr></table>
<div class="row mt">{"".join(downloads)}</div>
<details class="mt"><summary>Show certificate PEM</summary><pre>{e(m["cert_pem"])}</pre></details>{key_block}
</div>{renewal_card(base, serial, m)}{p12}{export}
<div class="card"><form method="post" action="{e(b)}/delete/{e(serial)}" onsubmit="return confirm('Delete this certificate and its key from the app? This does not revoke it.')">
<button class="danger" type="submit">Delete</button>
<span class="muted"> Removes it from this list (and its stored key). Copies already in /ssl are kept.</span></form></div>"""
    return page(base, m.get("name") or "Certificate", body, msg, kind)


def form_int(form: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(form.get(key) or default)
    except ValueError:
        raise pki.PKIError(f"{key} must be a number.")
    if not lo <= v <= hi:
        raise pki.PKIError(f"{key} must be between {lo} and {hi}.")
    return v


def renewal_meta(form: dict, opts: dict, days: int) -> dict:
    return {"issued_at": pki.now_iso(), "days": days, "auto_renew": form.get("auto_renew") == "1",
            "renew_new_key": bool(opts["renew_with_new_key"]), "export_folders": [], "restart_targets": []}


class Handler(BaseHTTPRequestHandler):
    server_version = "x509-ca"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)

    # ------------------------------------------------------------ helpers
    @property
    def base(self) -> str:
        return self.headers.get("X-Ingress-Path", "").rstrip("/")

    def _allowed(self) -> bool:
        if ALLOWED_CLIENT and self.client_address[0] != ALLOWED_CLIENT:
            self.send_error(HTTPStatus.FORBIDDEN)
            return False
        return True

    def send(self, body: bytes, ctype="text/html; charset=utf-8", status=200, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition", f"attachment; filename=\"{filename}\"")
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, path: str, msg: str = "", kind: str = "ok"):
        loc = f"{self.base}{path}"
        if msg:
            loc += f"?{kind}={quote(msg)}"
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def read_form(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise pki.PKIError("Request too large.")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        lists = parse_qs(raw, keep_blank_values=True)
        form = {k: v[0] for k, v in lists.items()}
        form["_lists"] = lists
        return form

    def flash(self, query: str) -> tuple[str, str]:
        q = parse_qs(query)
        for kind in ("err", "warn", "ok"):
            if kind in q:
                return q[kind][0], kind
        return "", "ok"

    # ------------------------------------------------------------- routes
    def do_GET(self):
        if not self._allowed():
            return
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        msg, kind = self.flash(url.query)
        try:
            if path == "/":
                return self.send(index_page(self.base, msg, kind))
            if path == "/ca.crt":
                ca = load_ca(options())
                return self.send(ca.cert_pem, "application/x-pem-file", filename="ca.crt")
            if m := re.fullmatch(r"/cert/([0-9a-f]+)", path):
                return self.send(cert_page(self.base, m[1], msg, kind))
            if m := re.fullmatch(r"/download/([0-9a-f]+)/bundle\.zip", path):
                return self.send(*self.zip_bundle(m[1]))
            if m := re.fullmatch(r"/download/([0-9a-f]+)/([a-z.]+)", path):
                data, fname = pki.get_file(m[1], m[2])
                return self.send(data, "application/x-pem-file", filename=fname)
            self.send_error(HTTPStatus.NOT_FOUND)
        except pki.PKIError as ex:
            self.send(page(self.base, "Error", "", str(ex), "err"), status=400)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.send(page(self.base, "Error", "", "Internal error, see the app log.", "err"), status=500)

    def do_POST(self):
        if not self._allowed():
            return
        path = urlparse(self.path).path.rstrip("/")
        back = "/"
        try:
            if m := re.fullmatch(r"/(p12|export|delete|settings|renew|untrack)/([0-9a-f]+)", path):
                back = f"/cert/{m[2]}"
            form = self.read_form()
            with pki.LOCK:
                return self.route_post(path, form, back)
        except pki.PKIError as ex:
            self.redirect(back, str(ex), "err")
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.redirect(back, "Internal error, see the app log.", "err")

    def route_post(self, path: str, form: dict, back: str):
        if path == "/issue":
            return self.issue(form)
        if path == "/sign":
            return self.sign(form)
        if m := re.fullmatch(r"/p12/([0-9a-f]+)", path):
            data, fname = pki.make_pkcs12(m[1], form.get("password", ""), form.get("legacy") == "1")
            return self.send(data, "application/x-pkcs12", filename=fname)
        if m := re.fullmatch(r"/export/([0-9a-f]+)", path):
            target = pki.export_to_ssl(m[1], form.get("folder", ""), track=form.get("track") == "1")
            return self.redirect(back, f"Files written to {target}/")
        if m := re.fullmatch(r"/settings/([0-9a-f]+)", path):
            targets = [t for t in form["_lists"].get("restart", []) if re.fullmatch(r"[a-z0-9_]+", t)]
            pki.update_meta(m[1], auto_renew=form.get("auto_renew") == "1",
                            renew_new_key=form.get("renew_new_key") == "1",
                            restart_targets=targets, notified_expiring=False, last_error=None)
            return self.redirect(back, "Renewal settings saved.")
        if m := re.fullmatch(r"/untrack/([0-9a-f]+)", path):
            meta = pki.read_meta(m[1])
            pki.update_meta(m[1], export_folders=[f for f in meta.get("export_folders", [])
                                                  if f != form.get("folder")])
            return self.redirect(back, f"/ssl/{form.get('folder')} will no longer be updated (files are kept).")
        if m := re.fullmatch(r"/renew/([0-9a-f]+)", path):
            new = renewer.renew_now(m[1], options())
            meta = pki.read_meta(new)
            extra = " Restarts are running in the background." if meta.get("restart_targets") else ""
            return self.redirect(f"/cert/{new}", f"Certificate renewed.{extra}")
        if m := re.fullmatch(r"/delete/([0-9a-f]+)", path):
            pki.delete_entry(m[1])
            return self.redirect("/", "Certificate deleted.")
        self.send_error(HTTPStatus.NOT_FOUND)

    # ------------------------------------------------------------ actions
    def issue(self, form: dict):
        opts = options()
        ca = load_ca(opts)
        key_type = form.get("key_type") or opts["default_key_type"]
        if key_type not in pki.KEY_TYPES:
            raise pki.PKIError("Unknown key type.")
        subject = pki.build_subject(form)
        sans = pki.parse_sans(form.get("sans", ""))
        days = form_int(form, "days", opts["default_days"], 1, 3650)
        profile = form.get("profile") or opts["default_profile"]
        key = pki.generate_key(key_type)
        cert, clamped = pki.build_certificate(ca, subject, key.public_key(), sans, days, profile)
        serial = pki.store(cert, key, ca, {
            "name": (form.get("name") or form.get("CN") or "").strip(),
            "profile": profile, "key_type": key_type, **renewal_meta(form, opts, days),
        })
        print(f"Issued {cert.subject.rfc4514_string()} serial={serial}", flush=True)
        self.after_issue(serial, clamped)

    def sign(self, form: dict):
        opts = options()
        ca = load_ca(opts)
        csr = pki.load_csr(form.get("csr", ""))
        sans = pki.parse_sans(form["sans"]) if form.get("sans", "").strip() else pki.csr_sans(csr)
        days = form_int(form, "days", opts["default_days"], 1, 3650)
        profile = form.get("profile") or opts["default_profile"]
        if len(csr.subject) == 0 and not sans:
            raise pki.PKIError("The CSR has neither a subject nor SANs.")
        cert, clamped = pki.build_certificate(ca, csr.subject, csr.public_key(), sans, days, profile)
        cns = [a.value for a in csr.subject if a.oid == pki.NameOID.COMMON_NAME]
        serial = pki.store(cert, None, ca, {
            "name": (form.get("name") or (cns[0] if cns else "")).strip(),
            "profile": profile, "key_type": None, **renewal_meta(form, opts, days),
        })
        print(f"Signed CSR {cert.subject.rfc4514_string()} serial={serial}", flush=True)
        self.after_issue(serial, clamped)

    def after_issue(self, serial: str, clamped: bool):
        if clamped:
            self.redirect(f"/cert/{serial}", "Issued. Validity was shortened so it does not outlive the CA certificate.", "warn")
        else:
            self.redirect(f"/cert/{serial}", "Certificate issued.")

    def zip_bundle(self, serial: str):
        m = pki.get_entry(serial)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("cert.pem", m["cert_pem"])
            z.writestr("chain.pem", m["ca_pem"])
            z.writestr("fullchain.pem", m["cert_pem"] + m["ca_pem"])
            if m["key_pem"]:
                z.writestr("privkey.pem", m["key_pem"])
        _, fname = pki.get_file(serial, "cert.pem")
        return buf.getvalue(), "application/zip", 200, fname.rsplit(".", 1)[0] + ".zip"


def main():
    pki.ISSUED_DIR.mkdir(parents=True, exist_ok=True)
    opts = options()
    try:
        ca = load_ca(opts)
        print(f"CA loaded: {ca.subject} (valid until {ca.not_after:%Y-%m-%d})", flush=True)
    except pki.PKIError as ex:
        print(f"WARNING: {ex}", flush=True)
    renewer.start(options)
    print(f"Listening on port {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
