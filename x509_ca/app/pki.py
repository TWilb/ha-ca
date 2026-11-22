"""Certificate issuing logic built on the `cryptography` package."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
ISSUED_DIR = DATA_DIR / "issued"
SSL_DIR = Path(os.environ.get("SSL_DIR", "/ssl"))

KEY_TYPES = ["ec-p256", "ec-p384", "rsa-2048", "rsa-3072", "rsa-4096", "ed25519"]
PROFILES = ["server", "client", "server+client"]
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Serialises every change to the certificate store (web requests and the renewal thread).
LOCK = threading.RLock()


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def now_iso() -> str:
    return now().isoformat()


class PKIError(Exception):
    """An error that is safe and useful to show to the user."""


# --------------------------------------------------------------------------- CA


@dataclass
class CA:
    cert: x509.Certificate
    key: object
    cert_pem: bytes

    @property
    def subject(self) -> str:
        return self.cert.subject.rfc4514_string()

    @property
    def not_after(self) -> dt.datetime:
        return self.cert.not_valid_after_utc

    @property
    def fingerprint(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex(":").upper()


def load_ca(cert_path: str, key_path: str, password: str | None) -> CA:
    try:
        cert_data = Path(cert_path).read_bytes()
    except OSError as e:
        raise PKIError(f"Cannot read CA certificate '{cert_path}': {e.strerror}") from e
    try:
        key_data = Path(key_path).read_bytes()
    except OSError as e:
        raise PKIError(f"Cannot read CA key '{key_path}': {e.strerror}") from e

    try:
        if b"-----BEGIN" in cert_data:
            # A bundle may contain several certificates; the first one is the CA.
            cert = x509.load_pem_x509_certificates(cert_data)[0]
        else:
            cert = x509.load_der_x509_certificate(cert_data)
    except ValueError as e:
        raise PKIError(f"CA certificate is not a valid PEM/DER certificate: {e}") from e

    pw = password.encode() if password else None
    try:
        if b"-----BEGIN" in key_data:
            key = serialization.load_pem_private_key(key_data, password=pw)
        else:
            key = serialization.load_der_private_key(key_data, password=pw)
    except TypeError as e:
        raise PKIError(
            "CA key is encrypted but no password was configured, or a password "
            "was configured for an unencrypted key."
        ) from e
    except ValueError as e:
        raise PKIError(f"Cannot load CA key (wrong password or bad format): {e}") from e

    pub = lambda k: k.public_bytes(  # noqa: E731
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if pub(key.public_key()) != pub(cert.public_key()):
        raise PKIError("The CA key does not match the CA certificate.")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            raise PKIError("The configured certificate is not a CA (basicConstraints CA:FALSE).")
    except x509.ExtensionNotFound:
        pass  # Old-style v1 CA certificates have no extensions; allow them.

    return CA(cert=cert, key=key, cert_pem=cert.public_bytes(serialization.Encoding.PEM))


# ------------------------------------------------------------------- building


def generate_key(key_type: str):
    if key_type == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ec-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if key_type.startswith("rsa-"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[4:]))
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise PKIError(f"Unknown key type: {key_type}")


def parse_sans(text: str) -> list[x509.GeneralName]:
    """Parse SANs separated by commas/whitespace. IPs and e-mail addresses are detected."""
    names: list[x509.GeneralName] = []
    seen = set()
    for raw in re.split(r"[,\s]+", text or ""):
        item = raw.strip()
        if not item or item.lower() in seen:
            continue
        seen.add(item.lower())
        for prefix in ("DNS:", "IP:", "email:", "URI:"):
            if item.lower().startswith(prefix.lower()):
                kind, item = prefix[:-1].upper(), item[len(prefix):]
                break
        else:
            kind = None
        try:
            if kind in (None, "IP"):
                names.append(x509.IPAddress(ipaddress.ip_address(item)))
                continue
        except ValueError:
            if kind == "IP":
                raise PKIError(f"Invalid IP address in SANs: {item}")
        if kind == "EMAIL" or (kind is None and "@" in item):
            names.append(x509.RFC822Name(item))
        elif kind == "URI":
            names.append(x509.UniformResourceIdentifier(item))
        else:
            if not re.fullmatch(r"(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?", item):
                raise PKIError(f"Invalid DNS name in SANs: {item}")
            names.append(x509.DNSName(item.rstrip(".").lower()))
    return names


def build_subject(fields: dict) -> x509.Name:
    mapping = [
        ("C", NameOID.COUNTRY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("L", NameOID.LOCALITY_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("CN", NameOID.COMMON_NAME),
    ]
    attrs = []
    for key, oid in mapping:
        value = (fields.get(key) or "").strip()
        if not value:
            continue
        if key == "C" and not re.fullmatch(r"[A-Za-z]{2}", value):
            raise PKIError("Country (C) must be a two-letter code, e.g. DE.")
        if len(value) > 64:
            raise PKIError(f"Subject field {key} is longer than 64 characters.")
        attrs.append(x509.NameAttribute(oid, value.upper() if key == "C" else value))
    if not attrs:
        raise PKIError("The subject needs at least a Common Name (CN).")
    return x509.Name(attrs)


def _sign_hash(ca_key):
    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    if isinstance(ca_key, ec.EllipticCurvePrivateKey) and ca_key.curve.key_size >= 384:
        return hashes.SHA384()
    return hashes.SHA256()


def build_certificate(ca: CA, subject: x509.Name, public_key, sans, days: int, profile: str):
    if profile not in PROFILES:
        raise PKIError(f"Unknown profile: {profile}")
    current = now()
    not_before = current - dt.timedelta(minutes=5)
    not_after = current + dt.timedelta(days=days)
    clamped = False
    if not_after > ca.not_after:
        not_after = ca.not_after
        clamped = True
    if not_after <= current:
        raise PKIError("The CA certificate has expired; it cannot issue certificates.")

    if profile in ("server", "server+client") and not sans:
        # Modern TLS clients ignore the CN and require a SAN.
        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            sans = parse_sans(cn[0].value)

    is_rsa = isinstance(public_key, rsa.RSAPublicKey)
    eku = []
    if "server" in profile:
        eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if "client" in profile:
        eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(public_key)
        .serial_number(int.from_bytes(secrets.token_bytes(19), "big") >> 1 or 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=is_rsa,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    try:
        ski = ca.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key())
    builder = builder.add_extension(aki, critical=False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    cert = builder.sign(ca.key, _sign_hash(ca.key))
    return cert, clamped


def load_csr(pem: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr(pem.strip().encode())
    except ValueError as e:
        raise PKIError(f"Not a valid PEM certificate signing request: {e}") from e
    if not csr.is_signature_valid:
        raise PKIError("The CSR signature is invalid.")
    return csr


def csr_sans(csr: x509.CertificateSigningRequest) -> list[x509.GeneralName]:
    try:
        return list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


# -------------------------------------------------------------------- storage


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def store(cert: x509.Certificate, key, ca: CA, meta: dict) -> str:
    serial = format(cert.serial_number, "x")
    d = ISSUED_DIR / serial
    d.mkdir(parents=True, exist_ok=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    (d / "cert.pem").write_bytes(cert_pem)
    (d / "ca.pem").write_bytes(ca.cert_pem)
    if key is not None:
        kp = d / "key.pem"
        kp.touch(mode=0o600)
        kp.write_bytes(_key_pem(key))
    meta = {
        **meta,
        "serial": serial,
        "subject": cert.subject.rfc4514_string(),
        "sans": [str(n.value) for n in _sans_of(cert)],
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "has_key": key is not None,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }
    (d / "meta.json").write_text(json.dumps(meta, indent=2))
    return serial


def _sans_of(cert):
    try:
        return list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


def _entry_dir(serial: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{1,64}", serial or ""):
        raise PKIError("Invalid serial.")
    d = ISSUED_DIR / serial
    if not d.is_dir():
        raise PKIError("Certificate not found.")
    return d


def read_meta(serial: str) -> dict:
    return json.loads((_entry_dir(serial) / "meta.json").read_text())


def update_meta(serial: str, **changes) -> dict:
    d = _entry_dir(serial)
    meta = json.loads((d / "meta.json").read_text())
    meta.update(changes)
    tmp = d / "meta.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(d / "meta.json")
    return meta


def get_entry(serial: str) -> dict:
    d = _entry_dir(serial)
    meta = json.loads((d / "meta.json").read_text())
    meta["cert_pem"] = (d / "cert.pem").read_text()
    meta["key_pem"] = (d / "key.pem").read_text() if (d / "key.pem").exists() else None
    meta["ca_pem"] = (d / "ca.pem").read_text()
    return meta


def list_entries() -> list[dict]:
    if not ISSUED_DIR.is_dir():
        return []
    out = []
    for d in ISSUED_DIR.iterdir():
        try:
            out.append(json.loads((d / "meta.json").read_text()))
        except (OSError, ValueError):
            continue
    out.sort(key=lambda m: m.get("issued_at", ""), reverse=True)
    return out


def delete_entry(serial: str) -> None:
    shutil.rmtree(_entry_dir(serial))


def get_file(serial: str, name: str) -> tuple[bytes, str]:
    """Return (content, filename) for a downloadable artefact."""
    e = get_entry(serial)
    base = _file_base(e)
    if name == "cert.pem":
        return e["cert_pem"].encode(), f"{base}.crt"
    if name == "key.pem" and e["key_pem"]:
        return e["key_pem"].encode(), f"{base}.key"
    if name == "fullchain.pem":
        return (e["cert_pem"] + e["ca_pem"]).encode(), f"{base}-fullchain.pem"
    if name == "ca.pem":
        return e["ca_pem"].encode(), "ca.crt"
    raise PKIError("File not found.")


def _file_base(e: dict) -> str:
    name = e.get("name") or e["serial"]
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:64] or e["serial"]


def make_pkcs12(serial: str, password: str, legacy: bool) -> tuple[bytes, str]:
    e = get_entry(serial)
    if not e["key_pem"]:
        raise PKIError("No private key is stored for this certificate (it was issued from a CSR).")
    key = serialization.load_pem_private_key(e["key_pem"].encode(), password=None)
    cert = x509.load_pem_x509_certificate(e["cert_pem"].encode())
    ca_cert = x509.load_pem_x509_certificate(e["ca_pem"].encode())
    if not password:
        enc = serialization.NoEncryption()
    elif legacy:
        # 3DES/SHA1 for old Android, macOS < 14, Java 8 and other legacy importers.
        enc = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(password.encode())
        )
    else:
        enc = serialization.BestAvailableEncryption(password.encode())
    data = pkcs12.serialize_key_and_certificates(
        _file_base(e).encode(), key, cert, [ca_cert], enc
    )
    return data, f"{_file_base(e)}.p12"


def export_to_ssl(serial: str, folder: str, track: bool = False) -> Path:
    """Write fullchain.pem / privkey.pem / cert.pem / chain.pem into /ssl/<folder>/."""
    if not SAFE_NAME.fullmatch(folder or ""):
        raise PKIError("Folder name may only contain letters, digits, '.', '_' and '-'.")
    e = get_entry(serial)
    target = SSL_DIR / folder
    target.mkdir(parents=True, exist_ok=True)
    (target / "cert.pem").write_text(e["cert_pem"])
    (target / "chain.pem").write_text(e["ca_pem"])
    (target / "fullchain.pem").write_text(e["cert_pem"] + e["ca_pem"])
    if e["key_pem"]:
        kp = target / "privkey.pem"
        kp.touch(mode=0o600)
        kp.write_text(e["key_pem"])
    if track and folder not in e.get("export_folders", []):
        update_meta(serial, export_folders=[*e.get("export_folders", []), folder])
    return target


# -------------------------------------------------------------------- renewal


def key_type_of(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"rsa-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {256: "ec-p256", 384: "ec-p384"}.get(key.curve.key_size, "ec-p256")
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ed25519"
    return "ec-p256"


# Settings that a renewed certificate inherits from its predecessor.
CARRY_OVER = ("name", "profile", "key_type", "days", "auto_renew", "renew_new_key",
              "export_folders", "restart_targets")


def renew(serial: str, ca: CA, require_extension: bool = True) -> tuple[str, bool]:
    """Issue a successor for `serial` with the same subject, SANs, usage and lifetime.

    Returns (new_serial, clamped). The old entry is marked as superseded.
    """
    with LOCK:
        e = get_entry(serial)
        if e.get("superseded_by"):
            raise PKIError("This certificate has already been renewed.")
        old = x509.load_pem_x509_certificate(e["cert_pem"].encode())
        if e["key_pem"]:
            old_key = serialization.load_pem_private_key(e["key_pem"].encode(), password=None)
            key = generate_key(e.get("key_type") or key_type_of(old_key)) if e.get("renew_new_key", True) else old_key
            public_key = key.public_key()
        else:  # issued from a CSR: re-certify the same public key
            key, public_key = None, old.public_key()
        days = e.get("days") or max(1, round(
            (old.not_valid_after_utc - old.not_valid_before_utc).total_seconds() / 86400))
        cert, clamped = build_certificate(ca, old.subject, public_key, _sans_of(old), days,
                                          e.get("profile", "server"))
        if require_extension and cert.not_valid_after_utc <= old.not_valid_after_utc + dt.timedelta(days=1):
            raise PKIError(
                f"The CA certificate expires on {ca.not_after:%Y-%m-%d}, so a renewed certificate "
                "would not last longer than the current one. Renew the CA certificate first.")
        meta = {k: e[k] for k in CARRY_OVER if k in e}
        new_serial = store(cert, key, ca, {**meta, "issued_at": now_iso(), "renewed_from": serial})
        update_meta(serial, superseded_by=new_serial, auto_renew=False)
        return new_serial, clamped


def renewal_due(meta: dict, days_before: int, at: dt.datetime | None = None) -> bool:
    """Due when inside the renewal window: `days_before`, but at most a third of the lifetime."""
    at = at or now()
    nb, na = dt.datetime.fromisoformat(meta["not_before"]), dt.datetime.fromisoformat(meta["not_after"])
    window = min(dt.timedelta(days=days_before), (na - nb) / 3)
    return na - at <= window
