# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from datetime import timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from common import APP_NAME, APP_VERSION, REPOSITORY_URL, ensure_dir, iso_now, sanitize_component, safe_exception, write_json, write_text


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    out: dict[str, str] = {}
    for attr in name:
        key = attr.oid._name or attr.oid.dotted_string
        if key in out:
            out[key] = f"{out[key]}; {attr.value}"
        else:
            out[key] = str(attr.value)
    return out


def _dt_text(value) -> str:
    if value is None:
        return ""
    try:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    except Exception:
        return str(value)


def _san_values(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    values: list[str] = []
    for item in ext:
        value = getattr(item, "value", item)
        if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            values.append(f"IP:{value}")
        else:
            prefix = "DNS:" if isinstance(item, x509.DNSName) else ""
            values.append(prefix + str(value))
    return values


def _cert_info(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    key_bits = getattr(pub, "key_size", None)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
    return {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": _dt_text(not_before),
        "not_after": _dt_text(not_after),
        "signature_algorithm": cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string,
        "public_key_bits": key_bits,
        "san": _san_values(cert),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "sha1_fingerprint": hashlib.sha1(der).hexdigest(),
    }


def _chain_item_to_der(item: Any) -> bytes:
    if isinstance(item, (bytes, bytearray, memoryview)):
        raw = bytes(item)
    elif hasattr(item, "public_bytes"):
        raw = item.public_bytes()
        if isinstance(raw, str):
            raw = raw.encode("ascii")
    else:
        raise TypeError(f"Unbekannter Zertifikatstyp in TLS-Kette: {type(item).__name__}")
    if raw.startswith(b"-----BEGIN CERTIFICATE-----"):
        return ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
    return raw


def capture_tls_host(host: str, output_dir: Path, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    output_dir = ensure_dir(output_dir)
    host = host.strip().lower().rstrip(".")
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "captured_at": iso_now(),
        "source": "direkter TLS-Handshake über Python ssl; Zertifikatsprüfung deaktiviert",
    }
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            peer_ip = raw_sock.getpeername()[0]
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cipher = tls_sock.cipher()
                chain_der: list[bytes] = []
                chain_method = "leaf certificate via getpeercert(binary_form=True)"

                get_chain = getattr(tls_sock, "get_unverified_chain", None)
                if callable(get_chain):
                    try:
                        raw_chain = get_chain() or []
                        chain_der = [_chain_item_to_der(item) for item in raw_chain]
                        if chain_der:
                            chain_method = "unverified server chain via ssl.SSLSocket.get_unverified_chain()"
                    except Exception as chain_exc:
                        result["chain_warning"] = safe_exception(chain_exc)

                if not chain_der:
                    leaf = tls_sock.getpeercert(binary_form=True)
                    if leaf:
                        chain_der = [bytes(leaf)]

                if not chain_der:
                    raise RuntimeError("Der Server hat beim TLS-Handshake kein Zertifikat geliefert.")

                result.update({
                    "ok": True,
                    "peer_ip": peer_ip,
                    "tls_version": tls_sock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "cipher_protocol": cipher[1] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "chain_capture": chain_method,
                    "chain": [],
                })

                host_dir = ensure_dir(output_dir / sanitize_component(host))
                for idx, der in enumerate(chain_der):
                    info = _cert_info(der)
                    stem = "leaf" if idx == 0 else f"chain_{idx:02d}"
                    der_path = host_dir / f"{stem}.der"
                    pem_path = host_dir / f"{stem}.pem"
                    der_path.write_bytes(der)
                    pem_path.write_text(ssl.DER_cert_to_PEM_cert(der), encoding="ascii")
                    info["der_file"] = f"{sanitize_component(host)}/{stem}.der"
                    info["pem_file"] = f"{sanitize_component(host)}/{stem}.pem"
                    result["chain"].append(info)
    except Exception as exc:
        result["ok"] = False
        result["error"] = safe_exception(exc)
    return result


def capture_tls(hosts: list[str], output_dir: Path) -> dict[str, Any]:
    output_dir = ensure_dir(output_dir)
    selected: list[str] = []
    for host in hosts:
        host = host.strip().lower().rstrip(".")
        if host and host not in selected:
            selected.append(host)
    results = [capture_tls_host(host, output_dir) for host in selected]
    bundle = {
        "tool": APP_NAME,
        "tool_version": APP_VERSION,
        "repository": REPOSITORY_URL,
        "captured_at": iso_now(),
        "hosts_attempted": selected,
        "source": "direkter TLS-Handshake zu TCP/443 über Python ssl; keine externe Zertifikatsanalyse-API",
        "hosts": results,
    }
    write_json(output_dir / "tls_certificates.json", bundle)
    lines = [
        f"{APP_NAME} – TLS-/SSL-Zertifikate", "=" * 72, "",
        f"Version: {APP_VERSION}", f"Projekt / Quellcode: {REPOSITORY_URL}", f"Erstellt: {bundle['captured_at']}",
        "Quelle: direkte TLS-Verbindung zum jeweils untersuchten Host auf TCP/443; keine externe Zertifikatsanalyse-API.",
        "Die Rohsicherung erfolgt ohne Vertrauensprüfung, damit auch abgelaufene oder selbstsignierte Zertifikate erhalten bleiben.",
        "Unter Python 3.13+ wird – sofern vom Server geliefert – die unverifizierte Zertifikatskette gesichert; bei älteren Python-Versionen mindestens das Server-/Leaf-Zertifikat.", "",
    ]
    for rec in results:
        lines += [f"HOST: {rec.get('host')}", "-" * 72]
        if not rec.get("ok"):
            lines += [f"Fehler: {rec.get('error')}", ""]
            continue
        lines += [
            f"Peer-IP: {rec.get('peer_ip')}", f"TLS-Version: {rec.get('tls_version')}",
            f"Cipher: {rec.get('cipher')} ({rec.get('cipher_bits')} Bit)",
            f"Zertifikatserfassung: {rec.get('chain_capture')}",
        ]
        if rec.get("chain_warning"):
            lines.append(f"Hinweis zur Kettenerfassung: {rec.get('chain_warning')}")
        if rec.get("chain"):
            leaf = rec["chain"][0]
            lines += [
                f"Subject: {leaf.get('subject')}", f"Issuer: {leaf.get('issuer')}",
                f"Serial: {leaf.get('serial')}", f"Gültig ab: {leaf.get('not_before')}", f"Gültig bis: {leaf.get('not_after')}",
                f"SAN: {', '.join(leaf.get('san') or []) or '-'}",
                f"SHA-256-Fingerprint: {leaf.get('sha256_fingerprint')}",
                f"SHA-1-Fingerprint: {leaf.get('sha1_fingerprint')}",
                f"Gesicherte Zertifikate der Kette: {len(rec.get('chain') or [])}",
            ]
        lines.append("")
    write_text(output_dir / "TLS_Zertifikate.txt", "\n".join(lines))
    return bundle
