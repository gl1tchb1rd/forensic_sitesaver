# Copyright (C) 2026 gl1tchb1rd
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from typing import Any

from OpenSSL import SSL, crypto

from common import APP_NAME, APP_VERSION, ensure_dir, iso_now, sanitize_component, safe_exception, write_json, write_text


def _name_to_dict(name: crypto.X509Name) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in name.get_components():
        out[key.decode("ascii", "replace")] = value.decode("utf-8", "replace")
    return out


def _cert_info(cert: crypto.X509) -> dict[str, Any]:
    der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    sans: list[str] = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            sans = [x.strip() for x in str(ext).split(",")]
    pub = cert.get_pubkey()
    return {
        "subject": _name_to_dict(cert.get_subject()),
        "issuer": _name_to_dict(cert.get_issuer()),
        "serial": format(cert.get_serial_number(), "x"),
        "not_before": cert.get_notBefore().decode("ascii", "replace"),
        "not_after": cert.get_notAfter().decode("ascii", "replace"),
        "signature_algorithm": cert.get_signature_algorithm().decode("ascii", "replace"),
        "public_key_bits": pub.bits(),
        "san": sans,
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "sha1_fingerprint": hashlib.sha1(der).hexdigest(),
        "der": der,
        "pem": pem,
    }


def capture_tls_host(host: str, output_dir: Path, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    output_dir = ensure_dir(output_dir)
    result: dict[str, Any] = {"host": host, "port": port, "captured_at": iso_now(), "source": "direkter TLS-Handshake"}
    raw_sock = None
    conn = None
    try:
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *_: True)
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        peer_ip = raw_sock.getpeername()[0]
        conn = SSL.Connection(context, raw_sock)
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.set_connect_state()
        conn.do_handshake()
        leaf = conn.get_peer_certificate()
        chain = conn.get_peer_cert_chain() or ([leaf] if leaf else [])
        result.update({
            "ok": True, "peer_ip": peer_ip, "tls_version": conn.get_protocol_version_name(),
            "cipher": conn.get_cipher_name(), "cipher_bits": conn.get_cipher_bits(),
            "chain": [],
        })
        host_dir = ensure_dir(output_dir / sanitize_component(host))
        for idx, cert in enumerate(chain):
            info = _cert_info(cert)
            der = info.pop("der")
            pem = info.pop("pem")
            stem = "leaf" if idx == 0 else f"chain_{idx:02d}"
            (host_dir / f"{stem}.der").write_bytes(der)
            (host_dir / f"{stem}.pem").write_bytes(pem)
            info["der_file"] = f"{sanitize_component(host)}/{stem}.der"
            info["pem_file"] = f"{sanitize_component(host)}/{stem}.pem"
            result["chain"].append(info)
    except Exception as exc:
        result["ok"] = False
        result["error"] = safe_exception(exc)
    finally:
        try:
            if conn is not None:
                conn.shutdown()
                conn.close()
        except Exception:
            pass
        try:
            if raw_sock is not None:
                raw_sock.close()
        except Exception:
            pass
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
        "tool": APP_NAME, "tool_version": APP_VERSION, "captured_at": iso_now(),
        "hosts_attempted": selected,
        "source": "direkter TLS-Handshake zu TCP/443; keine externe Zertifikatsanalyse-API",
        "hosts": results,
    }
    write_json(output_dir / "tls_certificates.json", bundle)
    lines = [
        f"{APP_NAME} – TLS-/SSL-Zertifikate", "=" * 72, "",
        f"Version: {APP_VERSION}", f"Erstellt: {bundle['captured_at']}",
        "Quelle: direkte TLS-Verbindung zum jeweils untersuchten Host auf TCP/443; keine externe Zertifikatsanalyse-API.",
        "Die Rohsicherung erfolgt ohne Vertrauensprüfung, damit auch abgelaufene oder selbstsignierte Zertifikate erhalten bleiben.", "",
    ]
    for rec in results:
        lines += [f"HOST: {rec.get('host')}", "-" * 72]
        if not rec.get("ok"):
            lines += [f"Fehler: {rec.get('error')}", ""]
            continue
        lines += [
            f"Peer-IP: {rec.get('peer_ip')}", f"TLS-Version: {rec.get('tls_version')}",
            f"Cipher: {rec.get('cipher')} ({rec.get('cipher_bits')} Bit)",
        ]
        if rec.get("chain"):
            leaf = rec["chain"][0]
            lines += [
                f"Subject: {leaf.get('subject')}", f"Issuer: {leaf.get('issuer')}",
                f"Serial: {leaf.get('serial')}", f"Gültig ab: {leaf.get('not_before')}", f"Gültig bis: {leaf.get('not_after')}",
                f"SAN: {', '.join(leaf.get('san') or []) or '-'}",
                f"SHA-256-Fingerprint: {leaf.get('sha256_fingerprint')}",
                f"SHA-1-Fingerprint: {leaf.get('sha1_fingerprint')}",
            ]
        lines.append("")
    write_text(output_dir / "TLS_Zertifikate.txt", "\n".join(lines))
    return bundle
