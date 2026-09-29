# Copyright (C) 2026 gl1tchb1rd
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse

APP_NAME = "gl1tchb1rd forensic sitesaver"
APP_VERSION = "1.0.0"
USER_AGENT = f"gl1tchb1rd-forensic-sitesaver/{APP_VERSION} (+forensic-preservation)"

MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "com.br", "com.mx", "com.tr",
    "com.cn", "com.hk", "com.sg", "co.za", "com.ar", "com.pl", "com.ua",
}

STATEFUL_GET_PATTERNS = (
    "/add-to-cart", "/add_to_cart", "?add-to-cart=", "?add_to_cart=",
    "action=add_to_cart", "action=checkout", "action=order", "/buy-now",
    "/buynow", "/place-order", "/place_order", "/order/create", "/orders/create",
    "/order/submit", "/payment/confirm", "/payments/confirm", "/purchase",
)

DISCLAIMER = (
    "Dieses Werkzeug dient ausschließlich der technischen Ermittlungsunterstützung und "
    "Dokumentation. Automatisch erhobene, zusammengeführte oder abgeleitete Angaben – "
    "insbesondere GeoIP-, Hosting-/Provider-, Registrar-/WHOIS-/RDAP-, Shop-, Zahlungs- "
    "und Mailserver-Zuordnungen – können unvollständig, veraltet oder fehlerhaft sein. "
    "Die Prüfung der Richtigkeit und Beweisbedeutung der Ergebnisse sowie die rechtliche "
    "Zulässigkeit sämtlicher daraus abgeleiteter Maßnahmen liegen ausschließlich in der "
    "Verantwortung der nutzenden Person bzw. Stelle. Das Programm ersetzt weder eine "
    "fachliche Einzelfallprüfung noch eine rechtliche Prüfung."
)


def iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def timestamp_slug() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_component(value: str, max_len: int = 120) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    value = re.sub(r"_+", "_", value).strip("._")
    return (value or "unbenannt")[:max_len]


def sanitize_url(url: str) -> str:
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url.split("?", 1)[0].split("#", 1)[0]


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Keine URL/Domain angegeben.")
    if "://" not in value:
        value = "https://" + value
    p = urlparse(value)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise ValueError("Ungültige HTTP-/HTTPS-Adresse.")
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def hostname_from_value(value: str) -> str:
    if "://" not in value:
        value = "https://" + value.strip()
    host = (urlparse(value).hostname or "").strip(".").lower()
    if not host:
        raise ValueError("Keine gültige Domain/Hostangabe.")
    return host


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_first_party(host: str, root_registered_domain: str) -> bool:
    return registrable_domain(host) == root_registered_domain


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def relative_to_case(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.name


def hash_tree(root: Path, output_name: str = "SHA256SUMS.txt", exclude: set[str] | None = None) -> Path:
    exclude = set(exclude or set()) | {output_name}
    entries: list[str] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name in exclude:
            continue
        rel = p.relative_to(root).as_posix()
        entries.append(f"{sha256_file(p)}  {rel}")
    out = root / output_name
    write_text(out, "\n".join(entries))
    return out


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num} B"


def folder_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def is_stateful_get(url: str) -> bool:
    low = url.lower()
    return any(pattern in low for pattern in STATEFUL_GET_PATTERNS)


def safe_exception(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"
