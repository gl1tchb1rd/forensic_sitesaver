# Copyright (C) 2026 gl1tchb1rd
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from importlib import metadata
from pathlib import Path
from typing import Any

from common import APP_NAME, APP_VERSION, iso_now, write_text

DIRECT_DEPENDENCIES = [
    ("playwright", "Apache-2.0", "https://github.com/microsoft/playwright-python/blob/main/LICENSE"),
    ("beautifulsoup4", "MIT", "https://pypi.org/project/beautifulsoup4/"),
    ("dnspython", "ISC", "https://pypi.org/project/dnspython/"),
    ("requests", "Apache-2.0", "https://pypi.org/project/requests/"),
    ("pyOpenSSL", "Apache-2.0", "https://pypi.org/project/pyOpenSSL/"),
    ("cryptography", "Apache-2.0 OR BSD-3-Clause", "https://pypi.org/project/cryptography/"),
    ("reportlab", "BSD", "https://pypi.org/project/reportlab/"),
]


def _license_files(dist: metadata.Distribution) -> list[Path]:
    found: list[Path] = []
    for item in dist.files or []:
        name = Path(str(item)).name.lower()
        if name.startswith(("license", "licence", "copying", "notice", "copyright")):
            try:
                p = Path(dist.locate_file(item))
                if p.is_file() and p.stat().st_size <= 500_000:
                    found.append(p)
            except Exception:
                pass
    unique: list[Path] = []
    seen: set[str] = set()
    for p in found:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def generate_installed_license_report(output: Path) -> None:
    lines = [
        f"{APP_NAME} – installierte Drittanbieter-Komponenten und Lizenztexte", "=" * 88, "",
        f"Programmversion: {APP_VERSION}", f"Erstellt: {iso_now()}", "",
        "Hinweis: Diese Datei wird aus der tatsächlich installierten, programminternen Python-Umgebung erzeugt.",
        "Die jeweiligen Drittanbieter behalten ihre eigenen Urheberrechte und Lizenzbedingungen.", "",
    ]
    distributions = sorted(metadata.distributions(), key=lambda d: (d.metadata.get("Name") or "").lower())
    for dist in distributions:
        name = dist.metadata.get("Name") or "(unbekannt)"
        version = dist.version
        license_expr = dist.metadata.get("License-Expression") or dist.metadata.get("License") or "nicht maschinenlesbar angegeben"
        homepage = dist.metadata.get("Home-page") or ""
        lines += ["#" * 88, f"PAKET: {name} {version}", f"Lizenz-Metadatum: {license_expr}"]
        if homepage:
            lines.append(f"Homepage: {homepage}")
        files = _license_files(dist)
        if not files:
            lines += ["Mitgelieferter Lizenztext: nicht automatisch gefunden; Paketmetadaten/Projektquelle beachten.", ""]
            continue
        for p in files:
            lines += ["", f"--- {p.name} ---"]
            try:
                lines.append(p.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                lines.append(f"[Lizenzdatei konnte nicht gelesen werden: {exc}]")
        lines.append("")
    write_text(output, "\n".join(lines))
