# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from common import APP_NAME
from license_tools import generate_installed_license_report

BASE_DIR = Path(__file__).resolve().parent


def check_outdated() -> list[dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    try:
        return json.loads(proc.stdout or "[]")
    except Exception:
        return []


def update_dependencies() -> None:
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "-r", str(BASE_DIR / "requirements.txt")], check=True)
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium", "firefox"], check=True)
    generate_installed_license_report(BASE_DIR / "INSTALLIERTE_LIZENZEN.txt")


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description=f"{APP_NAME} – Abhängigkeitsupdates")
    p.add_argument("--check-only", action="store_true")
    p.add_argument("--yes", action="store_true")
    args = p.parse_args()
    outdated = check_outdated()
    if not outdated:
        print("Keine über pip als veraltet gemeldeten Pakete in der aktuellen Umgebung.")
    else:
        for row in outdated:
            print(f"{row.get('name')}: {row.get('version')} -> {row.get('latest_version')}")
    if args.check_only:
        return 0
    if not args.yes:
        answer = input("Freigegebene Abhängigkeiten innerhalb der requirements.txt-Grenzen aktualisieren? [j/N]: ").strip().lower()
        if answer not in {"j", "ja", "y", "yes"}:
            return 0
    update_dependencies()
    print("Update abgeschlossen. INSTALLIERTE_LIZENZEN.txt wurde aktualisiert.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
