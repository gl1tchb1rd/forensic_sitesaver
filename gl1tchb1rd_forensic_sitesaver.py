#!/usr/bin/env python3
# Copyright (C) 2026 gl1tchb1rd
# SPDX-License-Identifier: GPL-3.0-or-later
"""Öffentlicher Starter für gl1tchb1rd forensic sitesaver.

Alle technischen Komponenten liegen bewusst im versteckten Unterordner .gl1tchb1rd.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TECH = ROOT / ".gl1tchb1rd"
VENV = TECH / ".venv"
REQ = TECH / "requirements.txt"


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def hide_technical_folder() -> None:
    if os.name == "nt":
        try:
            subprocess.run(["attrib", "+h", str(TECH)], capture_output=True, check=False)
        except Exception:
            pass


def ask_setup() -> bool:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw()
        answer = messagebox.askyesno(
            "gl1tchb1rd forensic sitesaver – Ersteinrichtung",
            "Die lokale Python-Umgebung ist noch nicht eingerichtet oder unvollständig.\n\n"
            "Jetzt die Open-Source-Abhängigkeiten und die Playwright-Browser installieren?\n\n"
            "Dafür ist eine Internetverbindung erforderlich."
        )
        root.destroy()
        return bool(answer)
    except Exception:
        answer = input("Ersteinrichtung erforderlich. Abhängigkeiten jetzt installieren? [j/N]: ").strip().lower()
        return answer in {"j", "ja", "y", "yes"}


def show_error(message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw(); messagebox.showerror("gl1tchb1rd forensic sitesaver", message); root.destroy()
    except Exception:
        print(message, file=sys.stderr)


def dependencies_ok(py: Path) -> bool:
    if not py.exists():
        return False
    code = r"""
import bs4,dns,requests,OpenSSL,cryptography,reportlab,playwright
from importlib.metadata import version
def vt(s):
    out=[]
    for p in s.split('.'):
        n=''.join(ch for ch in p if ch.isdigit())
        if not n: break
        out.append(int(n))
    return tuple(out)
assert vt(version('playwright')) >= (1,60), version('playwright')
"""
    return subprocess.run([str(py), "-c", code], capture_output=True).returncode == 0


def setup_environment() -> None:
    if not VENV.exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    py = venv_python()
    subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "-r", str(REQ)], check=True)
    subprocess.run([str(py), "-m", "playwright", "install", "chromium", "firefox"], check=True)
    # Lizenzinventar der tatsächlich installierten Umgebung.
    subprocess.run([str(py), str(TECH / "cli.py"), "licenses"], cwd=str(ROOT), check=False)


def main() -> int:
    hide_technical_folder()
    try:
        import tkinter  # noqa: F401
    except Exception:
        print(
            "Tkinter/Tk ist nicht verfügbar. Unter Debian/Ubuntu z.B.: sudo apt install python3-tk; "
            "unter Arch Linux: sudo pacman -S tk; unter Fedora: sudo dnf install python3-tkinter.",
            file=sys.stderr,
        )
        return 2

    py = venv_python()
    if not dependencies_ok(py):
        if not ask_setup():
            return 1
        try:
            setup_environment()
        except subprocess.CalledProcessError as exc:
            show_error(
                "Die Einrichtung konnte nicht vollständig abgeschlossen werden.\n\n"
                f"Fehlercode: {exc.returncode}\n\n"
                "Unter Linux können zusätzlich Playwright-Systembibliotheken erforderlich sein. "
                "Diese lassen sich aus einem Terminal mit dem Python der .venv über "
                "'python -m playwright install-deps chromium firefox' nachinstallieren."
            )
            return int(exc.returncode or 3)

    if not dependencies_ok(py):
        show_error("Die lokale Python-Umgebung ist weiterhin unvollständig. Bitte die Ersteinrichtung erneut ausführen.")
        return 3

    return subprocess.call([str(py), str(TECH / "gui.py")], cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
