# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
from pathlib import Path

from common import APP_NAME, APP_VERSION, hostname_from_value, sanitize_component, timestamp_slug
from capture import capture_website
from domain_analysis import analyze_domain, supplement_origin_ip
from har_analysis import analyze_har
from license_tools import generate_installed_license_report
from reports import export_reports
from updater import check_outdated, update_dependencies


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forensic-sitesaver", description=f"{APP_NAME} {APP_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("capture", help="Website vollständig passiv sichern")
    c.add_argument("url")
    c.add_argument("--output", type=Path, default=Path("Sicherungen"))
    c.add_argument("--browser", choices=["chromium", "firefox"], default="chromium")
    c.add_argument("--headless", action="store_true")
    c.add_argument("--max-pages", type=int, default=1000)
    c.add_argument("--segment-pages", type=int, default=20)
    c.add_argument("--delay-ms", type=int, default=500)
    c.add_argument("--timeout-ms", type=int, default=30000)
    c.add_argument("--allow-host", action="append", default=[])

    d = sub.add_parser("domain", help="Eigenständige Domain-/Hosting-/MX-Analyse")
    d.add_argument("domain")
    d.add_argument("--output", type=Path, default=Path("Domainanalysen"), help="Elternordner für die neue Analyse")
    d.add_argument("--pdf", action="store_true", help="Direkt eine PDF-Aktenausfertigung erzeugen")

    h = sub.add_parser("har", help="HAR-Datei oder Segmentordner analysieren")
    h.add_argument("input", type=Path)
    h.add_argument("--output", type=Path, required=True)
    h.add_argument("--base-url", default=None)

    o = sub.add_parser("origin", help="Bekannte Origin-/Server-IP manuell ergänzen")
    o.add_argument("--domain-dir", type=Path, required=True)
    o.add_argument("--ips", required=True, help="Kommagetrennte IP-Adressen")
    o.add_argument("--note", default="")

    e = sub.add_parser("export", help="Aktenberichte als PDF exportieren")
    e.add_argument("--source", type=Path, required=True)
    e.add_argument("--output", type=Path, required=True)
    e.add_argument("--no-combined", action="store_true")

    l = sub.add_parser("licenses", help="Lizenzübersicht der installierten Umgebung erzeugen")
    l.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "INSTALLIERTE_LIZENZEN.txt")

    u = sub.add_parser("update", help="Abhängigkeiten prüfen/aktualisieren")
    u.add_argument("--check-only", action="store_true")
    u.add_argument("--yes", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "capture":
        if args.max_pages < 0 or args.segment_pages < 1 or args.delay_ms < 0 or args.timeout_ms < 1000:
            raise SystemExit("Ungültige Crawl-Parameter.")
        path = capture_website(
            args.url, args.output, browser_name=args.browser, headless=args.headless,
            max_pages=args.max_pages, segment_pages=args.segment_pages,
            delay_ms=args.delay_ms, timeout_ms=args.timeout_ms, allow_hosts=args.allow_host,
        )
        print(f"ERGEBNIS_ORDNER={path}")
        return 0
    if args.command == "domain":
        host = hostname_from_value(args.domain)
        out = args.output.expanduser().resolve() / f"{timestamp_slug()}_domainanalyse_{sanitize_component(host)}"
        analyze_domain(args.domain, out)
        print(f"Domainanalyse abgeschlossen: {out}")
        if args.pdf:
            pdf_out = out.parent / (out.name + "_Aktenexport")
            export_reports(out, pdf_out, combined=True)
            print(f"PDF-Aktenexport: {pdf_out}")
        print(f"ERGEBNIS_ORDNER={out}")
        return 0
    if args.command == "har":
        analyze_har(args.input, args.output, args.base_url)
        print(f"HAR-Auswertung abgeschlossen: {args.output.resolve()}")
        return 0
    if args.command == "origin":
        ips = [x.strip() for x in args.ips.split(",") if x.strip()]
        supplement_origin_ip(args.domain_dir, ips, args.note)
        print("Origin-/Server-IP-Ergänzung abgeschlossen.")
        return 0
    if args.command == "export":
        export_reports(args.source, args.output, combined=not args.no_combined)
        print(f"Berichte exportiert: {args.output.resolve()}")
        return 0
    if args.command == "licenses":
        generate_installed_license_report(args.output)
        print(f"Lizenzübersicht erzeugt: {args.output.resolve()}")
        return 0
    if args.command == "update":
        outdated = check_outdated()
        if not outdated:
            print("Keine über pip als veraltet gemeldeten Pakete.")
        else:
            for row in outdated:
                print(f"{row.get('name')}: {row.get('version')} -> {row.get('latest_version')}")
        if args.check_only:
            return 0
        if args.yes:
            update_dependencies()
            return 0
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
