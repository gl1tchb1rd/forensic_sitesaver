# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from common import APP_NAME, APP_VERSION, DISCLAIMER, REPOSITORY_URL, ensure_dir, human_size, iso_now, relative_to_case, sha256_file, write_json, write_text


def write_capture_report(case_root: Path, statistics: dict[str, Any]) -> None:
    """Write the case-file narrative from measured capture data before PDF export."""
    s = statistics
    duration = f"{s['duration_seconds']:.1f}".replace(".", ",")
    page_limit = str(s["max_pages"]) if s["max_pages"] else "unbegrenzt"
    extra_hosts = ", ".join(s["allow_hosts"]) or "keine"
    lines = [
        f"{APP_NAME} – Sicherungsvermerk", "=" * 72, "",
        "GEGENSTAND DER SICHERUNG",
        f"Ausgangs-URL: {s['start_url']}",
        "Gegenstand dieses Vermerks ist die automatisierte technische Sicherung der aufgerufenen Website. "
        "Dokumentiert werden die während des Sicherungslaufs im Browser erfassten Seiten und deren "
        "Netzwerkkommunikation. Die Sicherung bildet den beobachteten Zustand innerhalb des angegebenen "
        "Zeitraums ab; sie stellt keine vollständige Kopie sämtlicher Inhalte des Webservers dar.", "",
        "BROWSERGESTÜTZTE ERFASSUNG",
        "Forensic SiteSaver startet über Playwright einen eigenen Browserprozess und legt darin eine neue, "
        "nicht persistente Browsersitzung an. Persönliche Browserprofile, bestehende Anmeldungen und Cookies "
        "werden nicht übernommen. Diese Trennung betrifft die Browsersitzung; sie ist keine getrennte "
        "virtuelle Maschine. Service Worker werden für die Sitzung blockiert.", "",
        "Ausgehend von der Ausgangsadresse werden die Seiten regulär per HTTP(S) aufgerufen und im Browser "
        "dargestellt. Auf der Website vorhandenes JavaScript kann dabei ausgeführt werden und Ressourcen "
        "auch von Drittanbietern anfordern. Nach dem Seitenaufruf wird auf den Ladezustand gewartet, soweit "
        "dies innerhalb der festgelegten Wartezeiten möglich ist. Aus den Links im dargestellten "
        "Seiteninhalt werden weitere Adressen ermittelt und nacheinander aufgerufen. Zulässig sind Ziele "
        "derselben registrierbaren Domain sowie ausdrücklich zusätzlich freigegebene Hosts. "
        "Links werden nicht angeklickt und Formulare nicht ausgefüllt oder abgesendet.", "",
        "AUFZEICHNUNG UND BILDSICHERUNG",
        "Die vom Browser erfassten HTTP-Anfragen und Antworten werden in segmentierten HAR-Dateien "
        "(HTTP Archive) im Modus full aufgezeichnet. Sie enthalten unter anderem Adressen, Methoden, "
        "Statuscodes, Header und Zeitinformationen sowie die vom Browser bereitgestellten Response-Inhalte. "
        "Die Inhalte werden dem jeweiligen HAR-Archiv angehängt. Dies ist eine Aufzeichnung auf "
        "Browser-/HTTP-Ebene, kein Paketmitschnitt des gesamten Netzwerkverkehrs des Rechners. "
        "Ein Playwright-Trace wird nicht erstellt.", "",
        "Für die erfassten Seiten wird der im Browser aufgebaute Seiteninhalt (DOM) gespeichert. "
        "Zusätzlich wird jeweils ein Screenshot der gesamten Seitenhöhe angefordert. Fehler bei "
        "Seitenaufrufen oder Screenshots werden gesondert dokumentiert. Auch eine dargestellte HTTP-Fehlerseite "
        "kann als Seite erfasst sein; die Seitenzahl allein belegt daher keine erfolgreichen HTTP-Antworten.", "",
        "SICHERHEIT WÄHREND DES AUFRUFS",
        "Die Sitzung lässt GET-, HEAD- und OPTIONS-Anfragen zu. Andere HTTP-Methoden, insbesondere POST, "
        "PUT, PATCH und DELETE, werden blockiert. Auch bekannte zustandsverändernde GET-Muster wie "
        "Warenkorb-, Bestell- und Zahlungsaktionen werden blockiert. Die Sperren können die Darstellung "
        "und Funktion der Website beeinflussen. Eine absolute Nebenwirkungsfreiheit lässt sich nicht "
        "garantieren, wenn ein fremder Server bereits gewöhnliche GET-Aufrufe als Zustandsänderung behandelt.", "",
        "HTTPS-Zertifikatsfehler verhindern den Aufruf in dieser Browsersitzung nicht. "
        "Der Browseraufruf allein bestätigt daher keine erfolgreiche Prüfung der Zertifikatsvertrauenskette. "
        "Die gesonderte TLS-Zertifikatserhebung wird im TLS-Bericht dokumentiert.", "",
        "ABGESICHERTE LOKALE AUSWERTUNGSFASSUNG",
        "Aus den gespeicherten Seiteninhalten und den erfassten Ressourcen wird ein lokaler Website-Spiegel "
        "erstellt. JavaScript, Frames und weitere aktive Inhalte werden entfernt oder neutralisiert; "
        "Formulare werden deaktiviert. Verweise werden auf vorhandene lokale Dateien umgeschrieben "
        "oder stillgelegt. Eine Content Security Policy unterbindet aktive Inhalte und externe "
        "Netzwerk-Nachladevorgänge in der lokalen Auswertungsfassung.", "",
        "Erfasste Bilder, Stylesheets, Fonts und Medien werden, soweit für die lokale Darstellung vorgesehen "
        "und verfügbar, byteidentisch aus der HAR-Sicherung extrahiert. Für Stylesheets werden zusätzlich "
        "angepasste Laufzeitkopien erzeugt. Die lokale Darstellung kann deshalb von der ursprünglichen "
        "interaktiven Website abweichen. Für die ursprüngliche aufgezeichnete HTTP-Kommunikation und "
        "die enthaltenen Response-Inhalte bleiben die HAR-Dateien die technische Primärquelle.", "",
        "ERGÄNZENDE AUSWERTUNG UND INTEGRITÄT",
        "Im Anschluss werden die HAR-Daten automatisiert ausgewertet und ergänzende Domain-, Hosting-, "
        "MX-/Mailserver- und TLS-Informationen erhoben. Verwendete externe Dienste, übertragene Werte "
        "und Zwecke sind in den Transparenzdateien dokumentiert. Die Sicherungsdateien werden nicht "
        "an einen KI- oder Cloud-Analysedienst übertragen.", "",
        "SHA-256-Prüfsummen werden für die HAR-Segmente und den Primärbestand erzeugt. Sie ermöglichen "
        "den Vergleich mit einem späteren Dateistand und damit die Erkennung nachträglicher Veränderungen; "
        "sie bestätigen nicht die sachliche Richtigkeit der Website-Inhalte. Die PDF-Berichte sind "
        "abgeleitete Aktenausfertigungen mit einem eigenen Exportmanifest. Sie sind vom "
        "Primärbestand in SHA256SUMS.txt ausgenommen.", "",
        "ZEITRAUM DER SICHERUNG",
        f"Beginn der Sicherung: {s['started_at']}",
        f"Beginn der Browseraufzeichnung: {s['browser_started_at']}",
        f"Ende der Browseraufzeichnung: {s['browser_finished_at']}",
        f"Ende der Datenerhebung und Auswertung: {s['finished_at']}",
        f"Dauer bis zum Ende der Datenerhebung und Auswertung: {duration} Sekunden",
        "Zeitangaben enthalten den Zeitzonenoffset und beruhen auf der Systemuhr. Die Dauer wird mit "
        "einer monotonen Uhr gemessen. PDF-Erstellung und abschließende Prüfsummenbildung folgen "
        "auf die Datenerhebung und Auswertung und sind in dieser Dauer nicht enthalten.", "",
        "UMFANG UND ERGEBNIS",
        f"Erfasste Seiten (gespeicherter DOM): {s['pages_captured']}",
        f"Davon Seiten mit HTTP-Fehlerstatus (ab 400): {s['http_error_pages']}",
        f"Fehler bei der Seitenerfassung: {s['page_capture_errors']}",
        f"Gespeicherte Full-Page-Screenshots: {s['screenshots_captured']}",
        f"Fehler bei der Screenshot-Erstellung: {s['screenshot_errors']}",
        f"HAR-Segmente: {s['har_segments']}",
        f"Im HAR dokumentierte Anfragen: {s['har_entries']}",
        f"Mitschnittgröße (gespeicherte HAR-Segmente): {human_size(s['har_bytes'])} ({s['har_bytes']} Bytes)",
        "Die Mitschnittgröße ist die Dateigröße der HAR-Archive einschließlich angehängter Inhalte. "
        "Archivkompression und HAR-Metadaten beeinflussen diese Größe; sie entspricht nicht der "
        "übertragenen Datenmenge auf Netzwerkebene.",
        f"Seiten in der lokalen Auswertungsfassung: {s['mirror_pages']}",
        f"Lokal extrahierte Ressourcen: {s['mirror_resources']}",
        f"Blockierte Netzwerkanfragen: {s['blocked_network_requests']}",
        f"Blockierte Navigationslinks: {s['blocked_navigation_links']}",
        f"Nicht weiterverfolgte externe Adressen: {s['external_links_not_followed']}",
        f"Bei Erreichen des Seitenlimits noch vorgemerkte Adressen: {s['remaining_pages']}", "",
        "PROGRAMM UND LAUFPARAMETER",
        f"Programm: {APP_NAME} {APP_VERSION}",
        f"Projekt / Quellcode: {REPOSITORY_URL}",
        f"Python-Version: {s['python_version']}",
        f"Playwright-Version: {s['playwright_version']}",
        f"Browser: {s['browser']} {s['browser_version']}",
        f"Browser ohne sichtbares Fenster (headless): {'ja' if s['headless'] else 'nein'}",
        f"Seitenlimit: {page_limit}",
        f"Seiten je HAR-Segment: {s['segment_pages']}",
        f"Pause zwischen Seitenaufrufen: {s['delay_ms']} ms",
        f"Navigationszeitlimit je Seitenaufruf: {s['timeout_ms']} ms",
        f"Zusätzlich freigegebene Hosts: {extra_hosts}", "",
        "ABLAGE UND PRÜFBARKEIT",
        "Die messbaren Laufdaten sind zusätzlich in 04_metadaten/Sicherungsstatistik.json gespeichert. "
        "Die Seitenliste liegt in 04_metadaten/visited_pages.json, die HAR-Segmentliste in "
        "01_har/HAR_Index.json. Blockierte Anfragen, nicht weiterverfolgte Links, verbleibende Adressen "
        "und etwaige Fehler sind in den zugehörigen Metadaten und Fehlerdateien dokumentiert.", "",
        "DISCLAIMER", "-" * 72, DISCLAIMER,
    ]
    write_json(case_root / "04_metadaten" / "Sicherungsstatistik.json", statistics)
    write_text(case_root / "Sicherungsvermerk.txt", "\n".join(lines))


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def _domain_source(base: Path) -> Path | None:
    candidates = [
        base / "Domain_Analyse_mit_manueller_Origin_IP.txt",
        base / "Domain_Analyse.txt",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def discover_report_sources(source: Path) -> tuple[Path, list[tuple[str, str, Path]]]:
    source = source.resolve()
    if (source / "Sicherungsvermerk.txt").exists():
        root = source
        reports: list[tuple[str, str, Path]] = []
        candidates = [
            ("01_Sicherungsvermerk.pdf", "Sicherungsvermerk", source / "Sicherungsvermerk.txt"),
            ("02_HAR-Auswertung.pdf", "HAR-Auswertung", source / "06_har_analyse" / "HAR_Auswertung.txt"),
        ]
        dom = _domain_source(source / "07_domain_analyse")
        if dom:
            candidates.append(("03_Domainanalyse.pdf", "Domainanalyse", dom))
        candidates.append(("04_TLS-Zertifikate.pdf", "TLS-Zertifikate", source / "08_tls_zertifikate" / "TLS_Zertifikate.txt"))
        reports.extend((fn, title, path) for fn, title, path in candidates if path.exists())
        return root, reports

    dom = _domain_source(source)
    if dom:
        return source, [("01_Domainanalyse.pdf", "Domainanalyse", dom)]
    raise FileNotFoundError("Weder ein vollständiger Sicherungsordner noch ein Domainanalyse-Ordner erkannt.")


def _clean_har_for_pdf(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    skipping = False
    for line in lines:
        low = line.strip().lower()
        if low.startswith("ausgewertete har-segmente"):
            skipping = line.strip().endswith(":")
            continue
        if skipping:
            if not line.strip():
                skipping = False
                out.append("")
            elif re.match(r"^[A-ZÄÖÜ0-9 /_\-]+$", line.strip()) and len(line.strip()) > 3:
                skipping = False
                out.append(line)
            continue
        out.append(line)
    return "\n".join(out)


def _pdf_story(title: str, source_paths: list[Path], source_root: Path, text: str):
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("g_title", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=16, leading=20, alignment=TA_CENTER, spaceAfter=10)
    meta_style = ParagraphStyle("g_meta", parent=styles["Normal"], fontName="Helvetica", fontSize=8.5, leading=11, textColor="#444444", spaceAfter=4)
    body_style = ParagraphStyle("g_body", parent=styles["Normal"], fontName="Helvetica", fontSize=9.5, leading=13, spaceAfter=2)
    heading_style = ParagraphStyle("g_heading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=8, spaceAfter=4)
    mono_style = ParagraphStyle("g_mono", parent=styles["Normal"], fontName="Courier", fontSize=7.5, leading=10, wordWrap="CJK", spaceAfter=2)

    story = [
        Paragraph(html.escape(title), title_style),
        Paragraph(f"{html.escape(APP_NAME)} {APP_VERSION}", meta_style),
        Paragraph(f"Projekt / Quellcode: {html.escape(REPOSITORY_URL)}", meta_style),
    ]
    for index, source_path in enumerate(source_paths, 1):
        rel = relative_to_case(source_path, source_root)
        label = "Quelle" if len(source_paths) == 1 else f"Quelle {index}"
        story.append(Paragraph(f"{label}: {html.escape(rel)}", meta_style))
        story.append(Paragraph(f"SHA-256: {sha256_file(source_path)}", mono_style))
    story += [
        Paragraph("Aktenausfertigung; die Quelldateien im Sicherungs-/Analyseordner bleiben maßgeblich.", meta_style),
        Spacer(1, 5 * mm),
    ]
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            story.append(Spacer(1, 2.5 * mm))
            continue
        stripped = line.strip()
        if stripped and set(stripped) <= {"-", "="}:
            continue
        is_heading = (
            stripped.isupper() and len(stripped) <= 80 and any(c.isalpha() for c in stripped)
        )
        style = heading_style if is_heading else body_style
        safe = html.escape(line).replace("  ", "&nbsp;&nbsp;")
        story.append(Paragraph(safe, style))
    return story


def _build_pdf(path: Path, title: str, source_paths: list[Path], source_root: Path, text: str) -> None:
    doc = SimpleDocTemplate(
        str(path), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"{APP_NAME} – {title}", author=APP_NAME,
    )
    story = _pdf_story(title, source_paths, source_root, text)
    doc.build(story)


def _strip_disclaimer_tail(text: str) -> str:
    """Remove DISCLAIMER sections without removing later report supplements."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip().upper() == "DISCLAIMER":
            i += 1
            if i < len(lines) and lines[i].strip() and set(lines[i].strip()) <= {"-", "="}:
                i += 1
            while i < len(lines) and lines[i].strip():
                i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            if out and out[-1] != "":
                out.append("")
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out).rstrip() + "\n"


def _compose_report_text(title: str, source_file: Path) -> tuple[str, list[Path]]:
    """Return PDF text and every source file that materially contributes to it."""
    text = _strip_disclaimer_tail(source_file.read_text(encoding="utf-8", errors="replace"))
    source_files = [source_file]

    if title == "Domainanalyse":
        whois_file = source_file.parent / "domain_whois.txt"
        if whois_file.exists():
            # WHOIS gehört fachlich zur Domainanalyse. Der PDF-Bericht führt
            # deshalb die strukturierte Domainanalyse und die erhobenen
            # WHOIS-Rohdaten als zwei nachvollziehbar gehashte Quellen zusammen.
            whois_text = whois_file.read_text(encoding="utf-8", errors="replace").strip()
            source_files.append(whois_file)
            text = (
                text.rstrip()
                + "\n\n"
                + "WHOIS-DATEN\n"
                + "=" * 72
                + "\n"
                + "Quelle: domain_whois.txt\n\n"
                + (whois_text if whois_text else "Keine WHOIS-Rohdaten vorhanden.")
                + "\n"
            )

        denic_file = source_file.parent / "denic_webwhois.txt"
        if denic_file.exists():
            denic_text = denic_file.read_text(encoding="utf-8", errors="replace").strip()
            source_files.append(denic_file)
            text = (
                text.rstrip()
                + "\n\n"
                + "DENIC-WEBWHOIS-DATEN (.DE)\n"
                + "=" * 72
                + "\n"
                + "Quelle: denic_webwhois.txt\n\n"
                + (denic_text if denic_text else "Keine DENIC-WebWhois-Rohdaten vorhanden.")
                + "\n"
            )

    if "HAR" in title.upper():
        text = _clean_har_for_pdf(text)

    return text, source_files


def export_reports(source: Path, output_dir: Path, combined: bool = True) -> dict[str, Any]:
    source_root, reports = discover_report_sources(Path(source))
    output_dir = Path(output_dir).expanduser().resolve()
    ensure_dir(output_dir)
    # PDF-Berichte sind bewusst abgeleitete Aktenausfertigungen. Sie dürfen im
    # Sicherungs-/Analyseordner liegen und besitzen ein eigenes Exportmanifest.
    # Vor einer Neuerzeugung (z. B. nach manueller Origin-IP-Ergänzung) werden
    # ausschließlich die von diesem Modul erzeugten PDF-/Manifestdateien ersetzt.
    for old in output_dir.iterdir():
        if old.is_file() and (old.suffix.lower() == ".pdf" or old.name in {"EXPORT_MANIFEST.json", "EXPORT_MANIFEST.txt"}):
            old.unlink()

    manifest: list[dict[str, Any]] = []
    combined_sections: list[tuple[str, list[Path], str]] = []
    for filename, title, source_file in reports:
        text, source_files = _compose_report_text(title, source_file)
        out = output_dir / filename
        _build_pdf(out, title, source_files, source_root, text)
        sources = [
            {
                "file": relative_to_case(path, source_root),
                "sha256": sha256_file(path),
            }
            for path in source_files
        ]
        row = {
            "title": title,
            "source_file": sources[0]["file"],
            "source_sha256": sources[0]["sha256"],
            "source_files": sources,
            "pdf_file": out.name,
            "pdf_sha256": sha256_file(out),
        }
        manifest.append(row)
        combined_sections.append((title, source_files, text))

    combined_file = None
    if combined and combined_sections:
        combined_file = output_dir / "Forensic_SiteSaver_Aktenberichte.pdf"
        styles = getSampleStyleSheet()
        cover_title = ParagraphStyle("cover", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, alignment=TA_CENTER)
        cover_body = ParagraphStyle("cover_body", parent=styles["Normal"], fontName="Helvetica", fontSize=10, leading=14)
        story = [
            Spacer(1, 35 * mm), Paragraph(html.escape(f"{APP_NAME} – Aktenberichte"), cover_title), Spacer(1, 8 * mm),
            Paragraph(f"Version {APP_VERSION}<br/>Projekt / Quellcode: {html.escape(REPOSITORY_URL)}<br/>Erstellt: {html.escape(iso_now())}", cover_body), Spacer(1, 8 * mm),
            PageBreak(),
        ]
        for idx, (title, source_files, text) in enumerate(combined_sections):
            if idx:
                story.append(PageBreak())
            story.extend(_pdf_story(title, source_files, source_root, text))
        doc = SimpleDocTemplate(
            str(combined_file), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
            topMargin=16 * mm, bottomMargin=16 * mm, title=f"{APP_NAME} – Aktenberichte", author=APP_NAME,
        )
        doc.build(story)

    bundle = {
        "tool": APP_NAME, "tool_version": APP_VERSION, "repository": REPOSITORY_URL, "created_at": iso_now(),
        "source_type": "full_capture" if (source_root / "Sicherungsvermerk.txt").exists() else "standalone_domain_analysis",
        "reports": manifest,
        "combined_pdf": ({"file": combined_file.name, "sha256": sha256_file(combined_file)} if combined_file else None),
    }
    write_json(output_dir / "EXPORT_MANIFEST.json", bundle)
    lines = [f"{APP_NAME} – Exportmanifest", "", f"Version: {APP_VERSION}", f"Projekt / Quellcode: {REPOSITORY_URL}", f"Erstellt: {bundle['created_at']}", ""]
    for row in manifest:
        lines.append(f"Bericht: {row['title']}")
        for idx, src in enumerate(row.get("source_files") or [], 1):
            label = "Quelle" if len(row["source_files"]) == 1 else f"Quelle {idx}"
            lines += [f"{label}: {src['file']}", f"SHA-256 {label}: {src['sha256']}"]
        lines += [f"PDF: {row['pdf_file']}", f"SHA-256 PDF: {row['pdf_sha256']}", ""]
    if combined_file:
        lines += [f"Sammel-PDF: {combined_file.name}", f"SHA-256 Sammel-PDF: {sha256_file(combined_file)}", ""]
    write_text(output_dir / "EXPORT_MANIFEST.txt", "\n".join(lines))
    return bundle
