# Forensic SiteSaver 1.2.0

Dieses Release ergänzt die Prüfung auf neue Programmversionen und verbessert die Sicherung und Offline-Darstellung von Websites. Die folgenden Änderungen umfassen **alle Neuerungen seit Version 1.1.0**, einschließlich der Korrekturen aus 1.1.1.

## Neue Updatefunktion

- **Automatische Prüfung beim Start:** SiteSaver vergleicht die installierte Version im Hintergrund mit dem neuesten freigegebenen GitHub-Release. Ein Hinweis erscheint nur, wenn tatsächlich eine neuere Version verfügbar ist. Bei aktuellem Versionsstand oder fehlender Internetverbindung gibt es keinen Dialog zum Wegklicken.
- **Manuelle Prüfung:** Im Reiter „Updates“ steht **„Nach Updates suchen“** zur Verfügung. Hier werden auch der aktuelle Versionsstand oder Verbindungsfehler angezeigt.
- **Release Notes und Download:** Bei einem Update lassen sich die Änderungen anzeigen und das Quellcode-ZIP der angebotenen Version herunterladen. Mit **„Später“** kann der Hinweis geschlossen werden. Die Installation erfolgt durch manuelles Entpacken und Starten der neuen Version.
- **Zuverlässiger Versionsvergleich:** Tags wie `v1.2.0` werden mit Programmversionen wie `1.2.0` korrekt verglichen. Auch `1.10.0` wird als neuer als `1.9.0` erkannt. Entwürfe und Vorabversionen werden nicht angeboten.
- Die bisherigen Updates für Python-Abhängigkeiten und Playwright-Browser bleiben separat verfügbar.

## Vollständigere Website-Sicherung und Offline-Ansicht

- **Sichtbare Produktkarten und Inhaltsbereiche:** Scrollabhängige `reveal`-Inhalte werden in der Offline-Ansicht statisch sichtbar gemacht. Ausdrücklich versteckte Menüs und Dialoge bleiben verborgen.
- **Lazy-Bilder:** Neue Aufnahmen scrollen während der Browseraufzeichnung begrenzt zu noch nicht geladenen Bildern und Reveal-Bereichen. Anschließend wird die ursprüngliche Scrollposition wiederhergestellt; Ablauf und Grenzen werden dokumentiert.
- **Canvas-Grafiken:** Auslesbare Canvas-Inhalte, beispielsweise Charts, werden bei neuen Sicherungen als PNG-Momentaufnahmen mit SHA-256-Prüfsumme und beobachteter Anzeigegröße gespeichert und in der Offline-Ansicht angezeigt. Animationen und Live-Aktualisierungen werden als statischer Aufnahmezustand wiedergegeben; fehlende Canvas-Sicherungen werden dokumentiert.
- **Überarbeitete Spiegel-Erstellung:** Die Vorschauerstellung aus K25-SiteSaver v1.5 wurde übernommen und mit den vorhandenen Bedienhilfen und Diagnoseformaten verbunden.

## Verbesserte Bilder, Ressourcen und HAR-Verarbeitung

- Tatsächlich gespeicherte Bildinhalte aus HTTP-304-Antworten werden wieder angezeigt. Fehlt der Inhalt, wird dies als fehlende Ressource ausgewiesen.
- HAR-Anhänge über `_file` und `_sha1`, ZIP-Unterordner sowie separate Anhänge neben HAR-Dateien werden unterstützt. Ungültige HAR-Dokumentkandidaten werden übersprungen; mehrdeutige oder außerhalb des HAR-Ordners liegende Dateizuordnungen werden abgewiesen.
- Unterschiedliche aufgezeichnete Fassungen derselben Ressource bleiben erhalten; die zuletzt erfolgreich gesicherte Fassung wird angezeigt. Bildvarianten aus `srcset` bleiben für den Browser auswählbar, und aufgezeichnete passive Ressourcen sind direkt lokal verlinkt.
- Bildzuordnungen berücksichtigen URL-kodierte Umlaute und Leerzeichen, maskierte CSS-Dateinamen, `image-set(...)`, relative Verweise in weitergeleiteten Stylesheets und genauere Inhaltstypen. Gesicherte Lazy-Ziele können fehlende Platzhalter ersetzen.
- Dateiendungen und Dateinamen berücksichtigen Inhaltstypen und Windows-Sondernamen. Sehr lange Ressourcenpfade werden verkürzt und im Manifest dokumentiert. Ältere CSS-Zeichensätze werden für die Offline-Laufzeitkopie korrekt gelesen.
- Die Diagnose fehlender Referenzen unterscheidet unter anderem nicht aufgezeichnete Ressourcen, fehlende Response-Inhalte, HTTP-Fehler, ausgebliebene Antworten und nicht gesicherte Weiterleitungsziele.
- Bestehende K25-SiteSaver-Sicherungen mit `dom_raw` und Windows-Pfadtrennern lassen sich in eine separate Offline-Ansicht überführen.

## Verbesserte Offline-Menüs

- Die Bedienung erfolgt über die ursprünglichen Menülinks und Schalter. Die zusätzlich eingefügten Untermenü-Pfeilknöpfe entfallen.
- Dropdowns öffnen beim Darüberfahren mit der Maus. Der Wechsel ins Untermenü sowie lokale Seitenlinks bleiben nutzbar.
- Bei Touch öffnet das erste Antippen eines geschlossenen Menülinks das Untermenü; ein zweites Antippen folgt dem Seitenziel. Tastaturbedienung über Pfeil nach unten, Leertaste, Enter und Escape wird unterstützt.
- Hinweisdialoge für gesperrte Linkziele bleiben mit der Menübedienung vereinbar.

## Sicherheit und Qualitätssicherung

- Die Offline-Ansicht lädt weiterhin keine externen Inhalte nach und führt keine fremden Originalskripte aus. HAR, ursprünglicher DOM und vorhandene Primärdaten bleiben unverändert.
- Zusätzliche Regressionstests decken Lazy-Bilder, Canvas-Grafiken, Produktkarten, Menüs, Bildvarianten, Datei-/HTTP-Ansichten, unterschiedliche Bildschirmbreiten und den Schutz der Primärdaten ab. Die Updatefunktion hat eigene Tests für Versionsvergleich, Netzwerkfehler und die stille Prüfung beim Start.

## Installation

Das Quellcode-ZIP zu **`v1.2.0`** vollständig in einen eigenen Programmordner entpacken, einschließlich des technischen Unterordners **`.forensic_sitesaver`**, und anschließend **`forensic_sitesaver.py`** starten. Python 3.10+ und Tk/Tkinter müssen vorhanden sein; die lokale Python-Umgebung und die Playwright-Browser werden bei Bedarf beim ersten Start eingerichtet.

Vorhandene Sicherungen bleiben in ihren bisherigen Ordnern. Eine neue Offline-Ansicht lässt sich über **„Ansicht aus Sicherung neu erzeugen“** in einem separaten Ordner erstellen. Bilder oder Canvas-Pixel, die in einer älteren Sicherung nicht erfasst wurden, benötigen eine neue Aufnahme.
