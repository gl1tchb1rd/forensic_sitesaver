# Changelog

## Noch nicht veröffentlicht

- Erkannte vorhandene Hamburger-Menüs und Dropdowns werden mit eigenem lokalem JavaScript bedienbar: CSP-Hashfreigabe ausschließlich dieses Controllers, Tastaturbedienung, verschachtelte Menüs und responsive Navigation. Originalskripte, fremde Eventhandler, Netzwerkanfragen und Formulare bleiben blockiert; `menue_manifest.json` dokumentiert die abgeleitete Bedienhilfe.
- Lokaler Website-Spiegel: eingebettete Bilder und SVG-Bilder bleiben sichtbar; Bildvarianten, erfasste Lazy-Bilder, Basis-URLs, Ressourcen-Weiterleitungen und CSS-Importe werden lokal aufgelöst. Neue Sicherungen dokumentieren die vom Browser ausgewählten Bildquellen, ohne den Original-DOM zu verändern.
- Navigation zwischen gesicherten Seiten erhält Sprungmarken und Image-Map-Verweise. Fehlende Ziele und Ressourcen werden in `fehlende_referenzen.json` ausgewiesen; der Index maskiert fremde Seitentitel und URLs als Text.
- Neue GUI-Funktion und CLI-Befehl `mirror` erzeugen eine korrigierte Ansicht aus vorhandenen Sicherungen in einem separaten Ausgabeordner, ohne Primärdaten oder deren Prüfsummen zu verändern.
- Regressionstests für Ressourcen, CSS, Navigation, unveränderte Primärdaten und Darstellung per Datei/HTTP in Chromium.
- Ausführlicher Sicherungsvermerk mit Beschreibung von Browsersitzung, HAR-Aufzeichnung, Screenshots, lokalem Website-Spiegel und ergänzenden Auswertungen.
- Tatsächlicher Sicherungsbeginn, Beginn und Ende der Browseraufzeichnung, Abschluss der Datenerhebung und Auswertung sowie gemessene Dauer.
- Kennzahlen zu Seiten, HTTP-Fehlerseiten, Screenshots, Erfassungsfehlern, gespeicherter HAR-Datenmenge, verbleibenden Adressen und Laufparametern; zusätzliche `Sicherungsstatistik.json` im Primärbestand.

## 1.0.0

Erste öffentliche Veröffentlichung von **Forensic SiteSaver**.

Enthalten sind insbesondere Website-Sicherung mit segmentierter HAR-Aufzeichnung, sicherer lokaler Website-Spiegel, Screenshots, HAR-Auswertung, eigenständige und integrierte Domain-/Hosting-/MX-Analyse, manuelle Origin-IP-Ergänzung, TLS-Zertifikatssicherung, automatische PDF-Aktenberichte im Ergebnisordner, externe-Dienste-Transparenz sowie GPL-/Drittanbieter-Lizenzdokumentation.

Weitere Punkte der finalen 1.0.0: vereinfachte GUI ohne separate HAR-/Export-Reiter sowie robustere TLS-Zertifikatserfassung über Python `ssl`.

Der Domain-PDF-Bericht führt die strukturierte Domainanalyse und die ergänzenden WHOIS-Details aus `domain_whois.txt` zusammen und dokumentiert beide Quelldateien samt SHA-256.

WHOIS folgt nun IANA-/Registry-Referrals bis zum Registrar; PDF-Aktenberichte enthalten keinen Disclaimer mehr (der Hinweis bleibt in der Programmoberfläche).

WHOIS-Referral-Chaining folgt nun generisch allen neu genannten WHOIS-Servern bis zum Ende der Kette; VeriSign wird bevorzugt mit `dom <domain>` abgefragt.

WHOIS-Referral-Erkennung ist jetzt tolerant gegenüber Einrückungen, Tabs und unterschiedlichen Feldbezeichnungen; `domain_whois.txt` protokolliert die erkannte Referral-Kette.

Für `.de`-Domains wird zusätzlich die öffentliche DENIC-WebWhois-Auskunft gesichert und ausgewertet (verwaltendes DENIC-Mitglied, Registrierungs-/Aktualisierungsdatum und ggf. öffentlich sichtbare Inhaberdaten).
