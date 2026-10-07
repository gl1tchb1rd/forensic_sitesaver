# Changelog

## 1.1.0

### Neue Funktionen

- Erkannte vorhandene Hamburger-Menüs und Dropdowns sind mit eigenem lokalem JavaScript bedienbar, einschließlich Tastaturbedienung, verschachtelter Menüs und responsiver Navigation. Die CSP erlaubt ausschließlich den eigenen Menücontroller per Hash; Originalskripte, fremde Eventhandler, externe Netzwerkzugriffe und Formulare bleiben blockiert. `menue_manifest.json` dokumentiert die abgeleitete Bedienhilfe.
- Deaktivierte externe und nicht gesicherte Links zeigen ihre vollständige Zieladresse mit Parametern und Sprungmarken bei Hover/Fokus sowie in einem lokalen Dialog mit dem Hinweis „Externe Links und Verbindungen sind gesperrt.“ Die Kopierfunktion bietet bei blockierter Zwischenablage eine manuelle Ausweichmöglichkeit. Das Ziel wird nicht aufgerufen; der eigene Linkcontroller wird ausschließlich per CSP-Hash freigegeben. `linkziele_manifest.json` dokumentiert die Adressen; deaktivierte Bildkartenbereiche erhalten zusätzliche Infoknöpfe.
- Die GUI-Funktion „Ansicht aus Sicherung neu erzeugen“ und der CLI-Befehl `mirror` erzeugen eine korrigierte Ansicht aus vorhandenen Sicherungen in einem separaten Ausgabeordner, ohne Primärdaten oder deren Prüfsummen zu verändern und ohne neue Website-Aufrufe.

### Fehlerkorrekturen

- Eingebettete Bilder und SVG-Bilder bleiben im lokalen Website-Spiegel sichtbar. Bildvarianten, bereits erfasste Lazy-Bilder, Basis-URLs, Ressourcen-Weiterleitungen und CSS-Importe werden lokal aufgelöst. Neue Sicherungen dokumentieren die vom Browser ausgewählten Bildquellen, ohne den Original-DOM zu verändern.
- Lokale Seitenlinks behalten Sprungmarken und Image-Map-Verweise. Fehlende Ziele und Ressourcen werden in `fehlende_referenzen.json` ausgewiesen; der Index behandelt fremde Seitentitel und URLs als Text.
- Die erzeugte Ansicht funktioniert sowohl beim direkten Öffnen als Datei als auch über einen lokalen statischen Webserver. Ihre UTF-8-Kennzeichnung entspricht den gespeicherten Inhalten und den CSP-Hashes.

### Berichte und Prüfung

- Ausführlicher Sicherungsvermerk mit Beschreibung von Browsersitzung, HAR-Aufzeichnung, Screenshots, lokalem Website-Spiegel und ergänzenden Auswertungen. Die eigenen Offline-Bedienhilfen und ihre Grenzen werden dokumentiert.
- Tatsächlicher Sicherungsbeginn, Beginn und Ende der Browseraufzeichnung, Abschluss der Datenerhebung und Auswertung sowie gemessene Dauer.
- Kennzahlen zu Seiten, HTTP-Fehlerseiten, Screenshots, Erfassungsfehlern, gespeicherter HAR-Datenmenge, verbleibenden Adressen und Laufparametern; zusätzliche `Sicherungsstatistik.json` im Primärbestand.
- Regressionstests für Ressourcen, CSS, Navigation, unveränderte Primärdaten, Offline-Menüs und Linkziel-Dialoge. Chromium-Prüfungen decken Datei-/HTTP-Ansichten, Tastaturbedienung, Kopiermöglichkeiten und die CSP-Sperren ab.

## 1.0.0

Erste öffentliche Veröffentlichung von **Forensic SiteSaver**.

Enthalten sind insbesondere Website-Sicherung mit segmentierter HAR-Aufzeichnung, sicherer lokaler Website-Spiegel, Screenshots, HAR-Auswertung, eigenständige und integrierte Domain-/Hosting-/MX-Analyse, manuelle Origin-IP-Ergänzung, TLS-Zertifikatssicherung, automatische PDF-Aktenberichte im Ergebnisordner, externe-Dienste-Transparenz sowie GPL-/Drittanbieter-Lizenzdokumentation.

Weitere Punkte der finalen 1.0.0: vereinfachte GUI ohne separate HAR-/Export-Reiter sowie robustere TLS-Zertifikatserfassung über Python `ssl`.

Der Domain-PDF-Bericht führt die strukturierte Domainanalyse und die ergänzenden WHOIS-Details aus `domain_whois.txt` zusammen und dokumentiert beide Quelldateien samt SHA-256.

WHOIS folgt nun IANA-/Registry-Referrals bis zum Registrar; PDF-Aktenberichte enthalten keinen Disclaimer mehr (der Hinweis bleibt in der Programmoberfläche).

WHOIS-Referral-Chaining folgt nun generisch allen neu genannten WHOIS-Servern bis zum Ende der Kette; VeriSign wird bevorzugt mit `dom <domain>` abgefragt.

WHOIS-Referral-Erkennung ist jetzt tolerant gegenüber Einrückungen, Tabs und unterschiedlichen Feldbezeichnungen; `domain_whois.txt` protokolliert die erkannte Referral-Kette.

Für `.de`-Domains wird zusätzlich die öffentliche DENIC-WebWhois-Auskunft gesichert und ausgewertet (verwaltendes DENIC-Mitglied, Registrierungs-/Aktualisierungsdatum und ggf. öffentlich sichtbare Inhaberdaten).
