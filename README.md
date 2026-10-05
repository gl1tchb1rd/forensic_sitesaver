# Forensic SiteSaver 1.0.0

`Forensic SiteSaver` ist ein plattformübergreifendes Python-Werkzeug zur passiven technischen Sicherung und Auswertung öffentlich erreichbarer Websites und Domains. Die Software richtet sich insbesondere an forensische bzw. ermittlungsunterstützende Arbeitsabläufe, ist aber nicht auf Behördennutzung beschränkt.

Projekt / Quellcode: https://github.com/gl1tchb1rd/forensic_sitesaver

## Start

Auf der obersten Ebene liegen bewusst nur diese README und die Startdatei:

```text
forensic_sitesaver.py
README.md
.forensic_sitesaver/   (technische Komponenten; unter Linux verborgen)
```

Windows: `forensic_sitesaver.py` starten oder in einer Eingabeaufforderung:

```bat
python forensic_sitesaver.py
```

Linux/macOS:

```bash
python3 forensic_sitesaver.py
```

Beim ersten Start wird im technischen Unterordner eine lokale `.venv` angelegt. Python-Abhängigkeiten sowie Chromium und Firefox werden von ihren jeweiligen Quellen installiert. Python 3.10+ und Tk/Tkinter müssen systemseitig vorhanden sein.

## Funktionen

- passive Website-Sicherung mit Playwright
- segmentierte HAR-Aufzeichnung (`full`, Response-Inhalte enthalten)
- kein Playwright-Trace
- Full-Page-Screenshots
- sicherer lokaler Website-Spiegel ohne externe Netzwerk-Nachladevorgänge
- byteidentische lokale Sicherung von während des Browserlaufs erfassten Bildern, CSS, Fonts und Medien
- automatische interne HAR-Auswertung einschließlich Backend-/API-Kandidaten, Shop-Systemen, Zahlungsdiensten und deduplizierten externen Verbindungen
- Domainanalyse als Bestandteil einer Vollsicherung **oder eigenständige Funktion ohne Website-Sicherung**
- DNS, Registrar, RDAP/WHOIS, Webserver-/Hostinghinweise und GeoIP
- `.de`-Sonderauswertung über die öffentliche DENIC-Domainabfrage: verwaltendes DENIC-Mitglied, Registrierungsdatum, letzte Aktualisierung und – soweit öffentlich – Inhaberdaten juristischer Personen; Rohdaten werden separat gesichert
- ausführliche MX-/Mailserveranalyse mit Priorität, Host, IPs, vermutetem Maildienst-Anbieter, Netz-/Hosting-Provider und GeoIP-Standorthinweisen
- Domain-PDF kombiniert die strukturierte `Domain_Analyse.txt` mit den ergänzenden WHOIS-Details aus `domain_whois.txt`; beide Quellen und SHA-256-Werte werden im PDF und Exportmanifest ausgewiesen
- WHOIS verfolgt Referral-Ketten generisch bis zum letzten erreichbaren WHOIS-Server (typisch IANA → Registry → Registrar); bereits besuchte Server werden zur Schleifenvermeidung nicht erneut abgefragt
- bekannte Origin-/Server-IP kann später manuell und klar gekennzeichnet ergänzt werden
- TLS-/SSL-Zertifikatssicherung
- automatische PDF-Aktenberichte im jeweiligen Ergebnisordner unter `PDF-Berichte/`; bei Vollsicherungen für Sicherungsvermerk, HAR-Auswertung, Domainanalyse und TLS-Bericht, bei Domainanalysen für die Domainanalyse
- SHA-256-Prüfsummen und Transparenzdateien zu externen Diensten/Datenquellen
- Updateprüfung für Abhängigkeiten (keine stille Selbstaktualisierung des Programmcodes)

## Ergebnisordner und PDF-Berichte

PDF-Aktenberichte werden automatisch erzeugt. Eine eigenständige Domainanalyse erzeugt nur einen Ergebnisordner; darin liegt der Bericht unter `PDF-Berichte/`. Auch bei einer vollständigen Website-Sicherung liegt `PDF-Berichte/` direkt im Sicherungsordner. Nach einer manuellen Origin-IP-Ergänzung wird der Domainbericht automatisch neu erzeugt.

`PDF-Berichte/` enthält abgeleitete Aktenausfertigungen und ein eigenes Exportmanifest mit SHA-256-Prüfsummen. Bei vollständigen Sicherungen wird dieser Ordner bewusst nicht in `SHA256SUMS.txt` der Primärsicherung aufgenommen, damit ein später dokumentierter Origin-IP-Nachtrag die Primärprüfsummen nicht verändert.

Der Sicherungsvermerk beschreibt den Ablauf in einer eigenen Browsersitzung, die HAR-Aufzeichnung, Screenshots, den abgesicherten lokalen Website-Spiegel und die ergänzenden Analysen. Er nennt den tatsächlichen Beginn der Sicherung, Beginn und Ende der Browseraufzeichnung sowie das Ende der Datenerhebung und Auswertung. PDF-Erstellung und abschließende Prüfsummenbildung erfolgen danach. Seitenzahl, HTTP-Fehlerseiten, Screenshot- und Erfassungsfehler, HAR-Anfragen, gespeicherte Mitschnittgröße und Laufparameter machen den Umfang nachvollziehbar. Die Mitschnittgröße bezeichnet die Größe der gespeicherten HAR-Archive, nicht die übertragene Datenmenge auf Netzwerkebene. Diese Laufdaten werden zusätzlich unter `04_metadaten/Sicherungsstatistik.json` gesichert und in den Primärprüfsummenbestand aufgenommen.

Die erweiterten Angaben werden bei neuen Sicherungen erzeugt. Bereits vorhandene Sicherungsvermerke werden beim PDF-Neuexport unverändert als Quelle verwendet; fehlende historische Laufdaten werden nicht nachträglich ergänzt.

Die Berichterzeugung lässt sich aus dem Repository-Verzeichnis ohne Browser-Downloads oder externe Domainabfragen prüfen:

```bash
PYTHONPATH=.forensic_sitesaver .forensic_sitesaver/.venv/bin/python -m unittest discover -s .forensic_sitesaver/tests -v
```

Die Tests verwenden simulierte Browseraufrufe und prüfen die tatsächlich erzeugten HAR-, Berichts-, PDF- und Prüfsummendateien. Für die zusätzliche Textprüfung des PDFs ist `pdftotext` aus Poppler erforderlich; dieser Test wird übersprungen, wenn das Werkzeug fehlt.

## Sicherheitsmodell

Der Crawler klickt keine Links und sendet keine Formulare. Aktive Navigation erfolgt nur zu zugelassenen HTTP(S)-Zielen. `POST`, `PUT`, `PATCH` und `DELETE` werden blockiert; bekannte zustandsverändernde GET-Muster wie Warenkorb-/Bestell-/Zahlungsaktionen werden ebenfalls blockiert. Eine absolute Nebenwirkungsfreiheit kann technisch nicht garantiert werden, wenn ein fremder Server entgegen HTTP-Konventionen bereits normale GET-Aufrufe als Zustandsänderung missbraucht.

Der lokale Website-Spiegel deaktiviert JavaScript, Frames, Formulare und externe Netzwerkverbindungen. Die unveränderte HAR bleibt technische Primärquelle.

## Externe Dienste und Datenschutz

Es gibt **keine KI-Anbindung und keine Cloud-Analyse**. HAR-Dateien, Screenshots und Sicherungspakete werden nicht an OpenAI, ChatGPT, Gemini oder andere KI-Dienste übertragen.

Für technische Infrastrukturinformationen können je nach Analyse DNS-Resolver, RDAP/WHOIS, `ipwho.is` und Team Cymru angesprochen werden. Jeder konkrete Analyselauf dokumentiert Dienst/Ziel, übertragenen Wert und Zweck in Transparenzdateien.

## Lizenz

Der eigene Programmcode wird unter **GNU General Public License Version 3 oder später (`GPL-3.0-or-later`)** veröffentlicht. Die GPL erlaubt nach ihren Bedingungen private, wissenschaftliche, behördliche und kommerzielle Nutzung sowie Änderung und Weitergabe.

Vollständiger GPL-Text und Drittanbieterhinweise:

```text
.forensic_sitesaver/LICENSE_GPL-3.0.txt
.forensic_sitesaver/LIZENZEN_UND_DRITTANBIETER.txt
```

Nach der Ersteinrichtung erzeugt die Software zusätzlich:

```text
.forensic_sitesaver/INSTALLIERTE_LIZENZEN.txt
```

Diese Datei basiert auf den tatsächlich installierten Paketen und übernimmt, soweit auffindbar, deren mitgelieferte Lizenz-/NOTICE-Texte. Playwright-Browser sind nicht Bestandteil dieses Quellcode-Pakets, sondern werden bei der lokalen Einrichtung separat bezogen und behalten ihre jeweiligen Lizenzen.

## Disclaimer

Dieses Werkzeug dient ausschließlich der technischen Ermittlungsunterstützung und Dokumentation. Automatisch erhobene, zusammengeführte oder abgeleitete Angaben – insbesondere GeoIP-, Hosting-/Provider-, Registrar-/WHOIS-/RDAP-, Shop-, Zahlungs- und Mailserver-Zuordnungen – können unvollständig, veraltet oder fehlerhaft sein. Die Prüfung der Richtigkeit und Beweisbedeutung der Ergebnisse sowie die rechtliche Zulässigkeit sämtlicher daraus abgeleiteter Maßnahmen liegen ausschließlich in der Verantwortung der nutzenden Person bzw. Stelle. Das Programm ersetzt weder eine fachliche Einzelfallprüfung noch eine rechtliche Prüfung.

## Öffentliche Version

`1.0.0` ist die erste als öffentliche Veröffentlichung vorgesehene Version. Frühere interne Entwicklungsstände sind nicht Teil des öffentlichen Changelogs.

## geplante Änderungen

Für die nächste Version werden folgende Änderungen geplant:
Auflistung aller externen Links und E-Mail-Adressen im Auswertungsbericht
Verbesserung und Fehlebehebung bei der Darstellung von JavaScript-Seiten beim Webseitenspiegel

Verbesserungsvorschläge jederzeit Willkommen
