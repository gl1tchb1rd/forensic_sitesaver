# gl1tchb1rd forensic sitesaver 1.0.0

`gl1tchb1rd forensic sitesaver` ist ein plattformübergreifendes Python-Werkzeug zur passiven technischen Sicherung und Auswertung öffentlich erreichbarer Websites und Domains. Die Software richtet sich insbesondere an forensische bzw. ermittlungsunterstützende Arbeitsabläufe, ist aber nicht auf Behördennutzung beschränkt.

## Start

Auf der obersten Ebene liegen bewusst nur diese README und die Startdatei:

```text
gl1tchb1rd_forensic_sitesaver.py
README.md
.gl1tchb1rd/   (technische Komponenten; unter Linux verborgen)
```

Windows: `gl1tchb1rd_forensic_sitesaver.py` starten oder in einer Eingabeaufforderung:

```bat
python gl1tchb1rd_forensic_sitesaver.py
```

Linux/macOS:

```bash
python3 gl1tchb1rd_forensic_sitesaver.py
```

Beim ersten Start wird im technischen Unterordner eine lokale `.venv` angelegt. Python-Abhängigkeiten sowie Chromium und Firefox werden von ihren jeweiligen Quellen installiert. Python 3.10+ und Tk/Tkinter müssen systemseitig vorhanden sein.

## Funktionen

- passive Website-Sicherung mit Playwright
- segmentierte HAR-Aufzeichnung (`full`, Response-Inhalte enthalten)
- kein Playwright-Trace
- Full-Page-Screenshots
- sicherer lokaler Website-Spiegel ohne externe Netzwerk-Nachladevorgänge
- byteidentische lokale Sicherung von während des Browserlaufs erfassten Bildern, CSS, Fonts und Medien
- HAR-Analyse einschließlich Backend-/API-Kandidaten, Shop-Systemen, Zahlungsdiensten und deduplizierten externen Verbindungen
- Domainanalyse als Bestandteil einer Vollsicherung **oder eigenständige Funktion ohne Website-Sicherung**
- DNS, Registrar, RDAP/WHOIS, Webserver-/Hostinghinweise und GeoIP
- ausführliche MX-/Mailserveranalyse mit Priorität, Host, IPs, vermutetem Maildienst-Anbieter, Netz-/Hosting-Provider und GeoIP-Standorthinweisen
- bekannte Origin-/Server-IP kann später manuell und klar gekennzeichnet ergänzt werden
- TLS-/SSL-Zertifikatssicherung
- PDF-Aktenexport für Sicherungsvermerk, HAR-Auswertung, Domainanalyse und TLS-Bericht; Domain-only-Analysen lassen sich ebenfalls als PDF exportieren
- SHA-256-Prüfsummen und Transparenzdateien zu externen Diensten/Datenquellen
- Updateprüfung für Abhängigkeiten (keine stille Selbstaktualisierung des Programmcodes)

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
.gl1tchb1rd/LICENSE_GPL-3.0.txt
.gl1tchb1rd/LIZENZEN_UND_DRITTANBIETER.txt
```

Nach der Ersteinrichtung erzeugt die Software zusätzlich:

```text
.gl1tchb1rd/INSTALLIERTE_LIZENZEN.txt
```

Diese Datei basiert auf den tatsächlich installierten Paketen und übernimmt, soweit auffindbar, deren mitgelieferte Lizenz-/NOTICE-Texte. Playwright-Browser sind nicht Bestandteil dieses Quellcode-Pakets, sondern werden bei der lokalen Einrichtung separat bezogen und behalten ihre jeweiligen Lizenzen.

## Disclaimer

Dieses Werkzeug dient ausschließlich der technischen Ermittlungsunterstützung und Dokumentation. Automatisch erhobene, zusammengeführte oder abgeleitete Angaben – insbesondere GeoIP-, Hosting-/Provider-, Registrar-/WHOIS-/RDAP-, Shop-, Zahlungs- und Mailserver-Zuordnungen – können unvollständig, veraltet oder fehlerhaft sein. Die Prüfung der Richtigkeit und Beweisbedeutung der Ergebnisse sowie die rechtliche Zulässigkeit sämtlicher daraus abgeleiteter Maßnahmen liegen ausschließlich in der Verantwortung der nutzenden Person bzw. Stelle. Das Programm ersetzt weder eine fachliche Einzelfallprüfung noch eine rechtliche Prüfung.

## Öffentliche Version

`1.0.0` ist die erste als öffentliche Veröffentlichung vorgesehene Version. Frühere interne Entwicklungsstände sind nicht Teil des öffentlichen Changelogs.
