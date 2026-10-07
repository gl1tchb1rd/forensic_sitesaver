# Forensic SiteSaver 1.1.0

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

Der lokale Website-Spiegel deaktiviert fremde Originalskripte, Frames, Formulare und externe Netzwerkverbindungen. Für erkannte Navigationsmenüs und die Anzeige ursprünglicher Linkziele wird ausschließlich eigener lokaler Bediencode freigegeben. Die unveränderte HAR bleibt technische Primärquelle.

Die Ansicht erhält eingebettete Bilder (`data:`), aufgezeichnete SVG-Bilder, lokale Bildvarianten aus `srcset`/`picture`, Sprungmarken und Verweise zwischen gesicherten Seiten. Bei neuen Sicherungen werden die vom Browser ausgewählten Bildquellen zusätzlich in der Seitenliste dokumentiert; der originale DOM bleibt unverändert. CSS-Importe und Bildreferenzen verwenden lokale Laufzeitkopien. Die Ansicht kann per Doppelklick auf `02_website/index.html` oder über einen lokalen statischen Webserver geöffnet werden.

Bei neuen Sicherungen scrollt der Browser während der HAR-Aufzeichnung zu noch nicht geladenen Lazy-Bildern, damit auch Bilder unterhalb des sichtbaren Ausschnitts angefordert werden können. Der Vorgang besucht höchstens 40 Bildpositionen und dauert höchstens acht Sekunden beziehungsweise das eingestellte Zeitlimit; anschließend wird die ursprüngliche Scrollposition wiederhergestellt. Der danach beobachtete DOM wird gespeichert, ohne Bildattribute künstlich zu ändern. `lazy_image_loading` in `04_metadaten/visited_pages.json` dokumentiert das Ergebnis und erreichte Grenzen.

Die lokale Zuordnung berücksichtigt URL-kodierte Umlaute und Leerzeichen, maskierte CSS-Dateinamen und `image-set(...)`. Relative Verweise in weitergeleiteten Stylesheets verwenden die endgültige Stylesheet-Adresse. Ein nicht gesicherter Lazy-Platzhalter kann durch sein bereits aufgezeichnetes Ziel ersetzt werden; unbrauchbare `picture`-Quellen verdecken das gesicherte Ersatzbild nicht mehr.

Die Ressourcenlesung übernimmt das robustere Vorgehen aus K25-SiteSaver: HAR-Anhänge können über `_file` oder `_sha1`, in ZIP-Unterordnern oder als separate Dateien neben einer HAR-Datei vorliegen. Abweichende ZIP-Pfade werden nur bei eindeutiger Zuordnung aufgelöst; separate Anhänge müssen innerhalb des HAR-Ordners liegen. Unterschiedliche gespeicherte Fassungen derselben Ressource bleiben erhalten, während die Ansicht die zuletzt erfolgreich aufgezeichnete Fassung verwendet. Lokale Dateien erhalten eine zum Inhaltstyp passende Endung und Windows-taugliche Dateinamen. Ältere CSS-Zeichensätze werden ausschließlich für die UTF-8-Laufzeitkopie umgewandelt.

Würde der vollständige Ressourcenpfad länger als 230 Zeichen, verwendet die Ansicht einen kurzen Dateinamen unter `ressourcen/_kurz`. Dadurch bleibt Platz für unterschiedliche Inhaltsfassungen unter der klassischen Windows-Pfadgrenze. Die Original-URL, Prüfsumme, lokale Ablage und Kennzeichnung `path_shortened` stehen in `ressourcen_manifest.json`; die Bildinhalte werden nicht verändert.

Nur bereits aufgezeichnete Inhalte sind verfügbar: Ein nie geladenes Lazy-Bild oder eine nicht besuchte Unterseite kann aus dem Mitschnitt nicht rekonstruiert werden. Solche Verweise stehen in `fehlende_referenzen.json`. Nicht gesicherte Links erhalten einen Hinweis und führen keinen externen Aufruf aus. Ausschließlich von Originalskripten erzeugte Navigation kann nicht rekonstruiert werden.

Die Diagnose enthält je fehlender Referenz eine Ursache (`reason`): `not_in_har` bedeutet, dass kein entsprechender Ressourceneintrag gefunden wurde; `response_body_missing` kennzeichnet fehlende Response-Inhalte, `http_error` eine erfolglose HTTP-Antwort und `no_response` eine ausgebliebene Antwort. Weitere Ursachen sind `unsupported_mime`, `redirect_target_not_archived` und für Seitenlinks `page_not_archived`. Wenn vorhanden, werden HTTP-Status und Inhaltstyp ergänzt. Fehlt das Bild selbst im Mitschnitt, ist eine neue Sicherung nötig.

Deaktivierte Links behalten ihren Text und eine Kennzeichnung wie „extern · deaktiviert“ oder „nicht gesichert · deaktiviert“. Beim Darüberfahren oder Tastaturfokus zeigt eine lokale Vorschau die vollständige ursprüngliche Zieladresse einschließlich Parametern und Sprungmarken. Ein Klick oder Enter/Leertaste öffnet ein kleines Dialogfenster mit der Adresse, **„URL kopieren“** und dem Hinweis **„Externe Links und Verbindungen sind gesperrt.“** Schließen/Escape führt den Fokus zum Ausgangspunkt zurück. Es wird weder ein externes Browserfenster geöffnet noch eine Verbindung zum Ziel aufgebaut. Falls der Browser automatisches Kopieren blockiert, bleibt die Adresse zum manuellen Kopieren markiert.

Die Ziele haben keinen navigierbaren `href`; auch E-Mail-, Telefon- und andere Aktionsadressen werden ausschließlich als Text dargestellt. Gesicherte Seitenlinks bleiben lokal navigierbar. Bei deaktivierten Bildkartenbereichen stehen zusätzliche „Bildlink“-Infoknöpfe zur Verfügung. `linkziele_manifest.json` dokumentiert die ursprünglichen Adressen und den CSP-Hash des eigenen Linkcontrollers. Im gespeicherten HTML enthält auch das `title`-Attribut die Zieladresse, falls JavaScript im Browser vollständig deaktiviert ist.

### Vorhandene Sicherung neu anzeigen

Im Reiter „Website-Sicherung“ erzeugt **„Ansicht aus Sicherung neu erzeugen“** eine neue Ansicht in einem separaten, leeren Ordner. Zuerst den ursprünglichen Sicherungsordner auswählen, anschließend den Ausgabeordner außerhalb der Sicherung. Danach dessen `index.html` öffnen. HAR, originaler DOM, Sicherungsvermerk und Primärprüfsummen werden ausschließlich gelesen. Es erfolgen keine neuen Website-Aufrufe.

Auch bestehende K25-SiteSaver-Sicherungen werden unterstützt: Die alte Seitenliste mit `dom_raw` und Windows-Pfadtrennern wird beim Lesen berücksichtigt; die ursprüngliche Sicherung bleibt erhalten.

Alternativ aus dem Programmordner (Windows: `.venv\\Scripts\\python.exe` statt `.venv/bin/python`):

```bash
.forensic_sitesaver/.venv/bin/python .forensic_sitesaver/cli.py mirror --source /pfad/zur/Sicherung --output /pfad/zur/NeuenAnsicht
```

### JavaScript bei der Offline-Auswertung

Vorhandene Hamburger-Menüs und Dropdowns erhalten eine lokale Ersatzbedienung. Die Erkennung unterstützt `aria-controls`, lokale Zielverweise, einfache ID-/Klassen-Ziele aus `data-target`/`data-bs-target`, Bootstrap-Dropdowns und typische Untermenüs unter `menu-item-has-children`. Voraussetzung ist ein bereits gespeichertes Navigationspanel mit Links. Ein echter Seitenlink bleibt erhalten und bekommt bei Bedarf einen separaten Untermenüknopf.

Der eigene Menücontroller öffnet und schließt Menüs, aktualisiert `aria-expanded`, unterstützt Enter/Leertaste/Escape, schließt Menüs bei Klick außerhalb und berücksichtigt verschachtelte Menüs sowie per CSS versteckte Desktop-/Mobil-Schalter. Er verändert ausschließlich vorhandene DOM-Elemente; er lädt keine Inhalte nach und führt keine fremden Skripte oder Eventhandler aus. Formulare und andere ursprüngliche Schaltflächen bleiben deaktiviert. Die CSP erlaubt nur die exakten SHA-256-Hashes der jeweils benötigten eigenen Controller, ohne `unsafe-inline` oder `unsafe-eval` für Skripte; `connect-src 'none'`, blockierte Frames und Worker bleiben erhalten. Seiten ohne erkannte Menüs und deaktivierte Linkziele erlauben weiterhin gar keine Skripte.

`menue_manifest.json` dokumentiert die Erkennung, nicht zugeordnete Schalter und den freigegebenen Controller-Hash. Das Verhalten ist eine abgeleitete Bedienhilfe und keine originalgetreue Wiedergabe des fremden JavaScripts. Websites mit eigenen Menüstrukturen können eine angepasste Erkennungsregel benötigen; vom Server nachzuladende Menüs bleiben unvollständig. Die Funktion wirkt bei neuen Sicherungen und bei **„Ansicht aus Sicherung neu erzeugen“**; vorhandene Primärdaten werden nicht umgeschrieben.

Fremde Originalskripte benötigen eine getrennte Wiedergabeumgebung. Eine belastbare Lösung kombiniert HAR-Wiedergabe ohne Netzwerk-Fallback (etwa Playwright `route_from_har(..., not_found="abort")`, inklusive Skript- und API-Antworten) mit einer Netzwerksperre auf Betriebssystemebene: zum Beispiel eine VM ohne virtuelle Netzwerkkarte oder eine isolierte Netzwerkumgebung ohne externen Zugang. Alle HAR-Segmente müssen dabei berücksichtigt werden; WebSockets und Service Worker sollten deaktiviert sein. Die HAR-Dateien können direkt aus dem Dateisystem beantwortet werden, sodass kein Webserver erforderlich ist.

`connect-src 'none'`, ein Sandbox-iframe oder das Überschreiben von `fetch` alleine verhindern nicht jeden Netzwerkweg, insbesondere Navigation und WebRTC. Deshalb aktiviert die normale HTML-Ansicht keine fremden Skripte. Ein JavaScript-Replay ist in dieser Version nicht implementiert. Auch ein isoliertes Replay kann nur aufgezeichnete Antworten wiedergeben; nicht erfasste API-Zustände bleiben unvollständig.

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

Aktueller Versionsstand: **1.1.0**. Die Änderungen gegenüber **1.0.0** sind in `.forensic_sitesaver/CHANGELOG.md` dokumentiert. Frühere interne Entwicklungsstände sind nicht Teil des öffentlichen Changelogs.

## geplante Änderungen

Für die nächste Version werden folgende Änderungen geplant:
Auflistung aller externen Links und E-Mail-Adressen im Auswertungsbericht
Isolierte HAR-Wiedergabe für JavaScript-Seiten

Verbesserungsvorschläge jederzeit Willkommen
