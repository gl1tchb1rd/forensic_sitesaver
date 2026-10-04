# Changelog

## 1.0.0

Erste öffentliche Veröffentlichung von **Forensic SiteSaver**.

Enthalten sind insbesondere Website-Sicherung mit segmentierter HAR-Aufzeichnung, sicherer lokaler Website-Spiegel, Screenshots, HAR-Auswertung, eigenständige und integrierte Domain-/Hosting-/MX-Analyse, manuelle Origin-IP-Ergänzung, TLS-Zertifikatssicherung, automatische PDF-Aktenberichte im Ergebnisordner, externe-Dienste-Transparenz sowie GPL-/Drittanbieter-Lizenzdokumentation.

Weitere Punkte der finalen 1.0.0: vereinfachte GUI ohne separate HAR-/Export-Reiter sowie robustere TLS-Zertifikatserfassung über Python `ssl`.

Der Domain-PDF-Bericht führt die strukturierte Domainanalyse und die ergänzenden WHOIS-Details aus `domain_whois.txt` zusammen und dokumentiert beide Quelldateien samt SHA-256.

WHOIS folgt nun IANA-/Registry-Referrals bis zum Registrar; PDF-Aktenberichte enthalten keinen Disclaimer mehr (der Hinweis bleibt in der Programmoberfläche).

WHOIS-Referral-Chaining folgt nun generisch allen neu genannten WHOIS-Servern bis zum Ende der Kette; VeriSign wird bevorzugt mit `dom <domain>` abgefragt.

WHOIS-Referral-Erkennung ist jetzt tolerant gegenüber Einrückungen, Tabs und unterschiedlichen Feldbezeichnungen; `domain_whois.txt` protokolliert die erkannte Referral-Kette.

Für `.de`-Domains wird zusätzlich die öffentliche DENIC-WebWhois-Auskunft gesichert und ausgewertet (verwaltendes DENIC-Mitglied, Registrierungs-/Aktualisierungsdatum und ggf. öffentlich sichtbare Inhaberdaten).
