# Strumenti e progetti simili

Confronto onesto con gli strumenti open source che fanno parti dello stesso lavoro. polyscan non li sostituisce: è un orchestratore leggero che lancia scanner affermati e trasforma i risultati in un registro dei rischi spiegato. Le informazioni sono state raccolte a novembre 2026 dalle fonti in fondo.

| Strumento | Cos'è | In comune con polyscan | Cosa ha in più | Cosa ha polyscan in più |
|---|---|---|---|---|
| **DefectDojo** | Piattaforma di vulnerability management (Django, con database) | Importa risultati di molti scanner, deduplica, accettazione del rischio, SLA, rapporti | Gerarchia prodotto/engagement/test, interfaccia web multiutente, metriche nel tempo, centinaia di parser, Jira | Lancia gli scanner da sé, punteggio probabilità × impatto con ragioni scritte, CWE→ATT&CK, regola "controllo fallito ≠ pulito"; zero server da gestire |
| **SecObserve** | Vulnerability management open source | Valutazione di gravità e stato, regole di valutazione, EPSS, scadenza delle accettazioni, VEX | Interfaccia web, licenze dei componenti (SBOM), notifiche Teams/Slack/email, metriche | Analisi statica e dinamica integrate, ATT&CK, KEV, rapporto di assessment unico |
| **CVE Prioritizer** | Script che combina CVSS, EPSS e CISA KEV | Stesse fonti di threat intelligence | Soglie configurabili | Applica le fonti a un registro completo, non solo a una lista di CVE |
| **OWASP Threat Dragon** | Modellazione delle minacce con diagrammi (fase di progetto) | STRIDE | Diagrammi di flusso dei dati, minacce *prima* di scrivere codice | Parte dai risultati reali delle scansioni |
| **Greenbone / OpenVAS** | Scanner di vulnerabilità di rete, anche autenticato | Scoperta di servizi esposti | Migliaia di test di rete, scansione da remoto | Codice sorgente, librerie, segreti, registro dei rischi |
| **OWASP ZAP** | DAST | polyscan lo usa (passivo) | Scansione attiva, proxy, HUD | Lo combina con il resto e con il rischio |
| **Trivy**, **Semgrep**, **Gitleaks**, **OSV-Scanner** | Scanner singoli | polyscan li usa | Ognuno è lo strumento di riferimento nella sua area | Li unisce, verifica che abbiano girato, dà priorità |
| **Nuclei** | Scanner a template | Controlli su servizi in esecuzione | Migliaia di template della comunità | Escluso di proposito: molti template inviano richieste offensive |

## Cosa è stato preso da questi progetti

- **Da DefectDojo e SecObserve:** il trattamento del rischio con responsabile e scadenza (`--decisions`), lo stato dei falsi positivi con traccia di chi ha deciso, il confronto tra scansioni (`polyscan diff`).
- **Da CVE Prioritizer, SecObserve e dalle pratiche CISA/FIRST:** KEV ed EPSS per dare priorità (`--intel`).
- **Dall'ecosistema (GitHub, DefectDojo):** l'output SARIF, così i risultati di polyscan si possono importare in DefectDojo o in GitHub Code Scanning invece di competere con loro.
- **Da Threat Dragon e dalla modellazione delle minacce:** la classificazione STRIDE di ogni rischio.

## Cosa manca ancora rispetto a loro (roadmap)

Fatto dopo la prima stesura: OWASP Risk Rating come seconda valutazione, audit della configurazione dei database, SBOM CycloneDX, controllo TLS, storia delle scansioni, login con form, applicazione di prova con database, CVE delle immagini Docker raggruppate in un rischio per immagine.

1. **Database delle scansioni e interfaccia web multiutente**: DefectDojo e SecObserve li hanno; polyscan lavora su file JSON (li si può importare in DefectDojo con SARIF).
2. **API (OpenAPI) e applicazioni a pagina singola**: non coperte dalla scansione dinamica; l'importazione OpenAPI di ZAP invia anche POST e DELETE, quindi è stata lasciata fuori.
3. **Login con token anti-CSRF, a più passaggi o OAuth**: serve il cookie di sessione passato a mano.
4. **Configurazione effettiva del database in esecuzione** (utenti, privilegi, ruoli): si controllano solo i file.

## Fonti

- DefectDojo, documentazione delle funzioni: https://documentation.defectdojo.com/usage/features
- DefectDojo, "Top 11 open source vulnerability management tools for 2026": https://defectdojo.com/blog/top-11-open-source-vulnerability-management-tools-for-2026
- SecObserve, funzioni: https://secobserve.github.io/SecObserve/getting_started/features
- CVE Prioritizer (Help Net Security, 2024): https://www.helpnetsecurity.com/2024/02/19/cve-prioritizer-open-source-vulnerability-patching/
- OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- OWASP Risk Rating Methodology: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- CISA KEV (mirror ufficiale su GitHub): https://github.com/cisagov/kev-data
- FIRST EPSS API: https://api.first.org/epss
- NIST SP 800-30 Rev. 1: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
