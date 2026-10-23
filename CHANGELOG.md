# Changelog

Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.1.0/).
Le versioni seguono [SemVer](https://semver.org/lang/it/). Finché la versione è `0.x`, l'interfaccia può cambiare.

## [Non rilasciato]

### Aggiunto
- **Java**: [SpotBugs](https://spotbugs.github.io) con il plugin Find Security Bugs, sulle classi compilate; solo la categoria sicurezza. Senza classi compilate il controllo è saltato con il motivo, e se il plugin non si carica fallisce.
- **PHP**: analisi dei flussi di dati non fidati con [Progpilot](https://github.com/designsecurity/progpilot), e `composer audit --locked` per le librerie. Ogni file PHP è controllato con `php -l` prima, perché Progpilot non dice nulla sui file che non riesce a leggere; i file non analizzati sono segnalati.
- Nell'action: installazione di Progpilot, SpotBugs e Find Security Bugs con versione fissa e sha256 controllato.
- Nuovo modulo `polyscan.sastrun`; `polyscan.auditrun` conosce anche `composer` (codici di uscita 0-3 con rapporto valido).

## [0.5.0] - 2026-10-22

### Aggiunto
- **Trivy**: vulnerabilità nelle immagini Docker nominate dal progetto (`FROM` dei Dockerfile e `image:` dei file Compose), solo gravità alta e critica, con la riga del file in cui cambiare il tag. Le immagini con variabili non sono controllabili e sono segnalate come tali.
- **`polyscan ports`**: legge con `ss` le porte TCP/UDP in ascolto sulla macchina e segnala i servizi raggiungibili da altre reti (database, API di Docker, Telnet, RDP...) e le porte non previste (`--expect`). Non invia nulla in rete; solo Linux.

### Corretto
- Semgrep non gira più con `--quiet`: se fallisce (per esempio senza internet per scaricare le regole) il rapporto ora dice perché, invece di "exit code 2" senza testo.
- Nell'action, un percorso che inizia con `-` non può più essere letto come opzione da `find`.

### Modificato
- Il campione di output reale di Trivy e di `ss` usato dai test viene ricavato dalla CI (`show-latest-pins` e il job `ports-check`).

## [0.4.0] - 2026-10-22

### Aggiunto
- **Valutazione del rischio** (`polyscan risk`): legge uno o più rapporti JSON di `scan` e `dast` e produce un registro dei rischi (probabilità × impatto su una matrice 5×5), con priorità, cosa fare, tempo di risposta suggerito e i motivi di ogni punteggio. Rapporti in testo, Markdown, HTML e JSON. Le verifiche non eseguite nei rapporti di partenza sono riportate e influenzano il codice di uscita.
- **`npm audit`** e **`cargo-audit`**: seconda fonte per le librerie vulnerabili di JavaScript/TypeScript e Rust, una volta per ogni file di blocco. Per RustSec la gravità è calcolata dal vettore CVSS v3.
- **Scansione di un sito in esecuzione** (`polyscan dast`, da 0.3) ora con **accesso autenticato**: `--auth-header-env` aggiunge un token o un cookie a ogni richiesta, così ZAP vede anche le pagine dietro login. Il segreto passa dallo standard input del container, mai da un argomento o da un file sul disco.
- **Action**: nuovi input per avviare e fermare l'app da scansionare (`target-url`, `start-command`, `stop-command`, `wait-timeout`), per l'accesso autenticato (`auth-header-name`, `auth-header-value`), per il registro dei rischi (`risk-assessment`, `risk-exposure`, `risk-data`) e `artifact-name`, `scan-code`.

### Sicurezza
- Il token di accesso di ZAP non è più scritto in un file sul computer (dove un altro utente di una macchina condivisa poteva leggerlo): ora vive solo dentro il container, scritto con `umask 077`.

### Note
- La scansione **attiva** di ZAP (che invia attacchi) non è inclusa: `dast` resta passivo.

## [0.3.0] - 2026

### Aggiunto
- Scansione di una cartella con Semgrep, Gitleaks, OSV-Scanner, Bandit e Checkov; un solo rapporto in testo, HTML, JSON e Markdown.
- Regole proprie di polyscan per iniezioni SQL, `docker-compose.yml` e `Dockerfile`.
- Ricerca di segreti nei vecchi commit (`--history`).
- Scansione passiva di un sito in esecuzione con OWASP ZAP (`polyscan dast`), con controllo del bersaglio (solo macchina e rete privata salvo `--allow-remote`).
- Versioni degli strumenti bloccate (immagini Docker per digest, Action per commit).
- Uso come GitHub Action.
