# Metodologia: come polyscan segue un vulnerability assessment

Questo documento collega le fasi di un assessment, come le descrivono gli standard, ai comandi di polyscan. Serve a chi deve presentare il lavoro (relazione, esame, cliente) e vuole mostrare *quale* metodo è stato seguito, non solo *quali* strumenti sono stati lanciati.

## Standard di riferimento

| Standard | Cosa prende polyscan |
|---|---|
| **NIST SP 800-115** (*Technical Guide to Information Security Testing and Assessment*) | Le quattro fasi del test: pianificazione, scoperta, attacco, rapporto. polyscan copre scoperta e rapporto; la fase di attacco è volutamente esclusa (vedi sotto). |
| **NIST SP 800-30 Rev. 1** (*Guide for Conducting Risk Assessments*) | Rischio = probabilità × impatto, con le ragioni scritte; preparare, condurre, comunicare e mantenere la valutazione. |
| **ISO/IEC 27005** e **NIST SP 800-39** | La risposta al rischio: mitigare, accettare, trasferire, evitare (`--decisions`). |
| **OWASP Top 10 (2021)**, **CWE**, **MITRE ATT&CK** | La classificazione delle minacce di ogni rischio. |
| **PTES** (*Penetration Testing Execution Standard*) e **OWASP WSTG** | Struttura del rapporto: ambito, sintesi, metodo, risultati, raccomandazioni. |
| **CISA KEV**, **FIRST EPSS** | Probabilità basata su sfruttamenti reali, non solo sulla gravità teorica. |
| **OASIS SARIF 2.1.0** | Formato di scambio dei risultati con altri strumenti (GitHub, DefectDojo, IDE). |

## Le fasi, passo per passo

### 1. Pianificazione e autorizzazione
Prima di tutto: cosa si testa, chi lo autorizza, cosa resta fuori. polyscan rifiuta di scansionare un sito non locale senza `--allow-remote`, e il rapporto finale scrive chi ha autorizzato il test (`--authorized-by`); se manca, lo dice in rosso.

### 2. Scoperta: analisi del codice e della configurazione (statica)
```bash
polyscan scan ./app --json scan.json --sarif scan.sarif --html scan.html
```
| Area | Strumenti |
|---|---|
| Codice (SAST) | Semgrep, Bandit (Python), Progpilot (PHP), SpotBugs + Find Security Bugs (Java), regole SQL di polyscan |
| Segreti | Gitleaks, anche su tutta la storia git |
| Librerie (SCA) | OSV-Scanner, npm audit, cargo-audit, composer audit |
| Container | Trivy sulle immagini Docker nominate nel progetto |
| Configurazione (IaC) | Checkov su Dockerfile, docker-compose, Kubernetes, Terraform |

### 3. Scoperta: applicazione in esecuzione e host (dinamica)
```bash
polyscan dast http://localhost:8000 --json dast.json      # ZAP, scansione passiva
polyscan ports --json ports.json                          # porte in ascolto (Linux)
```

### 4. Analisi del rischio
```bash
polyscan risk scan.json dast.json ports.json --exposure internet --data personal --intel --html rischi.html
```
Ogni gruppo di segnalazioni diventa un rischio con probabilità (1-5), impatto (1-5), livello, ragioni scritte, mitigazione, tempi di risposta suggeriti, CVE/CWE, OWASP, STRIDE e tecniche ATT&CK. Con `--intel` le CVE sfruttate attivamente (KEV) salgono in cima.

### 5. Trattamento
```bash
polyscan risk scan.json --decisions-template da-decidere.json   # una voce per rischio
# si compila il file: chi decide, cosa, entro quando
polyscan risk scan.json --decisions polyscan-risk.json
```

### 6. Rapporto
```bash
polyscan report scan.json dast.json ports.json --title "..." --target "..." --tester "..." \
  --authorized-by "..." --decisions polyscan-risk.json --intel --html assessment.html
```
Un solo documento stampabile (Salva come PDF dal browser) con: ambito e autorizzazione, sintesi per la direzione, metodo e copertura, matrice e registro, trattamento, minacce ATT&CK per tattica, retest, appendice sul metodo di calcolo.

### 7. Retest
Dopo le correzioni si ripete la scansione e:
```bash
polyscan diff scan-prima.json scan-dopo.json --html retest.html
polyscan report scan-dopo.json --retest scan-prima.json --html assessment-v2.html
```
Una segnalazione sparita conta come risolta solo se lo strumento ha girato davvero la seconda volta.

## Cosa NON fa (e perché)

- **Nessun attacco attivo** (exploit, fuzzing, brute force, scansione attiva di ZAP). È una scelta: il tool deve poter girare in CI e su sistemi condivisi senza rischio di danni. Per la fase di attacco di NIST SP 800-115 si usano strumenti dedicati, a mano, su una copia di test e con autorizzazione scritta; i loro risultati JSON possono comunque entrare nel registro.
- **Logica applicativa e autorizzazioni tra utenti**: richiedono un test manuale (OWASP WSTG, capitoli *Authorization* e *Business Logic*).
- **Firewall**: `polyscan ports` vede cosa ascolta sulla macchina, non cosa è filtrato davanti.

## Principio guida

Un controllo che non ha girato non deve mai sembrare pulito: errore, strumento mancante, rapporto vuoto o fonte di threat intelligence irraggiungibile diventano una lacuna visibile in ogni rapporto e il codice di uscita 3.
