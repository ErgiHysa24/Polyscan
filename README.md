# polyscan

Un comando solo per controllare la sicurezza di un progetto scritto in **Python, JavaScript/TypeScript, Java, PHP e Rust**. Guarda quali linguaggi ci sono in una cartella, lancia gli strumenti giusti e produce **un solo rapporto** (terminale, HTML, JSON).

```bash
polyscan scan . --html report.html
```

## Cosa controlla

| Controllo | Strumento | Linguaggi | Come gira |
|---|---|---|---|
| Codice pericoloso (SAST) | [Semgrep](https://semgrep.dev) | tutti e 5 | Docker o installato |
| Iniezioni SQL (regole di polyscan) | Semgrep, con `polyscan/rules/sql-injection.yml` | tutti e 5 | come Semgrep |
| Segreti nel codice | [Gitleaks](https://github.com/gitleaks/gitleaks) | qualsiasi | Docker o installato |
| Segreti nei vecchi commit (con `--history`) | Gitleaks, modalità `git` | qualsiasi | Docker o installato |
| Configurazione sbagliata: Dockerfile, Kubernetes, Terraform, workflow GitHub | [Checkov](https://www.checkov.io) | file di configurazione | Docker o installato |
| Configurazione sbagliata: `docker-compose.yml` | Semgrep, con `polyscan/rules/docker-compose.yml` | Compose | come Semgrep |
| Librerie con vulnerabilità note | [OSV-Scanner](https://google.github.io/osv-scanner/) | tutti e 5 (file di dipendenze) | Docker o installato |
| Codice Python, in più | [Bandit](https://bandit.readthedocs.io) | Python | solo installato (`pip install bandit`) |

OSV-Scanner legge `requirements.txt`, `package-lock.json`, `pom.xml`, `composer.lock` e `Cargo.lock`. Senza questi file non può controllare le librerie: il rapporto lo dice.

## Controlli SQL

Una **SQL injection** nasce quando una query viene costruita incollando testo (concatenazione, f-string, `format!`, `String.format`...) e poi eseguita: se una parte arriva dall'utente, può cambiare la query. polyscan include regole proprie per Semgrep che cercano proprio questo: un testo che contiene SQL, costruito a mano, che arriva a una chiamata che esegue la query (`execute`, `query`, `executeQuery`, `mysqli_query`, `sqlx::query`...). Il valore viene seguito attraverso le variabili dentro la stessa funzione.

| Linguaggio | Costruzioni riconosciute |
|---|---|
| Python | `+`, f-string, `%`, `.format()` |
| JavaScript / TypeScript | `+`, template literal con `${...}` |
| Java | `+`, `String.format`, `.formatted()` |
| PHP | `.`, stringhe con `$variabile`, `sprintf` |
| Rust | `format!` seguito da `execute`/`query`/`sqlx::query`... |

Le query con segnaposto (`?`, `%s`, `.bind()`, `params![]`) e le query fatte solo di costanti non vengono segnalate. Le regole sono provate con esempi `ruleid`/`ok` in `tests/sql/`. Per spegnerle: `--no-builtin-rules`.

Limiti: il seguire il valore funziona **dentro una funzione**; se la query viene costruita in una funzione e eseguita in un'altra, può sfuggire. Non guarda i file `.sql` e non capisce un ORM: controlla solo il codice dell'applicazione.

## Configurazione e storia git

**Configurazione.** Un'applicazione con database di solito ha un `Dockerfile` e un `docker-compose.yml`, e gli errori lì sono pericolosi quanto quelli nel codice: un container `privileged`, il socket di Docker montato, la porta del database aperta a tutta la rete, un'immagine `latest` che cambia da sola.
- **Checkov** controlla i `Dockerfile` (utente root, `ADD` al posto di `COPY`, tag `latest`, nessun `HEALTHCHECK`, porta 22), i manifest Kubernetes, Terraform e i workflow di GitHub. Parte da solo se trova questi file. Nella versione gratuita non dà una gravità: tutto è segnato "media".
- **Docker Compose** non ha controlli in Checkov, quindi polyscan ha regole proprie per Semgrep: `privileged: true`, `network_mode: host`, socket di Docker, porte di database pubblicate (`3306`, `5432`, `27017`, `6379`...), password scritte nel file (anche nella forma `- CHIAVE=valore`; le variabili `${...}` e le `*_FILE` sono accettate), immagini non fissate. Sono provate con esempi in `tests/compose/`.

**Storia git.** Una chiave cancellata con un commit resta leggibile a chi può leggere il repository. Con `--history` Gitleaks guarda anche tutti i vecchi commit e il rapporto indica il commit (solo le prime 8 cifre dell'hash: autore ed e-mail non vengono mai mostrati). Una chiave trovata così va considerata **compromessa e sostituita**: toglierla dal codice non basta. Richiede la cartella radice del repository con la storia completa: se manca `.git`, o il clone è parziale (`git clone --depth`, o `actions/checkout` senza `fetch-depth: 0`), il controllo risulta "non eseguito" invece di sembrare pulito.

```bash
polyscan scan . --history
```

Se il segreto è nei file di oggi e anche in un vecchio commit, compare due volte (una per ciascun controllo).

## Installazione

Serve Python 3.9 o più recente. Per Semgrep, Gitleaks e OSV-Scanner la via più semplice è **Docker Desktop** acceso: non devi installare nient'altro.

```bash
git clone https://github.com/ErgiHysa24/polyscan
cd polyscan
python -m venv .venv
source .venv/Scripts/activate      # Git Bash su Windows; su Linux/Mac: source .venv/bin/activate
pip install -e . bandit
polyscan doctor                    # mostra cosa è disponibile
```

## Uso

```bash
polyscan scan .                                  # cartella corrente
polyscan scan ../altro-progetto --html report.html --json report.json
polyscan scan . --exclude tests --exclude "*.min.js"
polyscan scan . --only semgrep,gitleaks
polyscan scan . --semgrep-config p/php           # altre regole Semgrep
polyscan scan . --mode docker                    # forza Docker (auto, docker, local)
polyscan scan . --history                        # cerca segreti anche nei vecchi commit
```

Prova subito sugli esempi inclusi (progetti con problemi inseriti apposta, uno per linguaggio):

```bash
polyscan scan examples/vulnerable-demo --html report.html
```

### Codici di uscita

| Codice | Significato |
|---|---|
| 0 | nessun problema grave e tutti i controlli eseguiti |
| 1 | trovato qualcosa con gravità pari o superiore a `--fail-on` (default `high`) |
| 2 | uso sbagliato (cartella inesistente, strumento sconosciuto) |
| 3 | un controllo **non è stato eseguito** per un errore (con `--strict` anche se manca lo strumento) |

Un controllo che non gira non viene mai mostrato come "pulito": nel rapporto compare `FAILED` o `NOT RUN` e un avviso rosso.

## GitHub Action

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
permissions:
  contents: read
jobs:
  polyscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ErgiHysa24/polyscan@main
        with:
          fail-on: high
          exclude: tests,examples
```

Il riepilogo appare nella pagina del job e il rapporto HTML è scaricabile come artifact (`polyscan-report`). Opzioni: `path`, `fail-on`, `mode`, `exclude`, `semgrep-config`, `strict`.

Per controllare anche le librerie nel tempo (nuove vulnerabilità escono anche se il codice non cambia) aggiungi un avvio settimanale:

```yaml
on:
  schedule:
    - cron: "0 6 * * 1"
```

## Sicurezza del tool

- Gli strumenti partono con liste di argomenti, mai tramite una shell: un nome di cartella con `;` o `$()` resta un nome.
- In Docker la cartella è montata in **sola lettura**.
- I segreti trovati non compaiono mai nei rapporti (né quelli di Gitleaks né le password che cita Bandit).
- Il testo che arriva dal codice scansionato è trattato come non fidato: nell'HTML passa dall'escape e la pagina vieta gli script; nel terminale i caratteri di controllo vengono tolti; nel Markdown viene neutralizzato.
- Niente telemetria: Semgrep parte con `--metrics=off --disable-version-check`.

## Aggiungere uno strumento

In `polyscan/tools.py`: scrivi una funzione `parse_...(testo, root)` che trasforma l'output JSON in oggetti `Finding`, una classe con `local_cmd` e `docker_cmd`, e aggiungila a `all_tools()`. Salva un output vero in `tests/fixtures/` e scrivi il test del parser.

## Cosa è stato verificato (versione 0.2)

- **111 test** (parser, rilevamento, esecuzione, rapporti, regole SQL e Compose, storia git). Alcune difese sono state provate rompendole di proposito (escape dell'HTML, segreti nascosti, output vuoto, regole SQL e Compose) per vedere che i test falliscano.
- **Provati con gli strumenti veri** sulla macchina di sviluppo: Semgrep, Gitleaks (cartella e storia), Bandit, Checkov. Le fixture in `tests/fixtures/` sono output reale, ridotto nel numero di risultati; `osv.json` è scritto a mano sullo schema documentato.
- **Provati dalla CI su GitHub** (job `demo-scan`, dove Docker e le banche dati sono raggiungibili): la modalità Docker e OSV-Scanner. Il job fallisce se uno strumento non gira o non trova nulla nei progetti demo.
- Le regole del registro Semgrep (`p/security-audit`, `p/owasp-top-ten`) richiedono rete: cosa trovano su Java, PHP e Rust dipende da quelle regole.

## Limiti

- Lo stesso problema può comparire due volte se lo vedono due strumenti (per esempio Semgrep e Bandit sulla stessa riga): vengono tolte solo le ripetizioni identiche dello stesso strumento.
- La prima scansione di un progetto vecchio darà molte segnalazioni: serve fare il triage, non è un errore del tool.
- Strumenti specifici per linguaggio (SpotBugs per Java, PHPStan, `cargo audit`, `npm audit`) non sono ancora inclusi.
- Checkov parte solo se trova un `Dockerfile`, un file Compose o un `.tf`: un progetto con soli manifest Kubernetes non viene controllato.
- Le regole Compose leggono righe singole: non seguono `extends`, le variabili di un file `.env` né i file inclusi.
- Non c'è un controllo del sito in esecuzione (intestazioni HTTP, cookie, login) né del database stesso.
- Nessuno strumento trova tutto: un risultato pulito riduce il rischio, non lo azzera.
