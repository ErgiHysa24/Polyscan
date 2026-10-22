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

## Cosa è stato verificato (versione 0.1)

- **92 test** (parser, rilevamento linguaggi, esecuzione, rapporti, uscite). Sono stati provati anche rompendo di proposito le difese (escape dell'HTML, segreti nascosti, output vuoto) per vedere che i test falliscano.
- **Provati con gli strumenti veri** su `examples/vulnerable-demo`: Semgrep (con regole locali), Gitleaks, Bandit. I loro file di prova in `tests/fixtures/` sono output reale.
- **Non provati con lo strumento vero** nell'ambiente di sviluppo: la lettura dei risultati di **OSV-Scanner** (il suo database non era raggiungibile: il file di prova è scritto a mano sullo schema documentato) e la modalità **Docker** (il servizio non era attivo: si è provata solo la costruzione dei comandi e la gestione dell'errore). Lo verifica il job `demo-scan` della CI su GitHub, dove tutto è raggiungibile.
- Le regole del registro Semgrep (`p/security-audit`, `p/owasp-top-ten`) richiedono rete e non sono state scaricate: cosa trovano su Java, PHP e Rust dipende da quelle regole.

## Limiti

- Lo stesso problema può comparire due volte se lo vedono due strumenti (per esempio Semgrep e Bandit sulla stessa riga): vengono tolte solo le ripetizioni identiche dello stesso strumento.
- La prima scansione di un progetto vecchio darà molte segnalazioni: serve fare il triage, non è un errore del tool.
- Strumenti specifici per linguaggio (SpotBugs per Java, PHPStan, `cargo audit`, `npm audit`) non sono ancora inclusi.
- Nessuno strumento trova tutto: un risultato pulito riduce il rischio, non lo azzera.
