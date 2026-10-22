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
| Sito in esecuzione (comando `polyscan dast`) | [OWASP ZAP](https://www.zaproxy.org), baseline passiva | un sito web | solo Docker |
| Configurazione sbagliata: `Dockerfile` (regole proprie) | Semgrep, con `polyscan/rules/dockerfile.yml` | Docker | come Semgrep |
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

## Scansione di un sito in esecuzione (`polyscan dast`)

Gli altri controlli leggono il codice; questo prova **il sito acceso**, come farebbe chi lo visita da fuori, con [OWASP ZAP](https://www.zaproxy.org/docs/docker/baseline-scan/) in modalità *baseline*: un crawler segue i link per qualche minuto e ZAP analizza le risposte. Trova intestazioni di sicurezza mancanti (CSP, anti-clickjacking), cookie senza `HttpOnly`/`SameSite`, informazioni che trapelano, form senza token anti-CSRF. **Non attacca** e non trova una SQL injection o una XSS profonda: servirebbe la scansione attiva, che non c'è.

```bash
python examples/vulnerable-web/server.py --host 0.0.0.0    # sito demo con difetti di proposito
polyscan dast http://localhost:8000 --html sito.html
polyscan dast http://192.168.1.20:5000 --minutes 3          # un sito della tua rete
```

Richiede Docker acceso (ZAP gira solo lì). Come funziona e cosa sapere:
- **Un risultato per tipo di problema**, non per pagina: "CSP header not set (40 URLs)" è una sola segnalazione, che mostra la prima pagina.
- **Un sito che non risponde è un errore**, non un sito pulito: ZAP in quel caso esce con codice 3 senza rapporto, e polyscan lo segnala come controllo fallito (uscita 3).
- **`localhost` dentro un container è il container stesso.** polyscan dà quindi a ZAP l'indirizzo `host.docker.internal`, che punta al tuo computer, e nel rapporto rimette quello che hai scritto tu. Su Linux il tuo sito deve ascoltare su `0.0.0.0` (non solo `127.0.0.1`); un sito che accetta solo certi nomi (`ALLOWED_HOSTS`, `SERVER_NAME`) può rifiutare quel nome.
- Il rapporto di ZAP passa da una **cartella temporanea** creata da polyscan e cancellata dopo: è l'unico punto scrivibile, il tuo progetto non viene mai montato. Se la scansione supera il tempo, il container viene fermato.
- Un sito dietro login si vede solo nelle pagine pubbliche (l'autenticazione non è ancora gestita); una pagina costruita quasi tutta in JavaScript può essere navigata male dal crawler normale.

## Configurazione e storia git

**Configurazione.** Un'applicazione con database di solito ha un `Dockerfile` e un `docker-compose.yml`, e gli errori lì sono pericolosi quanto quelli nel codice: un container `privileged`, il socket di Docker montato, la porta del database aperta a tutta la rete, un'immagine `latest` che cambia da sola.
- **Checkov** controlla i `Dockerfile` (utente root, `ADD` al posto di `COPY`, tag `latest`, nessun `HEALTHCHECK`, porta 22), i manifest Kubernetes, Terraform e i workflow di GitHub. Parte da solo se trova questi file. Nella versione gratuita non dà una gravità: tutto è segnato "media".
- **Dockerfile, regole proprie.** Servono per poter controllare la parte Docker anche senza Checkov e per poterle leggere e modificare. Cercano: immagine di base `latest` o senza versione (gli stadi `FROM build` di un multi-stage non contano), container che gira come root, `ADD` al posto di `COPY`, porta 22, password o token in `ENV`/`ARG` (restano in `docker history`), `curl ... | sh`, `chmod 777`. Provate con esempi in `tests/dockerfile/`. Alcune segnalazioni compaiono due volte, una per Checkov e una per queste regole; password in `ENV`, `curl | sh` e `chmod 777` le vedono solo le regole proprie.
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

Solo il codice:

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0        # serve solo con history: true
      - uses: ErgiHysa24/polyscan@main
        with:
          fail-on: high
          exclude: tests,examples
          history: "true"
```

Il riepilogo appare nella pagina del job e i rapporti (HTML, JSON, Markdown) sono scaricabili come artifact (`polyscan-report`).

Codice **e** applicazione in esecuzione (ZAP, solo controlli passivi). L'action avvia la tua app, aspetta che risponda, la scansiona e la ferma, anche se la scansione fallisce:

```yaml
      - uses: ErgiHysa24/polyscan@main
        with:
          target-url: http://localhost:8000
          start-command: docker compose up -d
          stop-command: docker compose down
          wait-timeout: "90"
          fail-on: high
```

| Opzione | Significato | Predefinito |
|---|---|---|
| `path`, `exclude`, `semgrep-config`, `history` | cosa scansionare nel codice | `.`, nessuna, regole di base, `false` |
| `scan-code` | `"false"` salta la scansione del codice (solo sito) | `true` |
| `target-url` | indirizzo dell'app da scansionare con ZAP | vuoto = nessuna scansione del sito |
| `start-command` | comando che avvia l'app (può restare in esecuzione) | vuoto |
| `stop-command` | comando che la ferma; gira sempre | vuoto |
| `wait-timeout` | secondi di attesa perché l'app risponda | `60` |
| `zap-minutes` | minuti di esplorazione di ZAP (1-30) | `1` |
| `allow-remote` | `"true"` per un bersaglio non locale (vedi sotto) | `false` |
| `artifact-name` | nome del rapporto caricato; cambialo se l'action gira più volte nella stessa esecuzione | `polyscan-report` |
| `fail-on`, `mode`, `strict` | soglia di fallimento, modalità, rigore | `high`, `auto`, `false` |

Uscite: `exit-code` (codice), `dast-exit-code` (sito), `report-dir`.

Cose da sapere:

- **`start-command` ha la stessa fiducia di un passo `run:`** del tuo workflow: è codice tuo. Non costruirlo mai con dati non fidati (titolo di una pull request, nome di un branch). Per questo l'action passa ogni input tramite variabili d'ambiente e non li incolla mai negli script; un test (`tests/test_action.py`) controlla che sia sempre così.
- Se il comando di avvio **fallisce** o l'app **non risponde** entro `wait-timeout`, il job fallisce subito e mostra le ultime righe scritte dall'app. ZAP non parte: un sito mai raggiunto non risulta mai "pulito".
- Su Linux l'app deve ascoltare su `0.0.0.0` (non solo `127.0.0.1`), perché ZAP gira in un container. Con `docker compose` le porte pubblicate vanno bene.
- Un bersaglio fuori dal runner o da una rete privata viene **rifiutato** a meno di `allow-remote: "true"`; vedi "Uso responsabile e autorizzazione".

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
- **Versioni bloccate** (vedi sotto): tutto ciò che viene scaricato ed eseguito è fissato a qualcosa che non può cambiare di nascosto.

### Versioni bloccate

Un'etichetta come `latest` o `v4` può essere spostata su contenuto diverso da chi controlla l'account: è così che gli attacchi alla catena di fornitura (come quelli a Trivy e KICS) raggiungono chi li usa. Un *digest* o un *commit* identifica invece il contenuto stesso: se cambia, non parte.

| Cosa | Come è fissato | Dove |
|---|---|---|
| Immagini Docker (Semgrep, Gitleaks, OSV-Scanner, Checkov, ZAP) | digest `sha256`, con la versione accanto | `IMAGES` in `polyscan/tools.py` |
| GitHub Actions (checkout, setup-python, upload-artifact) | hash del commit, con `# vX.Y.Z` in commento | `ci.yml`, `action.yml` |
| Semgrep nella CI, Bandit nell'action | versione esatta (`==`) | `ci.yml`, `action.yml` |

`tests/test_pins.py` fa fallire la CI se qualcuno aggiunge un'immagine `latest`, un'Action con `@v4` o un `pip install` senza versione. `polyscan doctor` mostra la versione di ogni immagine.

**Aggiornare** (a mano, di proposito): avvia il workflow *show-latest-pins* dalla scheda Actions di GitHub, che mostra le ultime versioni stabili con commit e digest; leggi le note di rilascio; cambia le righe; la CI dimostra che gli strumenti funzionano ancora. Dependabot propone da solo gli aggiornamenti delle Actions, aspettando 7 giorni dopo ogni rilascio, perché le versioni compromesse di solito si scoprono presto.

Limiti: il digest garantisce che l'immagine non cambi, non che sia priva di difetti; le dipendenze di sviluppo (pytest) e quelle indirette dei pacchetti pip non sono bloccate con hash.

## Uso responsabile e autorizzazione

Gli strumenti di oggi leggono **file sul tuo computer**: non contattano nessun sito. Qualsiasi controllo che invii richieste a un sito o a un server in esecuzione (come OWASP ZAP, quando sarà aggiunto) è un'altra cosa.

**Scansiona solo ciò che è tuo, o per cui hai un'autorizzazione esplicita.**

- **`localhost` e indirizzi della tua rete privata** (la tua macchina, i tuoi container, un ambiente di prova tuo): puoi procedere.
- **Qualsiasi altro sito o server**: scansiona *solo* se sei il proprietario o se hai ottenuto prima un'autorizzazione **scritta** da chi ne è responsabile, che indichi quali indirizzi, quali tipi di prova e in quale periodo. Un sito pubblico, un sito di un cliente, di un amico, di un datore di lavoro o di un'università **non è un bersaglio di prova**.
- **Anche un sito in hosting tuo** può avere regole del fornitore (hosting, cloud, CDN) sulle scansioni di sicurezza: controllale prima.
- **La scansione attiva è più pericolosa di quella passiva**: invia richieste malevole e può modificare o cancellare dati, riempire i log o rendere il servizio lento o non disponibile. Falla solo su un ambiente di prova con un database di prova, mai in produzione e mai con dati reali.

Scansionare sistemi altrui senza permesso può essere illegale. In Italia, per esempio, può rientrare nel reato di accesso abusivo a un sistema informatico (art. 615-ter del codice penale), e altri paesi hanno norme simili; "volevo solo provare" o "l'ho trovato aperto" non è una giustificazione. Questo testo non è un parere legale: se hai dubbi, chiedi a chi è responsabile del sistema o a un legale.

Il comando `polyscan dast` rispetta queste regole **nel codice**, non solo nel testo:
- accetta senza altro solo `localhost` e indirizzi privati; l'indirizzo viene *risolto* e si guarda dove porta, non come è scritto (`localhost.example.com` e `http://localhost@sito-altrui.com` sembrano locali e non lo sono: il secondo viene rifiutato);
- per qualsiasi altro sito si ferma **prima di mandare una sola richiesta**, spiega perché e chiede `--allow-remote`, cioè una tua dichiarazione che il sito è tuo o che hai l'autorizzazione scritta; se lo usi, il rapporto riporta una nota ben visibile;
- fa solo scansione **passiva** (naviga e osserva, non attacca). Non esiste un'opzione per la scansione attiva: arriverà solo con altre protezioni.

## Aggiungere uno strumento

In `polyscan/tools.py`: scrivi una funzione `parse_...(testo, root)` che trasforma l'output JSON in oggetti `Finding`, una classe con `local_cmd` e `docker_cmd`, e aggiungila a `all_tools()`. Salva un output vero in `tests/fixtures/` e scrivi il test del parser.

## Cosa è stato verificato (versione 0.3)

- **225 test** (parser, rilevamento, esecuzione, rapporti, regole SQL e Compose, storia git). Alcune difese sono state provate rompendole di proposito (escape dell'HTML, segreti nascosti, output vuoto, regole SQL e Compose) per vedere che i test falliscano.
- **Provati con gli strumenti veri** sulla macchina di sviluppo: Semgrep, Gitleaks (cartella e storia), Bandit, Checkov. Le fixture in `tests/fixtures/` sono output reale, ridotto nel numero di risultati; `osv.json` è scritto a mano sullo schema documentato.
- **Provati dalla CI su GitHub** (dove Docker e le banche dati sono raggiungibili): la modalità Docker e OSV-Scanner (job `demo-scan`, che fallisce se uno strumento non gira o non trova nulla nei progetti demo) e **ZAP** (job `dast-demo`: avvia il sito demo, lo scansiona, controlla che i difetti inseriti vengano trovati, che una porta chiusa dia un errore e che un sito altrui venga rifiutato). Il file `tests/fixtures/zap.json` è un rapporto vero di ZAP 2.17.0, ridotto a 5 segnalazioni.
- **L'action stessa** è provata dalla CI (job `action-dast`): avvia il sito demo, lo scansiona con ZAP, lo ferma; e due casi d'errore (comando di avvio che fallisce, app che non risponde) devono far fallire il job senza lanciare ZAP.
- **Il controllo del bersaglio** (`polyscan/target.py`) ha 40 test, fra cui i trucchi `user@host`, i nomi che sembrano locali, gli indirizzi misti e IPv6; le protezioni principali sono state provate rompendole di proposito.
- Le regole del registro Semgrep (`p/security-audit`, `p/owasp-top-ten`) richiedono rete: cosa trovano su Java, PHP e Rust dipende da quelle regole.

## Limiti

- Lo stesso problema può comparire due volte se lo vedono due strumenti (per esempio Semgrep e Bandit sulla stessa riga): vengono tolte solo le ripetizioni identiche dello stesso strumento.
- La prima scansione di un progetto vecchio darà molte segnalazioni: serve fare il triage, non è un errore del tool.
- Strumenti specifici per linguaggio (SpotBugs per Java, PHPStan, `cargo audit`, `npm audit`) non sono ancora inclusi.
- Checkov parte solo se trova un `Dockerfile`, un file Compose o un `.tf`: un progetto con soli manifest Kubernetes non viene controllato.
- Le regole Compose e Dockerfile leggono una riga alla volta: non seguono `extends`, le variabili di un file `.env`, i file inclusi né i comandi `RUN` spezzati su più righe con `\`.
- Il sito in esecuzione è controllato solo in modo passivo e senza login; il database stesso non è controllato.
- Nessuno strumento trova tutto: un risultato pulito riduce il rischio, non lo azzera.
