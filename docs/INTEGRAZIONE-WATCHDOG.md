# Integrare polyscan in WatchDog

polyscan è pensato per essere **uno dei motori** di WatchDog, non un'applicazione a parte.

| | WatchDog | polyscan |
|---|---|---|
| Cosa valuta | i **sistemi**: server Linux/macOS, servizi, configurazione del sistema operativo | l'**applicazione**: codice, librerie, segreti, container, database (file di configurazione), sito acceso, porte |
| Dove vivono i risultati | database PostgreSQL, interfaccia web multiutente, storico | file JSON |
| Chi decide e gestisce | WatchDog (utenti, ruoli, registro attività) | nessuno: polyscan produce dati |

Regola di divisione: **polyscan scansiona ed esporta, WatchDog importa, conserva e mostra.** Le funzioni di polyscan che esistono anche in WatchDog (registro dei rischi, trattamento, storico, rapporto HTML) servono quando polyscan è usato da solo, per esempio in una pipeline CI. Dentro WatchDog conviene usare i dati di polyscan e la logica, l'interfaccia e il database di WatchDog, senza duplicarli.

## Il contratto: due file JSON con uno schema

| File | Prodotto da | Schema | Campo `schema` |
|---|---|---|---|
| rapporto di scansione | `polyscan scan --json`, `polyscan dast --json`, `polyscan ports --json` | [`schema/polyscan-scan.schema.json`](schema/polyscan-scan.schema.json) | `"polyscan-scan/1"` |
| registro dei rischi | `polyscan risk --json` | [`schema/polyscan-risk.schema.json`](schema/polyscan-risk.schema.json) | `"polyscan-risk/1"` |

Gli schemi sono JSON Schema (draft 2020-12) e sono **verificati a ogni modifica** su rapporti veri: nei test e nella CI, sui rapporti reali dell'applicazione di prova (scan, dast, ports, risk). Se polyscan aggiunge o cambia un campo senza aggiornare lo schema, la CI fallisce. Il campo `schema` cambia numero (`/2`) solo quando un campo viene tolto o cambia significato: aggiungere campi non cambia la versione, quindi l'importatore deve **ignorare i campi che non conosce**.

## Cosa importare: le regole che contano

1. **Lo stato degli strumenti viene prima dei risultati.** Ogni voce di `tools[]` ha `status`:
   - `ok`: lo strumento ha girato, i suoi risultati sono completi;
   - `error`: è **fallito**, quindi zero risultati non dimostrano niente;
   - `unavailable`: non è installato;
   - `skipped`: non serve qui (`detail` dice perché, per esempio "no lockfile").

   WatchDog deve mostrare `error` e `unavailable` come **lacune** della valutazione, mai come "tutto a posto". È la stessa regola che WatchDog applica già ai propri controlli.
2. **Chiave stabile di una segnalazione:** `(tool, rule, file)`. Il numero di riga cambia quando si modifica il codice sopra, quindi non va usato per riconoscere la stessa segnalazione tra due scansioni (è la logica di `polyscan diff`).
3. **Chiave stabile di un rischio:** `(kind, rule)`. Gli id `R-001`, `R-002`... valgono solo dentro un rapporto, perché sono in ordine di punteggio.
4. **Il testo viene dal codice scansionato, quindi non è fidato.** `message`, `snippet`, `file` e `rule` vanno sempre messi in pagina con l'escape HTML, come fa la web app di WatchDog con il resto.
5. **I segreti non ci sono.** I rilevamenti di Gitleaks hanno `snippet: "[secret redacted]"`. In ogni altra riga di codice, il valore di password, token e chiavi è sostituito da `[redacted]` (`POSTGRES_PASSWORD=[redacted]`). WatchDog non deve quindi aggiungere protezioni particolari per questi campi, ma non deve neppure rileggere i file originali per "completarli".
6. **Gravità:** `critical`, `high`, `medium`, `low`, `info`, già normalizzate dallo strumento d'origine. Nel registro dei rischi `level` è invece la gravità del **rischio** (probabilità × impatto) e può essere diversa: una gravità `high` su un'applicazione solo locale può diventare un rischio `medium`.
7. **Data:** `generated` (UTC, ISO 8601) per ordinare le scansioni nello storico di WatchDog.

## Campi utili per le funzioni che WatchDog ha già

| Funzione di WatchDog | Campo di polyscan |
|---|---|
| Mappatura MITRE ATT&CK | `risks[].threat.attack[]` (`id`, `name`, `tactic`; nomi verificati su ATT&CK v20.0) |
| Mappatura di conformità | `findings[].cwe`, `risks[].threat.cwe`, `risks[].threat.owasp_top10` |
| Heatmap per aree | `findings[].category` (`code`, `secret`, `dependency`, `config`, `runtime`) e `tool` |
| Confronto tra scansioni | chiave `(tool, rule, file)`, vedi sopra |
| Priorità | `risks[].exploitation.kev` (CVE sfruttate attivamente), `risks[].exploitation.epss` |
| Seconda valutazione | `risks[].owasp_risk_rating` |

## Due modi di collegarli

**A. WatchDog importa i file (consigliato per iniziare).** polyscan gira dove sta il codice (sul PC dello sviluppatore, nella CI di GitHub con l'action) e WatchDog carica il JSON: è l'importazione che WatchDog ha già, da aggiornare a questo schema. È il modo più semplice: niente Docker dentro il container di WatchDog.

**B. Il worker di WatchDog lancia polyscan.** Il worker esegue `polyscan scan <cartella> --json <file>` (o `dast` sull'URL dell'applicazione) come sottoprocesso, senza shell e con gli argomenti in lista, e importa il risultato. Cose da sapere:

- **Codici di uscita:**

  | Codice | Significato |
  |---|---|
  | 0 | nessun problema sopra la soglia `--fail-on` |
  | 1 | problemi sopra la soglia |
  | 2 | uso sbagliato (argomenti, file) |
  | 3 | **almeno un controllo non ha girato**: importare comunque il JSON, ma segnare la scansione come incompleta |

  Con `--fail-on none` il codice 1 non compare.
- Molti strumenti girano in **Docker** (immagini fissate per digest). Il worker deve poter avviare container, cioè avere accesso al demone Docker: è un privilegio forte, da dare a un worker separato e non al container web. In alternativa si installano gli strumenti localmente (`polyscan doctor` dice cosa manca).
- Per `dast` valgono le stesse regole di WatchDog sulle reti autorizzate: polyscan rifiuta da sé gli indirizzi non privati senza `--allow-remote`.

## Esempio minimo di importazione (Python)

```python
import json, jsonschema

schema = json.load(open("polyscan-scan.schema.json"))
report = json.load(open("scan.json"))
jsonschema.validate(report, schema)          # rifiuta file malformati o di un'altra versione

gaps = [t for t in report["tools"] if t["status"] in ("error", "unavailable")]
for f in report["findings"]:
    key = (f["tool"], f["rule"], f["file"])  # stabile tra due scansioni
    ...                                      # salvare nel database di WatchDog
if gaps:
    ...                                      # segnare la scansione come INCOMPLETA, con t["detail"]
```
