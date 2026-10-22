# Workflow di esempio per la tua app

Questi file sono un punto di partenza da copiare nel repository della **tua** applicazione web, non servono a polyscan stesso (infatti non girano nella sua CI).

## File

- `security.yml` → va in `.github/workflows/security.yml` della tua app.
- `docker-compose.example.yml` → esempio di come avviare l'app con un database usa-e-getta.

## I tre punti su cui sbaglia quasi tutti

1. **L'app deve ascoltare su `0.0.0.0`, non su `127.0.0.1`.** ZAP gira in un container separato e raggiunge la tua app attraverso la rete Docker; se l'app ascolta solo su `127.0.0.1` dentro il suo container, nessuno la vede. Con `ports: - "8000:8000"` nel compose la porta è pubblicata e il job la trova su `localhost:8000`.
2. **Il database è usa-e-getta.** Il workflow lo crea all'avvio e lo distrugge alla fine (`docker compose down -v`). Non puntare mai `target-url` a un ambiente vero con dati reali.
3. **`start-command` è codice tuo, con la stessa fiducia di un passo `run:`.** Non costruirlo mai da dati non fidati (per esempio il titolo di una pull request).

## Scansione attiva

Questo workflow usa solo la scansione **passiva** (ZAP osserva le risposte, non attacca). La scansione **attiva** di ZAP invia payload veri e può modificare i dati: lanciala a mano con `zap-full-scan.py` sulla tua copia di prova seguendo la [documentazione di ZAP](https://www.zaproxy.org/docs/docker/full-scan/), poi dai il rapporto JSON a `polyscan risk`.
