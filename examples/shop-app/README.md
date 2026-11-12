# shop-app: a small web application with a database, to try polyscan end to end

**Deliberately insecure. Never deploy it, never expose it to a network you do not control.**

Flask + PostgreSQL in Docker Compose, with a real session login. It is the kind of target the
tool is meant for (web application + database + containers), small enough to read in ten minutes.

```bash
docker compose up -d --build          # http://localhost:5000  (user: alice  password: alice-demo-pw)
polyscan scan . --json scan.json
export SHOP_PASSWORD=alice-demo-pw
polyscan dast http://localhost:5000 --login-url http://localhost:5000/login --login-user alice \
    --login-password-env SHOP_PASSWORD --login-check-url http://localhost:5000/account --json dast.json
polyscan ports --json ports.json      # Linux
polyscan report scan.json dast.json ports.json --html assessment.html --intel --title "shop-app"
docker compose down -v
```

## Weaknesses planted on purpose

| Where | Weakness | Found by |
|---|---|---|
| `app.py` `/search` | SQL built by joining text with user input | Semgrep, Bandit |
| `app.py` | Flask `secret_key` written in the code, debug mode on | Bandit (B105, B201), Semgrep |
| `app.py` `/account` | technology banner only on the page behind the login | ZAP, only with the form login |
| `init.sql` | passwords stored as unsalted MD5 | Semgrep SQL rules / review |
| `docker-compose.yml` | default database password, database port published, app connects as superuser, `sslmode=disable` | db-config, Compose rules, Checkov, `polyscan ports` |
| `Dockerfile` | old base image, runs as root | Trivy, Checkov |
| `requirements.txt` | old library versions with known CVEs | OSV-Scanner |
