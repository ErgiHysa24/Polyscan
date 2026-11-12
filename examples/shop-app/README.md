# shop-app: a small web application with a database, to try polyscan end to end

**Deliberately insecure. Never deploy it, never expose it to a network you do not control.**

Flask + PostgreSQL in Docker Compose, with a real session login. It is the kind of target the
tool is meant for (web application + database + containers), small enough to read in ten minutes.

```bash
docker compose up -d --build          # http://localhost:5000
polyscan scan . --json scan.json
export SHOP_PASSWORD=alice-demo-pw
polyscan dast http://localhost:5000 --login-url http://localhost:5000/login --login-user alice \
    --login-password-env SHOP_PASSWORD --login-check-url http://localhost:5000/account --json dast.json
polyscan ports --json ports.json      # Linux
polyscan report scan.json dast.json ports.json --html assessment.html --intel --title "shop-app"
docker compose down -v
```

## Users

| User | Password | Second step |
|---|---|---|
| `alice` | `alice-demo-pw` | none (used by the automated scan) |
| `bob` | `bob-demo-pw` | authenticator app; add the key `JBSWY3DPEHPK3PXP` to your app by hand to get his codes |

## Login with an authenticator app (TOTP)

Log in, open **Account**, choose *Turn on two-step login*, scan the QR code with Google Authenticator,
Microsoft Authenticator or Authy, and type the 6-digit code. From then on the password alone is not
enough. `totp.py` (60 lines, standard library only) shows how the code is computed (RFC 6238):
the site and the phone share a secret, and both derive a 6-digit number from the secret and the
current 30-second step.

Unlike the rest of the application, this part is written to be correct: the secret is saved only
after a first valid code, a code works once (no replay), one step of clock drift is accepted,
five wrong codes end the attempt, and turning it off needs a valid code. What a real site would
add: recovery codes, the secret encrypted in the database, and a limit on attempts per account
(not only per session).

polyscan cannot pass the second step by itself: to scan as `bob`, log in with a browser and give
polyscan the session cookie (`--auth-header-env` with `--auth-header-name Cookie`).

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
