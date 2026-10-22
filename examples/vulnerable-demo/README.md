# vulnerable-demo

Tiny projects with deliberate security problems, one per language, used to
try polyscan. **Never deploy any of this code.** The key in `python/settings.py`
is fake.

    polyscan scan examples/vulnerable-demo --html report.html

## docker/

A Dockerfile and a Compose file with typical mistakes (`latest` tag, no user,
`ADD`, privileged container, Docker socket mounted, database port open to the
world, password written in the file). Checkov reads the Dockerfile; the Compose
file is covered by polyscan's own rules (`polyscan/rules/docker-compose.yml`).
