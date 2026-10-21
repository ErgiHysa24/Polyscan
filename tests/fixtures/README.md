# Test fixtures

`semgrep.json`, `gitleaks.json` and `bandit.json` are real output from those
tools run on `examples/vulnerable-demo`, with the folder path replaced by `/ROOT`
(in `bandit.json` the fake demo key is replaced by a placeholder).

`osv.json` is **written by hand** from the documented OSV-Scanner JSON schema:
the OSV database (api.osv.dev) was not reachable where the tests were
written. Re-generate it with real output when you can:

    osv-scanner scan source -r --format json examples/vulnerable-demo
