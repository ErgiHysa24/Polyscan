# Test fixtures

`semgrep.json`, `gitleaks.json` and `bandit.json` are real output from those
tools run on `examples/vulnerable-demo`, with the folder path replaced by `/ROOT`
(in `bandit.json` the fake demo key is replaced by a placeholder).

`osv.json` is **written by hand** from the documented OSV-Scanner JSON schema:
the OSV database (api.osv.dev) was not reachable where the tests were
written. Re-generate it with real output when you can:

    osv-scanner scan source -r --format json examples/vulnerable-demo

## 0.6 (Java, PHP)

- `composer-audit.json`: real `composer audit --format=json --locked` output on the PHP demo project (2 of its 14 advisories, as printed by CI).
- `progpilot.json`: real Progpilot v1.3.0 output on `examples/vulnerable-demo/php/index.php` (all 4 results).
- `spotbugs.xml`: SpotBugs 4.10.5 + Find Security Bugs 1.14.0 on the Java demo. Real values (bug types, priorities, ranks, CWE ids, messages, line numbers) copied from CI; the XML was **rebuilt from the printed fragments** (CI annotations are limited to 4096 characters) with the profile and statistics sections left out and ids shortened.

## Threat intelligence

- `kev.json`: 3 real entries (CVE-2019-11043, CVE-2021-44228, CVE-2017-5638) cut from the CISA KEV catalog 2026.11.10 (downloaded from CISA's GitHub mirror); header fields kept, `count` changed to 3.
- `epss.json`: real answer of `https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2017-5638,CVE-2026-69246&limit=3`, printed by the CI (`intel-sample` job) on 2026-11-12.

## TLS

- `testssl.json`: real output of testssl.sh 3.2.5 (`--protocols --server-defaults --std --fs --headers --severity LOW`) against `openssl s_server` with a self-signed certificate, reached through `host.docker.internal`; printed complete by the CI (`tls-sample` job, 9 entries).
