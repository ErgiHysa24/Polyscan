"""SBOM: the Trivy command is safe (read-only, no network), and a failed or empty SBOM is never written."""

import json
from types import SimpleNamespace

from polyscan import cli, sbom

GOOD = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0"},
                                                                         {"type": "application", "name": "requirements.txt"}]}  # fmt: skip


def proc(out="", err="", code=0):
    return SimpleNamespace(stdout=out, stderr=err, returncode=code)


def test_command_is_read_only_offline_and_pinned(tmp_path):
    cmd = sbom.command(tmp_path)
    assert cmd[:5] == ["docker", "run", "--rm", "--network", "none"]
    assert f"{tmp_path}:/src:ro" in cmd and "@sha256:" in cmd[cmd.index("fs") - 1]
    assert cmd[cmd.index("--format") + 1] == "cyclonedx" and "docker.sock" not in " ".join(cmd)


def test_good_document(tmp_path):
    data, count, why = sbom.generate(tmp_path, run=lambda *a, **k: proc(json.dumps(GOOD)))
    assert data and count == 1 and not why


def test_failures_are_not_an_sbom(tmp_path):
    assert sbom.generate(tmp_path, run=lambda *a, **k: proc("", "boom", 1))[2].startswith("trivy exit code 1")
    assert "not a CycloneDX" in sbom.generate(tmp_path, run=lambda *a, **k: proc("{}"))[2]
    empty = {**GOOD, "components": []}
    data, _, why = sbom.generate(tmp_path, run=lambda *a, **k: proc(json.dumps(empty)))
    assert data is None and "no library" in why
    assert "not a folder" in sbom.generate(tmp_path / "missing")[2]

    def no_docker(*a, **k):
        raise FileNotFoundError("docker")

    assert "needs Docker" in sbom.generate(tmp_path, run=no_docker)[2]


def test_cli(tmp_path, monkeypatch, capsys):
    out = tmp_path / "s.json"
    monkeypatch.setattr(sbom, "generate", lambda path: (GOOD, 1, ""))
    assert cli.main(["sbom", str(tmp_path), "--output", str(out)]) == 0 and json.loads(out.read_text())["bomFormat"] == "CycloneDX"
    out.unlink()
    monkeypatch.setattr(sbom, "generate", lambda path: (None, 0, "trivy exit code 1"))
    assert cli.main(["sbom", str(tmp_path), "--output", str(out)]) == 3 and not out.exists()
