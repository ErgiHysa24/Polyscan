"""Trivy on the images of a project: finding the image names, the runner, the parser."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from polyscan import imagescan
from polyscan.imagescan import find_images, refs_in_compose, refs_in_dockerfile, run_scan, trivy_command
from polyscan.models import ERROR, OK, SKIPPED, Severity
from polyscan.scanner import run_tool
from polyscan.tools import IMAGES, ScanOptions, Trivy, image_ref, parse_trivy

FIX = Path(__file__).parent / "fixtures"


# ----------------------------------------------------------------- finding image names


def test_dockerfile_from_lines():
    text = (
        "# comment\n"
        "FROM python:3.12-slim AS build\n"
        "RUN pip install x\n"
        "FROM --platform=linux/amd64 node:20@sha256:" + "a" * 64 + "\n"
        "from alpine:3.19 as final\n"
    )
    scan, skipped = refs_in_dockerfile(text, "Dockerfile")
    assert [(r.ref, r.line) for r in scan] == [("python:3.12-slim", 2), ("node:20@sha256:" + "a" * 64, 4), ("alpine:3.19", 5)]
    assert skipped == []


def test_scratch_stage_names_and_variables_are_not_images():
    text = "FROM golang:1.22 AS build\nFROM build AS test\nFROM scratch\nFROM ${BASE_IMAGE}\nFROM $OTHER:1\n"
    scan, skipped = refs_in_dockerfile(text, "Dockerfile")
    assert [r.ref for r in scan] == ["golang:1.22"]  # `build` is a stage, `scratch` is empty
    assert [r.ref for r in skipped] == ["${BASE_IMAGE}", "$OTHER:1"]


def test_compose_image_lines_and_quotes():
    text = (
        "services:\n  db:\n    image: postgres:16\n  cache:\n    image: 'redis:7'  # cache\n"
        "  app:\n    build: .\n  web:\n    image: \"nginx:1.27\"\n  x:\n    image: ${IMG}\n"
    )
    scan, skipped = refs_in_compose(text, "docker-compose.yml")
    assert [r.ref for r in scan] == ["postgres:16", "redis:7", "nginx:1.27"]
    assert [r.ref for r in skipped] == ["${IMG}"]


def test_one_scan_per_image_attributed_to_the_first_place(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Dockerfile").write_text("FROM python:3.12\n")
    (tmp_path / "docker-compose.yml").write_text("services:\n  x:\n    image: python:3.12\n  y:\n    image: redis:7\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dockerfile").write_text("FROM evil:1\n")
    refs, _ = find_images(tmp_path)
    assert sorted(r.ref for r in refs) == ["python:3.12", "redis:7"]
    assert {r.ref: r.source for r in refs}["python:3.12"] == "a/Dockerfile"


def test_excluded_folders_are_not_read(tmp_path):
    (tmp_path / "old").mkdir()
    (tmp_path / "old" / "Dockerfile").write_text("FROM python:2.7\n")
    assert find_images(tmp_path, ("old",)) == ([], [])


# ----------------------------------------------------------------- the runner


class P:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


REPORT = json.dumps({"SchemaVersion": 2, "Results": []})


def project(tmp_path, dockerfile="FROM python:3.12\n"):
    (tmp_path / "Dockerfile").write_text(dockerfile)
    return tmp_path


def test_trivy_command_is_pinned_a_list_and_without_the_project_or_docker_socket():
    cmd = trivy_command("python:3.12", "vol1")
    assert cmd[:3] == ["docker", "run", "--rm"] and cmd[-1] == "python:3.12"
    assert image_ref("trivy") in cmd and "@sha256:" in image_ref("trivy")
    joined = " ".join(cmd)
    assert "docker.sock" not in joined and "/src" not in joined
    assert cmd[cmd.index("--scanners") + 1] == "vuln"  # exactly: a secret scan could print secrets
    assert cmd[cmd.index("--image-src") + 1] == "remote"  # no Docker daemon needed


def test_normal_run_merges_reports_and_removes_the_volume(tmp_path):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return P(REPORT)

    code, merged, problems = run_scan(project(tmp_path), run=run)
    assert code == 0 and not problems and merged["images"][0]["ref"] == "python:3.12"
    assert calls[-1][:4] == ["docker", "volume", "rm", "-f"]  # the shared database volume is cleaned up


@pytest.mark.parametrize("proc", [P("", "manifest unknown", 1), P("not json", "", 0), P("{}", "", 0), P(REPORT, "", 2)])
def test_an_image_that_could_not_be_scanned_fails_the_run(tmp_path, proc):
    answers = {"n": 0}

    def run(cmd, **kw):
        if cmd[:3] == ["docker", "volume", "rm"]:
            return P()
        answers["n"] += 1
        return proc

    code, _, problems = run_scan(project(tmp_path), run=run)
    assert code == imagescan.EXIT_FAILED and problems and problems[0].startswith("python:3.12:")


def test_no_images_is_a_skip(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    assert run_scan(tmp_path)[0] == imagescan.EXIT_NO_IMAGES


@pytest.mark.parametrize("ref", ["--cache-dir=/", "-v/:/x", "bad ref", "a;b", "x/../y", "$(id)", "a`b`"])
def test_a_hostile_reference_never_reaches_a_command(tmp_path, ref):
    (tmp_path / "docker-compose.yml").write_text(f"services:\n  x:\n    image: {ref}\n")
    called = []
    code, _, problems = run_scan(tmp_path, run=lambda *a, **k: called.append(a) or P(REPORT))
    # a reference with a `$` is skipped as "variable"; every other bad one is refused: never executed
    assert not any(ref in " ".join(c[0]) for c in called)
    assert code in (imagescan.EXIT_FAILED, imagescan.EXIT_NO_IMAGES, 0)  # refused, not understood as an image, or skipped


def test_too_many_images_are_refused(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services:\n" + "".join(f"  s{i}:\n    image: img{i}:1\n" for i in range(25)))
    assert run_scan(tmp_path)[0] == imagescan.EXIT_FAILED


def test_a_variable_reference_alone_is_still_reported(tmp_path):
    code, merged, _ = run_scan(project(tmp_path, "FROM ${BASE}\n"), run=lambda *a, **k: P(REPORT))
    assert code == 0 and merged["images"] == [] and merged["skipped"][0]["ref"] == "${BASE}"


# ----------------------------------------------------------------- the parser

# Shape documented by Trivy (SchemaVersion 2). See also the real sample test below, if the fixture exists.
SYNTH = {"kind": "trivy", "skipped": [{"ref": "${X}", "source": "Dockerfile", "line": 9}], "images": [{
    "ref": "python:3.9.0", "source": "docker/old-base.Dockerfile", "line": 2,
    "report": {"SchemaVersion": 2, "Results": [
        {"Target": "python:3.9.0 (debian 10.6)", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-1", "PkgName": "libssl", "InstalledVersion": "1.1", "FixedVersion": "1.2",
             "Severity": "CRITICAL", "Title": "openssl overflow"},
            {"VulnerabilityID": "CVE-2021-2", "PkgName": "glibc", "InstalledVersion": "2.28", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2021-1", "PkgName": "libssl", "InstalledVersion": "1.1", "FixedVersion": "1.2",
             "Severity": "CRITICAL", "Title": "openssl overflow"},
        ]},
        {"Target": "Python", "Vulnerabilities": None},
    ]}}]}  # fmt: skip


def test_parser_findings_point_at_the_line_that_names_the_image():
    findings = parse_trivy(json.dumps(SYNTH), "/p")
    vulns = [f for f in findings if f.rule != "polyscan-image-not-scanned"]
    assert len(vulns) == 2  # the repeated one is counted once
    first = vulns[0]
    assert (first.file, first.line, first.category, first.tool) == ("docker/old-base.Dockerfile", 2, "dependency", "trivy")
    assert first.severity == Severity.CRITICAL and "Fixed in: 1.2" in first.message and first.message.startswith("python:3.9.0: libssl 1.1")
    assert "No fix published yet" in vulns[1].message


def test_a_reference_that_was_not_scanned_is_visible():
    (skipped,) = [f for f in parse_trivy(json.dumps(SYNTH), "/p") if f.rule == "polyscan-image-not-scanned"]
    assert skipped.severity == Severity.INFO and "NOT scanned" in skipped.message and skipped.line == 9


def test_image_without_vulnerabilities_is_no_findings():
    data = {"kind": "trivy", "images": [{"ref": "x:1", "source": "Dockerfile", "line": 1, "report": {"SchemaVersion": 2}}]}
    assert parse_trivy(json.dumps(data), "/p") == []


@pytest.mark.parametrize("bad", ["", "{}", "[]", '{"kind": "npm"}'])
def test_not_our_output_is_an_error_not_clean(bad):
    with pytest.raises((ValueError, TypeError)):
        parse_trivy(bad, "/p")


@pytest.mark.skipif(not (FIX / "trivy.json").exists(), reason="real sample not saved yet")
def test_real_trivy_output():
    findings = parse_trivy((FIX / "trivy.json").read_text(encoding="utf-8"), "/p")
    assert findings and all(f.rule and f.file and f.line for f in findings)


# ----------------------------------------------------------------- the tool


def test_tool_wiring_and_statuses(monkeypatch, tmp_path):
    tool = Trivy()
    assert tool.languages == frozenset({"docker"}) and "trivy" in IMAGES
    cmd = tool.local_cmd(str(tmp_path), ScanOptions(excludes=("old",)))
    assert cmd[:3] == [sys.executable, "-m", "polyscan.imagescan"] and cmd[-2:] == ["--exclude", "old"]

    def fake(code, out="", err=""):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: P(out, err, code))
        return run_tool(tool, "local", tmp_path, ScanOptions(), 10)

    assert fake(0, json.dumps(SYNTH)).status == OK
    assert fake(4, "", "no image references found").status == SKIPPED
    r = fake(3, "", "python:3.9.0: manifest unknown")
    assert r.status == ERROR and "manifest unknown" in r.detail
    assert fake(0, "").status == ERROR
