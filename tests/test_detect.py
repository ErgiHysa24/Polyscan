from polyscan.detect import detect_languages


def touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")


def test_detects_all_five_languages(tmp_path):
    for name in ("a.py", "b.js", "C.java", "d.php", "e.rs"):
        touch(tmp_path / "src" / name)
    assert detect_languages(tmp_path) == {
        "java": 1, "javascript": 1, "php": 1, "python": 1, "rust": 1,
    }  # fmt: skip


def test_manifest_alone_counts(tmp_path):
    touch(tmp_path / "Cargo.lock")
    assert detect_languages(tmp_path) == {"rust": 1}


def test_typescript_counts_as_javascript(tmp_path):
    touch(tmp_path / "a.ts")
    assert detect_languages(tmp_path) == {"javascript": 1}


def test_third_party_folders_are_ignored(tmp_path):
    touch(tmp_path / "node_modules" / "dep" / "index.js")
    touch(tmp_path / ".venv" / "lib" / "x.py")
    touch(tmp_path / "vendor" / "lib.php")
    touch(tmp_path / "app.py")
    assert detect_languages(tmp_path) == {"python": 1}


def test_empty_folder(tmp_path):
    assert detect_languages(tmp_path) == {}


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    touch(outside / "secret.php")
    project = tmp_path / "project"
    project.mkdir()
    try:
        (project / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        return  # symlinks not allowed on this system
    assert detect_languages(project) == {}


def test_user_excludes_also_apply_to_detection(tmp_path):
    touch(tmp_path / "app.py")
    touch(tmp_path / "examples" / "demo" / "x.php")
    assert detect_languages(tmp_path, frozenset({"examples"})) == {"python": 1}
    assert detect_languages(tmp_path, frozenset({"ex*"})) == {"python": 1}
