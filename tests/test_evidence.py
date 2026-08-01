import subprocess
import shutil
from pathlib import Path

import pytest

from acceptance.evidence import (
    build_manifest,
    prepare_evidence_dir,
    runtime_provenance,
    reproduction_command,
    source_state,
    verify_build_manifest,
    write_json,
)


def test_prepare_evidence_dir_removes_stale_artifacts(tmp_path: Path) -> None:
    evidence = tmp_path / "scenario"
    evidence.mkdir()
    (evidence / "stale.json").write_text("{}")

    prepare_evidence_dir(evidence)

    assert evidence.is_dir()
    assert list(evidence.iterdir()) == []


def test_prepare_evidence_dir_rejects_filesystem_root() -> None:
    with pytest.raises(ValueError):
        prepare_evidence_dir(Path("/"))


def test_reproduction_command_shell_quotes_exact_argv() -> None:
    assert reproduction_command(
        ["dc-product-acceptance", "--evidence", "/tmp/path with spaces", "$x"]
    ) == "dc-product-acceptance --evidence '/tmp/path with spaces' '$x'"


def test_source_state_binds_dirty_content(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
        check=True,
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("one\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-qm", "initial"], check=True
    )
    clean = source_state(tmp_path)

    tracked.write_text("two\n")
    (tmp_path / "untracked.txt").write_text("extra\n")
    dirty = source_state(tmp_path)

    assert clean["state"] == "clean"
    assert dirty["state"] == "dirty"
    assert dirty["workingTreeSha256"] != clean["workingTreeSha256"]
    assert " M tracked.txt" in dirty["status"]
    assert "?? untracked.txt" in dirty["status"]


def test_runtime_provenance_hashes_executable_and_dependencies() -> None:
    provenance = runtime_provenance(Path("/bin/sh"), ())

    assert len(provenance["executable"]["sha256"]) == 64
    assert provenance["dynamicDependencies"]
    assert all(
        len(value["sha256"]) == 64
        for value in provenance["dynamicDependencies"].values()
    )


def test_runtime_provenance_hashes_recursive_modules_and_dependencies(
    tmp_path: Path,
) -> None:
    executable = runtime_provenance(Path("/bin/sh"), ())
    dependency = Path(
        next(iter(executable["dynamicDependencies"].values()))["path"]
    )
    module_root = tmp_path / "modules"
    nested = module_root / "nested"
    nested.mkdir(parents=True)
    module = nested / "example.so"
    shutil.copy2(dependency, module)

    provenance = runtime_provenance(
        Path("/bin/sh"), (), module_paths=(module_root,)
    )

    assert len(provenance["dynamicModules"]) == 1
    recorded = provenance["dynamicModules"][0]
    assert recorded["relativePath"] == "nested/example.so"
    assert len(recorded["artifact"]["sha256"]) == 64
    assert "dynamicDependencies" in recorded


def initialized_repository(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Test"],
        check=True,
    )
    (path / "source.txt").write_text("built source\n")
    subprocess.run(["git", "-C", str(path), "add", "source.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "commit", "-qm", "initial"], check=True
    )


def test_build_manifest_cryptographically_binds_sources_and_artifacts(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    initialized_repository(source)
    executable = tmp_path / "executable"
    shutil.copy2("/bin/sh", executable)
    manifest_path = tmp_path / "build-manifest.json"
    manifest = build_manifest(
        executable, source, source, source, (), ()
    )
    write_json(manifest_path, manifest)

    verified = verify_build_manifest(
        manifest_path, executable, source, source, source, (), ()
    )
    assert verified["bindingSha256"] == manifest["bindingSha256"]

    (source / "source.txt").write_text("different source\n")
    with pytest.raises(RuntimeError, match="do not match"):
        verify_build_manifest(
            manifest_path, executable, source, source, source, (), ()
        )

    (source / "source.txt").write_text("built source\n")
    shutil.copy2("/bin/false", executable)
    with pytest.raises(RuntimeError, match="do not match"):
        verify_build_manifest(
            manifest_path, executable, source, source, source, (), ()
        )


def test_build_manifest_rejects_tampered_binding_digest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    initialized_repository(source)
    manifest_path = tmp_path / "build-manifest.json"
    manifest = build_manifest(Path("/bin/sh"), source, source, source, (), ())
    manifest["binding"]["sources"]["baresip"]["revision"] = "forged"
    write_json(manifest_path, manifest)

    with pytest.raises(ValueError, match="digest is invalid"):
        verify_build_manifest(
            manifest_path,
            Path("/bin/sh"),
            source,
            source,
            source,
            (),
            (),
        )


def test_build_manifest_detects_dlopen_module_replacement(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    initialized_repository(source)
    module_root = tmp_path / "modules"
    module_root.mkdir()
    dependency = Path(
        next(
            iter(
                runtime_provenance(Path("/bin/sh"), ())[
                    "dynamicDependencies"
                ].values()
            )
        )["path"]
    )
    module = module_root / "dtls_srtp.so"
    shutil.copy2(dependency, module)
    manifest_path = tmp_path / "build-manifest.json"
    manifest = build_manifest(
        Path("/bin/sh"),
        source,
        source,
        source,
        (),
        (),
        (module_root,),
    )
    write_json(manifest_path, manifest)
    verify_build_manifest(
        manifest_path,
        Path("/bin/sh"),
        source,
        source,
        source,
        (),
        (),
        (module_root,),
    )

    module.write_bytes(module.read_bytes() + b"replacement")
    with pytest.raises(RuntimeError, match="do not match"):
        verify_build_manifest(
            manifest_path,
            Path("/bin/sh"),
            source,
            source,
            source,
            (),
            (),
            (module_root,),
        )
