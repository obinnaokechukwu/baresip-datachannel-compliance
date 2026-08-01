from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import aiortc


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def reproduction_command(argv: list[str]) -> str:
    return shlex.join(argv)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def prepare_evidence_dir(path: Path) -> None:
    resolved = path.resolve()
    protected = {
        Path("/"),
        Path.home().resolve(),
        Path.cwd().resolve(),
        Path(__file__).parents[1].resolve(),
    }
    if resolved in protected or (resolved / ".git").exists():
        raise ValueError(
            f"evidence path must be a dedicated output directory: {resolved}"
        )
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def git_revision(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _run_git(path: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(path), *arguments],
        capture_output=True,
        check=False,
    )


def source_state(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    status = _run_git(resolved, "status", "--porcelain=v1", "-z")
    diff = _run_git(resolved, "diff", "--binary", "HEAD")
    if status.returncode or diff.returncode:
        return {
            "path": str(resolved),
            "revision": git_revision(resolved),
            "state": "unknown",
        }

    digest = hashlib.sha256()
    digest.update(diff.stdout)
    entries = [
        entry.decode(errors="surrogateescape")
        for entry in status.stdout.split(b"\0")
        if entry
    ]
    for entry in entries:
        digest.update(entry.encode(errors="surrogateescape"))
        if not entry.startswith("?? "):
            continue
        candidate = resolved / entry[3:]
        if candidate.is_file():
            digest.update(candidate.read_bytes())
        elif candidate.is_dir():
            for child in sorted(
                value for value in candidate.rglob("*") if value.is_file()
            ):
                digest.update(str(child.relative_to(resolved)).encode())
                digest.update(child.read_bytes())

    return {
        "path": str(resolved),
        "revision": git_revision(resolved),
        "state": "dirty" if entries else "clean",
        "status": entries,
        "workingTreeSha256": digest.hexdigest(),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _build_id(path: Path) -> str | None:
    result = subprocess.run(
        ["readelf", "-n", str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    match = re.search(r"Build ID:\s*(\S+)", result.stdout)
    return match.group(1) if match else None


def artifact(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    stat = resolved.stat()
    return {
        "path": str(resolved),
        "size": stat.st_size,
        "sha256": _sha256(resolved),
        "buildId": _build_id(resolved),
    }


def runtime_provenance(
    executable: Path,
    library_paths: tuple[Path, ...],
    additional_artifacts: tuple[Path, ...] = (),
    module_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    resolved_executable = executable.resolve()
    env = os.environ.copy()
    paths = [str(path.resolve()) for path in library_paths]
    if env.get("LD_LIBRARY_PATH"):
        paths.append(env["LD_LIBRARY_PATH"])
    env["LD_LIBRARY_PATH"] = ":".join(paths)
    result = subprocess.run(
        ["ldd", str(resolved_executable)],
        cwd=resolved_executable.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"ldd failed for {resolved_executable}: {result.stdout}"
        )

    dependencies: dict[str, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        if "=> not found" in line:
            raise RuntimeError(
                f"runtime dependency is unresolved for {resolved_executable}: "
                f"{line.strip()}"
            )
        match = re.match(r"\s*(\S+)\s+=>\s+(\S+)\s+\(", line)
        if match:
            name, value = match.groups()
        else:
            match = re.match(r"\s*(/\S+)\s+\(", line)
            if not match:
                continue
            value = match.group(1)
            name = Path(value).name
        dependency = Path(value)
        if not dependency.is_absolute():
            dependency = (resolved_executable.parent / dependency).resolve()
        if dependency.is_file():
            dependencies[name] = artifact(dependency)

    missing = [
        str(path.resolve())
        for path in additional_artifacts
        if not path.resolve().is_file()
    ]
    if missing:
        raise FileNotFoundError(
            "required runtime artifacts are missing: " + ", ".join(missing)
        )
    extras = [artifact(path) for path in additional_artifacts]
    modules: list[dict[str, Any]] = []
    for module_path in module_paths:
        root = module_path.resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"module path is not a directory: {root}")
        candidates = sorted(
            value for value in root.rglob("*.so") if value.is_file()
        )
        if not candidates:
            raise FileNotFoundError(f"module path contains no .so files: {root}")
        for candidate in candidates:
            module_runtime = runtime_provenance(candidate, library_paths)
            modules.append(
                {
                    "root": str(root),
                    "relativePath": str(candidate.relative_to(root)),
                    "artifact": module_runtime["executable"],
                    "dynamicDependencies": module_runtime[
                        "dynamicDependencies"
                    ],
                    "ldd": module_runtime["ldd"],
                }
            )
    return {
        "executable": artifact(resolved_executable),
        "librarySearchPath": paths,
        "dynamicDependencies": dependencies,
        "additionalArtifacts": extras,
        "dynamicModules": modules,
        "ldd": [
            re.sub(r"\s+\(0x[0-9a-fA-F]+\)$", "", line)
            for line in result.stdout.splitlines()
        ],
    }


def build_manifest(
    executable: Path,
    baresip: Path,
    libre: Path,
    harness: Path,
    library_paths: tuple[Path, ...],
    additional_artifacts: tuple[Path, ...] = (),
    module_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    binding = {
        "sources": {
            "baresip": source_state(baresip),
            "libre": source_state(libre),
            "harness": source_state(harness),
        },
        "runtime": runtime_provenance(
            executable, library_paths, additional_artifacts, module_paths
        ),
    }
    return {
        "schema": "baresip-datachannel-build-binding-v1",
        "binding": binding,
        "bindingSha256": _canonical_sha256(binding),
    }


def load_build_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if value.get("schema") != "baresip-datachannel-build-binding-v1":
        raise ValueError("unsupported build-manifest schema")
    binding = value.get("binding")
    if not isinstance(binding, dict):
        raise ValueError("build manifest lacks binding")
    if value.get("bindingSha256") != _canonical_sha256(binding):
        raise ValueError("build-manifest binding digest is invalid")
    return value


def verify_build_manifest(
    path: Path,
    executable: Path,
    baresip: Path,
    libre: Path,
    harness: Path,
    library_paths: tuple[Path, ...],
    additional_artifacts: tuple[Path, ...] = (),
    module_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    expected = load_build_manifest(path)
    actual = build_manifest(
        executable,
        baresip,
        libre,
        harness,
        library_paths,
        additional_artifacts,
        module_paths,
    )
    if actual["bindingSha256"] != expected["bindingSha256"]:
        raise RuntimeError(
            "current sources or artifacts do not match the cryptographic "
            "build manifest"
        )
    return actual


def chrome_version() -> str:
    executable = (
        os.environ.get("CHROMIUM")
        or next(
            (
                value
                for value in (
                    "/usr/bin/google-chrome",
                    "/usr/bin/chromium",
                )
                if Path(value).exists()
            ),
            "",
        )
    )
    if not executable:
        return "unavailable"
    result = subprocess.run(
        [executable, "--version"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() or result.stderr.strip()


def versions(baresip: Path, libre: Path) -> dict[str, Any]:
    harness = Path(__file__).parents[1]
    return {
        "platform": platform.platform(),
        "python": sys.version,
        "chrome": chrome_version(),
        "aiortc": aiortc.__version__,
        "baresip_revision": git_revision(baresip),
        "libre_revision": git_revision(libre),
        "harness_revision": git_revision(harness),
        "baresip": source_state(baresip),
        "libre": source_state(libre),
        "harness": source_state(harness),
    }
