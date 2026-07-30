from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .evidence import versions, write_json
from .model import Verdict


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def record_command(
    destination: Path,
    name: str,
    result: subprocess.CompletedProcess[str],
) -> None:
    (destination / f"{name}.command.txt").write_text(
        " ".join(result.args) + "\n"
    )
    (destination / f"{name}.log").write_text(result.stdout)


def dynamic_dependencies(path: Path) -> set[str]:
    result = run_command(["readelf", "-d", str(path)], cwd=path.parent)
    if result.returncode:
        raise RuntimeError(f"readelf failed for {path}: {result.stdout}")

    dependencies = set()
    for line in result.stdout.splitlines():
        if "(NEEDED)" not in line or "[" not in line or "]" not in line:
            continue
        dependencies.add(line.split("[", 1)[1].split("]", 1)[0])
    return dependencies


def find_library(root: Path, pattern: str) -> Path:
    matches = sorted(root.rglob(pattern))
    if not matches:
        raise FileNotFoundError(f"{pattern} not found below {root}")
    return matches[0]


def audit(args: argparse.Namespace) -> int:
    evidence = args.evidence.resolve()
    work = args.work.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    if work.parent == work or work == Path.home():
        raise ValueError("audit work directory must be a dedicated child path")
    failures: list[str] = []
    checks: dict[str, Any] = {}

    base_build = work / "libre-base-build"
    base_install = work / "libre-base-install"
    disabled_build = work / "baresip-disabled-build"
    for path in (base_build, base_install, disabled_build):
        if path.exists():
            shutil.rmtree(path)

    base_configure = run_command(
        [
            "cmake",
            "-S",
            str(args.libre.resolve()),
            "-B",
            str(base_build),
            "-DUSE_DATACHANNEL=OFF",
            f"-DCMAKE_INSTALL_PREFIX={base_install}",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_TESTING=OFF",
        ],
        cwd=work,
    )
    record_command(evidence, "libre-base-configure", base_configure)
    if base_configure.returncode:
        failures.append("base libre configuration failed")

    if not base_configure.returncode:
        base_build_result = run_command(
            ["cmake", "--build", str(base_build), "-j2"],
            cwd=work,
        )
        record_command(evidence, "libre-base-build", base_build_result)
        if base_build_result.returncode:
            failures.append("base libre build failed")
        else:
            base_install_result = run_command(
                ["cmake", "--install", str(base_build)],
                cwd=work,
            )
            record_command(evidence, "libre-base-install", base_install_result)
            if base_install_result.returncode:
                failures.append("base libre install failed")

    clean_env = os.environ.copy()
    clean_env.pop("CMAKE_PREFIX_PATH", None)
    clean_env["PKG_CONFIG_PATH"] = str(base_install / "lib" / "pkgconfig")
    empty_pkgconfig = work / "empty-pkgconfig"
    empty_pkgconfig.mkdir(exist_ok=True)
    clean_env["PKG_CONFIG_LIBDIR"] = str(empty_pkgconfig)
    negative_build = work / "baresip-negative-build"
    if negative_build.exists():
        shutil.rmtree(negative_build)
    negative_configure = run_command(
        [
            "cmake",
            "-S",
            str(args.baresip.resolve()),
            "-B",
            str(negative_build),
            "-DUSE_DATACHANNEL=ON",
            f"-DCMAKE_PREFIX_PATH={base_install}",
        ],
        cwd=work,
        env=clean_env,
    )
    record_command(evidence, "enabled-negative-configure", negative_configure)
    negative_failed = negative_configure.returncode != 0
    negative_diagnostic = (
        "USRSCTP" in negative_configure.stdout
        or "DATACHANNEL" in negative_configure.stdout
        or "datachannel" in negative_configure.stdout
    )
    checks["enabledMissingDependencyFails"] = negative_failed
    checks["enabledFailureNamesDependency"] = negative_diagnostic
    if not negative_failed:
        failures.append("enabled configuration succeeded without datachannel")
    if not negative_diagnostic:
        failures.append("enabled dependency failure lacked a useful diagnostic")

    disabled_configure = run_command(
        [
            "cmake",
            "-S",
            str(args.baresip.resolve()),
            "-B",
            str(disabled_build),
            "-DUSE_DATACHANNEL=OFF",
            f"-DCMAKE_PREFIX_PATH={base_install}",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_TESTING=OFF",
        ],
        cwd=work,
        env=clean_env,
    )
    record_command(evidence, "disabled-configure", disabled_configure)
    if disabled_configure.returncode:
        failures.append("disabled baresip configuration failed")
    else:
        disabled_build_result = run_command(
            ["cmake", "--build", str(disabled_build), "-j2"],
            cwd=work,
            env=clean_env,
        )
        record_command(evidence, "disabled-build", disabled_build_result)
        if disabled_build_result.returncode:
            failures.append("disabled baresip build failed")
        else:
            disabled_library = find_library(disabled_build, "libbaresip.so*")
            disabled_dependencies = dynamic_dependencies(disabled_library)
            checks["disabledDependencies"] = sorted(disabled_dependencies)
            forbidden = {
                dependency
                for dependency in disabled_dependencies
                if "usrsctp" in dependency
                or "re-datachannel" in dependency
            }
            if forbidden:
                failures.append(
                    "disabled build links datachannel dependencies: "
                    + ", ".join(sorted(forbidden))
                )

    enabled_install = args.enabled_libre_install.resolve()
    datachannel_library = find_library(
        enabled_install, "libre-datachannel.so*"
    )
    notice = (
        enabled_install
        / "share"
        / "licenses"
        / "libre-datachannel"
        / "usrsctp-LICENSE.md"
    )
    checks["enabledDatachannelLibrary"] = str(datachannel_library)
    checks["usrsctpNotice"] = str(notice)
    checks["usrsctpNoticePresent"] = notice.is_file()
    if not notice.is_file():
        failures.append("installed libre datachannel package lacks BSD notice")
    elif "Copyright" not in notice.read_text():
        failures.append("installed usrsctp notice is malformed")

    source_notice = (
        args.libre.resolve() / "third_party" / "usrsctp-LICENSE.md"
    )
    checks["sourceNoticeMatchesInstalled"] = (
        notice.is_file()
        and source_notice.is_file()
        and notice.read_bytes() == source_notice.read_bytes()
    )
    if not checks["sourceNoticeMatchesInstalled"]:
        failures.append("installed usrsctp notice differs from source notice")

    write_json(evidence / "checks.json", checks)
    write_json(
        evidence / "versions.json",
        versions(args.baresip.resolve(), args.libre.resolve()),
    )
    result = {
        "verdict": Verdict.FAIL if failures else Verdict.PASS,
        "failures": failures,
    }
    write_json(evidence / "result.json", result)
    (evidence / "command.txt").write_text(" ".join(sys.orig_argv) + "\n")
    print(json.dumps(result, indent=2))
    return 1 if failures else 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--baresip", type=Path, required=True)
    result.add_argument("--libre", type=Path, required=True)
    result.add_argument(
        "--enabled-libre-install",
        type=Path,
        required=True,
    )
    result.add_argument("--work", type=Path, required=True)
    result.add_argument("--evidence", type=Path, required=True)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        status = audit(args)
    except Exception as error:
        evidence = args.evidence.resolve()
        evidence.mkdir(parents=True, exist_ok=True)
        result = {
            "verdict": Verdict.INFRA_ERROR,
            "failures": [f"{type(error).__name__}: {error}"],
        }
        write_json(evidence / "result.json", result)
        print(json.dumps(result, indent=2))
        status = 2
    raise SystemExit(status)


if __name__ == "__main__":
    main()
