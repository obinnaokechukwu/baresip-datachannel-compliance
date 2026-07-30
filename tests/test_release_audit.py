from pathlib import Path

from acceptance.release_audit import dynamic_dependencies


def test_dynamic_dependencies_reads_needed_entries() -> None:
    dependencies = dynamic_dependencies(Path("/bin/sh"))

    assert dependencies
    assert any(name.startswith("libc.so") for name in dependencies)
