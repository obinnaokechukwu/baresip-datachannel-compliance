from pathlib import Path

from acceptance.baresip_probe import baseline
from acceptance.model import Verdict


def test_probe_reports_available_without_claiming_product_pass(
    tmp_path: Path,
) -> None:
    include = tmp_path / "include"
    include.mkdir()
    (include / "baresip.h").write_text(
        "int peerconnection_create_datachannel(void);\n"
        "int peerconnection_set_datachannel_handler(void);\n"
        "int datachannel_send(void);\n"
    )

    result = baseline(tmp_path)

    assert result["capability_status"] == "AVAILABLE_NOT_TESTED"
    assert "verdict" not in result


def test_probe_reports_missing_api_as_unsupported(tmp_path: Path) -> None:
    include = tmp_path / "include"
    include.mkdir()
    (include / "baresip.h").write_text("")

    result = baseline(tmp_path)

    assert result["capability_status"] is Verdict.UNSUPPORTED
