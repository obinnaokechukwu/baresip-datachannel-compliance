from acceptance.model import Verdict
from acceptance.product import calibrate_product_oracle


def test_product_oracles_detect_injected_violations() -> None:
    calibration = calibrate_product_oracle()

    assert calibration["known-good"] is Verdict.PASS
    assert calibration["malformed-known-good"] is Verdict.PASS
    for name in (
        "corrupt",
        "omit",
        "duplicate",
        "reorder",
        "malformed-delivery",
    ):
        assert calibration[name] is Verdict.FAIL
