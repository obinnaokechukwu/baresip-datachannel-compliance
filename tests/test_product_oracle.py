from acceptance.aiortc_endpoint import expand_bundle_transport_attributes
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


def test_aiortc_bundle_adapter_expands_only_required_dtls_attributes() -> None:
    sdp = (
        "v=0\r\n"
        "a=group:BUNDLE 0 1 2\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n"
        "a=mid:0\r\n"
        "a=setup:actpass\r\n"
        "a=fingerprint:sha-256 AA:BB\r\n"
        "a=tls-id:abcdefghijklmnopqrstuvwx\r\n"
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
        "a=mid:1\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "a=mid:2\r\n"
    )

    expanded = expand_bundle_transport_attributes(sdp)

    assert expanded.count("a=setup:actpass") == 3
    assert expanded.count("a=fingerprint:sha-256 AA:BB") == 3
    assert expanded.count("a=tls-id:abcdefghijklmnopqrstuvwx") == 1
    assert expanded.endswith("\r\n")
