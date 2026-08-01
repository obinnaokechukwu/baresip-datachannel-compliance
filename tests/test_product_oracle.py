from acceptance.aiortc_endpoint import (
    AiortcEndpoint,
    copy_application_attributes,
    expand_bundle_transport_attributes,
)
import acceptance.product as product
import asyncio

import pytest

from acceptance.model import Verdict
from acceptance.product import (
    ProductScenario,
    analyze_resources,
    calibrate_product_oracle,
    exception_verdict,
    impairment_failures,
    parallel_payloads,
    partial_reliability_failures,
    pion_process_failures,
    primary_host_sdp,
    primary_host_ip,
    relay_candidate_failures,
    run_product_scenario,
    terminate_and_reap,
    unexpected_message_failures,
    verified_dtls_count,
)


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


def test_aiortc_rfc8864_adapter_copies_only_application_attributes() -> None:
    source = (
        "v=0\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n"
        "a=mid:0\r\n"
        "a=dcmap:9 label=\"wrong-section\"\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "a=mid:1\r\n"
        "a=dcmap:1 subprotocol=\"sdp-test\";label=\"baresip-acceptance\"\r\n"
        "a=dcsa:1 x-example:opaque\r\n"
    )
    target = (
        "v=0\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n"
        "a=mid:0\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "a=mid:1\r\n"
    )

    adapted = copy_application_attributes(source, target, ("dcmap", "dcsa"))

    assert adapted.count("a=dcmap:") == 1
    assert "a=dcmap:9 label=\"wrong-section\"" not in adapted
    assert (
        "a=dcmap:1 subprotocol=\"sdp-test\";label=\"baresip-acceptance\""
        in adapted
    )
    assert "a=dcsa:1 x-example:opaque" in adapted
    assert adapted.endswith("\r\n")


def test_post_negotiation_timeout_is_a_product_failure() -> None:
    assert exception_verdict(TimeoutError(), True) is Verdict.FAIL
    assert exception_verdict(TimeoutError(), False) is Verdict.INFRA_ERROR
    assert exception_verdict(RuntimeError(), True) is Verdict.INFRA_ERROR


def test_dtls_evidence_requires_committed_fingerprint_verification() -> None:
    assert verified_dtls_count(
        "dtls_srtp: verified sha-256 fingerprint OK "
        "(committed identity)\n"
    ) == 1
    assert verified_dtls_count(
        "dtls_srtp: verified sha-256 fingerprint OK\n"
    ) == 0
    assert verified_dtls_count("verified sha-256 fingerprint OK\n") == 0


def test_primary_host_ip_uses_the_default_ipv4_route(monkeypatch) -> None:
    class Route:
        def __init__(self) -> None:
            self.connected_to = None
            self.closed = False

        def connect(self, address) -> None:
            self.connected_to = address

        def getsockname(self):
            return ("10.0.0.5", 43123)

        def close(self) -> None:
            self.closed = True

    route = Route()
    monkeypatch.setattr(
        "acceptance.product.socket.socket",
        lambda family, kind: route,
    )

    assert primary_host_ip() == "10.0.0.5"
    assert route.connected_to == ("192.0.2.1", 9)
    assert route.closed


def test_primary_host_sdp_removes_unrouted_and_srflx_candidates() -> None:
    sdp = (
        "v=0\r\n"
        "a=candidate:1 1 udp 1 10.0.0.5 5000 typ host\r\n"
        "a=candidate:2 1 udp 1 172.17.0.1 5001 typ host\r\n"
        "a=candidate:3 1 udp 1 203.0.113.5 5002 typ srflx "
        "raddr 10.0.0.5 rport 5000\r\n"
        "a=end-of-candidates\r\n"
    )

    actual = primary_host_sdp(sdp, "10.0.0.5")

    assert "10.0.0.5 5000 typ host" in actual
    assert "172.17.0.1" not in actual
    assert "typ srflx" not in actual
    assert actual.endswith("a=end-of-candidates\r\n")


def test_primary_host_sdp_rejects_missing_routed_candidate() -> None:
    with pytest.raises(RuntimeError, match="no host ICE candidate"):
        primary_host_sdp(
            "a=candidate:1 1 udp 1 172.17.0.1 5001 typ host\r\n",
            "10.0.0.5",
        )


@pytest.mark.asyncio
async def test_aiortc_gatherer_uses_only_primary_host_candidate() -> None:
    host_ip = primary_host_ip()
    peer = AiortcEndpoint(host_ip)
    try:
        channel = peer.pc.createDataChannel("candidate-test")
        peer._register(channel)
        peer.constrain_ice()
        await peer.pc.setLocalDescription(await peer.pc.createOffer())
        await peer._wait_ice_complete()
        assert peer.pc.localDescription is not None
        candidates = [
            line
            for line in peer.pc.localDescription.sdp.splitlines()
            if line.startswith("a=candidate:")
        ]
        assert len(candidates) == 1
        assert f" {host_ip} " in candidates[0]
        assert " typ host" in candidates[0]
    finally:
        await peer.close()


def test_resource_analysis_captures_peak_and_trend() -> None:
    baseline = {"rssBytes": 100, "fileDescriptors": 5, "threads": 2}
    samples = [
        {"cycle": -1, **baseline},
        {"cycle": 0, "rssBytes": 110, "fileDescriptors": 5, "threads": 2},
        {"cycle": 1, "rssBytes": 120, "fileDescriptors": 6, "threads": 2},
        {"cycle": 2, "rssBytes": 130, "fileDescriptors": 5, "threads": 2},
    ]

    analysis = analyze_resources(baseline, samples)

    assert analysis["rssBytes"]["peakGrowth"] == 30
    assert analysis["rssBytes"]["slopePerCycle"] == 10
    assert analysis["rssBytes"]["projectedGrowth"] == 30
    assert analysis["fileDescriptors"]["peakGrowth"] == 1


def test_partial_reliability_oracle_rejects_reliable_fallback() -> None:
    assert partial_reliability_failures(3, True, False) == []
    assert partial_reliability_failures(3, False, False) == [
        "partial-reliability probe saw no FORWARD-TSN; "
        "the channel behaved as reliable"
    ]
    assert partial_reliability_failures(3, True, True) == [
        "abandoned partial-reliability message was delivered"
    ]
    assert partial_reliability_failures(0, True, False) == [
        "partial-reliability probe did not drop DATA"
    ]


def test_forced_turn_requires_both_selected_candidates_to_be_relay() -> None:
    assert relay_candidate_failures(
        {"localCandidateType": "relay", "remoteCandidateType": "relay"}
    ) == []
    assert relay_candidate_failures(
        {"localCandidateType": "relay", "remoteCandidateType": "host"}
    ) == ["baresip selected remote candidate is not relay"]
    assert relay_candidate_failures(
        {"localCandidateType": "host", "remoteCandidateType": "relay"}
    ) == ["Pion selected local candidate is not relay"]


def test_pion_exit_and_verdict_fail_without_endpoint_failure_text() -> None:
    assert pion_process_failures(7, {"verdict": Verdict.PASS}) == [
        "Pion endpoint exited with status 7"
    ]
    assert pion_process_failures(0, {"verdict": Verdict.INFRA_ERROR}) == [
        "Pion endpoint verdict was 'INFRA_ERROR'"
    ]


def test_parallel_oracle_rejects_queued_extra_messages() -> None:
    event = {
        "name": "message",
        "body": {"label": "parallel-0", "type": "binary", "payloadHex": "00"},
    }
    assert unexpected_message_failures(0, [event]) == [
        "peer 0 received 1 unexpected extra messages"
    ]
    assert unexpected_message_failures(0, []) == []


def test_parallel_payloads_are_unique_per_association() -> None:
    values = [("binary", b"same")]
    assert parallel_payloads(0, values) != parallel_payloads(1, values)


def test_impairment_oracle_requires_measured_data_path_effects() -> None:
    metrics = {
        "dataDropped": 1,
        "dataDelayed": 1,
        "dataJittered": 1,
        "dataBandwidthDelayed": 1,
        "dataReordered": 1,
        "dataDuplicated": 1,
        "dataMtuDropped": 1,
        "bandwidthBitsPerSecond": 2_000_000,
        "mtu": 1400,
        "maxDatagramSize": 1401,
        "minAppliedDelayMillis": 1,
        "maxAppliedDelayMillis": 4,
    }
    assert impairment_failures(metrics, 1401) == []

    metrics["dataJittered"] = 0
    metrics["dataMtuDropped"] = 0
    assert impairment_failures(metrics, 1401) == [
        "TURN data traffic did not exercise dataJittered",
        "TURN data traffic did not exercise dataMtuDropped",
    ]


@pytest.mark.asyncio
async def test_failed_scenario_retains_reproducer_evidence(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    evidence = tmp_path / "evidence"
    scenario = ProductScenario("failing-evidence", "aiortc", False)

    verdict = await run_product_scenario(
        scenario,
        evidence,
        tmp_path / "missing-executable",
        source,
        source,
        (),
        "dc-product-acceptance --evidence '/tmp/with spaces'",
    )

    destination = evidence / scenario.name
    assert verdict is Verdict.INFRA_ERROR
    assert (destination / "scenario.json").is_file()
    assert (destination / "versions.json").is_file()
    assert (destination / "command.txt").read_text().startswith(
        "dc-product-acceptance"
    )
    assert (destination / "result.json").is_file()


@pytest.mark.asyncio
async def test_pion_invalid_json_preserves_stdout_and_writes_result_last(
    tmp_path, monkeypatch
) -> None:
    events: list[str] = []
    raw_stdout = b"not valid JSON\nwith diagnostic output\n"

    class Endpoint:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def start(self) -> None:
            events.append("endpoint-started")

        async def close(self) -> None:
            events.append("endpoint-closed")

    class Process:
        def __init__(self) -> None:
            self.returncode = 1
            self.communications = 0

        async def communicate(self, input=None):
            self.communications += 1
            if self.communications == 1:
                return raw_stdout, b"initial stderr\n"
            events.append("pion-reaped")
            return b"", b"final stderr\n"

    async def create_subprocess_exec(*args, **kwargs):
        return Process()

    original_write_json = product.write_json

    def ordered_write_json(path, payload) -> None:
        if path.name == "result.json":
            events.append("result-written")
        original_write_json(path, payload)

    monkeypatch.setattr(product, "BaresipEndpoint", Endpoint)
    monkeypatch.setattr(
        product.asyncio, "create_subprocess_exec", create_subprocess_exec
    )
    monkeypatch.setattr(product, "primary_host_ip", lambda: "192.0.2.10")
    monkeypatch.setattr(product, "write_json", ordered_write_json)

    source = tmp_path / "source"
    source.mkdir()
    evidence = tmp_path / "evidence"
    verdict = await product.run_pion_scenario(
        evidence,
        tmp_path / "baresip-webrtc",
        tmp_path / "pion-endpoint",
        source,
        source,
        (),
        "dc-product-acceptance",
    )

    destination = evidence / "baresip-pion-data-only"
    assert verdict is Verdict.INFRA_ERROR
    assert (destination / "pion.stdout").read_bytes() == raw_stdout
    assert (destination / "pion.log").read_bytes() == (
        b"initial stderr\nfinal stderr\n"
    )
    assert events[-1] == "result-written"
    assert events.index("endpoint-closed") < events.index("result-written")
    assert events.index("pion-reaped") < events.index("result-written")


@pytest.mark.asyncio
async def test_process_supervision_escalates_and_reaps_after_timeout() -> None:
    class Process:
        def __init__(self) -> None:
            self.returncode = None
            self.terminated = 0
            self.killed = 0
            self.communications = 0

        def terminate(self) -> None:
            self.terminated += 1

        def kill(self) -> None:
            self.killed += 1
            self.returncode = -9

        async def communicate(self):
            self.communications += 1
            if self.communications == 1:
                await asyncio.Event().wait()
            return b"stdout", b"stderr"

    process = Process()
    output = await terminate_and_reap(process, timeout=0.01)

    assert output == (b"stdout", b"stderr")
    assert process.terminated == 1
    assert process.killed == 1
    assert process.communications == 2
