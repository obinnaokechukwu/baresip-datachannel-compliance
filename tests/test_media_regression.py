from acceptance.product import inbound_packet_counts


def test_inbound_packet_counts_sums_media_rows() -> None:
    stats = {
        "rows": [
            {"type": "inbound-rtp", "kind": "audio", "packetsReceived": 4},
            {"type": "inbound-rtp", "kind": "audio", "packetsReceived": 6},
            {"type": "inbound-rtp", "kind": "video", "packetsReceived": 3},
            {"type": "outbound-rtp", "kind": "video", "packetsSent": 8},
        ]
    }

    assert inbound_packet_counts(stats) == {"audio": 10, "video": 3}
