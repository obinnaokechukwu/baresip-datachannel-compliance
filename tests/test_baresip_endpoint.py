from pathlib import Path

from acceptance.baresip_endpoint import BaresipEndpoint


def endpoint(*, relay_only: bool = False) -> BaresipEndpoint:
    return BaresipEndpoint(
        Path("/tmp/baresip-webrtc"),
        Path("/tmp/baresip"),
        (),
        Path("/tmp/baresip.log"),
        ice_server="turn:192.0.2.1:3478?transport=udp",
        ice_username="user",
        ice_password="password",
        ice_relay_only=relay_only,
    )


def test_default_ice_arguments_do_not_force_relay() -> None:
    assert endpoint()._ice_arguments() == [
        "-i",
        "turn:192.0.2.1:3478?transport=udp",
        "-u",
        "user",
        "-p",
        "password",
    ]


def test_relay_only_ice_arguments_enable_production_policy() -> None:
    assert endpoint(relay_only=True)._ice_arguments() == [
        "-i",
        "turn:192.0.2.1:3478?transport=udp",
        "-u",
        "user",
        "-p",
        "password",
        "-R",
    ]
