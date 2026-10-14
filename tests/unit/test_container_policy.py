import pytest
from wireclaw_api import Policy
from wireclaw_api.cli import policy_for_listener


def test_container_interface_binding_requires_explicit_container_policy():
    with pytest.raises(ValueError, match="loopback_required"):
        Policy(host="0.0.0.0")

    assert Policy(host="0.0.0.0", container_network=True).host == "0.0.0.0"


def test_container_policy_does_not_allow_other_non_loopback_interfaces():
    with pytest.raises(ValueError, match="loopback_required"):
        Policy(host="192.0.2.10", container_network=True)


def test_public_origin_port_is_separate_from_container_listener_port(monkeypatch):
    monkeypatch.setenv("WIRECLAW_PUBLIC_PORT", "18765")
    monkeypatch.setenv("WIRECLAW_BRIDGE_PORT", "18766")
    policy = policy_for_listener(host="0.0.0.0", listen_port=8765, container_network=True)
    assert policy.port == 18765
    assert policy.bridge_port == 18766
