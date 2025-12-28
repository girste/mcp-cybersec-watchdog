"""Test privacy utilities."""

from mcp_security.utils.privacy import mask_ip, mask_hostname


def test_mask_ipv4():
    """Test IPv4 address masking."""
    assert mask_ip("192.168.1.100") == "192.168.***.***"
    assert mask_ip("10.0.0.1") == "10.0.***.***"
    assert mask_ip("172.16.254.1") == "172.16.***.***"


def test_mask_ipv6():
    """Test IPv6 address masking."""
    assert mask_ip("2001:db8::1") == "2001:***"
    assert mask_ip("fe80::1") == "fe80:***"


def test_mask_edge_cases():
    """Test edge cases for IP masking."""
    assert mask_ip("unknown") == "unknown"
    assert mask_ip("") == ""
    assert mask_ip("invalid") == "***"


def test_mask_hostname():
    """Test hostname masking."""
    assert mask_hostname("server-prod-01") == "srv-se**"
    assert mask_hostname("webserver") == "srv-we**"
    assert mask_hostname("web") == "srv-****"
    assert mask_hostname("a") == "srv-****"
    assert mask_hostname("") == "srv-****"
