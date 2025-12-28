"""Test system detection utilities."""

from mcp_security.utils.detect import get_distro, get_os_info


def test_get_distro():
    """Test distro detection returns valid value."""
    distro = get_distro()
    assert distro in ("debian", "rhel", "arch", "unknown")


def test_get_os_info():
    """Test OS info structure."""
    os_info = get_os_info()

    assert "system" in os_info
    assert "distro" in os_info
    assert "kernel" in os_info
    assert "architecture" in os_info

    assert isinstance(os_info["system"], str)
    assert isinstance(os_info["distro"], str)
    assert isinstance(os_info["kernel"], str)
    assert isinstance(os_info["architecture"], str)
