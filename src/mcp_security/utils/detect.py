"""System and distro detection utilities."""

import os
import platform
import subprocess

from ..constants import (
    TIMEOUT_SHORT,
    PATH_AUTH_LOG_DEBIAN,
    PATH_AUTH_LOG_RHEL,
)


def get_distro():
    """Detect Linux distribution."""
    if os.path.exists("/etc/debian_version"):
        return "debian"
    elif os.path.exists("/etc/redhat-release"):
        return "rhel"
    elif os.path.exists("/etc/arch-release"):
        return "arch"
    return "unknown"


def get_os_info():
    """Get OS and kernel information."""
    return {
        "system": platform.system(),
        "distro": get_distro(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
    }


def get_auth_log_path():
    """Get authentication log path based on distro."""
    distro = get_distro()

    if distro in ("debian", "arch"):
        path = PATH_AUTH_LOG_DEBIAN
    elif distro == "rhel":
        path = PATH_AUTH_LOG_RHEL
    else:
        path = PATH_AUTH_LOG_DEBIAN

    return path if os.path.exists(path) else None


def detect_firewall():
    """Detect active firewall type."""
    checks = [
        ("ufw", ["ufw", "status"]),
        ("firewalld", ["firewall-cmd", "--state"]),
        ("iptables", ["iptables", "-L", "-n"]),
    ]

    for name, cmd in checks:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return name
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


def has_sudo():
    """Check if current user has sudo access."""
    try:
        result = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=TIMEOUT_SHORT)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def is_fail2ban_installed():
    """Check if fail2ban is installed and accessible."""
    try:
        result = subprocess.run(
            ["fail2ban-client", "version"], capture_output=True, timeout=TIMEOUT_SHORT
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_with_sudo(cmd, timeout=TIMEOUT_SHORT):
    """
    Run command with automatic sudo fallback.

    Tries command normally first, then with sudo if permission denied.
    Returns subprocess.CompletedProcess or None on failure.
    """
    try:
        # Try without sudo first
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # If successful, return result
        if result.returncode == 0:
            return result

        # Check if error is permission-related
        stderr_lower = result.stderr.lower()
        if any(
            keyword in stderr_lower
            for keyword in ["permission denied", "you must be root", "you need to be root"]
        ):
            # Try with sudo
            result = subprocess.run(
                ["sudo", "-n"] + cmd, capture_output=True, text=True, timeout=timeout
            )
            return result if result.returncode == 0 else None

        # Other error, return None
        return None

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
