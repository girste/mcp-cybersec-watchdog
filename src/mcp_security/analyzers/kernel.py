"""Kernel security hardening analysis."""

from ..utils.command import run_command_sudo


# Security-critical sysctl parameters
SECURITY_PARAMS = {
    # Network security
    "net.ipv4.conf.all.accept_source_route": {"expected": "0", "severity": "high"},
    "net.ipv4.conf.default.accept_source_route": {"expected": "0", "severity": "high"},
    "net.ipv4.conf.all.send_redirects": {"expected": "0", "severity": "medium"},
    "net.ipv4.conf.default.send_redirects": {"expected": "0", "severity": "medium"},
    "net.ipv4.icmp_echo_ignore_broadcasts": {"expected": "1", "severity": "low"},
    "net.ipv4.icmp_ignore_bogus_error_responses": {"expected": "1", "severity": "low"},
    "net.ipv4.conf.all.rp_filter": {"expected": "1", "severity": "medium"},
    "net.ipv4.conf.default.rp_filter": {"expected": "1", "severity": "medium"},
    "net.ipv4.tcp_syncookies": {"expected": "1", "severity": "medium"},
    # Kernel hardening
    "kernel.dmesg_restrict": {"expected": "1", "severity": "low"},
    "kernel.kptr_restrict": {"expected": "2", "severity": "medium"},
    "kernel.yama.ptrace_scope": {"expected": "1", "severity": "medium"},
    "kernel.kexec_load_disabled": {"expected": "1", "severity": "low"},
    # Filesystem security
    "fs.protected_hardlinks": {"expected": "1", "severity": "medium"},
    "fs.protected_symlinks": {"expected": "1", "severity": "medium"},
    "fs.suid_dumpable": {"expected": "0", "severity": "low"},
}


def get_sysctl_value(param):
    """Get current value of a sysctl parameter."""
    result = run_command_sudo(["sysctl", "-n", param])

    if not result:
        return None

    return result.stdout.strip()


def analyze_kernel():
    """Analyze kernel security hardening configuration."""
    params_status = {}
    issues = []

    for param, config in SECURITY_PARAMS.items():
        current_value = get_sysctl_value(param)

        if current_value is None:
            # Parameter not available on this system
            continue

        expected = config["expected"]
        is_secure = current_value == expected

        params_status[param] = {"current": current_value, "expected": expected, "secure": is_secure}

        if not is_secure:
            issues.append(
                {
                    "severity": config["severity"],
                    "message": f"Insecure kernel parameter: {param}={current_value}",
                    "recommendation": f"Set {param}={expected} in /etc/sysctl.conf or /etc/sysctl.d/",
                }
            )

    # Calculate security score
    total_params = len(params_status)
    secure_params = sum(1 for p in params_status.values() if p["secure"])

    hardening_percentage = (secure_params / total_params * 100) if total_params > 0 else 0

    return {
        "total_params_checked": total_params,
        "secure_params": secure_params,
        "hardening_percentage": round(hardening_percentage, 1),
        "parameters": params_status,
        "issues": issues,
    }
