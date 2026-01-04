"""Fail2ban analysis module."""

import re
from ..utils.command import run_command_sudo


def get_fail2ban_status():
    """Get fail2ban overall status."""
    result = run_command_sudo(["fail2ban-client", "status"])

    if result and result.success:

        # Extract jail list
        jails = []
        jail_match = re.search(r"Jail list:\s+(.*)", result.stdout)
        if jail_match:
            jails = [j.strip() for j in jail_match.group(1).split(",")]

        return {
            "active": True,
            "jails": jails,
        }

    return None


def get_jail_status(jail_name):
    """Get status for specific fail2ban jail."""
    result = run_command_sudo(["fail2ban-client", "status", jail_name])

    if result and result.success:

        output = result.stdout

        # Extract banned IPs count
        banned_match = re.search(r"Currently banned:\s*(\d+)", output)
        banned_count = int(banned_match.group(1)) if banned_match else 0

        return {
            "name": jail_name,
            "banned_count": banned_count,
        }

    return None


def analyze_fail2ban():
    """Analyze fail2ban configuration and status."""
    status = get_fail2ban_status()

    if not status:
        return {
            "installed": False,
            "active": False,
            "jails": [],
            "total_banned": 0,
        }

    total_banned = 0
    jail_details = []

    for jail in status["jails"]:
        jail_status = get_jail_status(jail)
        if jail_status:
            total_banned += jail_status["banned_count"]
            jail_details.append(jail_status)

    return {
        "installed": True,
        "active": status["active"],
        "jails": jail_details,
        "total_banned": total_banned,
    }
