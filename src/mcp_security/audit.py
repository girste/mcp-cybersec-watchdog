"""Main security audit orchestrator."""

from datetime import datetime

from .analyzers.firewall import analyze_firewall
from .analyzers.ssh import analyze_ssh
from .analyzers.threats import analyze_threats
from .analyzers.fail2ban import analyze_fail2ban
from .analyzers.services import analyze_services
from .analyzers.docker_sec import analyze_docker
from .analyzers.updates import analyze_updates
from .analyzers.mac import analyze_mac
from .analyzers.kernel import analyze_kernel
from .utils.detect import get_os_info, get_auth_log_path
from .utils.privacy import mask_ip, get_masked_hostname


def run_audit(mask_data=True):
    """Run complete security audit and return structured report."""

    # System info
    os_info = get_os_info()
    hostname = get_masked_hostname() if mask_data else os_info.get("hostname", "unknown")

    # Firewall analysis
    firewall = analyze_firewall()

    # SSH analysis
    ssh = analyze_ssh()

    # Threat analysis
    log_path = get_auth_log_path()
    threats = analyze_threats(log_path, days=7)

    # Mask IPs if privacy enabled
    if mask_data and threats["top_attackers"]:
        for attacker in threats["top_attackers"]:
            attacker["ip"] = mask_ip(attacker["ip"])

    # Fail2ban analysis
    fail2ban = analyze_fail2ban()

    # Services and open ports analysis
    services = analyze_services()

    # Docker security analysis
    docker = analyze_docker()

    # Security updates check
    updates = analyze_updates()

    # Mandatory Access Control (AppArmor/SELinux)
    mac = analyze_mac()

    # Kernel hardening
    kernel = analyze_kernel()

    # Generate recommendations
    recommendations = generate_recommendations(
        firewall, ssh, fail2ban, threats, services, docker, updates, mac, kernel
    )

    # Build report
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hostname": hostname,
        "os": f"{os_info['system']} ({os_info['distro']})",
        "kernel": os_info["kernel"],
        "firewall": firewall,
        "ssh": ssh,
        "threats": threats,
        "fail2ban": fail2ban,
        "services": services,
        "docker": docker,
        "updates": updates,
        "mac": mac,
        "kernel_hardening": kernel,
        "recommendations": recommendations,
    }

    return report


def generate_recommendations(firewall, ssh, fail2ban, threats, services, docker, updates, mac, kernel):
    """Generate prioritized security recommendations."""
    recommendations = []

    # Firewall recommendations
    if not firewall["active"]:
        recommendations.append({
            "priority": "critical",
            "title": "Enable firewall",
            "description": "No active firewall detected. Install and enable ufw or firewalld.",
            "command": "sudo ufw enable"
        })
    elif firewall["default_policy"] != "deny":
        recommendations.append({
            "priority": "high",
            "title": "Set restrictive firewall policy",
            "description": "Default policy should deny incoming connections.",
            "command": "sudo ufw default deny incoming"
        })

    # SSH recommendations
    for issue in ssh.get("issues", []):
        priority = issue["severity"]
        recommendations.append({
            "priority": priority,
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Fail2ban recommendations
    if not fail2ban["installed"] and threats["total_attempts"] > 50:
        recommendations.append({
            "priority": "medium",
            "title": "Install fail2ban",
            "description": f"Detected {threats['total_attempts']} failed login attempts. Fail2ban can auto-ban attackers.",
            "command": "sudo apt install fail2ban"
        })

    # Threat-based recommendations
    if threats["total_attempts"] > 1000:
        recommendations.append({
            "priority": "medium",
            "title": "High number of attack attempts",
            "description": f"{threats['total_attempts']} failed logins in {threats['period_days']} days. Consider stricter policies.",
            "command": None
        })

    # Services recommendations
    for issue in services.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Docker recommendations
    for issue in docker.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Updates recommendations
    for issue in updates.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # MAC (AppArmor/SELinux) recommendations
    for issue in mac.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Kernel hardening recommendations (limit to top 3 most severe)
    kernel_issues = sorted(kernel.get("issues", []), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))
    for issue in kernel_issues[:3]:
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    return recommendations
