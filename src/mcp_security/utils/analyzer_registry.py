"""Centralized analyzer registry and management."""

from typing import List, Dict, Any
from ..analyzers.firewall import analyze_firewall
from ..analyzers.ssh import analyze_ssh
from ..analyzers.threats import analyze_threats
from ..analyzers.fail2ban import analyze_fail2ban
from ..analyzers.services import analyze_services
from ..analyzers.docker_sec import analyze_docker
from ..analyzers.updates import analyze_updates
from ..analyzers.mac import analyze_mac
from ..analyzers.kernel import analyze_kernel
from ..analyzers.ssl import analyze_ssl
from ..analyzers.disk import analyze_disk
from ..analyzers.cve import analyze_cve
from ..analyzers.cis import analyze_cis
from ..analyzers.containers import analyze_containers
from ..analyzers.nist import analyze_nist
from ..analyzers.pci import analyze_pci
from ..analyzers.webheaders import analyze_webheaders
from ..analyzers.filesystem import analyze_filesystem
from ..analyzers.network import analyze_network
from ..analyzers.users import analyze_users
from ..analyzers.rootkit import analyze_rootkit
from ..analyzers.sudoers import analyze_sudoers
from ..analyzers.system_hardening import analyze_system_hardening
from ..analyzers.base import AnalyzerMetadata
from .detect import get_auth_log_path


def get_all_analyzers(config: Dict[str, Any]) -> List[AnalyzerMetadata]:
    """
    Get list of all available analyzers with metadata.

    This is the central registry for all security analyzers.
    Add new analyzers here to include them in the audit.

    Args:
        config: Configuration dict with 'checks' and other settings

    Returns:
        List of AnalyzerMetadata objects
    """
    auth_log_path = get_auth_log_path()
    threat_days = config.get("threat_analysis_days", 7)
    checks = config.get("checks", {})

    # Define all analyzers with their metadata
    # Pattern: AnalyzerMetadata(name, func, enabled_by_default, requires_sudo, kwargs)
    analyzers = [
        AnalyzerMetadata("firewall", analyze_firewall, True, True, {}),
        AnalyzerMetadata("ssh", analyze_ssh, True, False, {}),
        AnalyzerMetadata(
            "threats",
            analyze_threats,
            True,
            True,
            {"log_path": auth_log_path, "days": threat_days},
        ),
        AnalyzerMetadata("fail2ban", analyze_fail2ban, True, True, {}),
        AnalyzerMetadata("services", analyze_services, True, True, {}),
        AnalyzerMetadata("docker", analyze_docker, True, False, {}),
        AnalyzerMetadata("updates", analyze_updates, True, True, {}),
        AnalyzerMetadata("mac", analyze_mac, True, True, {}),
        AnalyzerMetadata("kernel", analyze_kernel, True, False, {}),
        AnalyzerMetadata("ssl", analyze_ssl, True, False, {}),
        AnalyzerMetadata("disk", analyze_disk, True, False, {}),
        AnalyzerMetadata("cve", analyze_cve, True, False, {}),
        AnalyzerMetadata("cis", analyze_cis, True, True, {}),
        AnalyzerMetadata("containers", analyze_containers, True, False, {}),
        AnalyzerMetadata("nist", analyze_nist, True, True, {}),
        AnalyzerMetadata("pci", analyze_pci, True, True, {}),
        AnalyzerMetadata("webheaders", analyze_webheaders, True, False, {}),
        AnalyzerMetadata("filesystem", analyze_filesystem, True, True, {}),
        AnalyzerMetadata("network", analyze_network, True, True, {}),
        AnalyzerMetadata("users", analyze_users, True, True, {}),
        AnalyzerMetadata("rootkit", analyze_rootkit, True, True, {}),
        AnalyzerMetadata("sudoers", analyze_sudoers, True, True, {}),
        AnalyzerMetadata("system_hardening", analyze_system_hardening, True, True, {}),
    ]

    # Filter by config
    enabled_analyzers = []
    for analyzer in analyzers:
        # Check if enabled in config (default to analyzer's enabled_by_default)
        is_enabled = checks.get(analyzer.name, analyzer.enabled_by_default)
        if is_enabled:
            enabled_analyzers.append(analyzer)

    return enabled_analyzers


def get_analyzer_by_name(name: str, config: Dict[str, Any]) -> AnalyzerMetadata:
    """
    Get specific analyzer by name.

    Args:
        name: Analyzer name
        config: Configuration dict

    Returns:
        AnalyzerMetadata or None if not found
    """
    analyzers = get_all_analyzers(config)
    for analyzer in analyzers:
        if analyzer.name == name:
            return analyzer
    return None
