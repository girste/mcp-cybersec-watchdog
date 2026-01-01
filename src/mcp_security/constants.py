"""Centralized constants for MCP Security."""

# Command execution timeouts (in seconds)
TIMEOUT_SHORT = 5  # Quick commands (version checks, status)
TIMEOUT_MEDIUM = 10  # Medium commands (docker ps, network scans)
TIMEOUT_LONG = 30  # Long commands (find, docker inspect)
TIMEOUT_VERY_LONG = 120  # Very long commands (trivy scans)

# File paths (Linux standard)
PATH_SSH_CONFIG = "/etc/ssh/sshd_config"
PATH_SUDOERS = "/etc/sudoers"
PATH_GRUB_CONFIGS = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
PATH_AUTH_LOG_DEBIAN = "/var/log/auth.log"
PATH_AUTH_LOG_RHEL = "/var/log/secure"

# Monitoring paths
PATH_LOG_DIR_ROOT = "/var/log/mcp-watchdog"
PATH_BASELINE_DIR_ROOT = "/var/lib/mcp-watchdog"

# Limits
MAX_WORLD_WRITABLE_FILES = 50  # Max files to report
MAX_SUID_FILES = 100  # Max SUID binaries to report
MAX_KERNEL_ISSUES_REPORT = 3  # Top kernel issues to show in recommendations

# System user boundaries
SYSTEM_UID_MAX = 999  # UIDs below this are system accounts
