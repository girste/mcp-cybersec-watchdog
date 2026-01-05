#!/bin/bash
# Setup passwordless sudo for security audit commands

SUDOERS_FILE="/etc/sudoers.d/mcp-security"
USER="${1:-$USER}"

echo "Setting up passwordless sudo for user: $USER"

# Create sudoers file
sudo tee "$SUDOERS_FILE" > /dev/null <<EOF
# MCP Cybersec Watchdog - Passwordless sudo for security audit commands

# Firewall analysis
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status verbose
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n
$USER ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd --state
$USER ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd --list-services

# Fail2ban analysis
$USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status*

# Threat analysis (log reading)
$USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/auth.log
$USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/secure

# Services and ports analysis
$USER ALL=(ALL) NOPASSWD: /usr/bin/ss -tulpn

# Security updates check
$USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get update -qq
$USER ALL=(ALL) NOPASSWD: /usr/bin/apt list --upgradable
$USER ALL=(ALL) NOPASSWD: /usr/bin/yum check-update --security -q

# AppArmor/SELinux status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/apparmor_status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/getenforce

# Kernel security parameters (specific allowed reads only)
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n kernel.dmesg_restrict
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n kernel.kptr_restrict
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n kernel.yama.ptrace_scope
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n kernel.kexec_load_disabled
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n kernel.randomize_va_space
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.conf.all.accept_source_route
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.conf.default.accept_source_route
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.conf.all.send_redirects
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.conf.default.send_redirects
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.icmp_ignore_bogus_error_responses
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.conf.all.rp_filter
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.conf.default.rp_filter
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n net.ipv4.tcp_syncookies
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n fs.protected_hardlinks
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n fs.protected_symlinks
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n fs.suid_dumpable
EOF

# Set correct permissions
sudo chmod 440 "$SUDOERS_FILE"

# Validate sudoers syntax
if sudo visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
    echo "✓ Passwordless sudo configured successfully"
    echo "✓ File: $SUDOERS_FILE"
else
    echo "✗ Error: Invalid sudoers configuration"
    sudo rm -f "$SUDOERS_FILE"
    exit 1
fi

echo ""
echo "You can now run security audits without entering password:"
echo "  python3 test_audit.py"
echo "  mcp-watchdog test"
