#!/bin/bash
# Setup passwordless sudo for security audit commands

SUDOERS_FILE="/etc/sudoers.d/mcp-security"
USER="${1:-$USER}"

echo "Setting up passwordless sudo for user: $USER"

# Create sudoers file
sudo tee "$SUDOERS_FILE" > /dev/null <<EOF
# MCP Security - Passwordless sudo for security audit commands
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status verbose
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n
$USER ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd --state
$USER ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd --list-services
$USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status*
$USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/auth.log
$USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/secure
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
