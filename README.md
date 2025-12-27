# 🐕 MCP Cybersec Watchdog

> Cybersecurity monitoring and analysis for Linux servers via MCP

Comprehensive security audit tool that analyzes firewall configuration, SSH hardening, threat patterns, and fail2ban status. Returns a structured security report with actionable recommendations.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Why?

Security audits are tedious. This tool gives you:
- **Complete security report in 30 seconds**
- **Factual analysis** - no subjective scoring, just data
- **AI-friendly JSON output** for integration with LLMs
- **Privacy-first** approach (data masking by default)
- **Actionable recommendations** with specific commands
- **Zero configuration** - works out of the box

## Features

✅ **Firewall Analysis** - Detects and analyzes ufw, iptables, or firewalld
✅ **SSH Hardening Check** - Validates sshd_config security settings
✅ **Threat Intelligence** - Analyzes failed login attempts and patterns
✅ **Fail2ban Integration** - Reports jail status and banned IPs
✅ **Privacy Masking** - Automatically masks sensitive data
✅ **Cross-distro** - Works on Debian, Ubuntu, RHEL, CentOS

## Quick Start

### Installation

```bash
pip install mcp-cybersec-watchdog

# Setup passwordless sudo (one-time, required for full analysis)
bash <(curl -s https://raw.githubusercontent.com/girste/mcp-cybersec-watchdog/main/setup-sudo.sh)
```

Or manual install:
```bash
git clone https://github.com/girste/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog
pip install -e .
./setup-sudo.sh
```

### Standalone Usage

```bash
# Run security audit (automatic sudo for privileged commands)
mcp-watchdog test
```

### MCP Integration

Add to your MCP settings:

```json
{
  "mcpServers": {
    "cybersec-watchdog": {
      "command": "mcp-watchdog",
      "env": {}
    }
  }
}
```

Then use from your AI assistant:

```
Run a security audit on this server
```

## Example Output

```json
{
  "timestamp": "2025-12-27T13:20:39Z",
  "hostname": "srv-pr**",
  "os": "Linux (debian)",
  "kernel": "6.8.0-87-generic",
  "firewall": {
    "type": "ufw",
    "active": true,
    "default_policy": "deny",
    "rules_count": 8,
    "open_ports": [80, 443, 2244]
  },
  "ssh": {
    "port": 2244,
    "permit_root_login": "no",
    "password_auth": "no",
    "pubkey_auth": "yes",
    "issues": []
  },
  "threats": {
    "period_days": 7,
    "total_attempts": 342,
    "unique_ips": 89,
    "top_attackers": [
      {"ip": "45.142.***.***", "attempts": 67}
    ],
    "patterns": ["ssh_brute_force"]
  },
  "fail2ban": {
    "installed": true,
    "active": true,
    "total_banned": 12
  },
  "recommendations": []
}
```

## Privacy

By default, the tool **masks sensitive data**:
- IP addresses: `91.99.***.***`
- Hostnames: `srv-ab**`

To get full unmasked data:

```python
# When calling via MCP
{"mask_data": false}
```

## Requirements

- Python 3.10+
- Linux (Debian/Ubuntu/RHEL/CentOS)
- sudo access (passwordless sudo for automated operation)

### Sudo Configuration

The tool needs sudo access for:
- **Firewall analysis**: `ufw`, `iptables`, `firewalld`
- **Fail2ban status**: `fail2ban-client`
- **Log analysis**: `/var/log/auth.log`

Run the setup script to configure passwordless sudo for these specific commands:

```bash
./setup-sudo.sh
```

This creates `/etc/sudoers.d/mcp-security` with minimal permissions for security audit commands only.

## What Gets Analyzed

### Firewall
- Active status
- Default policy (allow/deny)
- Number of rules
- Open ports

### SSH Configuration
- Port number
- Root login status
- Password authentication
- Pubkey authentication

### Threats
- Failed SSH login attempts (7 days)
- Unique attacker IPs
- Attack patterns (brute force, distributed)
- Top 10 attackers

### Fail2ban
- Installation status
- Active jails
- Banned IPs count

## Development

```bash
# Clone repo
git clone https://github.com/girste/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog

# Install in dev mode
pip install -e .

# Run tests
pytest

# Run standalone test
python3 test_audit.py
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes (keep code clean and concise)
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details

## Roadmap

- [ ] CVE scanning for installed packages
- [ ] SSL certificate expiration checks
- [ ] Docker container security analysis
- [ ] Continuous monitoring mode
- [ ] HTML/PDF report export
- [ ] CIS benchmark compliance checks

## Author

Created by [Girste](https://girste.com)

## Support

- 🐛 [Report bugs](https://github.com/girste/mcp-cybersec-watchdog/issues)
- 💡 [Request features](https://github.com/girste/mcp-cybersec-watchdog/issues)
- ⭐ Star this repo if you find it useful!
