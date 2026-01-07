# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **me@girste.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response time:** We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Security Considerations

This tool requires **passwordless sudo** for certain commands. The provided `setup-sudo.sh` script grants ONLY read-only access to security-related information:

- Firewall status (`ufw`, `iptables`)
- Log file reading (`/var/log/auth.log`, `/var/log/secure`)
- System information (`ss`, `systemctl`, `docker`)

**NO write access** is granted. Review the sudoers configuration in `/etc/sudoers.d/mcp-security` before installation.

## Secure Usage

1. **Review sudo permissions** before running setup script
2. **Enable data masking** (default) when sharing audit reports
3. **Use monitoring daemon** with appropriate intervals to avoid resource exhaustion
4. **Keep the tool updated** to get latest security checks

## Known Limitations

- Basic CVE scanning (install `trivy` for comprehensive scanning)
- Monitoring daemon stores logs locally (consider log rotation)
- Requires Linux (Ubuntu, Debian, RHEL, CentOS, Fedora)
