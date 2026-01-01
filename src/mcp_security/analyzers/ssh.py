"""SSH configuration analysis module."""

import re
from ..constants import PATH_SSH_CONFIG


def parse_sshd_config(config_path=PATH_SSH_CONFIG):
    """Parse SSH daemon configuration file."""
    config = {
        "port": 22,
        "permit_root_login": "unknown",
        "password_auth": "unknown",
        "pubkey_auth": "unknown",
    }

    try:
        with open(config_path) as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                line_lower = line.lower()

                # Port
                if line_lower.startswith("port "):
                    match = re.search(r"(\d+)", line)
                    if match:
                        config["port"] = int(match.group(1))

                # PermitRootLogin
                elif line_lower.startswith("permitrootlogin"):
                    if "no" in line_lower:
                        config["permit_root_login"] = "no"
                    elif "yes" in line_lower:
                        config["permit_root_login"] = "yes"
                    elif "prohibit-password" in line_lower:
                        config["permit_root_login"] = "prohibit-password"

                # PasswordAuthentication
                elif line_lower.startswith("passwordauthentication"):
                    config["password_auth"] = "no" if "no" in line_lower else "yes"

                # PubkeyAuthentication
                elif line_lower.startswith("pubkeyauthentication"):
                    config["pubkey_auth"] = "yes" if "yes" in line_lower else "no"

    except FileNotFoundError:
        pass

    return config


def analyze_ssh():
    """Analyze SSH configuration and security."""
    config = parse_sshd_config()

    issues = []

    if config["permit_root_login"] == "yes":
        issues.append(
            {
                "severity": "high",
                "message": "Root login is enabled",
                "recommendation": "Set 'PermitRootLogin no' in sshd_config",
            }
        )

    if config["password_auth"] == "yes":
        issues.append(
            {
                "severity": "medium",
                "message": "Password authentication is enabled",
                "recommendation": "Consider disabling password auth and using keys only",
            }
        )

    if config["port"] == 22:
        issues.append(
            {
                "severity": "low",
                "message": "SSH is on default port 22",
                "recommendation": "Consider using a non-standard port to reduce automated attacks",
            }
        )

    return {
        **config,
        "issues": issues,
    }
