"""Configuration loading."""

import json
from pathlib import Path


DEFAULT_CONFIG = {
    "checks": {
        "firewall": True,
        "ssh": True,
        "threats": True,
        "fail2ban": True,
        "services": True,
        "docker": True,
        "updates": True,
        "mac": True,
        "kernel": True,
    },
    "threat_analysis_days": 7,
    "mask_data": True,
}


def load_config():
    """Load config from .mcp-security.json if exists, otherwise use defaults."""
    config_locations = [
        Path.cwd() / ".mcp-security.json",
        Path.home() / ".mcp-security.json",
    ]

    for config_file in config_locations:
        if config_file.exists():
            try:
                with open(config_file) as f:
                    user_config = json.load(f)
                    config = DEFAULT_CONFIG.copy()
                    config.update(user_config)
                    return config
            except (json.JSONDecodeError, IOError):
                pass

    return DEFAULT_CONFIG.copy()
