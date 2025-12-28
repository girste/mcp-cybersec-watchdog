#!/usr/bin/env python3
"""MCP Server for security analysis."""

import json
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .audit import run_audit


app = Server("mcp-server-security")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available security audit tools."""
    return [
        Tool(
            name="security_audit",
            description="Run comprehensive cybersecurity audit of the Linux server. "
            "Analyzes: firewall (ufw/iptables/firewalld), SSH configuration, "
            "threat patterns, fail2ban, network services/open ports, Docker security, "
            "security updates, MAC (AppArmor/SELinux), and kernel hardening. "
            "Returns detailed JSON report with security score and actionable recommendations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mask_data": {
                        "type": "boolean",
                        "description": "Mask sensitive data like IPs and hostname (default: true)",
                        "default": True,
                    }
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Execute security audit tool."""
    if name != "security_audit":
        raise ValueError(f"Unknown tool: {name}")

    mask_data = arguments.get("mask_data", True)

    try:
        report = run_audit(mask_data=mask_data)

        return [TextContent(type="text", text=json.dumps(report, indent=2))]

    except Exception as e:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {"error": str(e), "message": "Failed to run security audit"}, indent=2
                ),
            )
        ]


async def main():
    """Run MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def cli_main():
    """CLI entry point for testing."""
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        from .utils.permissions import check_and_warn

        print("Running security audit...")
        check_and_warn()
        report = run_audit(mask_data=True, verbose=True)
        print("\n" + json.dumps(report, indent=2))
    else:
        import asyncio

        asyncio.run(main())


if __name__ == "__main__":
    cli_main()
