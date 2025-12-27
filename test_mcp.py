#!/usr/bin/env python3
"""Test MCP server with JSON-RPC protocol."""

import json
import subprocess
import sys


def send_jsonrpc_request(process, method, params=None, request_id=1):
    """Send JSON-RPC request to MCP server."""
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
    }
    if params:
        request["params"] = params

    request_json = json.dumps(request) + "\n"
    process.stdin.write(request_json)
    process.stdin.flush()

    # Read response
    response_line = process.stdout.readline()
    if not response_line:
        return None

    return json.loads(response_line)


def test_mcp_server():
    """Test MCP server end-to-end."""
    print("🐕 Testing MCP Cybersec Watchdog Server\n")

    # Start MCP server
    print("1. Starting MCP server...")
    process = subprocess.Popen(
        [sys.executable, "-m", "mcp_security.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    try:
        # Test 1: Initialize
        print("2. Initializing MCP connection...")
        response = send_jsonrpc_request(
            process,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        )

        if not response or "error" in response:
            print(f"✗ Initialize failed: {response}")
            return False

        print(f"✓ Server initialized: {response.get('result', {}).get('serverInfo', {}).get('name')}")

        # Test 2: List tools
        print("\n3. Listing available tools...")
        response = send_jsonrpc_request(process, "tools/list", {}, request_id=2)

        if not response or "error" in response:
            print(f"✗ List tools failed: {response}")
            return False

        tools = response.get("result", {}).get("tools", [])
        print(f"✓ Found {len(tools)} tool(s):")
        for tool in tools:
            print(f"  - {tool['name']}: {tool['description'][:80]}...")

        # Test 3: Call security_audit tool
        print("\n4. Running security_audit tool...")
        response = send_jsonrpc_request(
            process,
            "tools/call",
            {
                "name": "security_audit",
                "arguments": {"mask_data": True}
            },
            request_id=3
        )

        if not response or "error" in response:
            print(f"✗ Tool call failed: {response}")
            return False

        result = response.get("result", {})
        content = result.get("content", [])

        if not content:
            print("✗ No content in response")
            return False

        # Parse audit report
        audit_data = json.loads(content[0]["text"])

        print("✓ Security audit completed!")
        print(f"\n📊 Audit Results:")
        print(f"  Hostname: {audit_data.get('hostname')}")
        print(f"  OS: {audit_data.get('os')}")
        print(f"  Firewall: {audit_data.get('firewall', {}).get('type')} - {'Active' if audit_data.get('firewall', {}).get('active') else 'Inactive'}")
        print(f"  SSH Port: {audit_data.get('ssh', {}).get('port')}")
        print(f"  Services: {audit_data.get('services', {}).get('total_services')} ({audit_data.get('services', {}).get('exposed_services')} exposed)")
        print(f"  Docker: {audit_data.get('docker', {}).get('running_containers')} containers")
        print(f"  Updates: {audit_data.get('updates', {}).get('security_updates')} security updates")
        print(f"  MAC: {audit_data.get('mac', {}).get('type')} - {'Enabled' if audit_data.get('mac', {}).get('enabled') else 'Disabled'}")
        print(f"  Kernel Hardening: {audit_data.get('kernel_hardening', {}).get('hardening_percentage')}%")
        print(f"  Recommendations: {len(audit_data.get('recommendations', []))}")

        print("\n✅ ALL MCP TESTS PASSED")
        return True

    except Exception as e:
        print(f"\n✗ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Cleanup
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    sys.path.insert(0, "src")
    success = test_mcp_server()
    sys.exit(0 if success else 1)
