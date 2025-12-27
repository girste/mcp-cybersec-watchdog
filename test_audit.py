#!/usr/bin/env python3
"""Standalone test script for security audit."""

import json
import sys
sys.path.insert(0, 'src')

from mcp_security.audit import run_audit

if __name__ == "__main__":
    print("Running security audit...")
    print()

    try:
        report = run_audit(mask_data=True)
        print(json.dumps(report, indent=2))
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
