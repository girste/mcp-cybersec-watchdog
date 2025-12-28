"""Network services and open ports analysis."""

import re
from ..utils.detect import run_with_sudo


def parse_listening_ports():
    """Parse listening ports and services using ss command."""
    result = run_with_sudo(["ss", "-tulpn"])

    if not result:
        return []

    services = []

    for line in result.stdout.split("\n"):
        # Skip header and empty lines
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue

        # Parse ss output: protocol state recv-q send-q local_address:port peer_address:port process
        parts = line.split()
        if len(parts) < 5:
            continue

        protocol = parts[0]  # tcp or udp
        local_addr = parts[4]  # address:port

        # Extract port
        port_match = re.search(r":(\d+)$", local_addr)
        if not port_match:
            continue

        port = int(port_match.group(1))

        # Extract bind address
        addr = local_addr.rsplit(":", 1)[0]
        # Handle IPv6 addresses in brackets
        addr = addr.strip("[]")
        # Remove interface suffix (e.g., %lo, %eth0)
        base_addr = addr.split("%")[0]

        # Determine if exposed to external network
        is_external = base_addr not in ("127.0.0.1", "::1", "127.0.0.53", "127.0.0.54", "localhost")

        # Extract process info if available
        process = None
        if len(parts) >= 7:
            process_info = parts[6]
            # Extract process name from users:(("name",pid=123,fd=4))
            proc_match = re.search(r'\(\("([^"]+)"', process_info)
            if proc_match:
                process = proc_match.group(1)

        services.append(
            {
                "port": port,
                "protocol": protocol,
                "address": addr,
                "exposed": is_external,
                "process": process,
            }
        )

    return services


def categorize_services(services):
    """Categorize services by risk level."""
    # Well-known safe services
    safe_services = {
        22: "ssh",
        2244: "ssh-custom",
        80: "http",
        443: "https",
    }

    # Potentially risky services
    risky_ports = {
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
        9200: "elasticsearch",
    }

    categorized = {"safe": [], "risky": [], "unknown": []}

    for service in services:
        port = service["port"]

        if port in safe_services:
            categorized["safe"].append({**service, "name": safe_services[port]})
        elif port in risky_ports:
            categorized["risky"].append({**service, "name": risky_ports[port]})
        else:
            categorized["unknown"].append({**service, "name": "unknown"})

    return categorized


def analyze_services():
    """Analyze network services and open ports."""
    services = parse_listening_ports()

    if not services:
        return {
            "total_services": 0,
            "exposed_services": 0,
            "internal_only": 0,
            "by_category": {"safe": [], "risky": [], "unknown": []},
            "issues": [],
        }

    # Categorize services
    categorized = categorize_services(services)

    # Count exposed services
    exposed_count = sum(1 for s in services if s["exposed"])
    internal_count = len(services) - exposed_count

    # Identify security issues
    issues = []

    # Check for exposed risky services
    for service in categorized["risky"]:
        if service["exposed"]:
            issues.append(
                {
                    "severity": "high",
                    "message": f"Database service {service['name']} exposed on port {service['port']}",
                    "recommendation": f"Bind {service['name']} to localhost only or use firewall to restrict access",
                }
            )

    # Check for unknown exposed services
    exposed_unknown = [s for s in categorized["unknown"] if s["exposed"]]
    if len(exposed_unknown) > 3:
        issues.append(
            {
                "severity": "medium",
                "message": f"{len(exposed_unknown)} unknown services exposed to network",
                "recommendation": "Review and identify all exposed services, close unnecessary ports",
            }
        )

    return {
        "total_services": len(services),
        "exposed_services": exposed_count,
        "internal_only": internal_count,
        "by_category": categorized,
        "issues": issues,
    }
