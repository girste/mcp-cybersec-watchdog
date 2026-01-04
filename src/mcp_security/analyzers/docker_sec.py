"""Docker security analysis."""

import json
from ..utils.command import run_command


def check_docker_installed():
    """Check if Docker is installed and accessible."""
    result = run_command(["docker", "--version"], timeout=5)
    return result and result.success


def get_running_containers():
    """Get list of running Docker containers."""
    result = run_command(["docker", "ps", "--format", "{{json .}}"], timeout=10)

    if not result or not result.success:
        return []

    containers = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                container = json.loads(line)
                containers.append(
                    {
                        "name": container.get("Names", "unknown"),
                        "image": container.get("Image", "unknown"),
                        "status": container.get("Status", "unknown"),
                    }
                )
            except json.JSONDecodeError:
                continue

    return containers


def check_docker_rootless():
    """Check if Docker is running in rootless mode."""
    result = run_command(["docker", "info", "--format", "{{.SecurityOptions}}"], timeout=5)

    if result and result.success:
        return "rootless" in result.stdout.lower()

    return False


def check_privileged_containers():
    """Check for containers running in privileged mode."""
    result = run_command(["docker", "ps", "-q"], timeout=5)

    if not result or not result.success:
        return []

    container_ids = result.stdout.strip().split("\n")
    privileged_containers = []

    for container_id in container_ids:
        if not container_id:
            continue

        inspect_result = run_command(
            ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", container_id],
            timeout=5,
        )

        if inspect_result and inspect_result.success and inspect_result.stdout.strip() == "true":
            # Get container name
            name_result = run_command(
                ["docker", "inspect", "--format", "{{.Name}}", container_id],
                timeout=5,
            )
            name = (
                name_result.stdout.strip().lstrip("/")
                if name_result and name_result.success
                else container_id
            )
            privileged_containers.append(name)

    return privileged_containers


def analyze_docker():
    """Analyze Docker security configuration."""
    if not check_docker_installed():
        return {
            "installed": False,
            "running_containers": 0,
            "containers": [],
            "rootless": False,
            "privileged_containers": [],
            "issues": [],
        }

    containers = get_running_containers()
    rootless = check_docker_rootless()
    privileged = check_privileged_containers()

    issues = []

    # Check for privileged containers
    if privileged:
        issues.append(
            {
                "severity": "high",
                "message": f"{len(privileged)} container(s) running in privileged mode",
                "recommendation": "Avoid privileged mode unless absolutely necessary. Use capabilities instead.",
            }
        )

    # Check if running as root
    if not rootless and containers:
        issues.append(
            {
                "severity": "medium",
                "message": "Docker running as root (not rootless)",
                "recommendation": "Consider using Docker rootless mode for better security isolation",
            }
        )

    # Check for high number of containers
    if len(containers) > 20:
        issues.append(
            {
                "severity": "low",
                "message": f"{len(containers)} containers running",
                "recommendation": "Review and stop unnecessary containers to reduce attack surface",
            }
        )

    return {
        "installed": True,
        "running_containers": len(containers),
        "containers": containers,
        "rootless": rootless,
        "privileged_containers": privileged,
        "issues": issues,
    }
