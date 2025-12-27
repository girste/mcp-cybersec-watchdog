"""Docker security analysis."""

import json
import subprocess


def check_docker_installed():
    """Check if Docker is installed and accessible."""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_running_containers():
    """Get list of running Docker containers."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return []

        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    container = json.loads(line)
                    containers.append({
                        "name": container.get("Names", "unknown"),
                        "image": container.get("Image", "unknown"),
                        "status": container.get("Status", "unknown"),
                    })
                except json.JSONDecodeError:
                    continue

        return containers

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def check_docker_rootless():
    """Check if Docker is running in rootless mode."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.SecurityOptions}}"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            return "rootless" in result.stdout.lower()

        return False

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_privileged_containers():
    """Check for containers running in privileged mode."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return []

        container_ids = result.stdout.strip().split('\n')
        privileged_containers = []

        for container_id in container_ids:
            if not container_id:
                continue

            inspect_result = subprocess.run(
                ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", container_id],
                capture_output=True,
                text=True,
                timeout=5
            )

            if inspect_result.returncode == 0 and inspect_result.stdout.strip() == "true":
                # Get container name
                name_result = subprocess.run(
                    ["docker", "inspect", "--format", "{{.Name}}", container_id],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                name = name_result.stdout.strip().lstrip('/') if name_result.returncode == 0 else container_id
                privileged_containers.append(name)

        return privileged_containers

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def analyze_docker():
    """Analyze Docker security configuration."""
    if not check_docker_installed():
        return {
            "installed": False,
            "running_containers": 0,
            "containers": [],
            "rootless": False,
            "privileged_containers": [],
            "issues": []
        }

    containers = get_running_containers()
    rootless = check_docker_rootless()
    privileged = check_privileged_containers()

    issues = []

    # Check for privileged containers
    if privileged:
        issues.append({
            "severity": "high",
            "message": f"{len(privileged)} container(s) running in privileged mode",
            "recommendation": "Avoid privileged mode unless absolutely necessary. Use capabilities instead."
        })

    # Check if running as root
    if not rootless and containers:
        issues.append({
            "severity": "medium",
            "message": "Docker running as root (not rootless)",
            "recommendation": "Consider using Docker rootless mode for better security isolation"
        })

    # Check for high number of containers
    if len(containers) > 20:
        issues.append({
            "severity": "low",
            "message": f"{len(containers)} containers running",
            "recommendation": "Review and stop unnecessary containers to reduce attack surface"
        })

    return {
        "installed": True,
        "running_containers": len(containers),
        "containers": containers,
        "rootless": rootless,
        "privileged_containers": privileged,
        "issues": issues
    }
