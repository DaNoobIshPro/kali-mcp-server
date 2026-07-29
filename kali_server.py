import ipaddress
import logging
import os
import re
import subprocess

from mcp.server.fastmcp import FastMCP


SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_OUTPUT_LENGTH = int(os.getenv("MAX_OUTPUT_LENGTH", "10000"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kali-mcp-server")

mcp = FastMCP("kali-mcp-server")


def _truncate_output(output: str) -> str:
    if len(output) <= MAX_OUTPUT_LENGTH:
        return output
    return f"{output[:MAX_OUTPUT_LENGTH]}\n\n... (output truncated)"


def sanitize_target(target: str) -> tuple[str, str | None]:
    cleaned = target.strip()
    if not cleaned:
        return "", "Target is required"

    if len(cleaned) > 255:
        return "", "Target is too long"

    try:
        if "/" in cleaned:
            ipaddress.ip_network(cleaned, strict=False)
            return cleaned, None
        ipaddress.ip_address(cleaned)
        return cleaned, None
    except ValueError:
        pass

    if cleaned.startswith("-"):
        return "", "Invalid target format"

    if ".." in cleaned:
        return "", "Invalid target format"

    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}[A-Za-z0-9]$", cleaned):
        return "", "Invalid target format"

    return cleaned, None


def run_command(cmd: list[str], timeout: int) -> tuple[str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds.", 124
    except Exception as exc:  # pragma: no cover
        return f"Failed to run command: {exc}", 1

    output = (result.stdout or "").strip()
    error = (result.stderr or "").strip()
    combined = output if not error else f"{output}\n{error}".strip()

    if not combined:
        combined = "No output returned."

    return _truncate_output(combined), result.returncode


@mcp.tool()
async def discover_hosts(target: str) -> str:
    """Discover live hosts on a target IP, hostname, or CIDR range using nmap ping scan."""
    logger.info("discover_hosts called with target=%s", target)

    target_clean, error = sanitize_target(target)
    if error:
        return f"❌ Error: {error}"

    cmd = ["nmap", "-sn", "-T4", "--max-retries", "2", target_clean]
    output, returncode = run_command(cmd, timeout=min(SCAN_TIMEOUT, 120))

    live_hosts = re.findall(r"^Nmap scan report for (.+)$", output, flags=re.MULTILINE)

    if returncode != 0 and not live_hosts:
        return f"❌ Host discovery failed.\n\n{output}"

    if not live_hosts:
        return f"✅ Host discovery completed for {target_clean}.\n\nNo live hosts were found.\n\nRaw output:\n{output}"

    host_lines = "\n".join(f"- {host}" for host in live_hosts)
    return (
        f"✅ Host discovery completed for {target_clean}.\n\n"
        f"Live hosts found ({len(live_hosts)}):\n{host_lines}\n\n"
        f"Raw output:\n{output}"
    )


@mcp.tool()
async def host_details(target: str, ports: str = "top-100") -> str:
    """Get open ports and service details for a host using nmap service and default script scan."""
    logger.info("host_details called with target=%s ports=%s", target, ports)

    target_clean, error = sanitize_target(target)
    if error:
        return f"❌ Error: {error}"

    cmd = ["nmap", "-sV", "-sC", "-T4", "--open"]
    ports_clean = ports.strip().lower()

    if ports_clean == "top-100":
        cmd.extend(["--top-ports", "100"])
    elif ports_clean == "all":
        cmd.append("-p-")
    elif re.match(r"^[0-9,\-]+$", ports_clean):
        cmd.extend(["-p", ports_clean])
    else:
        return "❌ Error: ports must be 'top-100', 'all', or a port list/range like '22,80,443' or '1-1024'"

    cmd.append(target_clean)
    output, returncode = run_command(cmd, timeout=SCAN_TIMEOUT)

    if returncode != 0:
        return f"❌ Host detail scan failed for {target_clean}.\n\n{output}"

    return f"✅ Host details for {target_clean}:\n\n{output}"


if __name__ == "__main__":
    mcp.run()
