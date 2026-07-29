import logging
import os
import re
import subprocess
from typing import Tuple

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("kali-pentest-server")
logger = logging.getLogger("kali-mcp-server")
logging.basicConfig(level=logging.INFO)

SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_OUTPUT_LENGTH = int(os.getenv("MAX_OUTPUT_LENGTH", "10000"))


def _truncate_output(output: str) -> str:
    if len(output) <= MAX_OUTPUT_LENGTH:
        return output
    return f"{output[:MAX_OUTPUT_LENGTH]}\n\n[output truncated to {MAX_OUTPUT_LENGTH} characters]"


def sanitize_target(target: str) -> Tuple[str, str | None]:
    cleaned = target.strip()
    if not cleaned:
        return "", "target cannot be empty"
    if len(cleaned) > 255:
        return "", "target is too long"
    if not re.match(r"^[a-zA-Z0-9\.:/_\-]+$", cleaned):
        return "", "target contains invalid characters"
    return cleaned, None


def run_command(cmd: list[str], timeout: int | None = None) -> Tuple[str, int]:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout or SCAN_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "❌ Command timed out", 124
    except Exception as exc:  # defensive fallback
        return f"❌ Command failed: {exc}", 1

    output = (completed.stdout or "") + (completed.stderr or "")
    output = output.strip() or "(no output)"
    return _truncate_output(output), completed.returncode


@mcp.tool()
async def server_info() -> str:
    """Return server status, configured limits, and optional API key state."""
    wpscan_state = "configured" if os.getenv("WPSCAN_API_TOKEN") else "not configured"
    return (
        "🛡️ Kali MCP Server\n\n"
        f"- Scan timeout: {SCAN_TIMEOUT}s\n"
        f"- Max output length: {MAX_OUTPUT_LENGTH}\n"
        f"- WPScan API token: {wpscan_state}\n\n"
        "Available tools: server_info, ettercap_scan_hosts, ettercap_arp_poison, "
        "ettercap_dns_spoof, ettercap_packet_sniff"
    )


@mcp.tool()
async def ettercap_scan_hosts(interface: str = "eth0", target: str = "") -> str:
    """Scan network for active hosts using ettercap with optional target range."""
    logger.info("ettercap_scan_hosts called with interface=%s target=%s", interface, target)

    if not interface.strip():
        return "❌ Error: Network interface is required"
    if not re.match(r"^[a-zA-Z0-9]+$", interface):
        return "❌ Error: Invalid interface name format"

    cmd = ["ettercap", "-T", "-i", interface]

    if target.strip():
        cleaned_target, error = sanitize_target(target)
        if error:
            return f"❌ Error: {error}"
        cmd.extend(["-M", "arp:remote", f"/{cleaned_target}/"])
    else:
        cmd.extend(["-P", "list"])

    output, returncode = run_command(cmd, timeout=120)
    status = "✅ Success" if returncode == 0 else f"⚠️ Exit code: {returncode}"
    return (
        f"🌐 Ettercap host scan on {interface}\n"
        f"{status}\n\n"
        f"📊 Results:\n{output}\n\n"
        "💡 Note: Use ettercap_arp_poison for MITM testing (authorized environments only)."
    )


@mcp.tool()
async def ettercap_arp_poison(interface: str = "eth0", target1: str = "", target2: str = "") -> str:
    """Prepare ARP poisoning command. Not executed automatically for safety."""
    logger.info("ettercap_arp_poison called with interface=%s", interface)

    if not interface.strip():
        return "❌ Error: Network interface is required"
    if not target1.strip() or not target2.strip():
        return "❌ Error: Both target1 and target2 are required"
    if not re.match(r"^[a-zA-Z0-9]+$", interface):
        return "❌ Error: Invalid interface name format"

    target1_clean, error1 = sanitize_target(target1)
    if error1:
        return f"❌ Error in target1: {error1}"
    target2_clean, error2 = sanitize_target(target2)
    if error2:
        return f"❌ Error in target2: {error2}"

    cmd = [
        "ettercap",
        "-T",
        "-q",
        "-i",
        interface,
        "-M",
        "arp:remote",
        f"/{target1_clean}//",
        f"/{target2_clean}//",
    ]

    return (
        "⚠️ ARP poisoning is intentionally not auto-executed.\n\n"
        "Run manually only with written authorization:\n"
        f"{' '.join(cmd)}"
    )


@mcp.tool()
async def ettercap_dns_spoof(interface: str = "eth0", target: str = "", domain: str = "", fake_ip: str = "") -> str:
    """Prepare DNS spoofing command steps. Not executed automatically for safety."""
    logger.info("ettercap_dns_spoof called with interface=%s target=%s domain=%s", interface, target, domain)

    if not all([interface.strip(), target.strip(), domain.strip(), fake_ip.strip()]):
        return "❌ Error: interface, target, domain, and fake_ip are required"
    if not re.match(r"^[a-zA-Z0-9]+$", interface):
        return "❌ Error: Invalid interface name"

    target_clean, target_error = sanitize_target(target)
    if target_error:
        return f"❌ Error in target: {target_error}"
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", domain):
        return "❌ Error: Invalid domain format"

    fake_ip_clean, fake_ip_error = sanitize_target(fake_ip)
    if fake_ip_error:
        return f"❌ Error in fake_ip: {fake_ip_error}"

    return (
        "⚠️ DNS spoofing is intentionally not auto-executed.\n\n"
        "Manual steps:\n"
        f"1. echo \"{domain} A {fake_ip_clean}\" > /tmp/etter.dns\n"
        f"2. ettercap -T -i {interface} -M arp:remote /{target_clean}// -P dns_spoof"
    )


@mcp.tool()
async def ettercap_packet_sniff(interface: str = "eth0", filter_type: str = "tcp", duration: str = "30") -> str:
    """Prepare packet sniffing command details. Not executed automatically for safety."""
    logger.info("ettercap_packet_sniff called with interface=%s filter_type=%s", interface, filter_type)

    if not interface.strip():
        return "❌ Error: Network interface is required"
    if not re.match(r"^[a-zA-Z0-9]+$", interface):
        return "❌ Error: Invalid interface name"

    valid_filters = {"tcp", "udp", "icmp", "all"}
    selected_filter = filter_type.lower() if filter_type.lower() in valid_filters else "tcp"

    try:
        duration_int = int(duration.strip()) if duration.strip() else 30
    except ValueError:
        return f"❌ Error: Invalid duration value: {duration}"
    if not 1 <= duration_int <= 300:
        return "❌ Error: Duration must be between 1 and 300 seconds"

    return (
        "⚠️ Packet sniffing is intentionally not auto-executed.\n\n"
        f"Suggested command ({selected_filter} capture, {duration_int}s):\n"
        f"timeout {duration_int} ettercap -T -i {interface} -q"
    )


if __name__ == "__main__":
    mcp.run()
