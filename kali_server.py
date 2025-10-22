@mcp.tool()
async def ettercap_scan_hosts(interface: str = "eth0", target: str = "") -> str:
    """Scan network for active hosts using ettercap - specify network interface and optional target range."""
    logger.info(f"ettercap_scan_hosts called with interface={interface}, target={target}")
    
    if not interface.strip():
        return "❌ Error: Network interface is required"
    
    # Validate interface name
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return "❌ Error: Invalid interface name format"
    
    # Build command
    cmd = ["ettercap", "-T", "-i", interface]
    
    if target.strip():
        target, error = sanitize_target(target)
        if error:
            return f"❌ Error: {error}"
        cmd.extend(["-M", "arp:remote", f"/{target}/"])
    else:
        # Just scan for hosts
        cmd.extend(["-P", "list"])
    
    output, returncode = run_command(cmd, timeout=120)
    
    return f"🌐 Ettercap host scan on {interface}\n\n📊 Results:\n{output}\n\n💡 Note: Use ettercap_arp_poison for MITM attacks (use responsibly)"

@mcp.tool()
async def ettercap_arp_poison(interface: str = "eth0", target1: str = "", target2: str = "") -> str:
    """Perform ARP poisoning MITM attack - WARNING: This intercepts network traffic and should only be used with authorization."""
    logger.info(f"ettercap_arp_poison called with interface={interface}, target1={target1}, target2={target2}")
    
    if not interface.strip():
        return "❌ Error: Network interface is required"
    
    if not target1.strip() or not target2.strip():
        return "❌ Error: Both target1 and target2 are required for ARP poisoning"
    
    # Validate interface
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return "❌ Error: Invalid interface name format"
    
    # Validate targets
    target1, error1 = sanitize_target(target1)
    if error1:
        return f"❌ Error in target1: {error1}"
    
    target2, error2 = sanitize_target(target2)
    if error2:
        return f"❌ Error in target2: {error2}"
    
    # Build command - text mode, ARP poisoning
    cmd = [
        "ettercap",
        "-T",  # Text mode
        "-q",  # Quiet mode
        "-i", interface,
        "-M", "arp:remote",  # ARP poisoning
        f"/{target1}//",
        f"/{target2}//"
    ]
    
    return f"""⚠️ WARNING: ARP Poisoning Attack
    
This is a DESTRUCTIVE operation that will:
- Intercept traffic between {target1} and {target2}
- Modify ARP tables on target systems
- Could disrupt network connectivity

🔒 AUTHORIZATION REQUIRED

To execute this attack, you must:
1. Have written permission from network owner
2. Be conducting authorized penetration testing
3. Understand the legal implications

Command prepared but NOT executed for safety:
{' '.join(cmd)}

To manually execute (at your own risk and responsibility):
docker exec -it <container_name> {' '.join(cmd)}

💡 Alternative: Use ettercap_scan_hosts for non-invasive reconnaissance
"""

@mcp.tool()
async def ettercap_dns_spoof(interface: str = "eth0", target: str = "", domain: str = "", fake_ip: str = "") -> str:
    """Configure DNS spoofing with ettercap - redirect domain queries to fake IP address."""
    logger.info(f"ettercap_dns_spoof called with interface={interface}, target={target}, domain={domain}")
    
    if not all([interface.strip(), target.strip(), domain.strip(), fake_ip.strip()]):
        return "❌ Error: All parameters required: interface, target, domain, fake_ip"
    
    # Validate inputs
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return "❌ Error: Invalid interface name"
    
    target, error = sanitize_target(target)
    if error:
        return f"❌ Error in target: {error}"
    
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', domain):
        return "❌ Error: Invalid domain format"
    
    fake_ip_clean, error = sanitize_target(fake_ip)
    if error:
        return f"❌ Error in fake_ip: {error}"
    
    return f"""⚠️ WARNING: DNS Spoofing Configuration

This attack will redirect DNS queries for {domain} to {fake_ip}

🔒 AUTHORIZATION REQUIRED

DNS spoofing setup requires:
1. Create /tmp/etter.dns with: {domain} A {fake_ip}
2. Configure ettercap to use the DNS plugin
3. Start ARP poisoning

Command sequence (NOT executed for safety):
echo "{domain} A {fake_ip}" > /tmp/etter.dns
ettercap -T -i {interface} -M arp:remote /{target}// -P dns_spoof

This is NOT executed automatically. Manual execution required.

💡 Use ettercap_scan_hosts for safe reconnaissance instead
"""

@mcp.tool()
async def ettercap_packet_sniff(interface: str = "eth0", filter_type: str = "tcp", duration: str = "30") -> str:
    """Sniff network packets using ettercap - specify interface, filter type (tcp/udp/icmp), and duration in seconds."""
    logger.info(f"ettercap_packet_sniff called with interface={interface}, filter_type={filter_type}")
    
    if not interface.strip():
        return "❌ Error: Network interface is required"
    
    # Validate interface
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return "❌ Error: Invalid interface name"
    
    # Validate filter type
    valid_filters = ["tcp", "udp", "icmp", "all"]
    filter_type = filter_type.lower() if filter_type.lower() in valid_filters else "tcp"
    
    # Validate duration
    try:
        duration_int = int(duration) if duration.strip() else 30
        if duration_int < 1 or duration_int > 300:
            return "❌ Error: Duration must be between 1 and 300 seconds"
    except ValueError:
        return f"❌ Error: Invalid duration value: {duration}"
    
    return f"""⚠️ WARNING: Packet Sniffing Operation

This will capture network traffic on {interface} for {duration_int} seconds

🔒 AUTHORIZATION REQUIRED

Packet sniffing is only legal when:
- You own the network
- You have written permission
- You are conducting authorized testing

Command prepared (NOT executed for safety):
timeout {duration_int} ettercap -T -i {interface} -q

This requires manual execution with proper authorization.

💡 Safer alternative: Use ettercap_scan_hosts for host discovery only
"""