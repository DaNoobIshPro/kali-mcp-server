# kali-mcp-server

A Model Context Protocol (MCP) server that provides educational penetration testing tools through a safe, containerized interface.

## Purpose

This MCP server provides AI assistants with access to common security testing tools for authorized penetration testing and vulnerability assessment in controlled environments.

## ⚠️ Legal Warning

**USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST**

Unauthorized security testing is illegal. This tool is for:
- Testing your own systems
- Authorized penetration testing engagements
- Educational lab environments
- Security research with permission

## Features

### Current Implementation

- **`scan_summary`** - Quick host discovery to verify target is reachable
- **`nmap_scan`** - Network port scanning with quick/full/stealth/service modes
- **`nikto_scan`** - Web server vulnerability scanning
- **`sqlmap_test`** - SQL injection vulnerability testing (use with caution)
- **`wpscan_check`** - WordPress-specific vulnerability scanning
- **`dirb_directories`** - Hidden directory and file discovery
- **`searchsploit_lookup`** - Search ExploitDB for known vulnerabilities

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Sufficient system resources (Kali image is ~1GB)
- Network access to target systems
- Legal authorization to test target systems

## Installation

See the step-by-step instructions provided with the files.

## Usage Examples

In Claude Desktop, you can ask:

- "Run a quick nmap scan on 192.168.1.1"
- "Check 192.168.1.100 for open ports"
- "Scan mywebsite.local with nikto on port 8080"
- "Search exploitdb for apache vulnerabilities"
- "Run dirb on http://testsite.local to find hidden directories"
- "Check if http://testsite.local/login.php is vulnerable to SQL injection"
- "Scan my WordPress site at http://myblog.local for vulnerable plugins"

## Architecture
```
Claude Desktop → MCP Gateway → Pentest MCP Server → Security Tools
                                       ↓              (nmap, nikto, etc.)
                          Docker Desktop Secrets
                          (WPSCAN_API_TOKEN)
```

## Configuration

### Optional Environment Variables

Set these when creating the server configuration:

- `SCAN_TIMEOUT`: Maximum time for scans (default: 300 seconds)
- `MAX_OUTPUT_LENGTH`: Maximum output length (default: 10000 chars)
- `WPSCAN_API_TOKEN`: API token for WPScan vulnerability database

## Development

### Local Testing
```bash
# Set environment variables for testing
export SCAN_TIMEOUT=300
export MAX_OUTPUT_LENGTH=10000

# Run directly
python3 pentest_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 pentest_server.py
```

### Adding New Tools

1. Install the tool in the Dockerfile
2. Add the function to `pentest_server.py`
3. Decorate with `@mcp.tool()`
4. Update the catalog entry with the new tool name
5. Rebuild the Docker image

## Tool Details

### nmap_scan
