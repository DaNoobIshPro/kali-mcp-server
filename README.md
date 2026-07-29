# kali-mcp-server

A Model Context Protocol (MCP) server that exposes Kali security tooling in a controlled, containerized setup.

## ⚠️ Legal warning
Use only on systems you own or are explicitly authorized to test.

## What this project now includes (code basis)
- A runnable MCP server baseline in `/home/runner/work/kali-mcp-server/kali-mcp-server/kali_server.py`
- A compatibility launcher in `/home/runner/work/kali-mcp-server/kali-mcp-server/kali-pentest_server.py`
- Safe default behavior for high-risk operations (commands are prepared but not auto-executed)
- Input validation and command output size limits

## API keys: what you actually need
### Required for this server
- No mandatory API key for core tool execution.

### Optional for richer WPScan results
- `WPSCAN_API_TOKEN` (recommended when using WPScan features)

How to get it:
1. Create/sign in to a WPScan account at [https://wpscan.com](https://wpscan.com)
2. Generate an API token in your account settings
3. Add it to your environment

Example:
```bash
export WPSCAN_API_TOKEN="your_token_here"
```

## Choosing between different chat apps/clients
This MCP server can be used from different chat products. Pick based on your workflow:

| Chat/client type | Best when you want | Tradeoff |
|---|---|---|
| Claude Desktop (MCP-native) | Fast MCP setup and tool-first workflow | Less IDE-native coding UX |
| VS Code/Cursor style coding chat | Deep code editing + chat in same place | MCP wiring may need extra setup |
| Self-hosted web chat UI | Team/shared environment control | More ops/setup overhead |

### Simple decision guide
- Choose **Claude Desktop** if your priority is easiest MCP tool orchestration.
- Choose **IDE chat** if your priority is editing code and running tools in one interface.
- Choose **self-hosted chat** if your priority is team control and internal hosting.

## Configuration
Optional environment variables:
- `SCAN_TIMEOUT` (default: `300`)
- `MAX_OUTPUT_LENGTH` (default: `10000`)
- `WPSCAN_API_TOKEN` (optional)

## Local run
```bash
cd /home/runner/work/kali-mcp-server/kali-mcp-server
python3 -m pip install -r requirements.txt
python3 kali_server.py
```

## Available MCP tools (baseline)
- `server_info`
- `ettercap_scan_hosts`
- `ettercap_arp_poison` (manual-only guidance)
- `ettercap_dns_spoof` (manual-only guidance)
- `ettercap_packet_sniff` (manual-only guidance)

## Next build-out steps
- Add nmap/nikto/sqlmap/wpscan/dirb/searchsploit MCP tools back into the same validated pattern
- Add test coverage for input validation and command construction
- Add per-tool authorization gating policies
