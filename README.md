# VMware Aria Operations for Logs — MCP Server

[![PyPI version](https://img.shields.io/pypi/v/vmware-aria-logs)](https://pypi.org/project/vmware-aria-logs/)
[![Python 3.11+](https://img.shields.io/pypi/pyversions/vmware-aria-logs)](https://pypi.org/project/vmware-aria-logs/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Smithery](https://smithery.ai/badge/apollion69/vmware-aria-logs)](https://smithery.ai/server/apollion69/vmware-aria-logs)

MCP server for querying and analyzing logs from **VMware Aria Operations for Logs** (formerly vRealize Log Insight). Provides log search, mass incident detection, and optional VMware Aria Operations (vROps) correlation.

Built for use with [Claude Code](https://claude.ai/code), [Claude Desktop](https://claude.ai/download), [LobeChat](https://github.com/lobehub/lobe-chat), and any MCP-compatible client.

## Features

- **Log Search** — Query events with time range, text filters, and field constraints via Log Insight API v2
- **Incident Detection** — Signature-based clustering to identify mass log incidents (Stormbreaker engine)
- **API Surface Probe** — Detect appliance version and available API endpoints
- **Dashboard Listing** — Enumerate saved dashboards (legacy vRLIC API, deprecated on 8.18+)
- **vROps Correlation** — Cross-reference log entities with Aria Operations resources and alerts

## Quick Start

### Install via uvx (recommended)

```bash
uvx vmware-aria-logs
```

### Install via pip

```bash
pip install vmware-aria-logs
```

### Run with environment variables

```bash
export LI_BASE_URL=https://loginsight.example.com
export LI_USERNAME=admin
export LI_PASSWORD=your-password
export LI_PROVIDER=Local

vmware-aria-logs
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `query_events` | Search log events with time range, text filter, field constraints |
| `get_version` | Get appliance version and probe API surface |
| `list_dashboards` | List saved dashboards (legacy vRLIC API, deprecated on 8.18+) |
| `detect_incidents` | Mass incident detection via signature clustering |
| `find_vrops_resources` | Find entities in Aria Operations by name |
| `get_vrops_alerts` | Get alerts for specific vROps resources |

## Configuration

### Required Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LI_BASE_URL` | Log Insight appliance URL | — |
| `LI_USERNAME` | API username | `admin` |
| `LI_PASSWORD` | API password | — |
| `LI_PROVIDER` | Auth provider (Local, ActiveDirectory) | `Local` |
| `LI_VERIFY_TLS` | Verify TLS certificates | `false` |
| `LI_TIMEOUT_SEC` | HTTP request timeout (seconds) | `30` |

### Optional (vROps Correlation)

| Variable | Description | Default |
|----------|-------------|---------|
| `VROPS_BASE_URL` | Aria Operations URL | — |
| `VROPS_USERNAME` | vROps username | `admin` |
| `VROPS_PASSWORD` | vROps password | — |
| `VROPS_AUTH_SOURCE` | Auth source | `local` |
| `VROPS_VERIFY_TLS` | Verify TLS certificates | `false` |
| `VROPS_TIMEOUT_SEC` | HTTP request timeout (seconds) | `30` |

## Claude Code / MCP Client Configuration

```json
{
  "mcpServers": {
    "aria-logs": {
      "command": "uvx",
      "args": ["vmware-aria-logs"],
      "env": {
        "LI_BASE_URL": "https://loginsight.example.com",
        "LI_USERNAME": "admin",
        "LI_PASSWORD": "your-password"
      }
    }
  }
}
```

## Why This Server?

VMware Aria Operations for Logs (Log Insight) is widely deployed in enterprise VMware environments, but lacks modern AI-assisted log analysis tooling. This MCP server bridges that gap:

- **Zero dependencies** beyond the MCP SDK — uses Python stdlib `urllib` for HTTP
- **Stormbreaker engine** — unique signature-based clustering that finds mass incidents humans miss
- **vROps correlation** — cross-reference log events with infrastructure health in a single conversation
- **Works on v8.x+** — tested on Aria Operations for Logs 8.18.3, gracefully degrades deprecated APIs

## Also Available On

- [Smithery](https://smithery.ai/server/apollion69/vmware-aria-logs)
- [Glama](https://glama.ai/mcp/servers/apollion69/vmware-aria-logs)
- [PyPI](https://pypi.org/project/vmware-aria-logs/)

## License

MIT
