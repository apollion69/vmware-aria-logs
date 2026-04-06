# VMware Aria Operations for Logs — MCP Server

MCP server for querying and analyzing logs from VMware Aria Operations for Logs (formerly vRealize Log Insight). Provides log search, mass incident detection, and optional VMware Aria Operations (vROps) correlation.

## Features

- **Log Search** — Query events with time range, text filters, and field constraints via Log Insight API v2
- **Incident Detection** — Signature-based clustering to identify mass log incidents (Stormbreaker engine)
- **API Surface Probe** — Detect appliance version and available API endpoints
- **Dashboard Listing** — Enumerate saved dashboards (legacy vRLIC API)
- **vROps Correlation** — Cross-reference log entities with Aria Operations resources and alerts

## Quick Start

```bash
# Configure credentials
export LI_BASE_URL=https://loginsight.example.com
export LI_USERNAME=admin
export LI_PASSWORD=your-password
export LI_PROVIDER=Local

# Run
uvx vmware-aria-logs
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `query_events` | Search log events with time range, text filter, field constraints |
| `get_version` | Get appliance version and probe API surface |
| `list_dashboards` | List saved dashboards (legacy API) |
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

### Optional (vROps Correlation)

| Variable | Description | Default |
|----------|-------------|---------|
| `VROPS_BASE_URL` | Aria Operations URL | — |
| `VROPS_USERNAME` | vROps username | `admin` |
| `VROPS_PASSWORD` | vROps password | — |
| `VROPS_AUTH_SOURCE` | Auth source | `local` |

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

## License

MIT
