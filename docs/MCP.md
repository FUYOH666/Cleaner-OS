# MCP integration

System Cleaner can expose read-only tools over the [Model Context Protocol](https://modelcontextprotocol.io/) when installed with the `mcp` extra.

## Install

```bash
uv sync --extra mcp
# or
pip install "syscleaner[mcp]"
```

## Cursor example

Add to `.cursor/mcp.json` (adjust paths):

```json
{
  "mcpServers": {
    "syscleaner": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/Cleaner-OS",
        "syscleaner-mcp"
      ]
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `health` | Version and readiness |
| `scan_summary` | Summarize a saved `--save-results` JSON file |
| `export_plan` | Build cleanup plan JSON (`tier`: safe, moderate, risky) |

Apply/destructive actions are **not** exposed via MCP by default.

## Workflow

```bash
syscleaner scan --all --save-results scan.json
# In MCP client: scan_summary(scan_json_path="scan.json")
# Then: export_plan(scan_json_path="scan.json", tier="safe")
```

Run cleanup from the CLI: `syscleaner apply --from-scan scan.json --dry-run`.
