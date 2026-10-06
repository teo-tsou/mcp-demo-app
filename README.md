# MCP demo app

A small edge app that offers [MCP](https://modelcontextprotocol.io) tools to a platform's cluster assistant.

- `mcp-manifest.json` declares the server (port, path, Service) and its tools, and marks which tools are read-only.
  The platform reads this file from the **signed commit** it deploys; the assistant gets exactly these tools. A tool
  not marked `read_only` runs only after a person approves it in the chat.
- `server.py` is the MCP server: streamable HTTP, Python standard library only, no dependencies.
- `app.yaml` + `kustomization.yaml` deploy it (namespace `mcp-demo`, a ClusterIP Service — nothing is exposed; the
  platform reaches it through the cluster's API server).

| tool | kind | what |
|---|---|---|
| `get_status` | read-only | mode, uptime, calls served |
| `list_subscribers` | read-only | sample subscribers — one note contains a deliberate prompt injection, for testing |
| `set_mode` | needs approval | normal / maintenance |

Commits are signed; only commits signed by a trusted publisher are deployed.
