# MCP demo app

A small edge app that offers [MCP](https://modelcontextprotocol.io) tools to a platform's cluster assistant.
It follows the platform's **MCP app contract v2**.

- `mcp-manifest.json` declares the server (port, path, Service, optional scheme) and its tools, and marks which tools
  are read-only. The platform reads this file from the **signed commit** it deploys; the assistant gets exactly these
  tools. A tool not marked `read_only` runs only after a person approves it in the chat.
- `server.py` is the MCP server: streamable HTTP, Python, with the `cryptography` library only to check signatures
  (and, with `--tls`, to make its certificate).
- A small Helm chart (`Chart.yaml`, `templates/`) deploys it: namespace `mcp-demo` (named in `fleet.yaml`), a
  ClusterIP Service. Nothing is exposed; the platform reaches it through the cluster's API server.
- **Only the platform may call it.** Every request must carry the platform's token (header `X-Platform-Token`): a
  short-lived ECDSA P-256 signature by the platform's key. The token names this app's namespace and the SHA-256 of
  the exact request body, and each token is accepted once. The platform's public key arrives as the chart value
  `platformKey`, which `fleet.yaml` reads from the cluster (`${ .ClusterValues.platformMcpKey }`). Without a key,
  every call is refused.

| tool | kind | what |
|---|---|---|
| `get_status` | read-only | mode, uptime, calls served |
| `list_subscribers` | read-only | sample subscribers; one note contains a deliberate prompt injection, for testing |
| `set_mode` | needs approval | normal / maintenance |

Commits are signed; only commits signed by a trusted publisher are deployed.

## The token's audience (contract v2)

The manifest says `"version": 2`. The platform then signs every request for `aud = "mcp:ns/<namespace>"`, the
namespace it reaches the Service in. The server reads its own namespace at run time (the downward API:
`POD_NAMESPACE` from `metadata.namespace`) and accepts only that audience. So the app works whatever id an
administrator gives it when registering it. The platform accepts a version 2 manifest only when `fleet.yaml` names
the namespace (`defaultNamespace: mcp-demo` here).

Checks, in order: a platform key is configured; the signature verifies with it (ECDSA P-256, SHA-256);
`iss == "platform-hub"`; `aud == "mcp:ns/" + POD_NAMESPACE`; `body` is the SHA-256 of the request body;
`iat`/`exp` within 5 minutes and 30 s of skew; `jti` not seen before. Any failure: HTTP 401.

## Encrypted last hop (optional)

By default the cluster's API server reaches the server over plain HTTP inside the cluster. To encrypt that hop, add
`"scheme": "https"` to `server` in `mcp-manifest.json`:

```json
"server": {"port": 8811, "path": "/mcp", "service": "mcp-demo", "scheme": "https"}
```

That one change is enough: the chart then starts the server with `--tls`, which serves HTTPS with a self-signed
certificate generated at start (ECDSA P-256; the private key is held in memory and never written in clear), and the
platform calls `https:mcp-demo:8811`. The API server does not verify the certificate: the hop is encrypted, the
server's identity is not proven by it; the platform's signed token still proves every request came from the platform.
A site may require encrypted MCP; then only an `https` server is used there.

## Contract v1 (legacy)

With `"version": 1` the platform signs for `aud = "mcp:<app id>"`, the id the app is registered under, and the server
accepts `mcp:<APP_ID>` (environment variable `APP_ID`, default `mcp-demo`). The app then works only when registered
under exactly that id. `MCP_CONTRACT=1` or `2` forces either behaviour regardless of the manifest (a server without a
manifest, declared by an administrator, receives contract 2 tokens).
