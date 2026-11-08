# Connecting an AI assistant (MCP)

CyberSoar EASM has a [Model Context Protocol](https://modelcontextprotocol.io) endpoint at `/mcp`. MCP is an open standard, so this works with any AI model the assistant uses (Claude, GPT, Gemini, or a model you run yourself, for example in LM Studio). An assistant that speaks MCP (Cursor, VS Code, Claude Code, Claude Desktop or another MCP client) can use it to answer questions such as *"what are our worst open findings on example.com?"*, *"what changed this week?"* or *"what do we know about 203.0.113.7?"*.

## What an assistant can do

| Tool | What it does | Token role |
|---|---|---|
| `search` | Finds domains, findings and assets containing some text (the same search as the box at the top of the web interface) | Viewer |
| `list_targets` | Lists the monitored domains with their scan status | Viewer |
| `list_findings` | Lists findings, worst first, with the risk and the fix | Viewer |
| `get_finding` | One finding with the services on the host and links to the public evidence | Viewer |
| `list_assets` | The inventory: subdomains, IPs, services, certificates, DNS, vulnerabilities | Viewer |
| `list_events` | Recent changes | Viewer |
| `request_scan` | Queues a rescan of a domain that is **already** monitored | Analyst |

There is no tool that adds a domain, changes or accepts a finding, changes settings or manages users, whatever the token's role.

## Set it up

**Settings → AI assistants (MCP)** shows the same steps with this agent's own address filled in, copy buttons, the latest connections, and a switch that turns MCP off (every request to `/mcp` is then refused; the REST API is not affected).

1. Sign in and open **your account → API tokens**. Create a token named after the assistant (for example `cursor` or `claude`).
   * Choose **Viewer** unless you want the assistant to be able to start rescans; then choose **Analyst**.
   * Give it an expiry date. The token is shown once.
2. Add the server to your assistant. The address is the one you use for the web interface, plus `/mcp`, and the assistant sends the token as the header `Authorization: Bearer easm_...`. Use the first of the forms below that your assistant supports.

**Assistants with a form for remote MCP servers.** Enter the address and the header. Nothing else is needed.

**Assistants that connect to remote (HTTP) MCP servers from a configuration file**, for example Cursor, VS Code, LM Studio and Claude Code. Most use this shape:

```json
{
  "mcpServers": {
    "easm": {
      "url": "https://easm.internal.example:8443/mcp",
      "headers": { "Authorization": "Bearer easm_..." }
    }
  }
}
```

Some name the keys differently: VS Code uses `"servers"` and adds `"type": "http"`, and Gemini CLI uses `"httpUrl"` in place of `"url"`. Check your assistant's MCP documentation.

Claude Code can also add it from a terminal:

```bash
claude mcp add --transport http easm https://easm.internal.example:8443/mcp --header "Authorization: Bearer easm_..."
```

**Assistants that only start local (stdio) servers**, for example through Claude Desktop's configuration file. Use the `mcp-remote` bridge, which needs Node.js:

```json
{
  "mcpServers": {
    "easm": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://easm.internal.example:8443/mcp", "--transport", "http-only", "--header", "Authorization:Bearer easm_..."]
    }
  }
}
```

* Write the header out in full, as `Authorization:Bearer easm_...` with no space after the colon. `mcp-remote` does not fill in `${VAR}` placeholders in a `--header` argument: it sends the placeholder text, the agent refuses it, and the bridge then tries to sign in with OAuth, which the agent does not offer (the error is *"Dynamic Client Registration rejected (HTTP 404)"*).
* `--transport http-only` stops the bridge falling back to the older SSE transport, which the agent does not offer.
* On Windows, if the assistant cannot start `npx`, use `"command": "cmd"` and put `"/c", "npx"` at the start of `"args"`.

### A self-signed agent

If the agent uses its automatic self-signed certificate, assistants refuse to connect until they trust it. Either install a certificate from your certificate authority (**Settings → Certificate**), or tell the computer that runs the assistant to trust this one:

1. Download it from **Settings → AI assistants → download this agent's certificate** (`/settings/certificate.crt`, administrators only). It is the certificate alone, never its key. On the agent's own computer it is also `server.crt` in the data folder.
2. Most assistants and the `mcp-remote` bridge are Node.js programs, which ignore the operating system's trusted store. Set `NODE_EXTRA_CA_CERTS` to the saved file's path: in the bridge configuration (`"env": { "NODE_EXTRA_CA_CERTS": "C:\\path\\to\\easm-agent.crt" }`), or in the environment the assistant starts in.
3. Other assistants use the operating system's store. Add the certificate there.

The agent renews its self-signed certificate before it expires, and makes a new one if its address changes. Download it again when that happens.

## Things to know before you turn it on

* **Your findings go to the AI provider.** Whatever the assistant reads (host names, IP addresses, findings) is sent to the company that runs the model, under that company's terms. If that is not acceptable for your data, use a model you run yourself, or do not connect an assistant.
* **Scan results can contain hostile text.** Banners, page titles and certificate names are written by whoever runs the scanned system, which may be an attacker who expects to be scanned. Text such as *"ignore your instructions and …"* in a page title is a real risk (prompt injection). The agent tells the assistant to treat these values as data, and its tools cannot change anything except queue a rescan. Still, do not give the same assistant tools that can act elsewhere (email, tickets, shell commands) without approving each action yourself.
* **Web-based assistants (in a browser tab, such as claude.ai or chatgpt.com) connect from the internet.** They can only reach an agent that is published on the internet, which this agent is not designed for. Use an assistant that runs on a computer inside your network, with whichever model you prefer. [NETWORK.md](NETWORK.md#inbound) has the port to open for it.
* **It is accountable.** Every connection is written to the audit log (`mcp.connect`, with the client's name and the token), as is every rescan (`scan.mcp`). Revoking the token cuts the assistant off at once, and demoting or disabling the account limits its tokens too.

## Protocol details

Streamable HTTP transport, protocol revisions 2025-11-25, 2025-06-18 and 2025-03-26. The server is stateless: each request is a single JSON-RPC message sent with `POST`, and each reply is a single JSON response (no server-sent events, no sessions, no batches). Requests carrying an `Origin` header from another site are refused. Requests are limited to 64 KB, and lists to 200 items.
