# Claude Code Integration

MCPTrust works with [Claude Code](https://github.com/anthropics/claude-code), the terminal-based AI coding assistant.

## Quick Setup

```bash
# 1. Generate a v3 lockfile for your MCP server
mcptrust lock --v3 -- npx @modelcontextprotocol/server-filesystem /tmp

# 2. Add the server to Claude Code with MCPTrust proxy
claude mcp add my-server -- mcptrust proxy --lock mcp-lock.json -- npx @modelcontextprotocol/server-filesystem /tmp

# 3. Start Claude Code
claude
```

## Full Walkthrough

### Step 1: Install Prerequisites

```bash
# Install Claude Code
npm install -g @anthropic-ai/claude-code

# Install MCPTrust
go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest

# Install an MCP server (filesystem example)
npm install -g @modelcontextprotocol/server-filesystem
```

### Step 2: Generate Lockfile

```bash
# Create a v3 lockfile that locks all tools, prompts, and resources
mcptrust lock --v3 -- npx @modelcontextprotocol/server-filesystem /tmp
```

Output:
```
Scanning MCP server...
✓ Lockfile v3 created: mcp-lock.json
  Prompts: 0
  Templates: 0
  Tools: 14
```

### Step 3: Add MCP Server to Claude Code

```bash
# Use absolute paths for reliable execution
claude mcp add filesystem -- /path/to/mcptrust proxy --lock /path/to/mcp-lock.json -- npx @modelcontextprotocol/server-filesystem /tmp
```

### Step 4: Verify Connection

Inside Claude Code, type `/mcp` to see connected servers.

Then ask Claude to use the MCP tools:

```
> Use the filesystem server to list files in /tmp
```

### Expected Output

Claude Code will show the MCP tool being used:

```
● I'll use the filesystem MCP server to list the files in the /tmp directory.

● filesystem - list_directory (MCP)(path: "/tmp")
  ⎿ {
      "content": "[FILE] example.txt\n[DIR] cache\n[FILE] log.txt\n..."
    }

● Successfully listed the contents of /tmp:
  - example.txt
  - cache/
  - log.txt
  ...
```

> **Key indicator:** You should see `(MCP)` next to the tool name, confirming it's going through the MCPTrust proxy rather than a direct bash command.

## What Gets Enforced

With MCPTrust proxying your MCP server:

| Behavior | Without MCPTrust | With MCPTrust |
|----------|------------------|---------------|
| Server adds new tools at runtime | ✅ Allowed | 🚫 Blocked |
| Server exposes unlocked resources | ✅ Allowed | 🚫 Blocked |
| Tool calls to unknown tools | ✅ Allowed | 🚫 Blocked |
| Audit logging | ❌ None | ✅ Full trace |

## Troubleshooting

### MCP server not appearing

1. Ensure you're using **absolute paths** in the `claude mcp add` command
2. Check that the lockfile exists at the specified path
3. Use `--v3` flag when generating lockfiles (proxy requires v3 format)

### Command not found: mcptrust

Ensure MCPTrust is in your PATH, or use the absolute path:

```bash
claude mcp add my-server -- /usr/local/bin/mcptrust proxy --lock ...
```

### Lockfile version mismatch

```
Error: proxy requires lockfile v3, got 2.0
```

Regenerate with `--v3`:

```bash
mcptrust lock --v3 -- npx @modelcontextprotocol/server-filesystem /tmp
```

## See Also

- [CLI Reference](CLI.md)
- [Proxy Modes](../README.md#proxy-modes)
