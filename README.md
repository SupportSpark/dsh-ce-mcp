# dsh-ce-mcp

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) plugin that exposes the
**Cheat Engine MCP server** (`ce_mcp`) as DSH tools.

It bundles the upstream stdio MCP server unchanged and mounts it through
`@deepseek-ai/dsh-mcp-client`, so the model sees **127 `ce_*` tools** under the
`mcp__ce__*` namespace: memory reads/writes, AOB and value scans, pointer resolution,
disassembly, Lua execution, breakpoints, and more.

> Replaces the former `@tindalosko/dsh-cheatengine` plugin. That plugin talked to a separate
> HTTP bridge on port 17171 and shipped its own tool set; this one drives the pipe-based
> `ce_mcp` server directly, so the tool surface matches the upstream project 1:1.

---

## Requirements

| Item | Notes |
|---|---|
| DeepSeek Harness | 0.2.1-rc or newer |
| Node.js | ≥ 20 (the plugin spawns the server with the host's own Node) |
| Cheat Engine | Running, with the Lua bridge loaded — see below |

The tools are registered even when Cheat Engine is closed; they simply answer with a
"bridge not running" diagnostic until it comes up.

## Install

```bash
# from GitHub
dsh plugin --profile desktop add github:SupportSpark/dsh-ce-mcp

# or from a local clone
dsh plugin --profile desktop add file:/path/to/dsh-ce-mcp
```

`dsh plugin` forwards to `pnpm` inside the profile, and the package's
`dsh.bundle.patch` adds it to `dsh.profile.bundles`, so the plugin is active after the
next harness start.

## Activate the Cheat Engine side

The MCP server talks to Cheat Engine over the named pipe `\\.\pipe\ce_mcp_bridge`.
Load the bundled bridge once per Cheat Engine session:

1. Open Cheat Engine.
2. **Table → Show Cheat Table Lua Script**.
3. Load `mcp/ce_mcp_bridge.lua` from this package, or paste its contents.
4. Click **Execute**.
5. Wait for the `MCP` label to appear in the CE toolbar.

Then ask the agent to run `ce_ping` — it returns bridge health instead of the setup hint.

## Tool surface

All 127 tools come from the upstream registry (`mcp/src/tool-registry.js`); the DSH names are
`mcp__ce__<tool>`. A representative slice:

```
ce_ping                      ce_get_process_info       ce_list_processes
ce_attach_process            ce_enum_modules           ce_enum_memory_regions
ce_read_memory               ce_read_memory_batch      ce_write_memory
ce_write_memory_batch        ce_aob_scan               ce_aob_scan_unique
ce_scan_new                  ce_scan_next              ce_scan_results
ce_value_scan                ce_resolve_pointer        ce_get_address
ce_disassemble_bytes         ce_assemble_instruction   ce_check_assemble
ce_auto_assemble             ce_execute_lua            ce_get_stats
```

Run `node scripts/smoke.mjs` to list the full set from the bundled server without DSH.

## Layout

```
lib/index.js          cordis plugin: resolves and mounts the bundled MCP server
cordis.patch.yml      bundle patch that registers the plugin in a profile
mcp/                  upstream ce_mcp, unmodified
  ce_mcp_server.js    stdio MCP server
  ce_mcp_bridge.lua   Cheat Engine Lua bridge
  src/                pipe client + tool registry
  bin/cheatengine     upstream CLI entry
scripts/smoke.mjs     stdio handshake + tools/list smoke test
```

## How it works

`lib/index.js` computes the server path from its own module URL — no absolute paths are
hard-coded, so the package works from any install location — and mounts the MCP client
bridge with:

```js
ctx.plugin(mcpClient, {
  transport: 'stdio',
  serverName: 'ce',
  command: process.execPath,
  args: [serverPath],
  cwd: dirname(serverPath),
  failOnStartupError: false,
})
```

`failOnStartupError: false` keeps a missing Cheat Engine from taking the whole profile down.
If the host only publishes `@deepseek-ai/dsh-mcp-client` inside its own tree, the loader walks
up from `process.execPath` to find it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Cheat Engine MCP Bridge not running` | Bridge Lua not executed, or CE closed — follow the 5 steps above |
| No `mcp__ce__*` tools | Plugin not in the profile's bundle list, or the harness has not restarted since install |
| `serverName "ce" is already in use` | Another MCP client already claims `ce`; remove the duplicate registration |

## License

MIT — see [LICENSE](LICENSE). The bundled `mcp/` sources keep their upstream MIT license
(`mcp/package.json`, `mcp/README.md`).
