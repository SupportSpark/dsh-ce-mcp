/**
 * dsh-ce-mcp — expose the bundled Cheat Engine MCP server as DSH tools.
 *
 * The repository ships `mcp/` unchanged (ce_mcp_server.js, its CE Lua bridge,
 * and the pipe client). This plugin does not re-implement that protocol: it
 * mounts `@deepseek-ai/dsh-mcp-client`, which owns the stdio transport, tool
 * discovery and the `mcp__<serverName>__<tool>` naming, and points it at the
 * bundled server resolved from this module's own URL so the package works from
 * any install location.
 *
 * Requirements for the tools to answer: Cheat Engine must be running with
 * `mcp/ce_mcp_bridge.lua` loaded, so the named pipe `\\.\pipe\ce_mcp_bridge`
 * exists. Without it the server still starts and reports bridge health.
 */

import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** Public DSH plugin name; must match cordis.patch.yml. */
export const name = 'dsh-ce-mcp'

/** The nested MCP client publishes tools through this service. */
export const inject = ['tools']

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const SERVER_PATH = join(PACKAGE_ROOT, 'mcp', 'ce_mcp_server.js')

/**
 * Resolve the DSH MCP client bridge.
 *
 * A normal install resolves the bare specifier. When the host only exposes the
 * package inside its own tree (the profile does not vendor it), walk up from the
 * running executable to find the DeepSeek Harness install and import that copy.
 */
async function loadMcpClient() {
  try {
    return await import('@deepseek-ai/dsh-mcp-client')
  } catch (bareError) {
    const candidates = []
    let cursor = dirname(process.execPath)
    for (let depth = 0; depth < 6; depth += 1) {
      candidates.push(join(cursor, 'node_modules', '@deepseek-ai', 'dsh-mcp-client', 'lib', 'index.js'))
      candidates.push(join(cursor, 'resources', 'app', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-mcp-client', 'lib', 'index.js'))
      const parent = dirname(cursor)
      if (parent === cursor) break
      cursor = parent
    }
    for (const candidate of candidates) {
      if (!existsSync(candidate)) continue
      return await import(pathToFileURL(candidate).href)
    }
    throw new Error(
      `dsh-ce-mcp: cannot load @deepseek-ai/dsh-mcp-client (${String(bareError?.message ?? bareError)}). ` +
        'Install it as a peer dependency or run inside a DeepSeek Harness profile.',
    )
  }
}

export async function apply(ctx, config) {
  if (!existsSync(SERVER_PATH)) {
    throw new Error(`dsh-ce-mcp: bundled MCP server missing at ${SERVER_PATH}`)
  }
  const mcpClient = await loadMcpClient()
  const serverName = config?.serverName ?? 'ce'

  ctx.plugin(mcpClient, {
    transport: 'stdio',
    serverName,
    // Run the bundled server with the same Node that hosts DSH.
    command: process.execPath,
    args: [SERVER_PATH],
    cwd: dirname(SERVER_PATH),
    toolCallTimeoutMs: config?.toolCallTimeoutMs ?? 120_000,
    // A missing CE bridge must not take the whole profile down.
    failOnStartupError: false,
  })

  ctx.logger?.info?.('dsh-ce-mcp: mounted Cheat Engine MCP server "%s"', serverName)
}
