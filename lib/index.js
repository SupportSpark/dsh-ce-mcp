/**
 * dsh-ce-mcp — expose the bundled Cheat Engine MCP server as DSH tools.
 *
 * The repository ships `mcp/` unchanged (ce_mcp_server.js, its CE Lua bridge,
 * and the pipe client). This plugin does not re-implement that protocol: it
 * mounts `@deepseek-ai/dsh-mcp-client`, which owns the stdio transport, tool
 * discovery and the `mcp__<serverName>__<tool>` naming.
 *
 * The server is staged into a per-user runtime directory before it is spawned.
 * A DSH plugin lives inside the profile's `node_modules`, and package managers
 * replace that directory wholesale on upgrade; a child process running a script
 * from inside it holds a Windows handle that makes the replacement fail with
 * EPERM. Staging keeps `node_modules` free of open files, so `dsh plugin add`
 * and the plugin manager's retry both work while the plugin is active.
 *
 * Requirements for the tools to answer: Cheat Engine must be running with
 * `mcp/ce_mcp_bridge.lua` loaded (it also auto-starts when dropped into CE's
 * `autorun/` folder), so the named pipe `\\.\pipe\ce_mcp_bridge` exists. Without
 * it the server still starts and reports bridge health.
 */

import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** Public DSH plugin name; must match cordis.patch.yml. */
export const name = 'dsh-ce-mcp'

/** The nested MCP client publishes tools through this service. */
export const inject = ['tools']

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const PACKAGE_JSON = join(PACKAGE_ROOT, 'package.json')
const BUNDLED_MCP = join(PACKAGE_ROOT, 'mcp')

/** Per-user runtime directory, deliberately outside the profile's node_modules. */
const RUNTIME_ROOT = join(process.env.LOCALAPPDATA ?? tmpdir(), 'dsh-ce-mcp')
const STAGED_MCP = join(RUNTIME_ROOT, 'mcp')
const STAGE_MARKER = join(RUNTIME_ROOT, '.staged-version')

function packageVersion() {
  try {
    return String(JSON.parse(readFileSync(PACKAGE_JSON, 'utf8')).version ?? '0')
  } catch {
    return '0'
  }
}

/**
 * Copy `mcp/` into the runtime directory once per package version.
 *
 * A previous server may still hold a file in the staged tree; in that case the
 * existing copy is already the same generation and is reused as-is.
 */
function stageMcpSources(logger) {
  const version = packageVersion()
  const marker = existsSync(STAGE_MARKER) ? readFileSync(STAGE_MARKER, 'utf8').trim() : ''
  if (marker === version && existsSync(join(STAGED_MCP, 'ce_mcp_server.js'))) {
    return STAGED_MCP
  }
  try {
    mkdirSync(RUNTIME_ROOT, { recursive: true })
    cpSync(BUNDLED_MCP, STAGED_MCP, { recursive: true, force: true })
    writeFileSync(STAGE_MARKER, version, 'utf8')
  } catch (error) {
    if (existsSync(join(STAGED_MCP, 'ce_mcp_server.js'))) {
      logger?.warn?.('dsh-ce-mcp: could not refresh the staged server (%s); reusing %s', String(error?.message ?? error), STAGED_MCP)
      return STAGED_MCP
    }
    throw new Error(`dsh-ce-mcp: cannot stage mcp/ into ${STAGED_MCP}: ${String(error?.message ?? error)}`)
  }
  return STAGED_MCP
}

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
  if (!existsSync(join(BUNDLED_MCP, 'ce_mcp_server.js'))) {
    throw new Error(`dsh-ce-mcp: bundled MCP server missing at ${BUNDLED_MCP}`)
  }
  const mcpClient = await loadMcpClient()
  const staged = stageMcpSources(ctx.logger)
  const serverPath = join(staged, 'ce_mcp_server.js')
  const serverName = config?.serverName ?? 'ce'

  ctx.plugin(mcpClient, {
    transport: 'stdio',
    serverName,
    // Run the staged server with the same Node that hosts DSH.
    command: process.execPath,
    args: [serverPath],
    cwd: dirname(serverPath),
    toolCallTimeoutMs: config?.toolCallTimeoutMs ?? 120_000,
    // A missing CE bridge must not take the whole profile down.
    failOnStartupError: false,
  })

  ctx.logger?.info?.('dsh-ce-mcp: mounted Cheat Engine MCP server "%s" from %s', serverName, serverPath)
}
