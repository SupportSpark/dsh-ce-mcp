#!/usr/bin/env node
/**
 * Smoke test for the bundled Cheat Engine MCP server.
 *
 * Spawns `mcp/ce_mcp_server.js` over stdio, performs the MCP handshake and
 * prints the discovered tools. It does not need Cheat Engine running: without
 * the pipe the server still starts and the tools report bridge health.
 *
 *   node scripts/smoke.mjs
 */

import { spawn } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const server = join(root, 'mcp', 'ce_mcp_server.js')

const child = spawn(process.execPath, [server], { cwd: dirname(server), stdio: ['pipe', 'pipe', 'pipe'] })

let buffer = ''
const pending = new Map()
let nextId = 0

child.stdout.setEncoding('utf8')
child.stdout.on('data', (chunk) => {
  buffer += chunk
  let index
  while ((index = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, index).trim()
    buffer = buffer.slice(index + 1)
    if (!line) continue
    let message
    try {
      message = JSON.parse(line)
    } catch {
      continue
    }
    const resolver = pending.get(message.id)
    if (resolver) {
      pending.delete(message.id)
      resolver(message)
    }
  }
})

const stderr = []
child.stderr.setEncoding('utf8')
child.stderr.on('data', (chunk) => stderr.push(chunk))

function request(method, params) {
  nextId += 1
  const id = nextId
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout on ${method}`)), 30_000)
    pending.set(id, (message) => {
      clearTimeout(timer)
      if (message.error) reject(new Error(`${method}: ${JSON.stringify(message.error)}`))
      else resolve(message.result)
    })
  })
}

function notify(method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`)
}

try {
  const init = await request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'dsh-ce-mcp-smoke', version: '1.0.0' },
  })
  notify('notifications/initialized', {})
  console.log('server   :', init.serverInfo?.name, init.serverInfo?.version ?? '')
  const { tools } = await request('tools/list', {})
  console.log('tools    :', tools.length)
  for (const tool of tools) console.log('  -', tool.name)
  console.log('\nSMOKE OK')
} catch (error) {
  console.error('SMOKE FAILED:', error.message)
  if (stderr.length) console.error(stderr.join('').slice(-800))
  process.exitCode = 1
} finally {
  child.stdin.end()
  setTimeout(() => child.kill(), 500).unref()
}
