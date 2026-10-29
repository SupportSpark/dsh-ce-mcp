#!/usr/bin/env node
// -*- coding: utf-8 -*-
/**
 * Cheat Engine MCP Server - Main Server Implementation
 * JavaScript/Node.js version
 */

const { Config, TimeoutManager, MetricsCollector, log } = require('./src/base');
const { PipeClient } = require('./src/pipe-client');
const { ToolRegistry } = require('./src/tool-registry');

// Get version from package.json
const PACKAGE_VERSION = require('./package.json').version;

// ============ MCP Server ============
class CEMCPServer {
  constructor() {
    this.pipeClient = new PipeClient();
    this.pipeClient.startBackgroundReconnect();
    this.toolRegistry = new ToolRegistry();
    this.timeoutManager = new TimeoutManager();
    this.metricsCollector = new MetricsCollector();
    this.requestCount = 0;
  }

  async _diagnoseConnection() {
    const checks = [];
    const suggestions = [];
    let allPassed = true;

    // Check 1: Pipe existence
    let pipeExists = false;
    try {
      const testClient = new PipeClient();
      try {
        const connected = await testClient.connect(false, 1000);
        if (connected) {
          pipeExists = true;
          checks.push({
            name: 'pipe_exists',
            passed: true,
            message: `Pipe '${Config.PIPE_NAME}' available`,
          });
        } else {
          throw new Error('Connection failed');
        }
      } finally {
        testClient.stop();
      }
    } catch (err) {
      allPassed = false;
      checks.push({
        name: 'pipe_exists',
        passed: false,
        message: 'Pipe not found - CE bridge not running',
      });
      suggestions.push(
        '1. Open Cheat Engine',
        "2. Table -> Show Cheat Table Lua Script",
        '3. Paste ce_mcp_bridge.lua content and Execute',
        "4. Look for '[CheatEngine-MCP] Bridge started' message"
      );
    }

    // Check 2: CE process
    try {
      const { execSync } = require('child_process');
      const result = execSync('tasklist /FI "IMAGENAME eq cheatengine*" /FO CSV /NH', { 
        encoding: 'utf-8',
        timeout: 5000 
      });
      const ceRunning = result.toLowerCase().includes('cheatengine');
      if (ceRunning) {
        checks.push({
          name: 'ce_process',
          passed: true,
          message: 'Cheat Engine is running',
        });
      } else {
        allPassed = false;
        checks.push({
          name: 'ce_process',
          passed: false,
          message: 'Cheat Engine not found',
        });
        suggestions.unshift('Start Cheat Engine first!');
      }
    } catch (err) {
      checks.push({
        name: 'ce_process',
        passed: null,
        message: `Could not check: ${err.message}`,
      });
    }

    return {
      status: (allPassed && pipeExists) ? 'ok' : 'failed',
      pipe_name: Config.PIPE_NAME,
      checks,
      suggestions: suggestions.length > 0 ? suggestions : ['Connection should work - try again'],
    };
  }

  async executeTool(name, args) {
    const luaCmd = this.toolRegistry.getLuaCommand(name);
    if (!luaCmd) {
      return { error: `Unknown tool: ${name}` };
    }

    const timeoutSeconds = this.timeoutManager.getTimeout(name);
    const timeoutMs = timeoutSeconds * 1000;
    const startTime = Date.now();

    const response = await this.pipeClient.sendReceive(
      { command: luaCmd, params: args },
      timeoutMs,
      name
    );

    const duration = (Date.now() - startTime) / 1000;
    const isError = response.error !== undefined;
    this.metricsCollector.recordCall(name, duration, isError);

    if (isError) {
      // For ce_ping, return diagnostic info on connection failure
      if (name === 'ce_ping') {
        const diag = await this._diagnoseConnection();
        return { error: response.error, diagnostic: diag };
      }
      if (response.timeout_info) {
        return {
          error: response.error,
          timeout_info: response.timeout_info,
        };
      }
      return { error: response.error };
    }

    const result = response.result || response;

    // Attach health and server metrics to ce_ping response
    if (name === 'ce_ping') {
      const healthMetrics = this.pipeClient.getHealthMetrics();
      const serverMetrics = this.metricsCollector.getSummary();
      if (typeof result === 'object' && result !== null) {
        result.connection_health = healthMetrics;
        result.server_metrics = serverMetrics;
      } else {
        return {
          result,
          connection_health: healthMetrics,
          server_metrics: serverMetrics,
        };
      }
    }

    return result;
  }

  handleRequest(req) {
    const method = req.method || '';
    const reqId = req.id;
    const params = req.params || {};

    if (method === 'initialize') {
      return this._handleInitialize(reqId);
    } else if (method === 'notifications/initialized') {
      return null;
    } else if (method === 'tools/list') {
      return this._handleToolsList(reqId);
    } else if (method === 'tools/call') {
      return this._handleToolsCall(reqId, params);
    } else {
      return this._errorResponse(reqId, -32601, `Method not found: ${method}`);
    }
  }

  _handleInitialize(reqId) {
    return {
      jsonrpc: '2.0',
      id: reqId,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'cheatengine-mcp-bridge', version: PACKAGE_VERSION },
        instructions: (
          '# Cheat Engine MCP - AI Usage Guide\n\n' +
          '## Tool Selection Decision Tree\n\n' +
          '### Q: Do I know the address?\n' +
          '- NO, but can observe value changes -> ce_scan_new workflow (value hunting)\n' +
          '- YES, need stable pointer -> ce_find_pointer_path (auto) or manual F5+value_scan\n' +
          '- YES, want to read/write -> ce_read_memory / ce_write_memory\n' +
          '- YES, batch read/write -> ce_read_memory_batch / ce_write_memory_batch\n' +
          '- YES, unknown type -> ce_auto_guess to detect type\n\n' +
          '### Q: What am I searching for?\n' +
          '- Game values (health, gold) -> ce_scan_new (NOT ce_value_scan!)\n' +
          '- Code signatures -> ce_aob_scan / ce_aob_scan_unique (supports ?? wildcards)\n' +
          '- Pointer storage locations -> ce_value_scan (after getting register value from F5)\n' +
          '- Module info -> ce_enum_modules\n' +
          '- Window by title -> ce_find_window / ce_enum_windows\n\n' +
          '### Q: How to analyze code?\n' +
          '- View execution flow -> ce_break_and_trace (dynamic, real execution)\n' +
          '- Safely understand algorithm -> ce_symbolic_trace (static, no execution)\n' +
          '- Function structure -> ce_build_cfg + ce_detect_patterns\n' +
          '- Static analysis (calls/jumps/refs) -> ce_analyze_code\n' +
          '- Data flow tracing -> ce_trace_dataflow / ce_program_slice\n' +
          '- Find what reads/writes an address -> ce_find_what_accesses / ce_find_what_writes\n' +
          '- Find callers of a function -> ce_find_call_references\n' +
          '- Find code referencing an address -> ce_find_references\n' +
          '- Compare two functions -> ce_compare_functions\n' +
          '- Module overview (all functions/strings) -> ce_dissect_code\n\n' +
          '### Q: How to debug/trace?\n' +
          '- Single capture (function args) -> ce_break_and_get_regs\n' +
          '- Step-by-step trace -> ce_break_and_trace\n' +
          '- Non-blocking monitor -> ce_hook_function + ce_get_hook_log\n' +
          '- Set breakpoint -> ce_set_breakpoint (execute/write/access)\n' +
          '- Pause/resume game -> ce_pause_process / ce_resume_process\n' +
          '- Control speed -> ce_speedhack\n' +
          '- Read/modify registers -> ce_get_set_context (when broken)\n' +
          '- Thread-specific breakpoint -> ce_thread_breakpoint\n' +
          '- Start debugger with anti-debug bypass -> ce_debug_start(interface=2 for VEH)\n\n' +
          '### Q: How to work with symbols/pointers?\n' +
          '- Resolve expression to address -> ce_get_address\n' +
          '- Get symbol info at address -> ce_get_symbol\n' +
          '- Resolve pointer chain -> ce_resolve_pointer\n' +
          '- Register custom symbol -> ce_register_symbol\n' +
          '- Get RTTI class name -> ce_get_rtti\n' +
          '- Wait for symbols to load -> ce_symbol_control\n\n' +
          '### Q: How to inject/modify code?\n' +
          '- Simple AA script -> ce_auto_assemble\n' +
          '- Complex injection -> ce_compile_c_code (C with TCC)\n' +
          '- DLL injection -> ce_inject_dll\n' +
          '- .NET DLL injection -> ce_inject_dotnet_dll\n' +
          '- Make memory writable+executable -> ce_full_access\n' +
          '- Generate hook script -> ce_generate_api_hook_script\n' +
          '- Allocate code cave -> ce_allocate_memory(protection="rwx")\n\n' +
          '### Q: How to work with .NET/Unity?\n' +
          '- Analyze managed objects -> ce_dotnet_analyze (domains/modules/types/fields/objects)\n' +
          '- Compile and inject C# -> ce_compile_c_sharp + ce_inject_dotnet_dll\n\n' +
          '### Q: How to work with structures?\n' +
          '- Define struct layout -> ce_structure_manage (create/add_field/get)\n' +
          '- Infer struct from memory -> ce_analyze_struct_access\n' +
          '- Trace struct field access -> ce_trace_struct_access\n\n' +
          '### Q: How to work with files/tables?\n' +
          '- Save/load cheat table -> ce_save_table / ce_load_table\n' +
          '- Dump memory to file -> ce_dump_memory / ce_write_region_to_file\n' +
          '- Load file into memory -> ce_read_region_from_file\n' +
          '- File integrity check -> ce_md5_file / ce_file_version\n\n' +
          '### Q: Other utilities?\n' +
          '- Disassemble bytes/instructions -> ce_disassemble / ce_disassemble_bytes\n' +
          '- Assemble instruction to bytes -> ce_assemble_instruction\n' +
          '- Generate AOB signature -> ce_generate_signature\n' +
          '- Check AA script syntax -> ce_check_assemble\n' +
          '- Convert types -> ce_type_conversion\n' +
          '- Execute arbitrary Lua -> ce_execute_lua (last resort)\n' +
          '- Clean up all breakpoints/hooks -> ce_cleanup\n\n' +
          '## Workflow Templates\n\n' +
          '### 1. Value Hunting (find unknown address)\n' +
          "1. ce_attach_process(target='game.exe')\n" +
          "2. ce_scan_new(value='100', type='dword') -> returns session_id\n" +
          '3. [Take damage in game, health becomes 95]\n' +
          "4. ce_scan_next(session_id, value='95', scan_type='exact') -> count decreases\n" +
          '5. Repeat steps 3-4 until count < 10\n' +
          '6. ce_scan_results(session_id) -> get candidate addresses\n' +
          "7. ce_read_memory(address, type='dword') -> verify correct address\n" +
          '8. ce_scan_close(session_id) -> release resources (max 5 concurrent!)\n\n' +
          '### 2. Pointer Tracing (make address stable)\n' +
          "Method A (auto, try first): ce_find_pointer_path(address='0x12345678', user_prompted=true)\n" +
          'Method B (manual, if A fails):\n' +
          "1. ce_find_what_accesses(address='0x12345678', user_prompted=true, duration_ms=10000)\n" +
          '2. Get register value from result (e.g., RBX=0x255D5E758)\n' +
          "3. ce_value_scan(value='0x255D5E758', type='qword')\n" +
          '4. Find result with isStatic=true -> that\'s your base pointer!\n\n' +
          '### 3. Function Monitoring (non-blocking)\n' +
          "1. ce_hook_function(address='game.exe+12345', name='damageHook')\n" +
          '2. [Let game run, trigger events]\n' +
          "3. ce_get_hook_log(name='damageHook') -> captured args (x64: RCX,RDX,R8,R9)\n" +
          "4. ce_unhook_function(name='damageHook') -> cleanup when done\n\n" +
          '### 4. Code Analysis\n' +
          "1. ce_find_function_boundaries(address='game.exe+12345') -> get function start/end\n" +
          "2. ce_build_cfg(address=function_start) -> control flow graph\n" +
          "3. ce_detect_patterns(address=function_start) -> identify patterns (crypto, anti-debug, vtable)\n" +
          "4. ce_analyze_code(address=function_start) -> calls, jumps, memory refs\n\n" +
          '### 5. Code Injection (hook a function)\n' +
          "1. ce_aob_scan_unique(aob_string='48 89 5C 24 ?? 48 83 EC 20') -> find target address\n" +
          "2. ce_allocate_memory(size=4096, protection='rwx') -> code cave\n" +
          "3. ce_assemble_instruction(instruction='mov eax, 1337') -> get bytes\n" +
          "4. ce_write_memory(address=cave_addr, type='bytes', value=patch_bytes)\n" +
          "5. ce_auto_assemble(script='...') -> install hook\n\n" +
          '### 6. .NET/Unity Analysis\n' +
          "1. ce_dotnet_analyze(operation='domains') -> list app domains\n" +
          "2. ce_dotnet_analyze(operation='modules', domain_handle=X) -> list modules\n" +
          "3. ce_dotnet_analyze(operation='typedefs', module_handle=Y) -> list classes\n" +
          "4. ce_dotnet_analyze(operation='fields', module_handle=Y, typedef_token=Z) -> list fields\n" +
          "5. ce_dotnet_analyze(operation='objects', module_handle=Y, typedef_token=Z) -> find instances\n\n" +
          '### 7. Debugging\n' +
          "1. ce_debug_start(interface=2) -> VEH debugger (bypasses anti-debug)\n" +
          "2. ce_set_breakpoint(address='game.exe+12345', type='execute')\n" +
          '3. [Game breaks at breakpoint]\n' +
          "4. ce_get_set_context() -> read all registers\n" +
          "5. ce_debug_continue(method='run') -> resume execution\n" +
          "6. ce_detach_debugger() -> cleanup when done\n\n" +
          '## Tool Comparison (Correct vs Wrong)\n' +
          '| Purpose | Correct | Wrong |\n' +
          '| Find game values | ce_scan_new | ce_value_scan |\n' +
          '| Find code signature | ce_aob_scan | ce_scan_new |\n' +
          '| Find unique signature | ce_aob_scan_unique | ce_aob_scan |\n' +
          '| Batch read memory | ce_read_memory_batch | multiple ce_read_memory |\n' +
          '| Batch write memory | ce_write_memory_batch | multiple ce_write_memory |\n' +
          '| Monitor function | ce_hook_function | ce_break_and_get_regs |\n' +
          '| Find what writes only | ce_find_what_writes | ce_find_what_accesses |\n' +
          '| Find what reads+writes | ce_find_what_accesses | ce_find_what_writes |\n' +
          '| Safe code analysis | ce_symbolic_trace | ce_break_and_trace |\n' +
          '| Make memory RWX | ce_full_access | ce_set_memory_protection |\n\n' +
          '## System Limits\n' +
          '- Scan sessions: max 5 (auto-expire after 5 min inactivity)\n' +
          '- Hardware breakpoints: max 4 (shared by F5/F6/trace)\n' +
          '- Hook buffer: 64 records (circular, oldest overwritten when full)\n' +
          '- Pointer depth: max 10 levels\n' +
          '- Message size: 10MB per request/response\n\n' +
          '## Common Errors\n' +
          "- 'Process not attached' -> call ce_attach_process first\n" +
          "- 'Too many scan sessions' -> ce_scan_list() then ce_scan_close()\n" +
          "- 'Hardware breakpoint limit' -> ce_cleanup() to clear all\n" +
          "- 'Hook name already exists' -> ce_unhook_function(name) first\n" +
          "- 'Debugger not active' -> ce_debug_start() first\n" +
          "- 'Symbol not found' -> ce_symbol_control(operation='load_new') to refresh"
        ),
      },
    };
  }

  _handleToolsList(reqId) {
    return {
      jsonrpc: '2.0',
      id: reqId,
      result: { tools: this.toolRegistry.getAllSchemas() },
    };
  }

  async _handleToolsCall(reqId, params) {
    const toolName = params.name || '';
    const toolArgs = params.arguments || {};

    try {
      const result = await this.executeTool(toolName, toolArgs);

      // Check if error: has error field, success=false, and no partial results
      let isError = false;
      if (typeof result === 'object' && result !== null && result.error) {
        const hasPartialResult = ['chain', 'path', 'partialCENotation', 'finalAddress', 'final_address', 'ceNotation', 'ce_pointer_notation'].some(k => k in result);
        isError = !hasPartialResult;
      }

      const text = isError
        ? `Error: ${result.error}`
        : JSON.stringify(result, null, 2);

      return {
        jsonrpc: '2.0',
        id: reqId,
        result: {
          content: [{ type: 'text', text }],
          isError: isError,
        },
      };
    } catch (err) {
      return this._errorResponse(reqId, -32603, err.message);
    }
  }

  _errorResponse(reqId, code, message) {
    return {
      jsonrpc: '2.0',
      id: reqId,
      error: { code, message },
    };
  }

  async run() {
    log.info('Cheat Engine MCP Bridge Started. Waiting for input...');
    log.info(`Node.js version: ${process.version}`);

    // Use raw stdin/stdout for MCP protocol - no readline to avoid buffering issues
    process.stdin.setEncoding('utf8');
    
    let buffer = '';
    
    process.stdin.on('data', async (chunk) => {
      buffer += chunk;
      
      // Process complete lines
      let lines = buffer.split('\n');
      buffer = lines.pop(); // Keep incomplete line in buffer
      
      for (const line of lines) {
        if (!line.trim()) continue;
        
        this.requestCount++;
        
        try {
          const request = JSON.parse(line);
          const response = this.handleRequest(request);
          
          if (response) {
            // Handle async tool calls
            if (response instanceof Promise) {
              const result = await response;
              process.stdout.write(JSON.stringify(result) + '\n');
            } else {
              process.stdout.write(JSON.stringify(response) + '\n');
            }
          }
        } catch (err) {
          if (err instanceof SyntaxError) {
            log.error(`Failed to decode JSON: ${err.message}`);
          } else {
            log.error(`Critical Error (request #${this.requestCount}): ${err.stack}`);
          }
        }
      }
    });

    process.stdin.on('end', () => {
      log.info('Received end of input');
      this.pipeClient.stop();
      log.info(`Server Stopped (processed ${this.requestCount} requests)`);
      process.exit(0);
    });

    // Handle graceful shutdown
    process.on('SIGINT', () => {
      log.info('Received interrupt signal');
      this.pipeClient.stop();
      log.info(`Server Stopped (processed ${this.requestCount} requests)`);
      process.exit(0);
    });

    process.on('SIGTERM', () => {
      log.info('Received terminate signal');
      this.pipeClient.stop();
      log.info(`Server Stopped (processed ${this.requestCount} requests)`);
      process.exit(0);
    });
  }
}

// ============ Entry Point ============
function main() {
  const server = new CEMCPServer();
  
  // Handle uncaught exceptions to prevent crash
  process.on('uncaughtException', (err) => {
    log.error(`Uncaught Exception: ${err.message}`);
    log.error(err.stack);
    // Don't exit, try to continue
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    log.error(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
    // Don't exit, try to continue
  });
  
  server.run();
}

main();
