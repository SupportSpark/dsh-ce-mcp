English | [中文](README_CN.md)

# Cheat Engine MCP - AI-Assisted Reverse Engineering

MCP bridge enabling AI assistants to directly control Cheat Engine for game hacking and reverse engineering. **Provides 127 tools** across 14 categories.

## Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Connection Features](#connection-features)
- [Security Features](#security-features)
- [Tool Reference](#tool-reference)
  - [System & Connection](#system--connection)
  - [Memory Read/Write](#memory-readwrite)
  - [Scanning & Search](#scanning--search)
  - [Scan Sessions](#scan-sessions)
  - [Symbols & Addresses](#symbols--addresses)
  - [Disassembly & Code Analysis](#disassembly--code-analysis)
  - [Debugging & Breakpoints](#debugging--breakpoints)
  - [Analysis Tools](#analysis-tools)
  - [Advanced Analysis](#advanced-analysis)
  - [Code Emulation](#code-emulation)
  - [Memory Management](#memory-management)
  - [Process Control](#process-control)
  - [Injection](#injection)
  - [Debug Advanced](#debug-advanced)
  - [File Operations](#file-operations)
  - [Window Operations](#window-operations)
  - [Kernel Operations](#kernel-operations)
  - [Type Conversion](#type-conversion)
  - [Function Hooking](#function-hooking)
  - [Cheat Table](#cheat-table)
- [Recommended Workflows](#recommended-workflows)
- [Troubleshooting](#troubleshooting)
- [Version](#version)

## Architecture

```
AI <--MCP/JSON-RPC--> ce_mcp_server.js <--Named Pipe--> ce_mcp_bridge.lua (CE)
                           ↑
                  Background auto-reconnect
```

## Installation

### Quick Start (NPX) - Recommended

1. **Prerequisites**: Node.js 14+ (no other dependencies needed)

2. **Load in CE** (choose one):
   - **Auto-load**: Copy `ce_mcp_bridge.lua` to CE's `autorun` folder (e.g. `D:\Cheat Engine\autorun\`)
   - **Manual**: Press `Ctrl+Alt+L`, execute:
     ```lua
     dofile([[D:\path\to\ce_mcp_bridge.lua]])
     ```

3. **Configure MCP**:
   ```json
   {
     "mcpServers": {
       "cheat-engine": {
         "command": "npx",
         "args": ["-y", "cheatengine@latest"]
       }
     }
   }
   ```

### Manual Installation (Local)

If you prefer to run from source:

```json
{
  "mcpServers": {
    "cheat-engine": {
      "command": "node",
      "args": ["D:/path/to/ce_mcp/ce_mcp_server.js"]
    }
  }
}
```

## Connection Features

- **Auto-reconnect**: MCP Server automatically reconnects when CE restarts
- **Background retry**: Connection attempts run in background with exponential backoff
- **Diagnostic on failure**: `ce_ping` returns detailed diagnostic info when connection fails
- **Thread-safe**: All pipe operations are protected by locks

## Security Features

### Hook Name Validation

Hook names are validated to prevent AA script injection:
- Must start with letter or underscore
- Can only contain alphanumeric characters and underscores
- Pattern: `^[a-zA-Z_][a-zA-Z0-9_]*$`

Invalid names like `"my hook"` or `"hook;inject"` will be rejected.

---

## Tool Reference

### System & Connection

| Tool | Description |
|------|-------------|
| `ce_ping` | Test connection. Returns diagnostic info with troubleshooting suggestions on failure. |
| `ce_get_process_info(refresh_symbols?)` | Get attached process info: `{name, pid, is64bit, ce_version, debugger, symbols_ready, module_count}`. Set `refresh_symbols=true` before `ce_get_symbol` (can be slow 60-120s on first call). |
| `ce_attach_process(target)` | Attach to process by PID or name. Clears caches and scan sessions. |
| `ce_auto_assemble(script, target_self?, disable?, disable_info?)` | Execute AA script. Default: `[ENABLE]` section. Set `disable=true` + `disable_info` from previous run to execute `[DISABLE]`. Returns `{success, target_self, disableInfo?, action?}`. |
| `ce_execute_lua(code)` | Execute arbitrary Lua code in CE. |
| `ce_get_stats` | Bridge statistics: `{uptime, commands, summary, cache, scanSessions, connections, debugger}`. |
| `ce_get_logs(count?, min_level?)` | Log entries for debugging. `count` default 50, `min_level` default `INFO`. |

### Memory Read/Write

| Tool | Description |
|------|-------------|
| `ce_read_memory(address, type, size?, signed?)` | Read single value. `type`: byte/word/dword/qword/float/double/string/bytes. `signed` for word/dword. |
| `ce_read_memory_batch(requests)` | Read multiple addresses in one call. **Always prefer over multiple ce_read_memory.** `requests`: `[{address, type, id?, size?}]` |
| `ce_write_memory(address, type, value)` | Write value to memory. Returns `{success, address}`. |

### Scanning & Search

| Tool | Description |
|------|-------------|
| `ce_aob_scan(aob_string, module?, protection?, start?, stop?, max_results?)` | Scan for byte pattern with `??` wildcard support. Default protection: `"+X-C-W"`. |
| `ce_aob_scan_unique(aob_string, module?, protection?, start?, stop?)` | Scan for UNIQUE byte pattern - first match only. Much faster when expecting one result. Returns `{found, address}` or `{found: false}`. |
| `ce_check_assemble(script, enable?)` | Validate AA script syntax without executing. Returns `{valid, error_message}`. |
| `ce_dissect_code(module, analyze_functions?)` | Analyze all code in module using CE DissectCode. Returns `{module, functions, referenced_strings, stats}`. |
| `ce_dbvm_cloak(operation, address, virtual_address?)` | Hide modified code pages from anti-cheat using DBVM. Operations: `activate/deactivate/read_original/write_original`. |
| `ce_value_scan(value, type, module?, protection?, start?, stop?, max_results?, is_hex?)` | One-shot value scan for pointer tracing. Default protection: `"+W-C"`. **For iterative scanning use Scan Sessions.** |

### Scan Sessions

Implements CE's core "First Scan → Next Scan" workflow. Sessions auto-expire after 5 min inactivity. Max 5 concurrent sessions.

| Tool | Description |
|------|-------------|
| `ce_scan_new(value, type, module?, protection?)` | Start new scan session. Auto-aligns by type (4-byte for dword/float, 8-byte for qword/double). |
| `ce_scan_next(session_id, value, scan_type?, value2?)` | Filter existing session. `scan_type`: exact/increased/decreased/changed/unchanged/bigger_than/smaller_than/between. |
| `ce_scan_results(session_id, start_index?, limit?)` | Get paginated results. |
| `ce_scan_close(session_id)` | Close session and release resources. |
| `ce_scan_list` | List all active scan sessions. |
| `ce_enum_modules` | List loaded modules: `{count, modules: [{name, address, size, path, source}], used_fallback}`. |

### Symbols & Addresses

| Tool | Description |
|------|-------------|
| `ce_get_address(expression)` | Resolve address expression to numeric address. Supports nested: `"[[game.exe+100]+20]+8"`. |
| `ce_get_symbol(address, include_module?)` | Get symbol name with RTTI class info. |
| `ce_resolve_pointer(base, offsets, read_value?, value_type?)` | Resolve multi-level pointer chain. Returns `ceNotation` for CE address list. |
| `ce_auto_guess(address)` | Guess value type at address. |

### Disassembly & Code Analysis

| Tool | Description |
|------|-------------|
| `ce_disassemble(address, count?, direction?)` | Disassemble instructions. `count` default 10, `direction`: forward/backward. |
| `ce_get_instruction_info(address)` | Detailed single instruction info: `{address, opcode, params, bytes, bytesStr, size, isCall, isJump, isRet, isConditionalJump, parameterValue}`. |
| `ce_analyze_code(address, count?)` | Static analysis of code block (calls, jumps, refs). |

### Debugging & Breakpoints

| Tool | Description |
|------|-------------|
| `ce_set_breakpoint(address, type?, size?)` | Set hardware breakpoint. `type`: execute/write/access. |
| `ce_break_and_get_regs(address, timeout?, include_xmm?, stack_depth?)` | Breakpoint + capture registers + call stack. |
| `ce_break_and_trace(address, max_steps?, timeout?, stop_on_ret?, trace_into_call?, end_address?, initial_regs?)` | **Multi-step execution trace.** Most powerful debug tool. Stop reasons: ret/end_address/max_steps/timeout. |
| `ce_cleanup` | Remove all breakpoints and traces. Use when game freezes. |

### Analysis Tools

| Tool | Description |
|------|-------------|
| `ce_find_what_accesses(address, size?, duration_ms?, max_records?)` | Find code accessing address (CE's F5). Monitors reads+writes. |
| `ce_find_what_writes(address, size?, duration_ms?, max_records?)` | Find code writing to address (CE's F6). Monitors writes only. |
| `ce_find_pointer_path(address, max_depth?, strategy?)` | **Auto pointer chain tracing.** `max_depth` 1-10 (default 7), `strategy`: hybrid/f5/value_scan. |
| `ce_find_references(address, limit?)` | Find all code referencing an address. |
| `ce_find_call_references(address, module?, limit?)` | Find all CALL instructions targeting a function. |
| `ce_find_function_boundaries(address, max_search?)` | Detect function start/end by prologue/epilogue patterns. |
| `ce_generate_signature(address)` | Generate unique AOB signature. Returns `{address, signature, offset_from_start, byte_count, usage_hint}`. |

### Advanced Analysis

| Tool | Description |
|------|-------------|
| `ce_build_cfg(address, max_blocks?, max_instructions?, detect_loops?)` | Build Control Flow Graph. |
| `ce_detect_patterns(address, max_instructions?, patterns?)` | Detect patterns: switch tables, virtual calls, string refs, crypto constants. |
| `ce_compare_functions(address1, address2, max_instructions?)` | Compare two functions for similarity. |
| `ce_trace_dataflow(address, register, direction?, max_instructions?)` | Trace data flow for a register. |
| `ce_program_slice(address, criterion, direction?, max_instructions?)` | Compute program slice - instructions affecting/affected by a variable. |

### Code Emulation

| Tool | Description |
|------|-------------|
| `ce_symbolic_trace(address, count?, initial_state?, stop_on_call?, stop_on_ret?)` | Lightweight symbolic execution. `initial_state`: e.g. `{"rcx": "this_ptr", "rdx": "arg1"}`. |
| `ce_call_function(address, args?, call_method?, return_type?, timeout?)` | Call function in target process. **WARNING: Executes real code!** Up to 4 args. |

### Memory Management

| Tool | Description |
|------|-------------|
| `ce_allocate_memory(size, base_address?, protection?)` | Allocate memory. `protection`: rw/rwx. Returns `{success, address, size}`. |
| `ce_deallocate_memory(address, size?)` | Free allocated memory. |
| `ce_get_memory_protection(address)` | Get page protection: `{address, protection: {r, w, x}, base, regionSize}`. |
| `ce_set_memory_protection(address, size, readable?, writable?, executable?)` | Set page protection flags. |
| `ce_copy_memory(source_address, size, destination_address?, method?)` | Copy memory between regions. |
| `ce_compare_memory(address1, address2, size, method?)` | Compare two memory regions. |
| `ce_full_access(address, size)` | Set memory protection to RWX. |
| `ce_dump_memory(address, size, file_path, mode, verify?)` | Dump/load/compare memory with file. |

### Process Control

| Tool | Description |
|------|-------------|
| `ce_pause_process` | Pause/suspend target process. |
| `ce_resume_process` | Resume/unpause target process. |
| `ce_speedhack(speed)` | Set game speed. 1.0=normal, 0.5=half, 2.0=double. |
| `ce_enum_threads` | Enumerate threads in target process. |
| `ce_enum_handles(filter?)` | Enumerate system handles. |

### Injection

| Tool | Description |
|------|-------------|
| `ce_inject_dll(dll_path, skip_symbol_reload?)` | Inject DLL into target process. |
| `ce_inject_dotnet_dll(dll_path, class_name, method_name, parameters?, timeout?)` | Inject .NET DLL and execute static method. |
| `ce_compile_c_code(code, address?, target_self?)` | Compile C code using CE's TCC compiler and inject. |
| `ce_compile_c_sharp(code, references?)` | Compile C# code, get filename for injection. |

### Debug Advanced

| Tool | Description |
|------|-------------|
| `ce_debug_start(interface)` | Start debugger. `interface`: 0=default, 1=Windows, 2=VEH, 3=Kernel. |
| `ce_debug_status` | Debugger state: `{isDebugging, isBroken, canBreak, interface}`. |
| `ce_debug_continue(method)` | Continue from breakpoint. `method`: run/stepinto/stepover. |
| `ce_get_set_context(register_values?, include_xmm?)` | Get or set full register context when broken. |
| `ce_thread_no_break(operation, thread_id?)` | Exclude/include threads from breakpoints. `operation`: add/remove/list_threads. |
| `ce_debug_break_thread(thread_id)` | Force-break a specific thread. |
| `ce_detach_debugger` | Detach debugger cleanly. |

### File Operations

| Tool | Description |
|------|-------------|
| `ce_md5_file(file_path)` | Calculate MD5 hash of file. |
| `ce_file_version(file_path)` | Get file version info. |
| `ce_file_ops(operation, path, search_mask?, search_subdirs?)` | File ops: exists/delete/list_files/list_dirs. |
| `ce_write_region_to_file(address, size, file_path)` | Write memory region to file. |
| `ce_read_region_from_file(address, file_path)` | Load file into target process memory. |

### Window Operations

| Tool | Description |
|------|-------------|
| `ce_find_window(class_name?, caption?)` | Find windows by class name and/or caption. |
| `ce_enum_windows` | List all top-level windows with PID and caption. |

### Kernel Operations

| Tool | Description |
|------|-------------|
| `ce_allocate_shared_memory(name, size?)` | Create named shared memory mapped into target. |
| `ce_get_physical_address(address)` | Translate virtual to physical address. |

### Type Conversion

| Tool | Description |
|------|-------------|
| `ce_type_conversion(conversion, value, signed?)` | Convert between types. Conversions: word_to_bytes, dword_to_bytes, qword_to_bytes, float_to_bytes, double_to_bytes, string_to_bytes, bytes_to_word, bytes_to_dword, bytes_to_qword, bytes_to_float, bytes_to_double, bytes_to_string. |

### Function Hooking

| Tool | Description |
|------|-------------|
| `ce_hook_function(address, name, capture_args?, capture_return?)` | Hook function to intercept calls. `capture_args` 0-4 (default 4), `capture_return` (default true). Returns `{success, name, address, symbol, capture_args, capture_return, trampoline}`. |
| `ce_get_hook_log(name, limit?, clear?)` | Get captured call arguments. |
| `ce_unhook_function(name)` | Remove function hook. |
| `ce_list_hooks` | List all active hooks. |

### Cheat Table

| Tool | Description |
|------|-------------|
| `ce_get_address_list(include_script?)` | Get all records from Cheat Table. |
| `ce_add_address_record(description, address, value_type?, script?)` | Add new record to Cheat Table. |

---

## Recommended Workflows

### Pointer Tracing

```json
// Automatic (preferred)
{"name": "ce_find_pointer_path", "arguments": {"address": "0x255D5E758"}}
// Returns: base_address, offsets, ce_pointer_notation

// Manual (if automatic fails)
// 1. Find what accesses the address
{"name": "ce_find_what_accesses", "arguments": {"address": "0x255D5E758"}}
// 2. Get register value from result (e.g., RBX=0x255D5E658)
// 3. Search for pointer storing that value
{"name": "ce_value_scan", "arguments": {"value": "0x255D5E658", "type": "qword"}}
// 4. Repeat until finding game.exe+offset
```

### Function Analysis

```json
// 1. Find function boundaries
{"name": "ce_find_function_boundaries", "arguments": {"address": "0x14587EDB0"}}
// 2. Trace execution
{"name": "ce_break_and_trace", "arguments": {"address": "0x14587EDB0", "max_steps": 100}}
// 3. Generate signature for updates
{"name": "ce_generate_signature", "arguments": {"address": "0x14587EDB0"}}
```

### Reverse Engineering Unknown Code

```json
// 1. Disassemble
{"name": "ce_disassemble", "arguments": {"address": "0x14587EDB0", "count": 20}}
// 2. Symbolic trace to understand logic
{"name": "ce_symbolic_trace", "arguments": {"address": "0x14587EDB0", "initial_state": {"rcx": "this"}}}
// 3. Build CFG for complex functions
{"name": "ce_build_cfg", "arguments": {"address": "0x14587EDB0"}}
// 4. Detect patterns
{"name": "ce_detect_patterns", "arguments": {"address": "0x14587EDB0"}}
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection failed | Use `ce_ping` - returns diagnostic info with specific suggestions |
| CE restarted | MCP Server auto-reconnects, just reload the Lua script in CE |
| Pipe error | Run `CE_MCP.stop()` then `CE_MCP.start()` in CE |
| Permission denied | Run CE as administrator |
| Game frozen | Use `ce_cleanup()` to remove all breakpoints |
| Breakpoint not triggering | Ensure code path is executed in game |

## Status Check

```lua
CE_MCP.stats()  -- Check bridge status in CE
reloadMcpBridge()  -- Reload bridge after code changes
```

## References

- [CE Wiki](https://wiki.cheatengine.org/)
- [CE Lua API](https://wiki.cheatengine.org/index.php?title=Lua)

## Version

- **MCP Tools**: 127 tools
- **Categories**: 14 (System, Memory, Scanning, Symbols, Debug, Analysis, Injection, Table, DotNet, Process, FileIO, Window, Kernel, Type Conversion)
- **Lua Bridge**: ~10,400 lines

---

*Last updated: 2026-04-20*
