/**
 * Tool Registry for MCP Tools
 * Defines all 127 tools available in the Cheat Engine MCP Bridge
 */

const ToolCategory = {
  SYSTEM: 'system',
  MEMORY: 'memory',
  SCANNING: 'scanning',
  SYMBOLS: 'symbols',
  DEBUG: 'debug',
  ANALYSIS: 'analysis',
  INJECTION: 'injection',
  TABLE: 'table',
  DOTNET: 'dotnet',
  PROCESS: 'process',
  FILEIO: 'fileio',
  WINDOW: 'window',
  KERNEL: 'kernel',
};

class ToolParam {
  constructor(name, type, description = '', required = false, defaultValue = null, enumValues = null) {
    this.name = name;
    this.type = type;
    this.description = description;
    this.required = required;
    this.default = defaultValue;
    this.enum = enumValues || [];
  }
}

class Tool {
  constructor(name, description, luaCommand, category, params = []) {
    this.name = name;
    this.description = description;
    this.luaCommand = luaCommand;
    this.category = category;
    this.params = params;
  }

  toMCPSchema() {
    const properties = {};
    const required = [];

    for (const p of this.params) {
      const prop = { type: p.type };
      if (p.description) prop.description = p.description;
      if (p.default !== null) prop.default = p.default;
      if (p.enum && p.enum.length > 0) prop.enum = p.enum;
      properties[p.name] = prop;

      if (p.required) {
        required.push(p.name);
      }
    }

    return {
      name: this.name,
      description: this.description,
      inputSchema: {
        type: 'object',
        properties,
        required,
      },
    };
  }
}

class ToolRegistry {
  static MEM_TYPES = ['byte', 'word', 'dword', 'qword', 'float', 'double', 'string', 'bytes'];
  static MEM_TYPES_NO_BYTES = ['byte', 'word', 'dword', 'qword', 'float', 'double', 'string'];
  static MEM_TYPES_WITH_POINTER = ['byte', 'word', 'dword', 'qword', 'float', 'double', 'pointer'];
  static MEM_TYPES_WITH_SCRIPT = ['byte', 'word', 'dword', 'qword', 'float', 'double', 'string', 'bytes', 'script'];

  constructor() {
    this.tools = new Map();
    this.ADDR_PARAM = new ToolParam(
      'address',
      'string',
      "Address expression (e.g. 'game.exe+123' or '0x123456')",
      true
    );
    this._registerAllTools();
  }

  _registerAllTools() {
    this._registerSystemTools();
    this._registerMemoryTools();
    this._registerMemoryManagementTools();
    this._registerScanningTools();
    this._registerScanningEnhancedTools();
    this._registerSymbolTools();
    this._registerSymbolAdvancedTools();
    this._registerDebugTools();
    this._registerDebugAdvancedTools();
    this._registerProcessControlTools();
    this._registerAnalysisTools();
    this._registerInjectionTools();
    this._registerTableTools();
    this._registerDotNetTools();
    this._registerProcessTools();
    this._registerFileTools();
    this._registerWindowTools();
    this._registerKernelTools();
    this._registerTypeConversionTools();
  }

  _register(tool) {
    this.tools.set(tool.name, tool);
  }

  _registerSystemTools() {
    this._register(new Tool(
      'ce_ping',
      'Test connection to Cheat Engine and get bridge status. ' +
      'If connection fails, automatically returns diagnostic info with troubleshooting suggestions. ' +
      'Returns: {status, timestamp, process, pid, connections, debugger}.',
      'ping',
      ToolCategory.SYSTEM
    ));

    this._register(new Tool(
      'ce_get_process_info',
      '[INIT] Get current attached process info. CALL THIS FIRST in any session. ' +
      'Returns: {name, pid, is64bit, ce_version, debugger, symbols_ready, last_symbol_refresh, symbol_refresh_count, module_count, speedhack_speed, thread_count}. ' +
      'By default returns basic info instantly without symbol refresh. ' +
      'Set refresh_symbols=true to trigger symbol handler refresh (can be slow on first call for large processes). ' +
      'Symbol refresh is needed before ce_get_symbol can resolve symbols.',
      'get_process_info',
      ToolCategory.SYSTEM,
      [new ToolParam('refresh_symbols', 'boolean', 'Trigger symbol handler refresh (slow on first call)', false, false)]
    ));

    this._register(new Tool(
      'ce_execute_lua',
      'Execute Lua code with full access to CE APIs. ' +
      'USE WHEN: No existing tool covers your need, or you need custom CE scripting. ' +
      'CAUTION: Can crash the game if code is wrong. Returns: {result}.',
      'execute_lua',
      ToolCategory.SYSTEM,
      [new ToolParam('code', 'string', 'Lua code to execute', true)]
    ));

    this._register(new Tool(
      'ce_list_processes',
      'List running processes. ' +
      'USE WHEN: Finding the game process to attach to before using ce_attach_process. ' +
      'Returns: {count, processes: [{pid, name}]}.',
      'list_processes',
      ToolCategory.SYSTEM,
      [
        new ToolParam('filter', 'string', 'Filter processes by name (case-insensitive substring match)'),
        new ToolParam('max_results', 'integer', 'Maximum results to return (default: 100)', false, 100),
      ]
    ));

    this._register(new Tool(
      'ce_attach_process',
      'Attach to a process by PID or name. ' +
      'USE WHEN: Starting analysis on a game/process, must be called before most other tools work. ' +
      'Clears caches and scan sessions after attaching. ' +
      'Returns: {success, pid, name, is64bit}.',
      'attach_process',
      ToolCategory.SYSTEM,
      [new ToolParam('target', 'string', "Process ID (number) or process name (e.g. 'game.exe')", true)]
    ));

    this._register(new Tool(
      'ce_auto_assemble',
      'Execute Auto Assembler script with enhanced error handling. ' +
      'SUPPORTS: All CE AA commands - alloc, dealloc, globalalloc, createalloc, registersymbol, unregistersymbol, label, define, aobscan, aobscanmodule, aobscanregion, writebytes, readmem, fullaccess, include, loadbinary, assert, struct, luaCall, and inline assembly. ' +
      'LIMITATIONS (CE engine limits, not MCP): Complex x64 instructions may fail; large immediates (>32-bit) unsupported; define() macro with nested substitution may be unreliable; readmem() after jmp overwrite reads wrong bytes (use pre-read + db instead). ' +
      'WORKAROUND: Use ce_assemble_instruction + ce_write_memory for complex code. ' +
      'Returns: {success, target_self, disableInfo?, action?}. ' +
      'disableInfo contains alloc addresses, registered symbols, ccode symbols, and exception list for cleanup.',
      'auto_assemble',
      ToolCategory.SYSTEM,
      [
        new ToolParam('script', 'string', 'Auto Assembler script content. Supports all CE AA commands: alloc/dealloc, registersymbol/unregistersymbol, label, define, aobscan, fullaccess, writebytes, readmem, assert, include, and inline assembly.', true),
        new ToolParam('target_self', 'boolean', 'Target CE process itself (for internal scripts)', false, false),
        new ToolParam('disable', 'boolean', 'Execute [DISABLE] section with previous disableInfo', false, false),
        new ToolParam('disable_info', 'object', 'Previous disableInfo object from successful enable (required when disable=true)'),
      ]
    ));

    this._register(new Tool(
      'ce_get_stats',
      'Get bridge execution statistics including uptime, per-command metrics, cache hit rates, and scan session info. ' +
      'Returns: {uptime, commands, summary, cache, scanSessions, sessions, connections, debugger, active, logging, maxAllowed}.',
      'stats',
      ToolCategory.SYSTEM
    ));

    this._register(new Tool(
      'ce_get_logs',
      'Get log entries from the bridge. Useful for debugging connection issues or understanding internal behavior. ' +
      'Returns: {entries: [{timestamp, level, category, message}], totalEntries, currentLevel}.',
      'get_logs',
      ToolCategory.SYSTEM,
      [
        new ToolParam('count', 'integer', 'Maximum number of entries to return (default 50)', false, 50),
        new ToolParam('min_level', 'string', 'Minimum log level to include', false, 'INFO', ['DEBUG', 'INFO', 'WARN', 'ERROR']),
      ]
    ));
  }

  _registerMemoryTools() {
    this._register(new Tool(
      'ce_read_memory',
      'Read single memory value. ' +
      'PERFORMANCE: Use ce_read_memory_batch for multiple reads. ' +
      'TYPES: byte(8), word(16), dword(32), qword(64), float, double, string, bytes, integer(auto). ' +
      'NOTE: type="integer" auto-converts to dword or qword based on process bitness. ' +
      'Returns: {value}. ' +
      'EXAMPLE: address="game.exe+1234", type="dword" → {value: 1337}',
      'read_memory',
      ToolCategory.MEMORY,
      [
        this.ADDR_PARAM,
        new ToolParam('type', 'string', 'Data type: byte/word/dword/qword/float/double/string/bytes', true, null, ToolRegistry.MEM_TYPES),
        new ToolParam('size', 'integer', 'Size in bytes (for string/bytes types only)', false, 100),
        new ToolParam('signed', 'boolean', 'Interpret as signed integer (word/dword types)', false, false),
        new ToolParam('widechar', 'boolean', 'Read as wide/UTF-16 string (string type only)', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_read_memory_batch',
      '[PERFORMANCE] Read multiple memory addresses in ONE request. ' +
      'ALWAYS prefer this over multiple ce_read_memory calls for better performance. ' +
      'Example: [{"address": "game.exe+100", "type": "dword", "id": "hp"}, {"address": "game.exe+104", "type": "float", "id": "mp"}]. ' +
      'Returns: {results: {id_or_address: {value, error?}}}.',
      'read_memory_batch',
      ToolCategory.MEMORY,
      [new ToolParam('requests', 'array', 'Array of {address, type, id?, size?} objects', true)]
    ));

    this._register(new Tool(
      'ce_write_memory',
      'Write memory value. ' +
      'PERFORMANCE: Use ce_write_memory_batch for multiple writes. ' +
      'TYPES: Same as read_memory. byte arrays as hex string. ' +
      'Returns: {success, address}. ' +
      'EXAMPLE: address="0x123456", type="dword", value="1337" → {success: true}',
      'write_memory',
      ToolCategory.MEMORY,
      [
        this.ADDR_PARAM,
        new ToolParam('type', 'string', 'Data type (same options as read_memory)', true, null, ToolRegistry.MEM_TYPES),
        new ToolParam('value', 'string', 'Value: number, string, or space-separated hex bytes (e.g. "B8 37 13 00 00")', true),
        new ToolParam('widechar', 'boolean', 'Write as wide/UTF-16 string (string type only)', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_write_memory_batch',
      '[PERFORMANCE] Write multiple memory addresses in ONE request. ' +
      'ALWAYS prefer this over multiple ce_write_memory calls for better performance. ' +
      'Example: [{"address": "game.exe+100", "type": "dword", "value": "999"}, {"address": "game.exe+104", "type": "float", "value": "1.5"}]. ' +
      'Returns: {results: [{address, success, error?}]}.',
      'write_memory_batch',
      ToolCategory.MEMORY,
      [new ToolParam('requests', 'array', 'Array of {address, type, value} objects', true)]
    ));
  }

  _registerMemoryManagementTools() {
    this._register(new Tool(
      'ce_allocate_memory',
      'Allocate memory for code caves, hooks, data buffers. ' +
      'SUCCESS: Returns {success, address, size} with executable memory. ' +
      'FAILURE: Try smaller size or specify base_address near existing code. ' +
      'PROTECTION: Use "rwx" for code injection, "rw" for data. ' +
      'Returns: {success, address, size}.',
      'allocate_memory',
      ToolCategory.MEMORY,
      [
        new ToolParam('size', 'integer', 'Bytes to allocate (try 64-1024 for starters)', true),
        new ToolParam('base_address', 'string', 'Preferred address (optional, e.g. "0x10000000")'),
        new ToolParam('protection', 'string', 'Protection flags: "rwx" (exec), "rw" (data), "rx" (code)', false, 'rw'),
      ]
    ));

    this._register(new Tool(
      'ce_deallocate_memory',
      'Free previously allocated memory in the target process. ' +
      'USE WHEN: Cleaning up after code injection, freeing code caves allocated by ce_allocate_memory. ' +
      'Returns: {success, address}.',
      'deallocate_memory',
      ToolCategory.MEMORY,
      [
        new ToolParam('address', 'string', 'Address of previously allocated memory block', true),
        new ToolParam('size', 'integer', 'Size to free (optional, 0 = free all from address)'),
      ]
    ));

    this._register(new Tool(
      'ce_get_memory_protection',
      'Get memory page protection flags for an address. ' +
      'USE WHEN: Checking if memory is writable/executable before code patching. ' +
      'Returns: {address, protection: {r, w, x}}.',
      'get_memory_protection',
      ToolCategory.MEMORY,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_set_memory_protection',
      'Set memory page protection flags. USE WHEN: Making code writable for patching, ' +
      'making memory executable for injection. ' +
      'Returns: {success, address, protection: {r, w, x}}.',
      'set_memory_protection',
      ToolCategory.MEMORY,
      [
        this.ADDR_PARAM,
        new ToolParam('size', 'integer', 'Size of the region to change', true),
        new ToolParam('readable', 'boolean', 'Allow read access', false, true),
        new ToolParam('writable', 'boolean', 'Allow write access', false, true),
        new ToolParam('executable', 'boolean', 'Allow execute access', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_copy_memory',
      'Copy memory between regions. Supports 4 modes: ' +
      '0=target-to-target, 1=target-to-CE, 2=CE-to-target, 3=CE-to-CE. ' +
      'If no destination address given, CE allocates one automatically. ' +
      'Returns: {success, source, destination, size, method}.',
      'copy_memory',
      ToolCategory.MEMORY,
      [
        new ToolParam('source_address', 'string', 'Source address', true),
        new ToolParam('size', 'integer', 'Number of bytes to copy', true),
        new ToolParam('destination_address', 'string', 'Destination address (omit to auto-allocate)'),
        new ToolParam('method', 'integer', 'Copy mode: 0=target->target, 1=target->CE, 2=CE->target, 3=CE->CE', false, 0),
      ]
    ));

    this._register(new Tool(
      'ce_compare_memory',
      'Compare two memory regions. USE WHEN: Detecting code modifications, ' +
      'checking if patches were applied, verifying memory state. ' +
      'Returns: {match, result, firstDifferenceOffset?}.',
      'compare_memory',
      ToolCategory.MEMORY,
      [
        new ToolParam('address1', 'string', 'First memory address', true),
        new ToolParam('address2', 'string', 'Second memory address', true),
        new ToolParam('size', 'integer', 'Number of bytes to compare', true),
        new ToolParam('method', 'integer', 'Compare mode: 0=target-to-target, 1=addr1=target/addr2=CE, 2=both-CE', false, 0),
      ]
    ));

    this._register(new Tool(
      'ce_enum_memory_regions',
      'Enumerate ALL memory regions in the process. More comprehensive than ce_get_region_info. ' +
      'USE WHEN: Finding writable/executable regions for code injection, understanding process memory layout. ' +
      'Returns: {count, regions: [{baseAddress, allocationBase, allocationProtect, regionSize, state, protect, type}]}.',
      'enum_memory_regions',
      ToolCategory.MEMORY
    ));
  }

  _registerScanningTools() {
    this._register(new Tool(
      'ce_aob_scan',
      "Scan for byte pattern (AOB/signature) in memory. Supports ?? wildcards for variable bytes. " +
      "USE WHEN: Finding code by signature, locating functions, making version-independent scripts. " +
      "NOT FOR: Finding data values (use ce_scan_new or ce_value_scan). " +
      "Returns: {count, results: [addresses], truncated, module}.",
      'aob_scan',
      ToolCategory.SCANNING,
      [
        new ToolParam('aob_string', 'string', "e.g. '48 89 5C 24 ?? 48 83 EC 20'", true),
        new ToolParam('module', 'string', "Limit scan to specific module for better performance (e.g. 'game.exe', 'UnityPlayer.dll')"),
        new ToolParam('protection', 'string', 'Flags like +X-C-W', false, '+X-C-W'),
        new ToolParam('start', 'string', 'Start address (optional). If module is not specified, this defines the start of the scan range.'),
        new ToolParam('stop', 'string', 'Stop address (optional). If module is not specified, this defines the end of the scan range.'),
        new ToolParam('max_results', 'integer', 'Maximum results', false, 100),
      ]
    ));

    this._register(new Tool(
      'ce_value_scan',
      '[MANUAL POINTER TRACING - STEP 2] Scan memory for a specific value. ' +
      'USE WHEN: After ce_find_what_accesses returns a register value, search for that value to find pointer storage. ' +
      "Example: RBX=0x12345678 accessed your address -> scan for 0x12345678 (qword) -> find where pointer is stored. " +
      "NOT FOR: Finding game values like health/gold (use ce_scan_new for value hunting). " +
      'Auto-aligns scan based on type for performance (4-byte for dword/float, 8-byte for qword/double). ' +
      'Returns: {count, results: [{address, symbol, isStatic}], value_searched, type, module, truncated}. ' +
      'TIP: isStatic=true means the address is in a module (potential static base found!).',
      'value_scan',
      ToolCategory.SCANNING,
      [
        new ToolParam('value', 'string', "Value to search for (e.g. '0x255D5E758' or '12345')", true),
        new ToolParam('type', 'string', 'Value type', true, null, ToolRegistry.MEM_TYPES_NO_BYTES),
        new ToolParam('module', 'string', "Limit scan to specific module (e.g. 'game.exe')"),
        new ToolParam('protection', 'string', 'Memory protection flags (default: \'+W-C\' for writable memory)', false, '+W-C'),
        new ToolParam('start', 'string', 'Start address (optional)'),
        new ToolParam('stop', 'string', 'Stop address (optional)'),
        new ToolParam('max_results', 'integer', 'Maximum results', false, 100),
        new ToolParam('is_hex', 'boolean', 'Treat value as hexadecimal (auto-detected if omitted)'),
      ]
    ));

    this._register(new Tool(
      'ce_scan_new',
      '[VALUE HUNTING] Find unknown addresses by observing changes. ' +
      'WORKFLOW: scan_new → change value → scan_next → repeat until few results. ' +
      'EXAMPLE: health 100→95→scan_next(decreased) → find health address. ' +
      'PERFORMANCE: Auto-aligned scanning (4-byte for dword/float, 8-byte for qword/double). ' +
      'LIMIT: Maximum concurrent scan sessions enforced; close old sessions with scan_close if limit reached. ' +
      'Returns: {session_id, count, scan_number, type, value_searched, module}. Use ce_scan_next to filter, ce_scan_results for addresses.',
      'scan_new',
      ToolCategory.SCANNING,
      [
        new ToolParam('value', 'string', "Known value (e.g. '100', '0x64'). Skip for 'unknown' scan", false),
        new ToolParam('type', 'string', 'Data type: byte/word/dword/qword/float/double/string', true, null, ToolRegistry.MEM_TYPES_NO_BYTES),
        new ToolParam('scan_type', 'string', "'exact' (known value) or 'unknown' (no initial value)", false, 'exact', ['exact', 'unknown']),
        new ToolParam('module', 'string', 'Limit to specific module (e.g. "game.exe")'),
        new ToolParam('protection', 'string', 'Memory protection flags (default "+W-C")', false, '+W-C'),
        new ToolParam('start', 'string', 'Start address (optional)'),
        new ToolParam('stop', 'string', 'Stop address (optional)'),
        new ToolParam('is_hex', 'boolean', 'Treat value as hexadecimal (auto-detected)'),
      ]
    ));

    this._register(new Tool(
      'ce_scan_next',
      'Continue scanning (filter) an existing session. Supports various scan types. ' +
      'USE WHEN: Narrowing down scan results after initial scan with ce_scan_new. ' +
      'Returns: {session_id, count, scan_number, scan_type, value_searched}.',
      'scan_next',
      ToolCategory.SCANNING,
      [
        new ToolParam('session_id', 'string', 'Session ID from ce_scan_new', true),
        new ToolParam('value', 'string', 'Value to search for', true),
        new ToolParam('scan_type', 'string', 'Scan type for filtering', false, 'exact', 
          ['exact', 'increased', 'decreased', 'changed', 'unchanged', 'increased_by', 'decreased_by', 'bigger_than', 'smaller_than', 'between']),
        new ToolParam('value2', 'string', "Second value for 'between' scan type"),
        new ToolParam('is_hex', 'boolean', 'Treat value as hexadecimal'),
      ]
    ));

    this._register(new Tool(
      'ce_scan_results',
      'Get paginated results from a scan session. ' +
      'USE WHEN: Retrieving addresses found by ce_scan_new/ce_scan_next. ' +
      'Returns: {session_id, total_count, start_index, returned_count, has_more, results: [{index, address, symbol, value, isStatic}]}.',
      'scan_results',
      ToolCategory.SCANNING,
      [
        new ToolParam('session_id', 'string', 'Session ID from ce_scan_new', true),
        new ToolParam('start_index', 'integer', 'Starting index for pagination', false, 0),
        new ToolParam('limit', 'integer', 'Maximum results to return (max 1000)', false, 100),
      ]
    ));

    this._register(new Tool(
      'ce_scan_close',
      'Close a scan session and release resources. ' +
      'USE WHEN: Done with a scan session, freeing memory before opening new scans. ' +
      'Returns: {session_id, closed, active_sessions}.',
      'scan_close',
      ToolCategory.SCANNING,
      [new ToolParam('session_id', 'string', 'Session ID to close', true)]
    ));

    this._register(new Tool(
      'ce_scan_list',
      'List all active scan sessions. ' +
      'Returns: {active_sessions, max_sessions, sessions: [{session_id, count, scan_count, value_type, module, last_value, age_seconds, idle_seconds, timeout_in, memory_estimate}], total_memory_estimate: {bytes, kb, mb}}.',
      'scan_list',
      ToolCategory.SCANNING
    ));

    this._register(new Tool(
      'ce_enum_modules',
      'List all loaded modules (DLLs). Returns: {count, modules: [{name, address, size, path, source}], used_fallback}. ' +
      'NOTE: used_fallback=true means enumModules returned empty and AOBScan fallback was used.',
      'enum_modules',
      ToolCategory.SCANNING
    ));

    this._register(new Tool(
      'ce_get_address_list',
      'Get all records from Cheat Table (address list). ' +
      'Returns: {count, records: [{id, description, address, addressStr, value, valueType, isGroup, active, depth, children?, script?}]}.',
      'get_address_list',
      ToolCategory.SCANNING,
      [new ToolParam('include_script', 'boolean', 'Include script content for AA script entries', false, false)]
    ));

    this._register(new Tool(
      'ce_add_address_record',
      'Add a new record to Cheat Table. ' +
      'USE WHEN: Saving found addresses for later use, creating cheat entries with pointer paths. ' +
      'Returns: {success, id, description, address, value_type}.',
      'add_address_record',
      ToolCategory.SCANNING,
      [
        new ToolParam('description', 'string', 'Record description/name', true),
        new ToolParam('address', 'string', 'Address expression', true),
        new ToolParam('value_type', 'string', 'Value type', false, 'dword', 
          ToolRegistry.MEM_TYPES_WITH_SCRIPT),
        new ToolParam('script', 'string', 'AA script content (only for script type)'),
      ]
    ));
  }

  _registerScanningEnhancedTools() {
    this._register(new Tool(
      'ce_aob_scan_unique',
      '[FAST] Scan for a UNIQUE byte pattern - returns first match only. ' +
      'Much faster than ce_aob_scan when you expect exactly one result. ' +
      'USE WHEN: Finding unique code signatures, version-independent hooks. ' +
      'Returns: {found, address} or {found: false} if no match.',
      'aob_scan_unique',
      ToolCategory.SCANNING,
      [
        new ToolParam('aob_string', 'string', "e.g. '48 89 5C 24 ?? 48 83 EC 20'", true),
        new ToolParam('module', 'string', "Limit scan to specific module (e.g. 'game.exe')"),
        new ToolParam('protection', 'string', 'Flags like -C+X', false, '-C+X'),
        new ToolParam('start', 'string', 'Start address'),
        new ToolParam('stop', 'string', 'Stop address'),
      ]
    ));

    this._register(new Tool(
      'ce_check_assemble',
      'Validate Auto Assembler script syntax. ' +
      'DETECTION: Finds syntax errors, unsupported instructions, allocation issues. ' +
      'LIMITATIONS: Same as auto_assemble - complex instructions may pass validation but fail execution. ' +
      'Returns: {valid, error_message}. ' +
      'NOTE: Always test with small scripts first, use ce_assemble_instruction for complex code generation.',
      'check_assemble',
      ToolCategory.SCANNING,
      [
        new ToolParam('script', 'string', 'Auto Assembler script to validate. Keep syntax simple for reliable results.', true),
        new ToolParam('enable', 'boolean', 'Validate ENABLE section (true) or DISABLE section (false)', false, true),
        new ToolParam('target_self', 'boolean', 'Target CE process itself (for internal scripts)', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_generate_script',
      'Generate Auto Assembler script templates with known-good syntax. ' +
      'TEMPLATES: "alloc" (memory allocation), "registersymbol" (symbol registration), "globalalloc" (shared memory), "createalloc" (persistent allocation). ' +
      'WARNING: "writebytes" template is DEPRECATED - use ce_write_memory instead. ' +
      'PITFALLS: define() with nested substitution may fail; readmem() after jmp overwrite reads wrong bytes (pre-read original bytes + use db directive instead). ' +
      'Returns: {script, template, usage_hint}. ' +
      'RECOMMENDATION: Use as starting point, then simplify complex instructions.',
      'generate_script',
      ToolCategory.SCANNING,
      [
        new ToolParam('template', 'string', 'Template type: "alloc" (recommended), "registersymbol", "globalalloc"', true, null, 
          ['globalalloc', 'alloc', 'writebytes', 'registersymbol', 'createalloc']),
        new ToolParam('name', 'string', 'Name for allocated memory/symbol'),
        new ToolParam('size', 'integer', 'Allocation size (for alloc/globalalloc templates)'),
        new ToolParam('address', 'string', 'Target address (avoid writebytes template)'),
        new ToolParam('value', 'string', 'Value (avoid writebytes template)'),
      ]
    ));

    this._register(new Tool(
      'ce_memory_record_control',
      'Activate or deactivate Cheat Table address records. ' +
      'USE WHEN: Temporarily disabling cheat codes, testing different values, managing active cheats. ' +
      'Returns: {success, record_id, active}.',
      'memory_record_control',
      ToolCategory.SCANNING,
      [
        new ToolParam('record_id', 'string', 'Record ID from get_address_list', true),
        new ToolParam('active', 'boolean', 'True to activate, false to deactivate', true),
      ]
    ));

    this._register(new Tool(
      'ce_rip_scan',
      '[RIP-RELATIVE] Scan for RIP-relative memory references in code. ' +
      'USE WHEN: Analyzing position-independent code, finding dynamic addresses in x64 binaries. ' +
      'Scans for instructions that use RIP-relative addressing (e.g., [rip+offset]). ' +
      'Returns: {count, references: [{address, instruction, offset, target_address}]}.',
      'rip_scan',
      ToolCategory.SCANNING,
      [
        this.ADDR_PARAM,
        new ToolParam('scan_range', 'integer', 'Number of instructions to scan', false, 50),
        new ToolParam('module', 'string', 'Limit scan to specific module'),
      ]
    ));

    this._register(new Tool(
      'ce_disassemble_bytes',
      '[OFFLINE] Disassemble raw byte data without reading from process memory. ' +
      'USE WHEN: Analyzing byte patterns, shellcode, patch bytes, or data from files. ' +
      'Note: Instruction size is derived from the disassembled byte output, not from live memory reads. ' +
      'Returns: {instructions: [{address, opcode, bytes, size}]}.',
      'disassemble_bytes',
      ToolCategory.SCANNING,
      [
        new ToolParam('bytes', 'string', 'Hex byte string (e.g. "48 89 5C 24 08")', true),
        new ToolParam('base_address', 'string', 'Base address for display (optional)'),
        new ToolParam('count', 'integer', 'Maximum instructions to disassemble', false, 20),
      ]
    ));

    this._register(new Tool(
      'ce_assemble_instruction',
      'Assemble single instruction to machine code bytes. ' +
      'RELIABLE: Works with complex instructions that auto_assemble fails on. ' +
      'USE WHEN: auto_assemble fails, generating patch bytes, building code caves. ' +
      'Returns: {instruction, bytes, size}. ' +
      'EXAMPLE: "mov eax, 1337" → "B8 37 13 00 00" (5 bytes)',
      'assemble_instruction',
      ToolCategory.SCANNING,
      [
        new ToolParam('instruction', 'string', 'Assembly instruction (e.g. "mov rax, rbx", "push rbx"). More reliable than auto_assemble.', true),
        new ToolParam('address', 'string', 'Target address (affects relative addressing like jumps/calls)'),
        new ToolParam('preference', 'integer', 'Size preference: 0=auto, 1=short, 2=long, 3=far', false, 0),
      ]
    ));
  }

  _registerSymbolTools() {
    this._register(new Tool(
      'ce_get_address',
      "Resolve expression to address. " +
      "USE WHEN: Converting symbol names or pointer expressions to numeric addresses for other tools. " +
      "Returns: {expression, address, addressDec}. " +
      "Supports: 'game.exe+0x1234', '[[base]+10]+20', symbol names.",
      'get_address',
      ToolCategory.SYMBOLS,
      [new ToolParam('expression', 'string', 'Address expression to resolve', true)]
    ));

    this._register(new Tool(
      'ce_get_symbol',
      '[SYMBOL LOOKUP] Get symbol name, RTTI class info, and module details for an address. ' +
      'USE WHEN: Identifying what code/data an address belongs to, checking if address is in a module. ' +
      'Returns: {address, symbol, hasSymbol, rttiClassName, hasRTTI, inModule, inSystemModule, ' +
      'moduleInfo: {name, base, size, offset, is64bit, path}}. ' +
      "TIP: inModule=true with symbol containing '.exe+' or '.dll+' indicates a static address.",
      'get_symbol',
      ToolCategory.SYMBOLS,
      [
        this.ADDR_PARAM,
        new ToolParam('include_module', 'boolean', 'Include module name in symbol', false, true),
        new ToolParam('skip_cache', 'boolean', 'Skip symbol cache and force fresh lookup', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_get_region_info',
      'Get memory region info (base, size, protection). ' +
      'USE WHEN: Checking memory protection before writing/patching, understanding memory layout. ' +
      'Returns: {address, baseAddress, regionSize, protection: {r, w, x}, protectionStr}.',
      'get_region_info',
      ToolCategory.SYMBOLS,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_auto_guess',
      'Guess the value type at an address (byte/word/dword/qword/float/double/string/pointer). ' +
      'USE WHEN: Analyzing unknown memory, determining how to read a value. ' +
      'Returns: {address, readable, type_id, type_name, value, value_hex}. Useful for structure field analysis.',
      'auto_guess',
      ToolCategory.SYMBOLS,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_resolve_pointer',
      '[VERIFICATION] Resolve a KNOWN pointer chain to get final address and optionally read value. ' +
      'USE WHEN: You already have base+offsets and want to verify the chain works or read the value. ' +
      'Returns CE notation like \'[[game.exe+123]+10]+20\' for easy copy to CE. ' +
      'NOT FOR: Discovering pointer paths (use ce_find_pointer_path for discovery). ' +
      'Returns: {success, base, offsets, finalAddress, ceNotation, chain: [{level, address, symbol, offset, ptrValue?}], partialCENotation?, failedAtLevel?, error?}.',
      'resolve_pointer',
      ToolCategory.SYMBOLS,
      [
        new ToolParam('base', 'string', 'Base address or symbol', true),
        new ToolParam('offsets', 'array', 'Array of offsets, e.g. [0x100, 0x20, 0x8]', true),
        new ToolParam('read_value', 'boolean', 'Read value at final address', false, false),
        new ToolParam('value_type', 'string', 'Value type to read if read_value=true', false, 'dword',
          ToolRegistry.MEM_TYPES_WITH_POINTER),
      ]
    ));

    this._register(new Tool(
      'ce_register_symbol',
      'Register a custom symbol name pointing to an address. ' +
      'USE WHEN: Naming allocated memory, creating reusable address labels for AA scripts. ' +
      'Registered symbols appear in CE symbol handler and can be used in address expressions. ' +
      'Returns: {success, symbol, address}.',
      'register_symbol',
      ToolCategory.SYMBOLS,
      [
        new ToolParam('symbol', 'string', 'Symbol name to register (e.g. "myHookMem")', true),
        new ToolParam('address', 'string', 'Address or expression the symbol points to', true),
        new ToolParam('do_not_save', 'boolean', 'If true, symbol won\'t be saved with table', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_unregister_symbol',
      'Remove a previously registered custom symbol. ' +
      'USE WHEN: Cleaning up symbols created by ce_register_symbol or auto_assemble alloc blocks. ' +
      'Returns: {success, symbol}.',
      'unregister_symbol',
      ToolCategory.SYMBOLS,
      [new ToolParam('symbol', 'string', 'Symbol name to unregister', true)]
    ));
  }

  _registerSymbolAdvancedTools() {
    this._register(new Tool(
      'ce_pointer_size',
      'Get or set the pointer size for memory operations. ' +
      'USE WHEN: Working with 32-bit processes on 64-bit OS (WoW64), or forcing specific pointer width. ' +
      'Returns: {pointerSize, previousSize?}.',
      'pointer_size',
      ToolCategory.SYMBOLS,
      [new ToolParam('size', 'integer', 'Pointer size in bytes (4 or 8). Omit to just get current size.')]
    ));

    this._register(new Tool(
      'ce_symbol_control',
      'Control symbol loading and waiting. Operations: ' +
      '"wait_dotnet" (block until .NET symbols loaded), "wait_pdb" (block until PDB loaded), ' +
      '"wait_exports" (block until DLL exports loaded), "reinit_dotnet" (refresh .NET symbols after JIT), ' +
      '"enable_windows" (load Windows PDBs), "load_new" (scan for new modules), "done" (check if all done). ' +
      'Returns: {success, operation, result}.',
      'symbol_control',
      ToolCategory.SYMBOLS,
      [
        new ToolParam('operation', 'string', 'Operation to perform', true, null,
          ['wait_dotnet', 'wait_pdb', 'wait_exports', 'reinit_dotnet', 'enable_windows', 'load_new', 'done']),
        new ToolParam('module', 'string', 'Module name for reinit_dotnet operation'),
      ]
    ));

    this._register(new Tool(
      'ce_get_rtti',
      'Get C++ RTTI class name at an address. USE WHEN: Identifying C++ object types, ' +
      'analyzing virtual tables, understanding object hierarchies. ' +
      'Returns: {address, className, hasRTTI}.',
      'get_rtti',
      ToolCategory.SYMBOLS,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_comment',
      'Read or write user-defined comments at an address. ' +
      'USE WHEN: Annotating findings, saving analysis notes, reading existing table annotations. ' +
      'Returns: {address, comment?, success?}.',
      'comment',
      ToolCategory.SYMBOLS,
      [
        this.ADDR_PARAM,
        new ToolParam('text', 'string', 'Comment text to set. Omit to just read existing comment.'),
      ]
    ));

    this._register(new Tool(
      'ce_enum_symbols',
      'Enumerate registered custom symbols or get PDB structure elements. ' +
      'Operations: "registered" (list all registered symbols), "pdb_struct" (get structure elements from PDB). ' +
      'Returns: {operation, symbols?: [{name, address, size?}], elements?: [{offset, name, vartype}]}.',
      'enum_symbols',
      ToolCategory.SYMBOLS,
      [
        new ToolParam('operation', 'string', 'Operation: "registered" or "pdb_struct"', true, null, ['registered', 'pdb_struct']),
        new ToolParam('structure_name', 'string', 'Structure name for pdb_struct operation'),
      ]
    ));

    this._register(new Tool(
      'ce_get_address_safe',
      '[SAFE] Resolve symbol to address without throwing on failure. Returns nil instead of error. ' +
      'USE WHEN: Batch lookups where some symbols may not exist, exploratory pointer resolution. ' +
      'Returns: {expression, address, found}.',
      'get_address_safe',
      ToolCategory.SYMBOLS,
      [new ToolParam('expression', 'string', 'Address expression to resolve', true)]
    ));

    this._register(new Tool(
      'ce_get_symbol_info',
      'Get detailed symbol info including size. USE WHEN: Function boundary analysis, symbol size lookup. ' +
      'Returns: {modulename, searchkey, address, size, found}.',
      'get_symbol_info',
      ToolCategory.SYMBOLS,
      [new ToolParam('symbol_name', 'string', 'Symbol name to look up', true)]
    ));

    this._register(new Tool(
      'ce_add_symbol_module',
      'Load symbols from an arbitrary file (PDB, DLL) at a given base address. ' +
      'USE WHEN: Loading symbols for manually mapped code, dumped modules, offline PDB analysis. ' +
      'Returns: {success, path, base_address}.',
      'add_symbol_module',
      ToolCategory.SYMBOLS,
      [
        new ToolParam('path', 'string', 'Path to PDB or DLL file', true),
        new ToolParam('base_address', 'string', 'Base address for the module', true),
      ]
    ));

    this._register(new Tool(
      'ce_get_name_from_address',
      'Get detailed name string for address with control over what is included. ' +
      'USE WHEN: Richer naming than ce_get_symbol; section info reveals code/data segment placement. ' +
      'Returns: {address, name, has_module, has_symbol, has_section}.',
      'get_name_from_address',
      ToolCategory.SYMBOLS,
      [
        this.ADDR_PARAM,
        new ToolParam('include_modules', 'boolean', 'Include module names', false, true),
        new ToolParam('include_symbols', 'boolean', 'Include symbol names', false, true),
        new ToolParam('include_sections', 'boolean', 'Include section info', false, false),
      ]
    ));
  }

  _registerDebugTools() {
    this._register(new Tool(
      'ce_disassemble',
      'Basic disassembly - get raw instructions at an address. ' +
      'USE WHEN: You just need to see assembly code (opcodes, bytes). ' +
      'FOR DEEPER ANALYSIS: Use ce_analyze_code (extracts calls/jumps) or ce_build_cfg (function-level CFG). ' +
      'Returns: {instructions: [{address, opcode, bytes, size, modrmValueType?, modrmValue?, parameterValueType?, parameterValue?, isJump?, isCall?, isRet?, isConditionalJump?}], nextAddress, previousAddress}.',
      'disassemble',
      ToolCategory.DEBUG,
      [
        this.ADDR_PARAM,
        new ToolParam('count', 'integer', 'Number of instructions', false, 10),
        new ToolParam('direction', 'string', 'Disassembly direction: forward (default) or backward using getPreviousOpcode', false, 'forward', ['forward', 'backward']),
        new ToolParam('detailed', 'boolean', 'Include LastDisassembleData (modrm, parameter values, jump/call flags)', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_get_instruction_info',
      'Get detailed instruction info. ' +
      'USE WHEN: Needing full instruction details beyond basic disassembly, checking jump/call types. ' +
      'Returns: {address, opcode, params, bytes, bytesStr, size, isCall, isJump, isRet, isConditionalJump, parameterValue}.',
      'get_instruction_info',
      ToolCategory.DEBUG,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_set_breakpoint',
      'Set a hardware breakpoint. ' +
      'USE WHEN: Setting execute/write/access breakpoints for debugging, tracing code that accesses memory. ' +
      'Returns: {success, address, type, method, slot, reused}. Use ce_remove_breakpoint to remove.',
      'set_breakpoint',
      ToolCategory.DEBUG,
      [
        this.ADDR_PARAM,
        new ToolParam('type', 'string', 'Breakpoint type', false, 'execute', ['execute', 'write', 'access']),
        new ToolParam('size', 'integer', 'Size in bytes for write/access breakpoints', false, 1),
      ]
    ));

    this._register(new Tool(
      'ce_remove_breakpoint',
      'Remove a debug breakpoint. ' +
      'USE WHEN: Cleaning up after analysis, removing breakpoints set by ce_set_breakpoint or ce_break_and_get_regs. ' +
      'Returns: {success, address}.',
      'remove_breakpoint',
      ToolCategory.DEBUG,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_get_breakpoints',
      'List all active breakpoints. ' +
      'USE WHEN: Checking which breakpoints are set before adding new ones, debugging breakpoint conflicts. ' +
      'Returns: {count, breakpoints: [{address, type, size, thread_id?}], details: [{address, type, size, thread_id?, slot?}]}.',
      'get_breakpoints',
      ToolCategory.DEBUG
    ));

    this._register(new Tool(
      'ce_break_and_get_regs',
      '[SINGLE CAPTURE] Set breakpoint and capture registers ONCE when hit. ' +
      'USE WHEN: You need register values at ONE specific point (function args, pointer values). ' +
      'Returns all registers + call stack at breakpoint hit. ' +
      'FOR MULTI-STEP: Use ce_break_and_trace to trace execution flow. ' +
      'Returns: {address, callStack, returnAddress, rax-r15, rip, rflags, xmm?}. Throws error if not triggered within timeout.',
      'break_and_get_regs',
      ToolCategory.DEBUG,
      [
        this.ADDR_PARAM,
        new ToolParam('timeout', 'integer', 'Timeout in ms', false, 5000),
        new ToolParam('stack_depth', 'integer', 'Number of stack entries to read', false, 16),
        new ToolParam('include_xmm', 'boolean', 'Include XMM registers (SSE/AVX) for floating point analysis', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_break_and_trace',
      '[EXECUTION TRACE] Step-by-step code execution with full register capture. ' +
      'MOST POWERFUL: Captures register state at EACH instruction. ' +
      'USE WHEN: Understanding algorithms, data transformations, complex execution flow. ' +
      'ALTERNATIVE: ce_break_and_get_regs for single capture, ce_symbolic_trace for safe analysis. ' +
      'Returns: {address, steps, complete, timeout, stop_reason, trace: [{step, address, instruction, bytes, size, isCall, isJump, isRet, registers}]}. ' +
      'STOP: ret, end_address, max_steps, timeout.',
      'break_and_trace',
      ToolCategory.DEBUG,
      [
        this.ADDR_PARAM,
        new ToolParam('max_steps', 'integer', 'Max instructions to trace (default 100)', false, 100),
        new ToolParam('timeout', 'integer', 'Timeout ms (default 10000)', false, 10000),
        new ToolParam('stop_on_ret', 'boolean', 'Stop on ret instruction (default true)', false, true),
        new ToolParam('trace_into_call', 'boolean', 'Step into calls vs step over (default false)', false, false),
        new ToolParam('end_address', 'string', 'Stop when this address reached'),
        new ToolParam('initial_regs', 'object', 'Set initial registers: {"rcx": "0x12345", "rdx": 100}'),
      ]
    ));

    this._register(new Tool(
      'ce_thread_breakpoint',
      '[THREAD-SPECIFIC] Set breakpoint that only triggers on specific thread. ' +
      'USE WHEN: Debugging multi-threaded code, avoiding false hits from other threads. ' +
      'Returns: {success, address, thread_id}.',
      'thread_breakpoint',
      ToolCategory.DEBUG,
      [
        this.ADDR_PARAM,
        new ToolParam('thread_id', 'integer', 'Thread ID (use ce_enum_threads to find IDs)', true),
        new ToolParam('type', 'string', 'Breakpoint type', false, 'execute', ['execute', 'write', 'access']),
        new ToolParam('size', 'integer', 'Size in bytes for write/access breakpoints', false, 1),
      ]
    ));
  }

  _registerProcessControlTools() {
    this._register(new Tool(
      'ce_pause_process',
      'Pause/suspend the target process. USE WHEN: Freezing game state for analysis, ' +
      'stopping execution to safely examine memory. ' +
      'Returns: {success, wasPaused}.',
      'pause_process',
      ToolCategory.DEBUG
    ));

    this._register(new Tool(
      'ce_resume_process',
      'Resume/unpause the target process. USE WHEN: After ce_pause_process or when game is stuck. ' +
      'Returns: {success, wasPaused}.',
      'resume_process',
      ToolCategory.DEBUG
    ));

    this._register(new Tool(
      'ce_speedhack',
      'Set game speed using CE speedhack. USE WHEN: Speeding up slow animations, ' +
      'slowing down fast actions for observation, bypassing timed checks. ' +
      'Speed 1.0 = normal, 0.5 = half speed, 2.0 = double speed. ' +
      'Returns: {success, speed, wasEnabled}.',
      'speedhack',
      ToolCategory.DEBUG,
      [new ToolParam('speed', 'number', 'Speed multiplier (1.0=normal, 0.5=half, 2.0=double)', true)]
    ));

    this._register(new Tool(
      'ce_enum_threads',
      'Enumerate threads in the target process. USE WHEN: Finding thread IDs for ' +
      'thread-specific breakpoints, analyzing multi-threaded code, debugging race conditions. ' +
      'Returns: {count, threads: [{id}]}.',
      'enum_threads',
      ToolCategory.DEBUG
    ));

    this._register(new Tool(
      'ce_enum_handles',
      'Enumerate system handles. USE WHEN: Anti-cheat analysis, finding handles ' +
      'to the target process, debugging resource leaks. ' +
      'Returns: {count, handles: [{processID, objectTypeIndex, handleAttributes, handleValue, object, grantedAccess}]}.',
      'enum_handles',
      ToolCategory.DEBUG,
      [
        new ToolParam('filter', 'integer', 'Filter: 0=all, 1=target process handles only, 2=handles TO target process, 3=handles to CE process', false, 2),
      ]
    ));
  }

  _registerAnalysisTools() {
    // Analysis tools - first batch
    this._register(new Tool(
      'ce_find_what_accesses',
      '[F5 TRACE] Find code accessing address (reads+writes). ' +
      'MONITORS: 10 seconds - user must trigger access during this time. ' +
      'SUCCESS: Returns register values (e.g., RBX=0x12345678) showing pointer used. ' +
      'WORKFLOW: Get register value → ce_value_scan → repeat until static base found. ' +
      'Returns: {address, mode, size, duration_ms, total_hits, unique_instructions, results: [{address, symbol, instruction, bytes, count, registers, lastValue}]}.',
      'find_what_accesses',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('user_prompted', 'boolean',
          "AI MUST tell user 'I will monitor for 10 seconds, please change the value in game NOW' BEFORE calling. " +
          "This parameter is a workflow reminder guard - not used by CE, but you must set it to true to confirm user was prompted.",
          true),
        new ToolParam('size', 'integer', 'Monitor size: 1/2/4/8 bytes (default 4)', false, 4),
        new ToolParam('duration_ms', 'integer', 'Monitor duration ms (default 10000 = 10s)', false, 10000),
        new ToolParam('max_records', 'integer', 'Max records before stopping (default 1000)', false, 1000),
      ]
    ));

    this._register(new Tool(
      'ce_find_what_writes',
      'Find code that WRITES to an address (like CE\'s F6 key). Monitors writes only, ignores reads. ' +
      'This tool monitors for 10 seconds - user must trigger memory write during this time. ' +
      'USE WHEN: Finding what MODIFIES a value (e.g., what decreases player health). ' +
      'USE ce_find_what_accesses instead if you need both reads and writes for pointer tracing. ' +
      'Returns: {address, mode, size, duration_ms, total_hits, unique_instructions, results: [{address, symbol, instruction, bytes, count, registers, lastValue}]}.',
      'find_what_writes',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('user_prompted', 'boolean',
          "AI MUST tell user 'I will monitor for 10 seconds, please trigger a write in game NOW' BEFORE calling. " +
          'This parameter is a workflow reminder guard - not used by CE, but you must set it to true to confirm user was prompted.',
          true),
        new ToolParam('size', 'integer', 'Size to monitor (1/2/4/8 bytes)', false, 4),
        new ToolParam('duration_ms', 'integer', 'Monitoring duration in milliseconds (default 10000 = 10 seconds)', false, 10000),
        new ToolParam('max_records', 'integer', 'Maximum hit records before stopping', false, 1000),
      ]
    ));

    this._register(new Tool(
      'ce_analyze_code',
      'Static analysis of code block - disassembly PLUS extracted calls, jumps, memory references. ' +
      'USE WHEN: Understanding what a code section does without execution. ' +
      'Returns call targets, jump destinations, memory access patterns. ' +
      'FOR FUNCTION-LEVEL: Use ce_build_cfg. FOR DYNAMIC ANALYSIS: Use ce_break_and_trace. ' +
      'Returns: {range: {start, stop}, instructions, analysis: {calls, jumps, memory}}.',
      'analyze_code',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('count', 'integer', 'Number of instructions to analyze', false, 20),
      ]
    ));

    this._register(new Tool(
      'ce_build_cfg',
      'Build Control Flow Graph for an entire function. ' +
      'USE WHEN: Analyzing function structure, finding loops, understanding complex branching. ' +
      'Returns basic blocks, edges, loop detection, cyclomatic complexity. ' +
      'TIP: Use ce_find_function_boundaries first if you don\'t know function start address. ' +
      'Returns: {function_start, block_count, edge_count, instruction_count, blocks: [{id, start, stop, instruction_count, instructions, successors, predecessors, jump_type, jump_target, is_entry, is_exit, is_loop_header, has_back_edge}], edges, loops, metrics: {cyclomatic_complexity, exit_points, loop_count, max_depth_reached}, call_targets: [{target, call_count}]}.',
      'build_cfg',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('max_instructions', 'integer', 'Maximum instructions to analyze (default 500)', false, 500),
        new ToolParam('max_blocks', 'integer', 'Maximum basic blocks (default 100)', false, 100),
        new ToolParam('detect_loops', 'boolean', 'Detect and annotate loop structures', false, true),
        new ToolParam('include_disasm', 'boolean', 'Include disassembly in each block', false, true),
      ]
    ));

    this._register(new Tool(
      'ce_detect_patterns',
      '[PATTERN RECOGNITION] Detect common code patterns in a function. ' +
      'USE WHEN: Quick function classification, finding crypto code, detecting anti-debug, locating string usage. ' +
      'Detects: switch_tables (jump tables), virtual_calls (vtable calls), string_refs (string literals), ' +
      'crypto_constants (MD5/SHA/TEA/Blowfish magic numbers), anti_debug (IsDebuggerPresent/rdtsc), ' +
      'comparisons (cmp/test), memory_patterns (struct field access). ' +
      'Returns: {function_start, instructions_scanned, patterns: {switch_tables, virtual_calls, string_refs, crypto_constants, anti_debug, comparisons, memory_patterns}, ' +
      'summary: {has_switch, has_virtual_calls, has_strings, has_crypto, has_anti_debug, unique_offsets}}.',
      'detect_patterns',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('max_instructions', 'integer', 'Maximum instructions to scan', false, 200),
        new ToolParam('patterns', 'array', 'Specific patterns to detect (omit for all)'),
      ]
    ));

    this._register(new Tool(
      'ce_compare_functions',
      'Compare two functions for similarity. Returns matching blocks, differing instructions, ' +
      'and similarity score. Useful for patch analysis and finding similar code. ' +
      'Returns: {function1, function2, similarity_percent, matching_instructions, matches, differences: {only_in_func1, only_in_func2}, verdict}.',
      'compare_functions',
      ToolCategory.ANALYSIS,
      [
        new ToolParam('address1', 'string', 'First function address', true),
        new ToolParam('address2', 'string', 'Second function address', true),
        new ToolParam('max_instructions', 'integer', 'Max instructions per function', false, 200),
      ]
    ));

    this._register(new Tool(
      'ce_trace_dataflow',
      "Trace how a SINGLE register's value flows through code. " +
      "USE WHEN: 'Where does RAX get its value?' or 'Where is RCX used after this?'. " +
      'Tracks ONE register only. FOR CROSS-REGISTER: Use ce_program_slice which follows data across mov/xchg. ' +
      'Returns: {function_start, traced_register, base_register, aliases_checked, definitions: [where value comes from], uses: [where value goes], data_flow, summary: {definition_count, use_count, total_references}}.',
      'trace_dataflow',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('register', 'string', "Register to trace (e.g. 'rax', 'rcx')", true),
        new ToolParam('max_instructions', 'integer', 'Max instructions to analyze', false, 100),
        new ToolParam('direction', 'string', "Trace direction: 'forward' (uses) or 'backward' (definitions)", false, 'both', ['forward', 'backward', 'both']),
      ]
    ));

    this._register(new Tool(
      'ce_program_slice',
      '[ADVANCED] Compute program slice - find ALL instructions affecting a value (backward) or affected by it (forward). ' +
      "USE WHEN: Understanding 'how is this value computed' across multiple registers and memory operations. " +
      'Unlike ce_trace_dataflow, follows data through register transfers (mov rax,rbx). ' +
      'Essential for complex algorithm reverse engineering. ' +
      'Returns: {function_start, criterion, direction, slice_size, total_instructions, slice, unresolved_dependencies, coverage_percent}.',
      'program_slice',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('criterion', 'string', "Slicing criterion: register name (e.g. 'rax') or memory pattern (e.g. '[rbx+10]')", true),
        new ToolParam('direction', 'string', "Slice direction: 'backward' (what affects this) or 'forward' (what this affects)", false, 'backward', ['backward', 'forward']),
        new ToolParam('max_instructions', 'integer', 'Max instructions to analyze', false, 200),
        new ToolParam('follow_calls', 'boolean', 'Follow into called functions (increases depth but slower)', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_analyze_struct_access',
      'Infer structure fields by scanning memory values at an address. ' +
      'USE WHEN: Analyzing object/struct layout, finding field offsets. ' +
      'Scans memory range and guesses field types. ' +
      'Returns: {base, fields, scanned_bytes}. ' +
      'FOR DYNAMIC ANALYSIS: Use ce_trace_struct_access to see what code accesses the struct.',
      'analyze_struct_access',
      ToolCategory.ANALYSIS,
      [
        new ToolParam('base_address', 'string', this.ADDR_PARAM.description, true),
        new ToolParam('scan_range', 'integer', 'Range to scan in bytes', false, 512),
      ]
    ));

    this._register(new Tool(
      'ce_trace_struct_access',
      'Dynamic trace: Monitor what code accesses a memory region. ' +
      'USE WHEN: Finding which code reads/writes struct fields, understanding object usage patterns. ' +
      'Returns: {address, count, log}. ' +
      'FOR STATIC ANALYSIS: Use ce_analyze_struct_access to infer field types from values.',
      'trace_struct_access',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('size', 'integer', 'Size to monitor', false, 4),
        new ToolParam('mode', 'string', 'Trace mode', false, 'read_write', ['read_write', 'write']),
        new ToolParam('duration_ms', 'integer', 'Duration in milliseconds', false, 1000),
      ]
    ));

    this._register(new Tool(
      'ce_cleanup',
      'Force remove ALL breakpoints and traces set by MCP tools. ' +
      'USE WHEN: Game frozen due to stuck breakpoint, cleaning up after analysis, resetting debug state. ' +
      'Safe to call anytime - cleans up zombie resources. ' +
      'Returns: {success, cleaned, details, slots_freed}.',
      'cleanup_breakpoints',
      ToolCategory.ANALYSIS
    ));

    this._register(new Tool(
      'ce_find_pointer_path',
      '[AUTOMATIC] Find static pointer path to dynamic address. ' +
      'MONITORS: ~10 seconds per level - user must interact with value during this time. ' +
      'SUCCESS: Returns {base_address, offsets, ce_pointer_notation} for direct CE use. ' +
      'FAILURE: Use manual workflow: ce_find_what_accesses → ce_value_scan → repeat. ' +
      'STRATEGIES: hybrid (recommended), f5 (pure F5), value_scan (pure pointer search). ' +
      'Returns: {success, base_address, offsets, ce_pointer_notation, steps, suggestions}.',
      'find_pointer_path',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('user_prompted', 'boolean',
          "AI MUST tell user 'I will trace pointers, please interact with the value NOW (change it, take damage, use feature)' BEFORE calling. " +
          "This parameter is a workflow reminder guard - not used by CE, but you must set it to true to confirm user was prompted.",
          true),
        new ToolParam('max_depth', 'integer', 'Max pointer depth 1-10 (default 7)', false, 7),
        new ToolParam('duration_ms', 'integer', 'Monitoring duration per level ms (default 10000)', false, 10000),
        new ToolParam('max_results', 'integer', 'Max candidate pointers per level (default 10)', false, 10),
        new ToolParam('strategy', 'string', 
          "Search strategy: 'hybrid' (F5 + value_scan + scoring), 'f5' (pure F5), 'value_scan' (pure pointers)", 
          false, 'hybrid', ['hybrid', 'f5', 'value_scan']),
      ]
    ));

    this._register(new Tool(
      'ce_find_references',
      'Find all code locations referencing an address. Returns: {target, count, total_found, truncated, references: [{address, instruction, symbol}], arch, pattern_used}.',
      'find_references',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('limit', 'integer', 'Maximum results to return', false, 50),
      ]
    ));

    this._register(new Tool(
      'ce_find_call_references',
      'Find all CALL instructions targeting a function (who calls this function). ' +
      'USE WHEN: Understanding function usage, finding entry points, tracing call hierarchy. ' +
      'Auto-detects module from target address for better performance. ' +
      'Returns: {function_address, count, total_matches, segments_scanned, callers: [{address, instruction, symbol}], module}.',
      'find_call_references',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('module', 'string', "Limit scan to specific module (e.g. 'game.exe'). If omitted, auto-detects from target address."),
        new ToolParam('limit', 'integer', 'Maximum results to return', false, 100),
      ]
    ));

    this._register(new Tool(
      'ce_find_function_boundaries',
      'Find function start/end by prologue/epilogue patterns. ' +
      "USE WHEN: You have an address inside a function and need to find where the function starts/ends. " +
      'WORKFLOW: Use this first, then ce_build_cfg for full function analysis. ' +
      'Returns: {found, query_address, function_start, function_end, function_size, prologue_type, arch, note?}.',
      'find_function_boundaries',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('max_search', 'integer', 'Maximum bytes to search for boundaries', false, 4096),
      ]
    ));

    this._register(new Tool(
      'ce_checksum_memory',
      'Calculate MD5 hash of a memory region. ' +
      'USE WHEN: Detecting code modifications, verifying patches, checking if memory changed. ' +
      'LIMIT: Maximum 1MB per hash. Returns: {address, size, md5_hash}.',
      'checksum_memory',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('size', 'integer', 'Number of bytes to hash', false, 256),
      ]
    ));

    this._register(new Tool(
      'ce_generate_signature',
      'Generate unique AOB signature for code at an address. ' +
      'USE WHEN: Creating version-independent scripts, documenting code locations for future game updates. ' +
      'WORKFLOW: Generate signature here -> after game update, use ce_aob_scan to relocate. ' +
      'Returns: {address, signature, offset_from_start, byte_count, usage_hint}.',
      'generate_signature',
      ToolCategory.ANALYSIS,
      [this.ADDR_PARAM]
    ));

    this._registerHookTools();
    this._registerEmulationTools();
    this._registerStructureTools();
  }

  _registerStructureTools() {    this._register(new Tool(
      'ce_structure_manage',
      'Manage custom structure definitions for memory analysis. ' +
      'USE WHEN: Defining object layouts, accessing struct fields by name, documenting memory patterns. ' +
      'Operations: "list" (list all structures), "get" (get structure definition), ' +
      '"create" (create new structure), "delete" (delete structure), "add_field" (add field to structure). ' +
      'Returns: {success, operation, structures?: [{name, size, fields}], structure?: {name, size, fields}}.',
      'structure_manage',
      ToolCategory.ANALYSIS,
      [
        new ToolParam('operation', 'string', 'Operation to perform', true, null,
          ['list', 'get', 'create', 'delete', 'add_field']),
        new ToolParam('name', 'string', 'Structure name (for get/create/delete/add_field)'),
        new ToolParam('size', 'integer', 'Total structure size (for create)'),
        new ToolParam('field_name', 'string', 'Field name (for add_field)'),
        new ToolParam('field_offset', 'integer', 'Field offset (for add_field)'),
        new ToolParam('field_type', 'string', 'Field type: byte/word/dword/qword/float/double/string/bytes (for add_field)'),
      ]
    ));

    this._register(new Tool(
      'ce_dissect_code',
      '[MODULE ANALYSIS] Analyze all code in a module or memory region using CE DissectCode. ' +
      'USE WHEN: Getting overview of module structure, finding all referenced functions and strings. ' +
      'MODULE: Can be a module name (e.g. "game.exe") or an address range string (e.g. "0x140000-0x150000"). ' +
      'Returns: {module, functions: [{address, name?}], referenced_strings: [{address, value}], stats}.',
      'dissect_code',
      ToolCategory.ANALYSIS,
      [
        new ToolParam('module', 'string', 'Module name or address range (e.g. "game.exe" or "0x140000-0x150000")', true),
        new ToolParam('analyze_functions', 'boolean', 'Find and analyze all functions', false, true),
      ]
    ));
  }

  _registerHookTools() {
    this._register(new Tool(
      'ce_hook_function',
      '[NON-BLOCKING] Hook a function to intercept calls and capture arguments automatically. ' +
      'USE WHEN: Monitoring function calls without stopping execution (e.g., logging all damage events). ' +
      'Captures first 4 args: x64 uses RCX/RDX/R8/R9, x32 uses stack. ' +
      'WORKFLOW: ce_hook_function -> let game run -> ce_get_hook_log to retrieve captured data. ' +
      'FOR SINGLE CAPTURE: Use ce_break_and_get_regs instead. ' +
      'Returns: {success, name, address, symbol, capture_args, capture_return, max_records, trampoline, log_buffer, warning?}.',
      'hook_function',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('name', 'string', 'Hook identifier name', true),
        new ToolParam('capture_args', 'integer', 'Number of arguments to capture (0-4, default 4)', false, 4),
        new ToolParam('capture_return', 'boolean', 'Capture return value (default true). Note: x64 return capture is NOT thread-safe for concurrent callers.', false, true),
        new ToolParam('max_records', 'integer', 'Fixed at 64 (circular buffer). Parameter accepted but currently hardcoded.', false, 64),
      ]
    ));

    this._register(new Tool(
      'ce_unhook_function',
      'Remove a function hook by name and restore original code. ' +
      'Call this when finished analyzing to clean up resources and free memory. ' +
      'Returns: {success, name, address, total_calls}.',
      'unhook_function',
      ToolCategory.ANALYSIS,
      [new ToolParam('name', 'string', 'Hook identifier name', true)]
    ));

    this._register(new Tool(
      'ce_list_hooks',
      'List all active function hooks with their status and call counts. ' +
      'Use to check which hooks are currently installed before adding new ones. ' +
      'Returns: {hooks: [{name, address, symbol, capture_args, capture_return, call_count}]}.',
      'list_hooks',
      ToolCategory.ANALYSIS
    ));

    this._register(new Tool(
      'ce_get_hook_log',
      'Get captured function call arguments. Returns entries with args[1-4] containing: ' +
      'x64: RCX(this/arg1), RDX(arg2), R8(arg3), R9(arg4); ' +
      'x32: stack params [esp+10/14/18/1C]. ' +
      'Values are hex addresses/integers. total_calls shows how many times function was called. ' +
      'Returns: {name, address, symbol, capture_return, total_calls, entries_returned, entries, cleared}.',
      'get_hook_log',
      ToolCategory.ANALYSIS,
      [
        new ToolParam('name', 'string', 'Hook identifier name', true),
        new ToolParam('clear', 'boolean', 'Clear log after reading', false, false),
        new ToolParam('limit', 'integer', 'Max records to return (1-64, default 50)', false, 50),
      ]
    ));

    this._register(new Tool(
      'ce_clear_hook_log',
      'Clear the call log and reset total_calls counter for a hook. ' +
      'Use when: 1) Starting fresh measurement, 2) Log buffer full (64 entries max), ' +
      '3) Want to count calls from a specific point. Omit name to clear all hooks. ' +
      'Returns: {success, name?, previous_count?}.',
      'clear_hook_log',
      ToolCategory.ANALYSIS,
      [new ToolParam('name', 'string', 'Hook name (omit to clear all)')]
    ));
  }

  _registerEmulationTools() {
    this._register(new Tool(
      'ce_call_function',
      '[DANGEROUS] Call a function in target process - EXECUTES REAL CODE! ' +
      'USE WHEN: Testing function behavior, calling game functions programmatically. ' +
      'Uses x64 fastcall (RCX, RDX, R8, R9). May crash game if used incorrectly. ' +
      'Returns: {success, return_value, return_value_hex, return_value_formatted, return_type, function_address, args_passed}.',
      'call_function',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('args', 'array', 'Function arguments (up to 4 for fastcall). Can be integers or address expressions.', false, []),
        new ToolParam('call_method', 'integer', 'Calling method for executeCodeEx: 0=default/auto, 1=stdcall, 2=cdecl, 3=fastcall, 4=thiscall. If omitted, bridge auto-fallbacks for compatibility.'),
        new ToolParam('timeout', 'integer', 'Timeout in milliseconds', false, 5000),
        new ToolParam('return_type', 'string', 'How to interpret return value', false, 'qword', 
          ToolRegistry.MEM_TYPES_WITH_POINTER),
      ]
    ));

    this._register(new Tool(
      'ce_symbolic_trace',
      '[SAFE] Symbolic execution without running code. ' +
      'SECURITY: Safe for dangerous/anti-debug code analysis. ' +
      'OUTPUT: Readable expressions like \'rax = ((arg0 + 5) << 2)\'. ' +
      'INSTRUCTIONS: mov, movzx, movsxd, lea, add, sub, xor, and, or, shl, shr, imul, cmp, test, cmovxx. ' +
      'ALTERNATIVE: ce_break_and_trace for real execution. ' +
      'Returns: {start_address, instructions_traced, stop_reason, trace: [{address, instruction, effect}], final_state, initial_state}.',
      'symbolic_trace',
      ToolCategory.ANALYSIS,
      [
        this.ADDR_PARAM,
        new ToolParam('count', 'integer', 'Max instructions to trace (default 30)', false, 30),
        new ToolParam('initial_state', 'object', 'Initial registers: {"rcx": "this_ptr", "rdx": "arg1", "r8": 0}'),
        new ToolParam('stop_on_call', 'boolean', 'Stop on call instruction (default true)', false, true),
        new ToolParam('stop_on_ret', 'boolean', 'Stop on ret instruction (default true)', false, true),
        new ToolParam('simplify', 'boolean', 'Simplify expressions: x^x=0, x+0=x (default true)', false, true),
      ]
    ));
   }

   _registerInjectionTools() {
    this._register(new Tool(
      'ce_inject_dll',
      'Inject a DLL into the target process. USE WHEN: Adding custom code, ' +
      'loading mod frameworks, injecting hook libraries. ' +
      'Returns: {success, dllPath}.',
      'inject_dll',
      ToolCategory.INJECTION,
      [
        new ToolParam('dll_path', 'string', 'Full path to the DLL file to inject', true),
        new ToolParam('skip_symbol_reload', 'boolean', 'Skip waiting for symbol reload after injection', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_inject_dotnet_dll',
      'Inject a .NET DLL and execute a static method. USE WHEN: Interacting with ' +
      'managed code (Unity/Mono games), calling .NET methods from CE. ' +
      'Returns: {success, returnValue, dllPath, className, methodName}.',
      'inject_dotnet_dll',
      ToolCategory.INJECTION,
      [
        new ToolParam('dll_path', 'string', 'Full path to the .NET DLL', true),
        new ToolParam('class_name', 'string', 'Full class name (namespace.class)', true),
        new ToolParam('method_name', 'string', 'Static method name to call', true),
        new ToolParam('parameters', 'string', 'String parameters to pass to the method', false, ''),
        new ToolParam('timeout', 'integer', 'Timeout in milliseconds', false, 30000),
      ]
    ));

    this._register(new Tool(
      'ce_compile_c_code',
      'Compile C code and inject into target process. USE WHEN: Writing complex ' +
      'hooks in C, creating efficient code caves, implementing custom logic. ' +
      "Uses CE's built-in TCC compiler. Returns symbol addresses on success. " +
      'Returns: {success, symbols: {name: address}}.',
      'compile_c_code',
      ToolCategory.INJECTION,
      [
        new ToolParam('code', 'string', 'C source code to compile', true),
        new ToolParam('address', 'string', 'Base address for allocation (optional)'),
        new ToolParam('target_self', 'boolean', 'Compile into CE process instead of target', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_full_access',
      '[CONVENIENCE] Set memory protection to RWX (read+write+execute) in one call. ' +
      'USE WHEN: Making memory executable for code injection, quick patching. ' +
      'Returns: {success, address, protection: {r, w, x}}.',
      'full_access',
      ToolCategory.INJECTION,
      [
        this.ADDR_PARAM,
        new ToolParam('size', 'integer', 'Size of the region to change', true),
      ]
    ));

    this._register(new Tool(
      'ce_dump_memory',
      'Dump memory region to file or load from file. ' +
      'USE WHEN: Saving memory snapshots, comparing memory states, loading custom data. ' +
      'Modes: "dump" (save to file), "load" (load from file), "compare" (compare file with memory). ' +
      'Returns: {success, file_path, checksum?}. For compare mode: {success, match, file_path}.',
      'dump_memory',
      ToolCategory.INJECTION,
      [
        this.ADDR_PARAM,
        new ToolParam('size', 'integer', 'Number of bytes to dump/load', true),
        new ToolParam('file_path', 'string', 'Path to dump file or load from', true),
        new ToolParam('mode', 'string', 'Operation mode: "dump", "load", or "compare"', true, null, 
          ['dump', 'load', 'compare']),
        // verify parameter not implemented in Lua handler - removed to avoid confusion
      ]
    ));

    this._register(new Tool(
      'ce_execute_method',
      '[DANGEROUS] Call a method with explicit class instance (this pointer) in target process. ' +
      'USE WHEN: Calling OOP/virtual methods where RCX/ECX = this pointer. ' +
      'Note: All arguments are passed as integers. For float/string args, use ce_call_function with typed params instead. ' +
      'Returns: {success, return_value}.',
      'execute_method',
      ToolCategory.INJECTION,
      [
        this.ADDR_PARAM,
        new ToolParam('class_instance', 'string', 'Class instance address (this pointer)', true),
        new ToolParam('args', 'array', 'Method arguments', false, []),
        new ToolParam('call_method', 'integer', '0=stdcall, 1=cdecl', false, 0),
        new ToolParam('instance_register', 'integer', 'Register for instance (1=ECX/RCX default)', false, 1),
        new ToolParam('timeout', 'integer', 'Timeout in milliseconds', false, 5000),
      ]
    ));

    this._register(new Tool(
      'ce_create_remote_thread',
      'Create a thread in the target process at a given address. ' +
      'USE WHEN: Executing code asynchronously in target, more flexible than call_function for long-running ops. ' +
      'Returns: {success}. Note: thread_id not returned by CE API.',
      'create_remote_thread',
      ToolCategory.INJECTION,
      [
        this.ADDR_PARAM,
        new ToolParam('parameter', 'integer', 'Parameter to pass to thread function', false, 0),
      ]
    ));

    this._register(new Tool(
      'ce_compile_c_sharp',
      'Compile C# code and get auto-generated filename for injection. ' +
      'USE WHEN: .NET code injection for Unity/Mono games; pair with ce_inject_dotnet_dll. ' +
      'Returns: {success, filename, warnings?}.',
      'compile_c_sharp',
      ToolCategory.INJECTION,
      [
        new ToolParam('code', 'string', 'C# source code', true),
        new ToolParam('references', 'array', 'List of .NET assembly references', false, []),
      ]
    ));

    this._register(new Tool(
      'ce_generate_api_hook_script',
      'Generate complete Auto Assembler hook script for intercepting an API/function. ' +
      'USE WHEN: The most common RE task after finding a target function. Produces ready-to-execute hook. ' +
      'Returns: {script, address, jump_address}.',
      'generate_api_hook_script',
      ToolCategory.INJECTION,
      [
        this.ADDR_PARAM,
        new ToolParam('jump_address', 'string', 'Address to jump to (your hook function)', true),
        new ToolParam('new_call_address', 'string', 'Address to get original call address'),
        new ToolParam('target_self', 'boolean', 'Target CE process itself', false, false),
      ]
    ));
  }

  _registerTableTools() {
    this._register(new Tool(
      'ce_load_table',
      'Load a Cheat Engine table (.CT or .CETRAINER file). USE WHEN: Loading ' +
      'pre-made cheat tables, restoring saved analysis state. ' +
      'Returns: {success, filename, merged}.',
      'load_table',
      ToolCategory.TABLE,
      [
        new ToolParam('filename', 'string', 'Path to .CT or .CETRAINER file', true),
        new ToolParam('merge', 'boolean', 'Merge with current table instead of replacing', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_save_table',
      'Save the current cheat table to a file. USE WHEN: Persisting analysis results, ' +
      'saving pointer paths and address records for later use. ' +
      'Returns: {success, filename}.',
      'save_table',
      ToolCategory.TABLE,
      [
        new ToolParam('filename', 'string', 'Path to save .CT file', true),
        new ToolParam('protect', 'boolean', 'Protect the table (only for .CETRAINER)', false, false),
      ]
    ));
  }

  _registerDotNetTools() {
    this._register(new Tool(
      'ce_dotnet_analyze',
      'Analyze .NET managed objects and classes in the target process. ' +
      'USE WHEN: Analyzing Unity/Mono games, finding managed object instances, ' +
      'inspecting .NET class fields and methods. ' +
      'Operations: "domains" (list app domains), "modules" (list modules in domain), ' +
      '"typedefs" (list classes in module), "methods" (list methods in class), ' +
      '"fields" (list fields in class), "objects" (find instances of type), ' +
      '"address_data" (inspect object at address). ' +
      'Returns: {success, operation, data}.',
      'dotnet_analyze',
      ToolCategory.DOTNET,
      [
        new ToolParam('operation', 'string', 'Analysis operation', true, null,
          ['domains', 'modules', 'typedefs', 'methods', 'fields', 'objects', 'address_data']),
        new ToolParam('domain_handle', 'integer', 'Domain handle (for modules operation)'),
        new ToolParam('module_handle', 'integer', 'Module handle (for typedefs/methods/fields/objects)'),
        new ToolParam('typedef_token', 'integer', 'TypeDef token (for methods/fields/objects)'),
        new ToolParam('address', 'string', 'Address to inspect (for address_data operation)'),
      ]
    ));
  }

  _registerDebugAdvancedTools() {
    this._register(new Tool(
      'ce_debug_start',
      'Start the debugger with a specific interface. USE WHEN: Choosing debug method for anti-debug bypass. ' +
      'VEH (2) avoids usermode anti-debug, Kernel (3) for driver-level. ' +
      'Returns: {success, interface}.',
      'debug_start',
      ToolCategory.DEBUG,
      [
        new ToolParam('interface', 'integer', 'Debug interface: 0=default, 1=Windows, 2=VEH, 3=Kernel', true, null, [0, 1, 2, 3]),
      ]
    ));

    this._register(new Tool(
      'ce_debug_status',
      'Get current debugger state. USE WHEN: Checking if debugger is ready before setting breakpoints. ' +
      'Returns: {isDebugging, isBroken, canBreak, interface}.',
      'debug_status',
      ToolCategory.DEBUG
    ));

    this._register(new Tool(
      'ce_debug_continue',
      'Continue execution from a breakpoint. USE WHEN: Manual step-through debugging. ' +
      'Methods: "run" (continue), "stepinto" (single step into calls), "stepover" (step over calls). ' +
      'Returns: {success, method}.',
      'debug_continue',
      ToolCategory.DEBUG,
      [
        new ToolParam('method', 'string', 'Continue method', true, null, ['run', 'stepinto', 'stepover']),
      ]
    ));

    this._register(new Tool(
      'ce_get_set_context',
      'Get or set full register context when debugger is broken. ' +
      'USE WHEN: Reading XMM/FP registers, modifying register values to change execution flow. ' +
      'Set register_values to modify registers (e.g., {"RAX": "0x1234", "RCX": 0}). ' +
      'Returns: {registers, xmm_registers?}.',
      'get_set_context',
      ToolCategory.DEBUG,
      [
        new ToolParam('register_values', 'object', 'Register values to set (e.g., {"RAX": "0x1234"}). Omit to just read.'),
        new ToolParam('include_xmm', 'boolean', 'Include XMM/FP registers', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_thread_no_break',
      'Exclude/include threads from triggering breakpoints. ' +
      'USE WHEN: Filtering noisy threads in multi-threaded targets. ' +
      'Operations: "add" (exclude thread), "remove" (include thread), "list_threads" (list all process threads). ' +
      'Note: "list" is not supported as CE has no API to retrieve the no-break exclusion list. ' +
      'Returns: {success, operation, thread_id?, threads?}.',
      'thread_no_break',
      ToolCategory.DEBUG,
      [
        new ToolParam('operation', 'string', 'Operation', true, null, ['add', 'remove', 'list_threads']),
        new ToolParam('thread_id', 'integer', 'Thread ID for add/remove operations'),
      ]
    ));

    this._register(new Tool(
      'ce_debug_break_thread',
      'Force-break a specific thread at its current instruction. ' +
      'USE WHEN: Suspending a thread without needing a breakpoint address. ' +
      'Returns: {success, thread_id}.',
      'debug_break_thread',
      ToolCategory.DEBUG,
      [new ToolParam('thread_id', 'integer', 'Thread ID to break', true)]
    ));

    this._register(new Tool(
      'ce_detach_debugger',
      'Detach debugger from target process cleanly. ' +
      'USE WHEN: Cleanup after analysis to avoid leaving debug artifacts. ' +
      'Returns: {success}.',
      'detach_debugger',
      ToolCategory.DEBUG
    ));
  }

  _registerProcessTools() {
    this._register(new Tool(
      'ce_open_file_as_process',
      '[OFFLINE] Open a file on disk as if it were a live process. ' +
      'USE WHEN: Analyzing binaries without running them, examining PE files, dumped memory, firmware. ' +
      'Returns: {success, filename, is64bit}.',
      'open_file_as_process',
      ToolCategory.PROCESS,
      [
        new ToolParam('filename', 'string', 'Path to file to open', true),
        new ToolParam('is64bit', 'boolean', 'Treat as 64-bit process'),
        new ToolParam('start_address', 'string', 'Optional start address'),
      ]
    ));

    this._register(new Tool(
      'ce_create_process',
      'Launch a new process under debugger control. ' +
      'USE WHEN: Starting target from scratch, breaking at entry point for from-scratch analysis. ' +
      'Returns: {success, pid, name}.',
      'create_process',
      ToolCategory.PROCESS,
      [
        new ToolParam('path', 'string', 'Path to executable', true),
        new ToolParam('parameters', 'string', 'Command line parameters'),
        new ToolParam('debug', 'boolean', 'Start under debugger', false, false),
        new ToolParam('break_on_entry', 'boolean', 'Break at entry point', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_get_foreground_process',
      'Get PID of the currently focused/foreground process. ' +
      'USE WHEN: Quick discovery of what game/application is running. ' +
      'Returns: {pid, name}.',
      'get_foreground_process',
      ToolCategory.PROCESS
    ));

    this._register(new Tool(
      'ce_close_remote_handle',
      'Close a handle in a remote process. USE WHEN: Anti-anti-cheat, closing handles that detect CE. ' +
      'Returns: {success}.',
      'close_remote_handle',
      ToolCategory.PROCESS,
      [
        new ToolParam('handle', 'integer', 'Handle value to close', true),
        new ToolParam('process_id', 'integer', 'Process ID (optional, defaults to target)'),
      ]
    ));

    this._register(new Tool(
      'ce_duplicate_handle',
      'Duplicate handles between processes. USE WHEN: Getting access to target process resources. ' +
      'Returns: {success, new_handle}.',
      'duplicate_handle',
      ToolCategory.PROCESS,
      [
        new ToolParam('handle', 'integer', 'Handle to duplicate', true),
        new ToolParam('mode', 'integer', '0=target->CE, 1=CE->target, or provide fromPID/toPID'),
        new ToolParam('from_pid', 'integer', 'Source process ID'),
        new ToolParam('to_pid', 'integer', 'Destination process ID'),
      ]
    ));

    this._register(new Tool(
      'ce_target_info',
      'Get target architecture details. USE WHEN: Determining calling conventions, pointer sizes, assembly mode. ' +
      'Returns: {is64bit, isX86, isArm, isAndroid, isRosetta, abi, ceIs64bit, pointerSize}.',
      'target_info',
      ToolCategory.PROCESS
    ));
  }

  _registerFileTools() {
    this._register(new Tool(
      'ce_md5_file',
      'Calculate MD5 hash of a file on disk. USE WHEN: Verifying file integrity, detecting game updates. ' +
      'Returns: {file_path, md5}.',
      'md5_file',
      ToolCategory.FILEIO,
      [new ToolParam('file_path', 'string', 'Path to file', true)]
    ));

    this._register(new Tool(
      'ce_file_version',
      'Get file version info. USE WHEN: Identifying exact game/DLL version for version-specific analysis. ' +
      'Returns: {version, major, minor, release, build}.',
      'file_version',
      ToolCategory.FILEIO,
      [new ToolParam('file_path', 'string', 'Path to file', true)]
    ));

    this._register(new Tool(
      'ce_file_ops',
      'File system operations: check existence, delete, list files, list directories. ' +
      'Operations: "exists", "delete", "list_files", "list_dirs". ' +
      'Returns: {operation, result}.',
      'file_ops',
      ToolCategory.FILEIO,
      [
        new ToolParam('operation', 'string', 'Operation', true, null, ['exists', 'delete', 'list_files', 'list_dirs']),
        new ToolParam('path', 'string', 'File/directory path', true),
        new ToolParam('search_mask', 'string', 'Search mask for list_files (e.g. "*.dll")'),
        new ToolParam('search_subdirs', 'boolean', 'Search subdirectories', false, false),
      ]
    ));

    this._register(new Tool(
      'ce_write_region_to_file',
      'Write a memory region directly to a file. ' +
      'USE WHEN: Saving memory dumps for offline analysis, faster alternative to ce_dump_memory for simple dumps. ' +
      'Returns: {success, file_path, bytes_written}.',
      'write_region_to_file',
      ToolCategory.FILEIO,
      [
        this.ADDR_PARAM,
        new ToolParam('size', 'integer', 'Number of bytes to write', true),
        new ToolParam('file_path', 'string', 'Output file path', true),
      ]
    ));

    this._register(new Tool(
      'ce_read_region_from_file',
      'Load a file directly into target process memory. ' +
      'USE WHEN: Loading shellcode, custom data, or restoring saved memory dumps. ' +
      'Returns: {success, file_path, address}.',
      'read_region_from_file',
      ToolCategory.FILEIO,
      [
        this.ADDR_PARAM,
        new ToolParam('file_path', 'string', 'Input file path', true),
      ]
    ));
  }

  _registerWindowTools() {
    this._register(new Tool(
      'ce_find_window',
      'Find windows by class name and/or caption. USE WHEN: Finding game window when process name unknown. ' +
      'Returns: {found, handle, caption, class_name, process_id}.',
      'find_window',
      ToolCategory.WINDOW,
      [
        new ToolParam('class_name', 'string', 'Window class name (optional)'),
        new ToolParam('caption', 'string', 'Window caption/title substring (optional)'),
      ]
    ));

    this._register(new Tool(
      'ce_enum_windows',
      'List all top-level windows with PID and caption. ' +
      'USE WHEN: Discovering running game windows as alternative to process listing. ' +
      'Returns: {count, windows: [{handle, caption, process_id}]} where handle is a hex string.',
      'enum_windows',
      ToolCategory.WINDOW
    ));
  }

  _registerKernelTools() {
    this._register(new Tool(
      'ce_allocate_shared_memory',
      'Create named shared memory region mapped into target process. ' +
      'USE WHEN: IPC between CE and other tools, cross-process data sharing. ' +
      'Returns: {success, name, address, size}.',
      'allocate_shared_memory',
      ToolCategory.KERNEL,
      [
        new ToolParam('name', 'string', 'Shared memory name', true),
        new ToolParam('size', 'integer', 'Size in bytes (default 4096)', false, 4096),
      ]
    ));

    this._register(new Tool(
      'ce_get_physical_address',
      'Translate virtual address to physical address. USE WHEN: Bypassing virtual memory protections. ' +
      'Returns: {virtual_address, physical_address}.',
      'get_physical_address',
      ToolCategory.KERNEL,
      [this.ADDR_PARAM]
    ));

    this._register(new Tool(
      'ce_dbvm_cloak',
      'Hide modified code pages from anti-cheat integrity checks using DBVM. ' +
      'DBVM cloak operates on 4096-byte pages. Operations: "activate" (cloak page), "deactivate" (uncloak), "read_original" (read pre-modification), "write_original" (restore bytes). ' +
      'Returns: {success, operation, data?}.',
      'dbvm_cloak',
      ToolCategory.KERNEL,
      [
        new ToolParam('operation', 'string', 'Operation', true, null, ['activate', 'deactivate', 'read_original', 'write_original']),
        this.ADDR_PARAM,
        new ToolParam('virtual_address', 'string', 'Virtual base address (optional, for activate when physical differs from virtual)'),
      ]
    ));
  }

  _registerTypeConversionTools() {
    this._register(new Tool(
      'ce_type_conversion',
      'Convert between numeric/string types and byte arrays. ' +
      'USE WHEN: Constructing patch bytes, interpreting raw memory data, preparing write values. ' +
      'Conversions: word->bytes, dword->bytes, qword->bytes, float->bytes, double->bytes, string->bytes, ' +
      'bytes->word, bytes->dword, bytes->qword, bytes->float, bytes->double, bytes->string. ' +
      'NOTE: For bytes->word/dword conversions only, set signed=true to interpret as signed integer. ' +
      'Returns: {input_type, output_type, value, result}.',
      'type_conversion',
      ToolCategory.SYSTEM,
      [
        new ToolParam('conversion', 'string', 'Conversion type', true, null,
          ['word_to_bytes', 'dword_to_bytes', 'qword_to_bytes', 'float_to_bytes', 'double_to_bytes', 'string_to_bytes',
           'bytes_to_word', 'bytes_to_dword', 'bytes_to_qword', 'bytes_to_float', 'bytes_to_double', 'bytes_to_string']),
        new ToolParam('value', 'string', 'Input value (number, string, or space-separated bytes)', true),
        new ToolParam('signed', 'boolean', 'Interpret as signed (for bytes->word/dword conversions only)', false, false),
      ]
    ));
  }

  getTool(name) {
    return this.tools.get(name) || null;
  }

  getAllSchemas() {
    return Array.from(this.tools.values()).map(tool => tool.toMCPSchema());
  }

  getLuaCommand(toolName) {
    const tool = this.tools.get(toolName);
    return tool ? tool.luaCommand : null;
  }
}

module.exports = { ToolRegistry, ToolCategory, Tool, ToolParam };
