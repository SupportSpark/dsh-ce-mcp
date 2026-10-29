--[[
  CE MCP Bridge v6.0.0
]]

-- ============ Cached Globals ============
local string_format = string.format
local string_char = string.char
local string_byte = string.byte
local string_sub = string.sub
local string_gsub = string.gsub
local string_gmatch = string.gmatch
local string_find = string.find
local string_unpack = string.unpack
local string_match = string.match
local table_insert = table.insert
local table_concat = table.concat
local table_remove = table.remove
local table_sort = table.sort
local table_unpack = table.unpack or unpack
local math_floor = math.floor
local math_abs = math.abs
local math_min = math.min
local math_max = math.max
local pcall = pcall
local tonumber = tonumber
local tostring = tostring
local type = type
local pairs = pairs
local ipairs = ipairs
local os_clock = os.clock

local function bit_xor(a, b)
    local r = 0
    local m = 1
    while a > 0 or b > 0 do
        local ab = a % 2
        local bb = b % 2
        if ab ~= bb then r = r + m end
        m = m * 2
        a = math_floor(a / 2)
        b = math_floor(b / 2)
    end
    return r
end

-- ============ Config ============
local Config = {
    PIPE_NAME = "ce_mcp_bridge",
    DEBUG_MODE = false,
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024,
    PIPE_BUFFER_SIZE = 1024 * 1024,
    PIPE_MAX_INSTANCES = 1,
    HEARTBEAT_INTERVAL = 100,
    CLEANUP_INTERVAL = 60,
    MAX_CONSECUTIVE_ERRORS = 10,
    MAX_SESSION_ERRORS = 5,
    MAX_AOB_RESULTS = 1000,
    MAX_TRACE_ENTRIES = 1000,
    POLL_INTERVAL_INITIAL = 10,
    POLL_INTERVAL_MAX = 50,
    -- Hook configuration
    MAX_HOOK_RECORDS = 64,
    HOOK_ENTRY_SIZE_X64 = 40,  -- 4 args (32 bytes) + return_value (8 bytes)
    HOOK_ENTRY_SIZE_X32 = 20,  -- 4 args (16 bytes) + return_value (4 bytes)
    HOOK_HEADER_SIZE_X64 = 32,
    HOOK_HEADER_SIZE_X32 = 16,
    -- Pointer tracing
    MAX_POINTER_DEPTH = 10,
    POINTER_TRACE_DURATION = 10000,  -- 10 seconds per level for user to trigger access
    POINTER_STEP_DELAY = 50,  -- Configurable delay between pointer trace steps (ms)
    -- Memory limits
    MAX_SCAN_ADDRESS = 0x7FFFFFFFFFFF,
    MAX_CHECKSUM_SIZE = 0x100000,
    -- Watchdog: auto-cleanup stale breakpoint states to prevent game freeze
    WATCHDOG_TIMEOUT = 30,
    WATCHDOG_CHECK_INTERVAL = 5,
    HEARTBEAT_TIMEOUT = 120,
    -- Scan Session configuration
    MAX_SCAN_SESSIONS = 5,           -- Maximum concurrent scan sessions
    SCAN_SESSION_TIMEOUT = 300,      -- Session timeout in seconds (5 minutes)
    SCAN_DEFAULT_PAGE_SIZE = 100,    -- Default page size for scan results
    SCAN_MAX_PAGE_SIZE = 1000,       -- Maximum page size for scan results
}

-- ============ Context ============
local Context = {
    serverRunning = false,
    pipeServer = nil,
    activeBreakpoints = {},
    hwBreakpointSlots = {},
    lastCleanup = 0,
    lastWatchdogCheck = 0,
    lastActivityTime = 0,  -- Heartbeat: last successful communication timestamp
    connectionCount = 0,
    traceData = nil,
    traceAddr = nil,
    traceActive = false,
    bpResult = nil,
    bpTriggered = false,
    bpTimestamp = 0,  -- Timestamp when breakpoint was triggered (for watchdog)
    traceLog = nil,
    traceComplete = false,
    traceStepCount = 0,
    traceTimestamp = 0,  -- Timestamp when trace started (for watchdog)
    findWhatData = nil,
    findWhatAddr = nil,
    findWhatActive = false,
    findWhatHits = 0,
    findWhatTimestamp = 0,  -- Timestamp when find_what started (for watchdog)
}

-- ============ Address Cache ============
local AddressCache = {
    moduleBase = {},
    symbols = {},
    currentPID = 0,
    maxSymbols = 5000,
}

local CacheTTL = {
    STATIC_SYMBOL = 300,
    DYNAMIC_EXPR = 5,
}

local ValueTypeMap = {
    byte = vtByte, word = vtWord, dword = vtDword, qword = vtQword,
    float = vtSingle, double = vtDouble, string = vtString,
    bytes = vtByteArray, script = vtAutoAssembler,
    pointer = vtQword,
}

local VtToNameMap = {
    [vtByte] = "byte", [vtWord] = "word", [vtDword] = "dword",
    [vtQword] = "qword", [vtSingle] = "float", [vtDouble] = "double",
    [vtString] = "string", [vtByteArray] = "bytes", [vtAutoAssembler] = "script",
}

-- ============ Scan Sessions ============
local ScanSessions = {}
local ScanSessionCounter = 0

-- ============ Logger Module ============
-- Structured logging system with level filtering and log rotation

local LogLevel = {
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4
}

local Logger = {
    level = LogLevel.INFO,
    maxEntries = 1000,
    entries = {},
    head = 1,
    entryCount = 0
}

-- Set the minimum log level
function Logger.setLevel(level)
    if type(level) == "number" and level >= LogLevel.DEBUG and level <= LogLevel.ERROR then
        Logger.level = level
    end
end

-- Get level name from level number
function Logger.getLevelName(level)
    local names = { [1] = "DEBUG", [2] = "INFO", [3] = "WARN", [4] = "ERROR" }
    return names[level] or "UNKNOWN"
end

-- Core logging function with level filtering and rotation
function Logger.log(level, category, message, data)
    if level < Logger.level then return end

    local entry = {
        timestamp = os.time(),
        level = level,
        levelName = Logger.getLevelName(level),
        category = category or "General",
        message = message or "",
        data = data
    }

    if Logger.entryCount < Logger.maxEntries then
        Logger.entryCount = Logger.entryCount + 1
        Logger.entries[Logger.entryCount] = entry
    else
        Logger.entries[Logger.head] = entry
        Logger.head = (Logger.head % Logger.maxEntries) + 1
    end

    if Config.DEBUG_MODE then
        print(string_format("[CE-MCP-%s] [%s] %s",
            Logger.getLevelName(level), category or "General", message or ""))
    end
end

-- Convenience methods for each log level
function Logger.debug(category, message, data)
    Logger.log(LogLevel.DEBUG, category, message, data)
end

function Logger.info(category, message, data)
    Logger.log(LogLevel.INFO, category, message, data)
end

function Logger.warn(category, message, data)
    Logger.log(LogLevel.WARN, category, message, data)
end

function Logger.error(category, message, data)
    Logger.log(LogLevel.ERROR, category, message, data)
end

-- Get log entries with optional filtering
-- count: maximum number of entries to return (default: 100)
-- minLevel: minimum log level to include (default: DEBUG)
function Logger.getEntries(count, minLevel)
    count = count or 100
    minLevel = minLevel or LogLevel.DEBUG

    local result = {}
    local total = Logger.entryCount

    if total == 0 then return result end

    if total < Logger.maxEntries then
        local startIdx = math_max(1, total - count + 1)
        for i = startIdx, total do
            local entry = Logger.entries[i]
            if entry and entry.level >= minLevel then
                table_insert(result, entry)
            end
        end
    else
        local n = math_min(count, Logger.maxEntries)
        for i = 0, n - 1 do
            local idx = ((Logger.head + i - 1) % Logger.maxEntries) + 1
            local entry = Logger.entries[idx]
            if entry and entry.level >= minLevel then
                table_insert(result, entry)
            end
        end
    end

    return result
end

-- Clear all log entries
function Logger.clear()
    Logger.entries = {}
    Logger.head = 1
    Logger.entryCount = 0
end

-- Get current log statistics
function Logger.getStats()
    local levelCounts = { [1] = 0, [2] = 0, [3] = 0, [4] = 0 }
    local total = Logger.entryCount
    local limit = math_min(total, Logger.maxEntries)
    for i = 1, limit do
        local entry = Logger.entries[i]
        if entry and entry.level and levelCounts[entry.level] then
            levelCounts[entry.level] = levelCounts[entry.level] + 1
        end
    end

    return {
        totalEntries = Logger.entryCount,
        maxEntries = Logger.maxEntries,
        currentLevel = Logger.level,
        currentLevelName = Logger.getLevelName(Logger.level),
        counts = {
            debug = levelCounts[LogLevel.DEBUG],
            info = levelCounts[LogLevel.INFO],
            warn = levelCounts[LogLevel.WARN],
            error = levelCounts[LogLevel.ERROR]
        }
    }
end

-- ============ ErrorContextBuilder Module ============
-- Enriches error messages with contextual information for better diagnostics

local ErrorContextBuilder = {}

-- Build a generic error message with context
-- @param command: The command name that caused the error
-- @param originalError: The original error message
-- @param context: Optional table with additional context fields
-- @return: Enriched error message string
function ErrorContextBuilder.build(command, originalError, context)
    local parts = {
        string_format("[%s] %s", tostring(command or "unknown"), tostring(originalError or "Unknown error"))
    }

    if context then
        if context.address then
            table_insert(parts, string_format("Address: %s", tostring(context.address)))
        end
        if context.expression then
            table_insert(parts, string_format("Expression: %s", tostring(context.expression)))
        end
        if context.step then
            table_insert(parts, string_format("Step: %s", tostring(context.step)))
        end
        if context.type then
            table_insert(parts, string_format("Type: %s", tostring(context.type)))
        end
        if context.protection then
            table_insert(parts, string_format("Protection: %s", tostring(context.protection)))
        end
        if context.debuggerState then
            table_insert(parts, string_format("Debugger: %s", tostring(context.debuggerState)))
        end
        if context.size then
            table_insert(parts, string_format("Size: %s", tostring(context.size)))
        end
    end

    return table_concat(parts, " | ")
end

-- Build an address resolution error with expression and step context
-- @param command: The command name
-- @param expression: The address expression that failed to resolve
-- @param step: The resolution step that failed (e.g., "module lookup", "offset calculation")
-- @param originalError: The original error message
-- @return: Enriched error message string
function ErrorContextBuilder.addressError(command, expression, step, originalError)
    return ErrorContextBuilder.build(command, originalError, {
        expression = expression,
        step = step
    })
end

-- Build a memory operation error with address, type, and protection context
-- @param command: The command name
-- @param address: The memory address (number or string)
-- @param memType: The memory type (e.g., "dword", "float")
-- @param originalError: The original error message
-- @return: Enriched error message string
function ErrorContextBuilder.memoryError(command, address, memType, originalError)
    local protection = nil
    local addrStr = nil

    -- Format address
    if type(address) == "number" then
        addrStr = string_format("0x%X", address)
    else
        addrStr = tostring(address)
    end

    -- Try to get memory protection flags
    pcall(function()
        local info = getRegionInfo(address)
        if info then
            protection = info.Protection
        end
    end)

    return ErrorContextBuilder.build(command, originalError, {
        address = addrStr,
        type = memType,
        protection = protection
    })
end

-- Build a breakpoint operation error with address and debugger state context
-- @param command: The command name
-- @param address: The breakpoint address (number or string)
-- @param originalError: The original error message
-- @return: Enriched error message string
function ErrorContextBuilder.breakpointError(command, address, originalError)
    local debuggerState = "unknown"
    local addrStr = nil

    -- Format address
    if type(address) == "number" then
        addrStr = string_format("0x%X", address)
    else
        addrStr = tostring(address)
    end

    -- Try to get debugger state
    pcall(function()
        local isDebugging = debug_isDebugging() or false
        local debugInterface = debug_getCurrentDebuggerInterface()
        local isBroken = debug_isBroken() or false
        local canBreak = debug_canBreak() or false

        debuggerState = string_format("active=%s, interface=%s, broken=%s, canBreak=%s",
            tostring(isDebugging),
            tostring(debugInterface or "none"),
            tostring(isBroken),
            tostring(canBreak))
    end)

    return ErrorContextBuilder.build(command, originalError, {
        address = addrStr,
        debuggerState = debuggerState
    })
end

-- ============ Metrics Module ============
-- Tracks execution statistics for commands and cache operations

local Metrics = {
    commands = {},      -- Per-command execution statistics
    cache = {           -- Cache hit/miss statistics
        hits = 0,
        misses = 0
    },
    startTime = os_clock()  -- Server start time for uptime calculation
}

-- Record a command execution
-- @param command: The command name
-- @param duration: Execution duration in seconds
-- @param success: Whether the command succeeded (default: true)
function Metrics.recordCommand(command, duration, success)
    if not command then return end

    -- Initialize command stats if not exists
    if not Metrics.commands[command] then
        Metrics.commands[command] = {
            count = 0,
            totalTime = 0,
            errors = 0,
            minTime = nil,
            maxTime = nil,
            lastTime = 0
        }
    end

    local stats = Metrics.commands[command]
    stats.count = stats.count + 1
    stats.totalTime = stats.totalTime + (duration or 0)
    stats.lastTime = os_clock()

    -- Track min/max times
    if duration then
        if not stats.minTime or duration < stats.minTime then
            stats.minTime = duration
        end
        if not stats.maxTime or duration > stats.maxTime then
            stats.maxTime = duration
        end
    end

    -- Track errors
    if success == false then
        stats.errors = stats.errors + 1
    end
end

-- Record a cache hit
function Metrics.recordCacheHit()
    Metrics.cache.hits = Metrics.cache.hits + 1
end

-- Record a cache miss
function Metrics.recordCacheMiss()
    Metrics.cache.misses = Metrics.cache.misses + 1
end

-- Get comprehensive metrics summary
-- @return: Table with uptime, command stats, and cache stats
function Metrics.getSummary()
    local commandStats = {}
    local totalCommands = 0
    local totalErrors = 0
    local totalTime = 0

    for cmd, stats in pairs(Metrics.commands) do
        local avgTime = stats.count > 0 and (stats.totalTime / stats.count) or 0
        commandStats[cmd] = {
            count = stats.count,
            totalTime = stats.totalTime,
            avgTime = avgTime,
            minTime = stats.minTime or 0,
            maxTime = stats.maxTime or 0,
            errors = stats.errors,
            errorRate = stats.count > 0 and (stats.errors / stats.count * 100) or 0
        }
        totalCommands = totalCommands + stats.count
        totalErrors = totalErrors + stats.errors
        totalTime = totalTime + stats.totalTime
    end

    local cacheTotal = Metrics.cache.hits + Metrics.cache.misses
    local cacheHitRate = cacheTotal > 0 and (Metrics.cache.hits / cacheTotal * 100) or 0

    return {
        uptime = os_clock() - Metrics.startTime,
        commands = commandStats,
        summary = {
            totalCommands = totalCommands,
            totalErrors = totalErrors,
            totalTime = totalTime,
            avgTimePerCommand = totalCommands > 0 and (totalTime / totalCommands) or 0
        },
        cache = {
            hits = Metrics.cache.hits,
            misses = Metrics.cache.misses,
            total = cacheTotal,
            hitRate = cacheHitRate
        }
    }
end

-- Reset all metrics (useful for testing)
function Metrics.reset()
    Metrics.commands = {}
    Metrics.cache = { hits = 0, misses = 0 }
    Metrics.startTime = os_clock()
end

-- Get metrics for a specific command
-- @param command: The command name
-- @return: Command stats or nil if not found
function Metrics.getCommandStats(command)
    local stats = Metrics.commands[command]
    if not stats then return nil end

    local avgTime = stats.count > 0 and (stats.totalTime / stats.count) or 0
    return {
        count = stats.count,
        totalTime = stats.totalTime,
        avgTime = avgTime,
        minTime = stats.minTime or 0,
        maxTime = stats.maxTime or 0,
        errors = stats.errors,
        errorRate = stats.count > 0 and (stats.errors / stats.count * 100) or 0
    }
end

-- ============ ModuleManager Module ============
-- Manages module detection and automatic symbol refresh

local ModuleManager = {
    knownModules = {},
    lastHash = 0,
    lastRefreshTime = 0,
    lastCheckTime = 0,
    checkInterval = 10,
    refreshCount = 0,
    symbolsReady = false
}

-- Calculate a hash of the current module set for change detection
-- The hash is based on module addresses and sizes
-- @return: number representing the module set hash
function ModuleManager.getModuleHash()
    local hash = 2166136261
    local ok, modules = pcall(enumModules)

    if not ok or not modules then
        return hash
    end

    for _, m in ipairs(modules) do
        local addr = m.Address or 0
        local size = m.Size or 0
        hash = bit_xor(hash, addr)
        hash = (hash * 16777619) % 4294967296
        hash = bit_xor(hash, size)
        hash = (hash * 16777619) % 4294967296
    end

    return hash
end

-- Get the current module list with details
-- @return: table of module info objects
function ModuleManager.getModuleList()
    local result = {}
    local ok, modules = pcall(enumModules)

    if not ok or not modules then
        return result
    end

    for _, m in ipairs(modules) do
        table_insert(result, {
            name = m.Name or "unknown",
            base = m.Address or 0,
            size = m.Size or 0
        })
    end

    return result
end

-- Check if the module set has changed since last check
-- @return: boolean indicating if modules changed, table of changes
function ModuleManager.checkForChanges()
    local now = os_clock()

    -- Rate limit checks
    if now - ModuleManager.lastCheckTime < ModuleManager.checkInterval then
        return false, nil
    end
    ModuleManager.lastCheckTime = now

    local currentHash = ModuleManager.getModuleHash()
    local changed = currentHash ~= ModuleManager.lastHash

    if changed then
        -- Detect what changed
        local changes = {
            added = {},
            removed = {}
        }

        local currentModules = ModuleManager.getModuleList()
        local currentByName = {}

        -- Build lookup table for current modules
        for _, m in ipairs(currentModules) do
            currentByName[m.name:lower()] = m
        end

        -- Find removed modules
        for name, oldMod in pairs(ModuleManager.knownModules) do
            if not currentByName[name] then
                table_insert(changes.removed, {
                    name = oldMod.name,
                    base = oldMod.base
                })
            end
        end

        -- Find added modules
        for _, m in ipairs(currentModules) do
            local key = m.name:lower()
            if not ModuleManager.knownModules[key] then
                table_insert(changes.added, {
                    name = m.name,
                    base = m.base,
                    size = m.size
                })
            end
        end

        -- Update known modules
        ModuleManager.knownModules = {}
        for _, m in ipairs(currentModules) do
            ModuleManager.knownModules[m.name:lower()] = {
                name = m.name,
                base = m.base,
                size = m.size
            }
        end

        ModuleManager.lastHash = currentHash

        -- Auto-refresh symbols if modules changed
        if #changes.added > 0 or #changes.removed > 0 then
            ModuleManager.refreshSymbols()
            Logger.info("ModuleManager", string_format("Modules changed: +%d -%d, symbols refreshed",
                #changes.added, #changes.removed), changes)
        end

        return true, changes
    end

    return false, nil
end

-- Refresh the symbol handler and clear caches
function ModuleManager.refreshSymbols()
    local ok, err = pcall(reinitializeSymbolhandler)
    if ok then
        ModuleManager.symbolsReady = true
    else
        Logger.warn("ModuleManager", "Failed to refresh symbols: " .. tostring(err))
    end

    if Utils and Utils.clearAddressCache then
        Utils.clearAddressCache()
    else
        AddressCache.moduleBase = {}
        AddressCache.symbols = {}
    end

    ModuleManager.lastRefreshTime = os.time()
    ModuleManager.refreshCount = ModuleManager.refreshCount + 1
end

-- Get the timestamp of the last symbol refresh
-- @return: number (Unix timestamp)
function ModuleManager.getLastRefreshTime()
    return ModuleManager.lastRefreshTime
end

-- Get module manager statistics
-- @return: table with module manager stats
function ModuleManager.getStats()
    local moduleCount = 0
    for _ in pairs(ModuleManager.knownModules) do
        moduleCount = moduleCount + 1
    end

    return {
        module_count = moduleCount,
        last_refresh_time = ModuleManager.lastRefreshTime,
        last_check_time = ModuleManager.lastCheckTime,
        refresh_count = ModuleManager.refreshCount,
        current_hash = ModuleManager.lastHash
    }
end

-- Initialize module manager with current module state
-- Called on process attach or server start
function ModuleManager.initialize()
    ModuleManager.lastHash = ModuleManager.getModuleHash()
    ModuleManager.lastCheckTime = os_clock()

    -- Populate known modules
    local modules = ModuleManager.getModuleList()
    ModuleManager.knownModules = {}
    for _, m in ipairs(modules) do
        ModuleManager.knownModules[m.name:lower()] = {
            name = m.name,
            base = m.base,
            size = m.size
        }
    end

    -- Set initial refresh time
    if ModuleManager.lastRefreshTime == 0 then
        ModuleManager.lastRefreshTime = os.time()
    end

    Logger.info("ModuleManager", string_format("Initialized with %d modules", #modules))
end

-- Reset module manager state (called on process detach)
function ModuleManager.reset()
    ModuleManager.knownModules = {}
    ModuleManager.lastHash = 0
    ModuleManager.lastCheckTime = 0
    -- Don't reset lastRefreshTime or refreshCount - keep for stats
    Logger.debug("ModuleManager", "Module manager reset")
end

-- ============ Utils ============
local Utils = {}

function Utils.debugPrint(...)
    if Config.DEBUG_MODE then
        print("[CE-MCP]", ...)
    end
end

function Utils.formatHex(num)
    if not num then return "0x0" end
    if type(num) == "string" then
        if num:match("^0[xX]") then
            num = tonumber(num) or 0
        else
            num = tonumber(num, 16) or 0
        end
    end
    return string_format("0x%X", num)
end

-- Count elements in a table
function Utils.tableCount(tbl)
    local count = 0
    if tbl then
        for _ in pairs(tbl) do
            count = count + 1
        end
    end
    return count
end

function Utils.clearAddressCache()
    AddressCache.moduleBase = {}
    AddressCache.symbols = {}
    AddressCache.currentPID = 0
    Utils.debugPrint("Address cache cleared")
end

-- ============ Scan Session Management ============
function Utils.generateSessionId()
    ScanSessionCounter = ScanSessionCounter + 1
    return string_format("scan_%d_%d", os.time(), ScanSessionCounter)
end

function Utils.cleanupScanSession(sessionId)
    local session = ScanSessions[sessionId]
    if not session then return false end

    pcall(function()
        if session.foundList then
            session.foundList.deinitialize()
        end
    end)
    pcall(function()
        if session.memscan then
            session.memscan.destroy()
        end
    end)

    ScanSessions[sessionId] = nil
    Utils.debugPrint("Scan session cleaned up: " .. sessionId)
    return true
end

function Utils.cleanupAllScanSessions()
    local count = 0
    for sessionId in pairs(ScanSessions) do
        if Utils.cleanupScanSession(sessionId) then
            count = count + 1
        end
    end
    return count
end

function Utils.cleanupExpiredScanSessions()
    local now = os_clock()
    local expired = {}

    for sessionId, session in pairs(ScanSessions) do
        if now - session.lastAccess > Config.SCAN_SESSION_TIMEOUT then
            table_insert(expired, sessionId)
        end
    end

    for _, sessionId in ipairs(expired) do
        Utils.cleanupScanSession(sessionId)
        Utils.debugPrint("Expired scan session cleaned: " .. sessionId)
    end

    return #expired
end

function Utils.countActiveScanSessions()
    local count = 0
    for _ in pairs(ScanSessions) do
        count = count + 1
    end
    return count
end

-- Estimate memory usage for a scan session based on result count and value type
function Utils.estimateScanSessionMemory(count, valueType)
    -- Base overhead for memscan and foundList objects (approximate)
    local baseOverhead = 1024  -- 1 KB base overhead

    -- Size per result entry (address + value storage)
    local addressSize = 8  -- Assume 64-bit for safety; actual check done at runtime if available
    pcall(function()
        if not targetIs64Bit() then
            addressSize = 4
        end
    end)

    -- Value size based on type
    local valueSizes = {
        byte = 1,
        word = 2,
        dword = 4,
        qword = 8,
        float = 4,
        double = 8,
        string = 64  -- Average estimate for strings
    }
    local valueSize = valueSizes[valueType] or 4

    -- Each result entry: address + value + metadata overhead
    local entryOverhead = 16  -- Metadata per entry (flags, index, etc.)
    local perEntrySize = addressSize + valueSize + entryOverhead

    -- Total memory estimate in bytes
    local totalBytes = baseOverhead + (count * perEntrySize)

    return {
        bytes = totalBytes,
        kb = math_floor(totalBytes / 1024),
        mb = math_floor(totalBytes / (1024 * 1024) * 100) / 100,  -- 2 decimal places
        per_entry = perEntrySize
    }
end

-- Get list of active scan sessions with details
-- @return table of session info objects
function Utils.getActiveScanSessionsList()
    local sessions = {}
    local now = os_clock()

    for sessionId, session in pairs(ScanSessions) do
        local count = 0
        pcall(function()
            if session.foundList then
                session.foundList.initialize()
                count = session.foundList.Count or 0
            end
        end)

        -- Estimate memory usage (Requirements 6.3)
        local memoryEstimate = Utils.estimateScanSessionMemory(count, session.valueType or "dword")

        table_insert(sessions, {
            session_id = sessionId,
            value_type = session.valueType or "unknown",
            count = count,
            module = session.module,
            last_value = session.lastValue,
            age_seconds = math_floor(now - session.created),
            idle_seconds = math_floor(now - session.lastAccess),
            timeout_in = math_floor(Config.SCAN_SESSION_TIMEOUT - (now - session.lastAccess)),
            memory_estimate = memoryEstimate
        })
    end

    return sessions
end

-- Cleanup zombie breakpoints/traces on server start/stop
function Utils.cleanupZombieState()
    local cleaned = { breakpoints = 0, traces = 0, find_what = 0, scan_sessions = 0 }

    for addr in pairs(Context.activeBreakpoints) do
        if pcall(debug_removeBreakpoint, addr) then
            cleaned.breakpoints = cleaned.breakpoints + 1
        end
    end

    if Context.traceAddr then
        pcall(debug_removeBreakpoint, Context.traceAddr)
        Context.traceAddr = nil
        cleaned.traces = cleaned.traces + 1
    end

    if Context.findWhatAddr then
        pcall(debug_removeBreakpoint, Context.findWhatAddr)
        Context.findWhatAddr = nil
        cleaned.find_what = cleaned.find_what + 1
    end

    local bpList = debug_getBreakpointList and debug_getBreakpointList() or nil
    if bpList then
        for _, bp in ipairs(bpList) do
            pcall(debug_removeBreakpoint, bp)
            cleaned.breakpoints = cleaned.breakpoints + 1
        end
    end

    -- Cleanup all scan sessions
    cleaned.scan_sessions = Utils.cleanupAllScanSessions()

    Context.activeBreakpoints = {}
    Context.hwBreakpointSlots = {}
    Context.traceData = nil
    Context.traceActive = false
    Context.bpResult = nil
    Context.bpTriggered = false
    Context.bpTimestamp = 0  -- Reset watchdog timestamp
    Context.traceLog = nil
    Context.traceComplete = false
    Context.traceStepCount = 0
    Context.traceTimestamp = 0  -- Reset watchdog timestamp
    Context.findWhatData = nil
    Context.findWhatActive = false
    Context.findWhatHits = 0
    Context.findWhatTimestamp = 0  -- Reset watchdog timestamp

    pcall(debug_continueFromBreakpoint, co_run)

    local total = cleaned.breakpoints + cleaned.traces + cleaned.find_what + cleaned.scan_sessions
    if total > 0 then
        Utils.debugPrint(string_format("Zombie cleanup: %d bp, %d trace, %d find_what, %d scan_sessions",
            cleaned.breakpoints, cleaned.traces, cleaned.find_what, cleaned.scan_sessions))
    end

    return cleaned
end

function Utils.checkProcessSwitch()
    local pid = getOpenedProcessID() or 0
    if pid ~= AddressCache.currentPID then
        if AddressCache.currentPID ~= 0 then
            Utils.debugPrint("Process switched, clearing cache")
            Utils.clearAddressCache()
            ModuleManager.reset()
            ModuleManager.initialize()
        end
        AddressCache.currentPID = pid
    end
end

-- Enhanced safeGetAddress with ErrorContextBuilder integration and Metrics tracking
-- @param addrStr: Address string or number to resolve
-- @param command: Optional command name for error context (default: "address_resolution")
function Utils.safeGetAddress(addrStr, command)
    if addrStr == nil then return nil end
    if type(addrStr) == "number" then return addrStr end

    command = command or "address_resolution"
    Utils.checkProcessSwitch()

    -- Fast path: module+offset format
    local moduleName, offsetStr = addrStr:match("^([%w_%.%-]+)%+(.+)$")

    if moduleName and offsetStr then
        local modKey = moduleName:lower()
        local baseAddr = AddressCache.moduleBase[modKey]

        if not baseAddr then
            -- Cache miss for module base
            Metrics.recordCacheMiss()
            baseAddr = getAddress(moduleName)
            if baseAddr and baseAddr ~= 0 then
                AddressCache.moduleBase[modKey] = baseAddr
                Utils.debugPrint("Cached module base: " .. moduleName .. " = " .. Utils.formatHex(baseAddr))
            else
                -- Module not found - use ErrorContextBuilder for enriched error
                error(ErrorContextBuilder.addressError(command, addrStr, "module lookup",
                    "Module not found: " .. moduleName))
            end
        else
            -- Cache hit for module base
            Metrics.recordCacheHit()
        end

        if baseAddr then
            local offset = tonumber(offsetStr, 16) or tonumber(offsetStr)
            if offset then
                return baseAddr + offset
            else
                -- Invalid offset - use ErrorContextBuilder for enriched error
                error(ErrorContextBuilder.addressError(command, addrStr, "offset calculation",
                    "Invalid offset: " .. offsetStr))
            end
        end
    end

    local cached = AddressCache.symbols[addrStr]
    if cached and (os_clock() - cached.ts) < cached.ttl then
        -- Cache hit for symbol
        Metrics.recordCacheHit()
        return cached.addr
    end

    -- Cache miss for symbol
    Metrics.recordCacheMiss()

    local addr = getAddressSafe(addrStr)
    if not addr or addr == 0 then
        error(ErrorContextBuilder.addressError(command, addrStr, "symbol resolution",
            "Invalid address: " .. tostring(addrStr)))
    end

    local ttl = CacheTTL.DYNAMIC_EXPR
    local ok, isInMod = pcall(inModule, addr)
    if ok and isInMod then ttl = CacheTTL.STATIC_SYMBOL end

    AddressCache.symbols[addrStr] = { addr = addr, ts = os_clock(), ttl = ttl }
    return addr
end

function Utils.checkProcess()
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        error("No process opened in Cheat Engine")
    end
    return pid
end

function Utils.findModule(moduleName)
    local mods = enumModules()
    if not mods or not moduleName then return nil end
    local target = moduleName:lower()
    for _, m in ipairs(mods) do
        if m.Name:lower() == target or m.Name:lower():find(target, 1, true) then
            return m
        end
    end
    return nil
end

function Utils.periodicCleanup()
    local now = os_clock()
    if now - Context.lastCleanup > Config.CLEANUP_INTERVAL then
        local toRemove = {}
        local symbolCount = 0
        for key, entry in pairs(AddressCache.symbols) do
            symbolCount = symbolCount + 1
            if now - entry.ts > entry.ttl * 2 then
                table_insert(toRemove, key)
            end
        end
        for _, key in ipairs(toRemove) do
            AddressCache.symbols[key] = nil
            symbolCount = symbolCount - 1
        end

        if symbolCount > AddressCache.maxSymbols then
            local entries = {}
            for key, entry in pairs(AddressCache.symbols) do
                table_insert(entries, {key = key, ts = entry.ts})
            end
            table_sort(entries, function(a, b) return a.ts < b.ts end)
            local excess = symbolCount - AddressCache.maxSymbols
            for i = 1, math_min(excess, #entries) do
                AddressCache.symbols[entries[i].key] = nil
            end
        end

        Context.lastCleanup = now
        Utils.debugPrint("Periodic cleanup: removed " .. #toRemove .. " expired cache entries")
    end

    -- Watchdog: check for stale debug states that could freeze the game
    if now - Context.lastWatchdogCheck > Config.WATCHDOG_CHECK_INTERVAL then
        Context.lastWatchdogCheck = now
        local watchdogTriggered = false
        local reason = nil

        -- Check stale breakpoint state
        if Context.bpTriggered and Context.bpTimestamp > 0 then
            if now - Context.bpTimestamp > Config.WATCHDOG_TIMEOUT then
                reason = "breakpoint timeout"
                watchdogTriggered = true
            end
        end

        -- Check stale trace state
        if Context.traceActive and Context.traceTimestamp > 0 then
            if now - Context.traceTimestamp > Config.WATCHDOG_TIMEOUT then
                reason = "trace timeout"
                watchdogTriggered = true
            end
        end

        -- Check stale find_what state
        if Context.findWhatActive and Context.findWhatTimestamp > 0 then
            if now - Context.findWhatTimestamp > Config.WATCHDOG_TIMEOUT then
                reason = "find_what timeout"
                watchdogTriggered = true
            end
        end

        if watchdogTriggered then
            Utils.debugPrint("Watchdog triggered: " .. reason .. ", cleaning up zombie state...")
            Utils.cleanupZombieState()
        end

        -- Heartbeat: check for MCP Server disconnection
        -- Only trigger if there are active debug states that could freeze the game
        local hasActiveDebugState = Context.bpTriggered or Context.traceActive or Context.findWhatActive
        if hasActiveDebugState and Context.lastActivityTime > 0 then
            if now - Context.lastActivityTime > Config.HEARTBEAT_TIMEOUT then
                Utils.debugPrint("Heartbeat timeout: MCP Server may have disconnected, cleaning up debug states...")
                Utils.cleanupZombieState()
                Context.lastActivityTime = 0  -- Reset to prevent repeated cleanup
            end
        end

        -- Cleanup expired scan sessions
        local expiredSessions = Utils.cleanupExpiredScanSessions()
        if expiredSessions > 0 then
            Utils.debugPrint("Cleaned up " .. expiredSessions .. " expired scan sessions")
        end

        -- Check for module changes and auto-refresh symbols
        local modulesChanged, changes = ModuleManager.checkForChanges()
        if modulesChanged and changes then
            Utils.debugPrint(string_format("Module changes detected: +%d added, -%d removed",
                #changes.added, #changes.removed))
        end
    end
end

function Utils.validateParams(params, required)
    for _, name in ipairs(required) do
        if params[name] == nil then
            error("Missing required parameter: " .. name)
        end
    end
end

-- ============ RAII Wrappers ============

function Utils.withDisassembler(callback)
    local d = createDisassembler()
    local success, result = pcall(callback, d)
    pcall(function() d.destroy() end)
    if not success then error(result) end
    return result
end

function Utils.withBreakpointState(callback)
    Context.bpResult = nil
    Context.bpTriggered = false
    local success, result = pcall(callback)
    local savedResult = Context.bpResult
    local savedTriggered = Context.bpTriggered
    Context.bpResult = nil
    Context.bpTriggered = false
    if not success then error(result) end
    return savedResult, savedTriggered
end

function Utils.withTraceState(callback)
    Context.traceLog = {}
    Context.traceComplete = false
    Context.traceStepCount = 0
    local success, result = pcall(callback)
    local savedLog = Context.traceLog
    local savedComplete = Context.traceComplete
    local savedStepCount = Context.traceStepCount
    Context.traceLog = nil
    Context.traceComplete = nil
    Context.traceStepCount = nil
    if not success then error(result) end
    return savedLog, savedComplete, savedStepCount
end

function Utils.adaptiveWait(condition, timeout, onPoll)
    local start = os_clock()
    local interval = Config.POLL_INTERVAL_INITIAL
    local pollCount = 0

    while not condition() and (os_clock() - start) * 1000 < timeout do
        if onPoll then onPoll(pollCount) end
        sleep(interval)
        pollCount = pollCount + 1
        if interval < Config.POLL_INTERVAL_MAX then
            interval = math_min(interval + 5, Config.POLL_INTERVAL_MAX)
        end
    end

    return condition()
end

function Utils.getRegisters()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            rax = Utils.formatHex(RAX or 0),
            rbx = Utils.formatHex(RBX or 0),
            rcx = Utils.formatHex(RCX or 0),
            rdx = Utils.formatHex(RDX or 0),
            rsi = Utils.formatHex(RSI or 0),
            rdi = Utils.formatHex(RDI or 0),
            rbp = Utils.formatHex(RBP or 0),
            rsp = Utils.formatHex(RSP or 0),
            r8 = Utils.formatHex(R8 or 0),
            r9 = Utils.formatHex(R9 or 0),
            r10 = Utils.formatHex(R10 or 0),
            r11 = Utils.formatHex(R11 or 0),
            r12 = Utils.formatHex(R12 or 0),
            r13 = Utils.formatHex(R13 or 0),
            r14 = Utils.formatHex(R14 or 0),
            r15 = Utils.formatHex(R15 or 0),
            rip = Utils.formatHex(RIP or 0),
            rflags = Utils.formatHex(EFLAGS or 0)
        }
    else
        return {
            eax = Utils.formatHex(EAX or 0),
            ebx = Utils.formatHex(EBX or 0),
            ecx = Utils.formatHex(ECX or 0),
            edx = Utils.formatHex(EDX or 0),
            esi = Utils.formatHex(ESI or 0),
            edi = Utils.formatHex(EDI or 0),
            ebp = Utils.formatHex(EBP or 0),
            esp = Utils.formatHex(ESP or 0),
            eip = Utils.formatHex(EIP or 0),
            eflags = Utils.formatHex(EFLAGS or 0)
        }
    end
end

function Utils.getXMMRegisters()
    local xmm = {}
    local count = targetIs64Bit() and 16 or 8

    for i = 0, count - 1 do
        local ok, ptr = pcall(debug_getXMMPointer, i)
        if ok and ptr and ptr ~= 0 then
            local floats, doubles = {}, {}
            local hexLow, hexHigh = nil, nil

            pcall(function()
                for j = 0, 3 do floats[j + 1] = readFloatLocal(ptr + j * 4) end
                for j = 0, 1 do doubles[j + 1] = readDoubleLocal(ptr + j * 8) end
                hexLow = readQwordLocal(ptr)
                hexHigh = readQwordLocal(ptr + 8)
            end)

            xmm["xmm" .. i] = {
                floats = floats,
                doubles = doubles,
                hex = string_format("%016X%016X", hexHigh or 0, hexLow or 0)
            }
        end
    end
    return xmm
end

function Utils.getStackPointer()
    return targetIs64Bit() and (RSP or 0) or (ESP or 0)
end

-- ============ JSON ============
local JSON = {}

local nativeJson = nil
pcall(function()
    if json and type(json.encode) == "function" and type(json.decode) == "function" then
        nativeJson = json
        Utils.debugPrint("Using native JSON module")
    end
end)

local escapeCharMap = {
    ["\\"] = "\\\\", ['"'] = '\\"', ["\b"] = "\\b",
    ["\f"] = "\\f", ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t",
}
local function escapeChar(c)
    return escapeCharMap[c] or string_format("\\u%04x", string_byte(c))
end
local function encodeString(s)
    return '"' .. string_gsub(s, '[%z\1-\31\\"]', escapeChar) .. '"'
end

function JSON.encode(obj, maxDepth)
    maxDepth = maxDepth or 50
    local seen = {}

    local function encodeValue(val, depth)
        if depth > maxDepth then return '"[max depth exceeded]"' end

        local t = type(val)
        if t == "nil" then return "null"
        elseif t == "boolean" then return val and "true" or "false"
        elseif t == "number" then
            if val ~= val or val == math.huge or val == -math.huge then return "null" end
            if math_floor(val) == val and math_abs(val) < 9007199254740992 then
                return string_format("%.0f", val)
            else
                return tostring(val)
            end
        elseif t == "string" then
            return encodeString(val)
        elseif t == "table" then
            if seen[val] then return '"[circular reference]"' end
            seen[val] = true

            local isArray = rawget(val, 1) ~= nil or next(val) == nil
            if isArray then
                local n = #val
                for k in pairs(val) do
                    if type(k) ~= "number" or k < 1 or k > n or math_floor(k) ~= k then
                        isArray = false
                        break
                    end
                end
            end

            local parts = {}
            local result
            if isArray then
                for i = 1, #val do parts[i] = encodeValue(val[i], depth + 1) end
                result = "[" .. table_concat(parts, ",") .. "]"
            else
                local n = 0
                for k, v in pairs(val) do
                    n = n + 1
                    parts[n] = encodeString(tostring(k)) .. ":" .. encodeValue(v, depth + 1)
                end
                result = "{" .. table_concat(parts, ",") .. "}"
            end

            seen[val] = nil
            return result
        end
        return "null"
    end

    return encodeValue(obj, 0)
end

function JSON.decode(str)
    if not str or str == "" then return nil end
    local pos, len = 1, #str
    local MAX_DEPTH = 100

    local function skip()
        while pos <= len do
            local b = string_byte(str, pos)
            if b <= 32 then pos = pos + 1 else break end
        end
    end

    local function parseString()
        pos = pos + 1
        local result = {}
        while pos <= len do
            local c = string_byte(str, pos)
            if c == 34 then
                pos = pos + 1
                return table_concat(result)
            elseif c == 92 then
                pos = pos + 1
                local nextC = string_byte(str, pos)
                if nextC == 34 then table_insert(result, '"')
                elseif nextC == 92 then table_insert(result, '\\')
                elseif nextC == 47 then table_insert(result, '/')
                elseif nextC == 98 then table_insert(result, '\b')
                elseif nextC == 102 then table_insert(result, '\f')
                elseif nextC == 110 then table_insert(result, '\n')
                elseif nextC == 114 then table_insert(result, '\r')
                elseif nextC == 116 then table_insert(result, '\t')
                elseif nextC == 117 then
                    local hex = string_sub(str, pos + 1, pos + 4)
                    local code = tonumber(hex, 16)
                    if code then
                        if code < 0x80 then
                            table_insert(result, string_char(code))
                        elseif code < 0x800 then
                            table_insert(result, string_char(0xC0 + math_floor(code / 0x40)))
                            table_insert(result, string_char(0x80 + (code % 0x40)))
                        else
                            table_insert(result, string_char(0xE0 + math_floor(code / 0x1000)))
                            table_insert(result, string_char(0x80 + (math_floor(code / 0x40) % 0x40)))
                            table_insert(result, string_char(0x80 + (code % 0x40)))
                        end
                    end
                    pos = pos + 4
                else
                    table_insert(result, string_char(nextC))
                end
                pos = pos + 1
            else
                table_insert(result, string_char(c))
                pos = pos + 1
            end
        end
        return table_concat(result)
    end

    local function parseNumber()
        local start = pos
        if string_byte(str, pos) == 45 then pos = pos + 1 end
        while pos <= len do
            local c = string_byte(str, pos)
            if (c >= 48 and c <= 57) or c == 46 or c == 101 or c == 69 or c == 43 or c == 45 then
                pos = pos + 1
            else break end
        end
        return tonumber(string_sub(str, start, pos - 1))
    end

    local function parseValue(depth)
        if depth > MAX_DEPTH then
            error("JSON nesting too deep")
        end
        skip()
        if pos > len then return nil end
        local c = string_byte(str, pos)

        if c == 123 then -- {
            pos = pos + 1
            local obj = {}
            skip()
            if string_byte(str, pos) == 125 then pos = pos + 1; return obj end
            while true do
                local key = parseValue(depth + 1)
                skip()
                if string_byte(str, pos) == 58 then pos = pos + 1 end
                obj[key] = parseValue(depth + 1)
                skip()
                local nc = string_byte(str, pos)
                if nc == 125 then pos = pos + 1; return obj end
                if nc == 44 then pos = pos + 1 end
            end
        elseif c == 91 then -- [
            pos = pos + 1
            local arr = {}
            skip()
            if string_byte(str, pos) == 93 then pos = pos + 1; return arr end
            while true do
                table_insert(arr, parseValue(depth + 1))
                skip()
                local nc = string_byte(str, pos)
                if nc == 93 then pos = pos + 1; return arr end
                if nc == 44 then pos = pos + 1 end
            end
        elseif c == 34 then return parseString()
        elseif c == 116 then pos = pos + 4; return true
        elseif c == 102 then pos = pos + 5; return false
        elseif c == 110 then pos = pos + 4; return nil
        else return parseNumber() end
    end

    local ok, res = pcall(parseValue, 0)
    return ok and res or nil
end

-- Override with native JSON if available
if nativeJson then
    JSON.encode = function(obj, maxDepth)
        local ok, result = pcall(nativeJson.encode, obj)
        return ok and result or nil
    end
    JSON.decode = function(str)
        local ok, result = pcall(nativeJson.decode, str)
        return ok and result or nil
    end
end


-- ============ Handlers: System ============
local Handlers = {}

-- Helper: Get debugger status info
local function getDebuggerStatus()
    local status = {
        active = false,
        interface = nil,
        interfaceName = "none",
        canBreak = false,
        isBroken = false,
        isStepping = false
    }
    pcall(function()
        status.active = debug_isDebugging() or false
        status.interface = debug_getCurrentDebuggerInterface()
        status.canBreak = debug_canBreak() or false
        status.isBroken = debug_isBroken() or false
        status.isStepping = debug_isStepping() or false
        -- Map interface number to name
        local interfaceNames = {
            [1] = "Windows", [2] = "VEH", [3] = "Kernel",
            [4] = "Mac", [5] = "GDB"
        }
        status.interfaceName = interfaceNames[status.interface] or "none"
    end)
    return status
end

Handlers.ping = function()
    return {
        status = "ok",
        timestamp = os.time(),
        process = process or "N/A",
        pid = getOpenedProcessID() or 0,
        connections = Context.connectionCount,
        debugger = getDebuggerStatus()
    }
end

Handlers.get_process_info = function(params)
    params = params or {}

    if ModuleManager.lastHash == 0 then
        ModuleManager.initialize()
    end

    if params.refresh_symbols == true then
        ModuleManager.refreshSymbols()
    else
        ModuleManager.checkForChanges()
    end

    local moduleStats = ModuleManager.getStats()

    local speedhackSpeed = 1.0
    pcall(function() speedhackSpeed = speedhack_getSpeed() or 1.0 end)

    local threadCount = 0
    pcall(function()
        local list = createStringlist()
        getThreadlist(list)
        threadCount = list.getCount()
        list:destroy()
    end)

    return {
        name = process or "N/A",
        pid = getOpenedProcessID(),
        is64bit = targetIs64Bit(),
        ce_version = getCEVersion(),
        debugger = getDebuggerStatus(),
        symbols_ready = ModuleManager.symbolsReady,
        last_symbol_refresh = ModuleManager.getLastRefreshTime(),
        symbol_refresh_count = moduleStats.refresh_count,
        module_count = moduleStats.module_count,
        speedhack_speed = speedhackSpeed,
        thread_count = threadCount,
    }
end

Handlers.execute_lua = function(p)
    Utils.validateParams(p, {"code"})
    local fn, err = loadstring(p.code)
    if not fn then error("Syntax error: " .. tostring(err)) end
    local ok, result = pcall(fn)
    if not ok then error("Runtime error: " .. tostring(result)) end
    return { result = result }
end

-- Handler: stats - Return comprehensive execution statistics
Handlers.stats = function(p)
    local metrics = Metrics.getSummary()
    local logStats = Logger.getStats()

    -- Add scan session info
    local scanSessionCount = Utils.countActiveScanSessions()
    local scanSessions = {}
    for sessionId, session in pairs(ScanSessions) do
        table_insert(scanSessions, {
            id = sessionId,
            scanCount = session.scanCount or 0,
            resultCount = session.resultCount or 0,
            lastAccess = session.lastAccess or 0
        })
    end

    return {
        uptime = metrics.uptime,
        commands = metrics.commands,
        summary = metrics.summary,
        cache = metrics.cache,
        logging = logStats,
        scanSessions = {
            active = scanSessionCount,
            maxAllowed = Config.MAX_SCAN_SESSIONS,
            sessions = scanSessions
        },
        connections = Context.connectionCount,
        debugger = getDebuggerStatus()
    }
end

Handlers.get_logs = function(p)
    local count = p and p.count or 50
    local minLevelStr = p and p.min_level or "INFO"
    local minLevel = LogLevel[minLevelStr:upper()] or LogLevel.INFO

    local entries = Logger.getEntries(count, minLevel)
    local formattedEntries = {}
    for _, entry in ipairs(entries) do
        table_insert(formattedEntries, {
            timestamp = entry.timestamp,
            level = entry.levelName,
            category = entry.category,
            message = entry.message
        })
    end

    return {
        entries = formattedEntries,
        totalEntries = Logger.entryCount,
        currentLevel = Logger.getLevelName(Logger.level)
    }
end

-- ============ Handlers: Memory ============
local MemoryReaders = {
    byte = function(addr, _, signed) return readBytes(addr, 1, true)[1] end,
    word = function(addr, _, signed) return readSmallInteger(addr, signed) end,
    dword = function(addr, _, signed) return readInteger(addr, signed) end,
    qword = function(addr) return readQword(addr) end,
    pointer = function(addr) return readPointer(addr) end,
    float = function(addr) return readFloat(addr) end,
    double = function(addr) return readDouble(addr) end,
    string = function(addr, sz, signed, widechar) return readString(addr, sz or 100, widechar) end,
    bytes = function(addr, sz) return readBytes(addr, sz or 100, true) end,
}

local MemoryWriters = {
    byte = writeBytes,
    word = writeSmallInteger,
    dword = writeInteger,
    qword = writeQword,
    pointer = writePointer,
    float = writeFloat,
    double = writeDouble,
    string = function(addr, val, widechar) return writeString(addr, val, widechar) end,
    bytes = writeBytes,
}

Handlers.read_memory = function(p)
    Utils.checkProcess()
    p.type = p.type or p.valueType
    if p.type == "integer" then
        p.type = p.size and p.size >= 8 and "qword" or "dword"
    end
    Utils.validateParams(p, {"address", "type"})

    local addr = Utils.safeGetAddress(p.address, "read_memory")
    local reader = MemoryReaders[p.type]
    if not reader then
        error(ErrorContextBuilder.memoryError("read_memory", p.address, p.type,
            "Unknown type: " .. p.type))
    end

    -- Wrap the read operation with error context
    local widechar = p.type == "string" and p.widechar or nil
    local ok, result = pcall(reader, addr, p.size, p.signed, widechar)
    if not ok then
        error(ErrorContextBuilder.memoryError("read_memory", addr, p.type, tostring(result)))
    end

    return { value = result }
end

Handlers.read_memory_batch = function(p)
    Utils.checkProcess()
    p.requests = p.requests or p.addresses
    Utils.validateParams(p, {"requests"})

    if type(p.requests) ~= "table" or #p.requests == 0 then
        error("read_memory_batch: 'requests' must be a non-empty array")
    end
    if #p.requests > 100 then
        error("read_memory_batch: too many requests (max 100), got " .. #p.requests)
    end

    local results = {}
    for _, item in ipairs(p.requests) do
        if not item.address then
            results[item.id or "unknown"] = { value = nil, error = "Missing 'address' field" }
            goto batch_continue
        end
        if not item.type then
            results[item.id or item.address] = { value = nil, error = "Missing 'type' field" }
            goto batch_continue
        end

        local ok, res = nil, nil
        ok, res = pcall(function()
            local addr = Utils.safeGetAddress(item.address, "read_memory_batch")
            local reader = MemoryReaders[item.type]
            if not reader then
                error(ErrorContextBuilder.memoryError("read_memory_batch", item.address, item.type,
                    "Unknown type: " .. tostring(item.type)))
            end
            return reader(addr, item.size)
        end)
        if ok then
            results[item.id or item.address] = { value = res }
        else
            results[item.id or item.address] = { value = nil, error = tostring(res) }
        end
        ::batch_continue::
    end
    return { results = results }
end

Handlers.write_memory = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address", "type", "value"})

    local addr = Utils.safeGetAddress(p.address, "write_memory")
    local writer = MemoryWriters[p.type]
    if not writer then
        error(ErrorContextBuilder.memoryError("write_memory", p.address, p.type,
            "Unknown type: " .. p.type))
    end

    -- Wrap the write operation with error context
    local ok, success = pcall(writer, addr, p.value, p.widechar)
    if not ok then
        error(ErrorContextBuilder.memoryError("write_memory", addr, p.type, tostring(success)))
    end

    return { address = Utils.formatHex(addr), success = success }
end

-- ============ Handlers: Scanning ============
Handlers.aob_scan = function(p)
    Utils.checkProcess()
    p.aob_string = p.aob_string or p.pattern
    Utils.validateParams(p, {"aob_string"})

    local cleanAob = string_gsub(p.aob_string, "%s+", " ")
    cleanAob = string_gsub(cleanAob, "^%s*(.-)%s*$", "%1")

    local protection = p.protection or "+X-C-W"
    local maxResults = math_min(p.max_results or 100, Config.MAX_AOB_RESULTS)

    -- Determine scan range
    local startAddr, stopAddr = nil, nil
    local scanModule = nil

    -- Use module parameter to limit scan range (performance optimization)
    if p.module then
        local m = Utils.findModule(p.module)
        if m then
            startAddr = m.Address
            local modSize = m.Size or getModuleSize(m.Name) or 0
            stopAddr = m.Address + modSize
            scanModule = m.Name
            Utils.debugPrint("AOB scan limited to module: " .. m.Name .. " (" .. Utils.formatHex(startAddr) .. " - " .. Utils.formatHex(stopAddr) .. ")")
        else
            error("Module not found: " .. p.module)
        end
    else
        if p.start then
            startAddr = Utils.safeGetAddress(p.start, "aob_scan")
        end
        if p.stop then
            stopAddr = Utils.safeGetAddress(p.stop, "aob_scan")
        end
    end

    -- Fast path: use AOBScanUnique when only 1 result needed and no range restriction
    if maxResults == 1 and not p.module and not p.start and not p.stop then
        local ok, result = pcall(AOBScanUnique, cleanAob, protection)
        if ok and result then
            return {
                count = 1,
                results = { Utils.formatHex(result) },
                truncated = false,
                module = nil
            }
        end
        return { count = 0, results = {}, truncated = false, module = nil }
    end

    -- Execute scan
    -- Use createMemScan to properly support start/stop range (AOBScan function doesn't support range args correctly)
    local memscan = createMemScan()
    local foundList = createFoundList(memscan)
    local scanOk = false
    
    local vtByteArray = vtByteArray or 7
    local rtRounded = rtRounded or 0
    local fsmNotAligned = fsmNotAligned or 0
    local soExactValue = soExactValue or 1

    pcall(function()
        memscan.firstScan(
            soExactValue, vtByteArray, rtRounded, 
            cleanAob, "", 
            startAddr or 0, stopAddr or 0x7FFFFFFFFFFFFFFF, 
            protection, fsmNotAligned, "", 
            true, false, false, false
        )
        memscan.waitTillDone()
        scanOk = true
    end)

    if not scanOk then
        pcall(function() foundList.deinitialize() end)
        pcall(function() memscan.destroy() end)
        error("AOB Scan failed")
    end

    foundList.initialize()
    local totalCount = foundList.Count or 0
    
    local results = {}
    local count = math_min(totalCount, maxResults)

    for i = 0, count - 1 do
        local addr = foundList.Address[i]
        if addr then
            if type(addr) == "string" then
                table_insert(results, addr)
            elseif type(addr) == "number" then
                table_insert(results, Utils.formatHex(addr))
            end
        end
    end

    foundList.deinitialize()
    memscan.destroy()

    return {
        count = totalCount,
        results = results,
        truncated = totalCount > maxResults,
        module = scanModule  -- Return actual scanned module name
    }
end

Handlers.value_scan = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"value", "type"})

    local valueStr = tostring(p.value)
    local valueType = p.type or "dword"
    local maxResults = math_min(p.max_results or 100, Config.MAX_AOB_RESULTS)
    local protection = p.protection or "+W-C"  -- writable memory only

    -- Determine scan range
    local startAddr, stopAddr = 0, Config.MAX_SCAN_ADDRESS
    local scanModule = nil

    if p.module then
        -- Limit to specific module
        local m = Utils.findModule(p.module)
        if m then
            startAddr = m.Address
            stopAddr = m.Address + (m.Size or getModuleSize(m.Name) or 0)
            scanModule = m.Name
        else
            error("Module not found: " .. p.module)
        end
    elseif p.start then
        startAddr = Utils.safeGetAddress(p.start)
        if p.stop then
            stopAddr = Utils.safeGetAddress(p.stop)
        end
    end

    -- Map type string to CE vartype
    local vt = ValueTypeMap[valueType] or vtDword

    -- Determine if hex input
    local isHex = p.is_hex
    if isHex == nil then
        -- Auto-detect: hex if starts with 0x or is integer type
        isHex = valueStr:match("^0[xX]") ~= nil or
                (valueType ~= "float" and valueType ~= "double" and valueType ~= "string")
    end

    -- Clean value format (remove 0x prefix)
    local scanValue = valueStr
    if isHex and scanValue:match("^0[xX]") then
        scanValue = scanValue:sub(3)
    end

    -- Create scan objects
    local memscan = createMemScan()
    local foundList = createFoundList(memscan)

    -- Execute scan
    local scanOk = pcall(function()
        -- Determine alignment
        local alignType = fsmAligned
        local alignParam = "4"
        if vt == vtQword or vt == vtDouble then alignParam = "8" end
        if vt == vtByte then alignType = fsmNotAligned end
        
        memscan.firstScan(soExactValue, vt, rtRounded, scanValue, "",
            startAddr, stopAddr, protection, alignType, alignParam,
            isHex, false, false, false)
        memscan.waitTillDone()
    end)

    if not scanOk then
        pcall(function() foundList.deinitialize() end)
        pcall(function() memscan.destroy() end)
        error("Scan failed")
    end

    foundList.initialize()

    -- Collect results
    local results = {}
    local totalCount = foundList.Count or 0
    local count = math_min(totalCount, maxResults)

    for i = 0, count - 1 do
        local addr = foundList.Address[i]
        if addr then
            local addrNum = type(addr) == "string" and tonumber(addr, 16) or addr
            local symbol = nil
            local isInModule = false

            pcall(function()
                symbol = getNameFromAddress(addrNum, true)
                isInModule = inModule(addrNum)
            end)

            table_insert(results, {
                address = Utils.formatHex(addrNum),
                symbol = symbol,
                isStatic = (symbol ~= nil) and
                    (symbol:find("%.exe%+") ~= nil or symbol:find("%.dll%+") ~= nil)
            })
        end
    end

    -- Cleanup
    foundList.deinitialize()
    memscan.destroy()

    return {
        count = totalCount,
        results = results,
        truncated = totalCount > maxResults,
        value_searched = valueStr,
        type = valueType,
        module = scanModule
    }
end

-- ============ Handlers: Scan Sessions ============
-- Implements First Scan -> Next Scan workflow with session management

Handlers.scan_new = function(p)
    Utils.checkProcess()

    local scanType = p.scan_type or "exact"

    if scanType ~= "unknown" then
        Utils.validateParams(p, {"value", "type"})
    else
        Utils.validateParams(p, {"type"})
    end

    -- Check session limit (Requirements 6.1, 6.2)
    local activeCount = Utils.countActiveScanSessions()
    if activeCount >= Config.MAX_SCAN_SESSIONS then
        -- Get list of active sessions for error message
        local activeSessions = Utils.getActiveScanSessionsList()
        local sessionDescriptions = {}

        for _, session in ipairs(activeSessions) do
            local desc = string_format("%s (type=%s, count=%d, idle=%ds)",
                session.session_id,
                session.value_type,
                session.count,
                session.idle_seconds)
            table_insert(sessionDescriptions, desc)
        end

        local errorMsg = string_format(
            "Maximum scan sessions reached (%d/%d). Active sessions: [%s]. Close existing sessions with scan_close first.",
            activeCount,
            Config.MAX_SCAN_SESSIONS,
            table_concat(sessionDescriptions, ", "))

        Logger.warn("scan_new", "Session limit reached", {
            active_count = activeCount,
            max_sessions = Config.MAX_SCAN_SESSIONS,
            sessions = activeSessions
        })

        error(errorMsg)
    end

    local valueStr = tostring(p.value)
    local valueType = p.type or "dword"
    local protection = p.protection or "+W-C"

    -- Determine scan range
    local startAddr, stopAddr = 0, Config.MAX_SCAN_ADDRESS
    local scanModule = nil

    if p.module then
        local m = Utils.findModule(p.module)
        if m then
            startAddr = m.Address
            stopAddr = m.Address + (m.Size or getModuleSize(m.Name) or 0)
            scanModule = m.Name
        else
             error("Module not found: " .. p.module)
        end
    elseif p.start then
        startAddr = Utils.safeGetAddress(p.start)
        if p.stop then
            stopAddr = Utils.safeGetAddress(p.stop)
        end
    end

    -- Map type string to CE vartype
    local vt = ValueTypeMap[valueType] or vtDword

    -- Determine if hex input
    -- Only treat as hex if explicitly specified or value starts with 0x
    local isHex = p.is_hex
    if isHex == nil then
        isHex = valueStr:match("^0[xX]") ~= nil
    end

    local scanValue = valueStr
    if isHex and scanValue:match("^0[xX]") then
        scanValue = scanValue:sub(3)
    end

    -- Create scan objects
    local memscan = createMemScan()
    local foundList = createFoundList(memscan)

    -- Execute first scan
    local scanOk = pcall(function()
        -- Determine alignment
        local alignType = fsmAligned
        local alignParam = "4"
        if vt == vtQword or vt == vtDouble then alignParam = "8" end
        if vt == vtByte then alignType = fsmNotAligned end

        if scanType == "unknown" then
            memscan.firstScan(soUnknownValue, vt, rtRounded, "", "",
                startAddr, stopAddr, protection, alignType, alignParam,
                false, false, false, false)
        else
            memscan.firstScan(soExactValue, vt, rtRounded, scanValue, "",
                startAddr, stopAddr, protection, alignType, alignParam,
                isHex, false, false, false)
        end
        memscan.waitTillDone()
    end)

    if not scanOk then
        pcall(function() foundList.deinitialize() end)
        pcall(function() memscan.destroy() end)
        error("First scan failed")
    end

    foundList.initialize()
    local totalCount = foundList.Count or 0

    -- Generate session ID and store
    local sessionId = Utils.generateSessionId()
    local now = os_clock()

    ScanSessions[sessionId] = {
        memscan = memscan,
        foundList = foundList,
        created = now,
        lastAccess = now,
        scanCount = 1,
        valueType = valueType,
        vt = vt,
        protection = protection,
        startAddr = startAddr,
        stopAddr = stopAddr,
        module = scanModule,
        lastValue = scanType == "unknown" and "" or valueStr,
        initialScanType = scanType,
    }

    Utils.debugPrint("Created scan session: " .. sessionId .. " with " .. totalCount .. " results")

    return {
        session_id = sessionId,
        count = totalCount,
        scan_number = 1,
        value_searched = valueStr,
        type = valueType,
        module = scanModule
    }
end

Handlers.scan_next = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"session_id", "value"})

    local session = ScanSessions[p.session_id]
    if not session then
        error("Session not found: " .. tostring(p.session_id))
    end

    -- Update last access time
    session.lastAccess = os_clock()

    local valueStr = tostring(p.value)
    local scanType = p.scan_type or "exact"

    -- Map scan type to CE scan option
    local scanOptionMap = {
        exact = soExactValue,
        increased = soIncreasedValue,
        decreased = soDecreasedValue,
        changed = soChanged,
        unchanged = soUnchanged,
        increased_by = soIncreasedValueBy,
        decreased_by = soDecreasedValueBy,
        bigger_than = soBiggerThan,
        smaller_than = soSmallerThan,
        between = soValueBetween
    }
    local scanOption = scanOptionMap[scanType] or soExactValue

    -- Determine if hex input
    -- Only treat as hex if explicitly specified or value starts with 0x
    local isHex = p.is_hex
    if isHex == nil then
        isHex = valueStr:match("^0[xX]") ~= nil
    end

    local scanValue = valueStr
    if isHex and scanValue:match("^0[xX]") then
        scanValue = scanValue:sub(3)
    end

    -- For between scan, need second value
    local scanValue2 = ""
    if scanType == "between" and p.value2 then
        scanValue2 = tostring(p.value2)
        if isHex and scanValue2:match("^0[xX]") then
            scanValue2 = scanValue2:sub(3)
        end
    end

    -- Execute next scan
    local scanOk = pcall(function()
        session.memscan.nextScan(scanOption, rtRounded, scanValue, scanValue2,
            isHex, false, false, false, false)
        session.memscan.waitTillDone()
    end)

    if not scanOk then
        error("Next scan failed")
    end

    session.foundList.initialize()
    local totalCount = session.foundList.Count or 0
    session.scanCount = session.scanCount + 1
    session.lastValue = valueStr

    Utils.debugPrint("Scan session " .. p.session_id .. " next scan: " .. totalCount .. " results")

    return {
        session_id = p.session_id,
        count = totalCount,
        scan_number = session.scanCount,
        scan_type = scanType,
        value_searched = valueStr
    }
end

Handlers.scan_results = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"session_id"})

    local session = ScanSessions[p.session_id]
    if not session then
        error("Session not found: " .. tostring(p.session_id))
    end

    -- Update last access time
    session.lastAccess = os_clock()

    local startIndex = p.start_index or 0
    local limit = math_min(p.limit or Config.SCAN_DEFAULT_PAGE_SIZE, Config.SCAN_MAX_PAGE_SIZE)

    session.foundList.initialize()
    local totalCount = session.foundList.Count or 0

    local results = {}
    local endIndex = math_min(startIndex + limit, totalCount)

    for i = startIndex, endIndex - 1 do
        local addr = session.foundList.Address[i]
        if addr then
            local addrNum = type(addr) == "string" and tonumber(addr, 16) or addr
            local symbol = nil
            local currentValue = nil

            pcall(function()
                symbol = getNameFromAddress(addrNum, true)
            end)

            -- Read current value
            pcall(function()
                local reader = MemoryReaders[session.valueType]
                if reader then
                    currentValue = reader(addrNum)
                end
            end)

            table_insert(results, {
                index = i,
                address = Utils.formatHex(addrNum),
                symbol = symbol,
                value = currentValue,
                isStatic = (symbol ~= nil) and
                    (symbol:find("%.exe%+") ~= nil or symbol:find("%.dll%+") ~= nil)
            })
        end
    end

    return {
        session_id = p.session_id,
        total_count = totalCount,
        start_index = startIndex,
        returned_count = #results,
        has_more = endIndex < totalCount,
        results = results
    }
end

Handlers.scan_close = function(p)
    Utils.validateParams(p, {"session_id"})

    local success = Utils.cleanupScanSession(p.session_id)

    return {
        session_id = p.session_id,
        closed = success,
        active_sessions = Utils.countActiveScanSessions()
    }
end

Handlers.scan_list = function()
    local sessions = {}
    local now = os_clock()
    local totalMemoryBytes = 0

    for sessionId, session in pairs(ScanSessions) do
        session.foundList.initialize()
        local count = session.foundList.Count or 0

        -- Estimate memory usage (Requirements 6.3)
        local memoryEstimate = Utils.estimateScanSessionMemory(count, session.valueType)
        totalMemoryBytes = totalMemoryBytes + memoryEstimate.bytes

        table_insert(sessions, {
            session_id = sessionId,
            count = count,
            scan_count = session.scanCount,
            value_type = session.valueType,
            module = session.module,
            last_value = session.lastValue,
            age_seconds = math_floor(now - session.created),
            idle_seconds = math_floor(now - session.lastAccess),
            timeout_in = math_floor(Config.SCAN_SESSION_TIMEOUT - (now - session.lastAccess)),
            -- Memory estimation (Requirements 6.3)
            memory_estimate = memoryEstimate
        })
    end

    -- Calculate total memory estimate
    local totalMemory = {
        bytes = totalMemoryBytes,
        kb = math_floor(totalMemoryBytes / 1024),
        mb = math_floor(totalMemoryBytes / (1024 * 1024) * 100) / 100
    }

    return {
        active_sessions = #sessions,
        max_sessions = Config.MAX_SCAN_SESSIONS,
        sessions = sessions,
        total_memory_estimate = totalMemory
    }
end

-- ============ Handlers: Process Automation ============

Handlers.list_processes = function(p)
    local filter = p.filter and p.filter:lower() or nil
    local maxResults = p.max_results or 100

    local pl = getProcessList()
    local results = {}
    local count = 0

    for pid, name in pairs(pl) do
        if type(pid) == "number" and type(name) == "string" then
            -- Apply filter if specified
            if not filter or name:lower():find(filter, 1, true) then
                table_insert(results, { pid = pid, name = name })
                count = count + 1
                if count >= maxResults then break end
            end
        end
    end

    -- Sort by name
    table_sort(results, function(a, b) return a.name:lower() < b.name:lower() end)

    return {
        count = #results,
        processes = results
    }
end

Handlers.attach_process = function(p)
    Utils.validateParams(p, {"target"})

    local target = p.target
    local pid = nil
    local processName = nil

    -- Check if target is a PID (number) or process name (string)
    if type(target) == "number" or (type(target) == "string" and target:match("^%d+$")) then
        pid = tonumber(target)
        processName = nil
    else
        -- Target is a process name
        processName = target
        pid = getProcessIDFromProcessName(processName)
        if not pid or pid == 0 then
            error("Process not found: " .. tostring(processName))
        end
    end

    -- Attach to process
    local success = pcall(function()
        openProcess(pid)
    end)

    if not success then
        error("Failed to attach to process: " .. tostring(target))
    end

    -- Clear caches after attaching to new process
    Utils.clearAddressCache()
    Utils.cleanupAllScanSessions()

    -- Wait a moment for CE to initialize
    sleep(100)

    return {
        success = true,
        pid = getOpenedProcessID(),
        name = processName or getProcessNameFromID(pid) or "N/A",
        is64bit = targetIs64Bit()
    }
end

Handlers.auto_assemble = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"script"})

    local script = p.script
    local targetSelf = p.target_self or false
    local disable = p.disable or false

    if disable then
        local disableInfoRaw = p.disable_info
        if not disableInfoRaw then
            error("disable_info required when disable=true. Pass the disableInfo from a previous enable execution.")
        end
        local ok, err = pcall(function()
            autoAssemble(script, disableInfoRaw)
        end)
        if not ok then
            error("Auto Assemble disable failed: " .. tostring(err))
        end
        return { success = true, action = "disable" }
    end

    local success, disableInfo = nil, nil
    local ok, err = pcall(function()
        success, disableInfo = autoAssemble(script, targetSelf)
    end)
    if not ok then
        error("Auto Assemble crashed: " .. tostring(err))
    end

    if not success then
        error("Auto Assemble failed: " .. tostring(disableInfo))
    end

    local result = {
        success = true,
        target_self = targetSelf
    }

    if disableInfo then
        local diResult = {}
        pcall(function()
            if disableInfo.allocs then
                diResult.allocs = {}
                for name, info in pairs(disableInfo.allocs) do
                    diResult.allocs[name] = {
                        address = Utils.formatHex(info.address or 0),
                        size = info.size or 0,
                    }
                end
            end
            if disableInfo.registeredsymbols then
                diResult.registered_symbols = {}
                for i, sym in ipairs(disableInfo.registeredsymbols) do
                    table_insert(diResult.registered_symbols, sym)
                end
            end
            if disableInfo.symbols then
                diResult.symbols = {}
                for name, addr in pairs(disableInfo.symbols) do
                    diResult.symbols[name] = Utils.formatHex(addr)
                end
            end
            if disableInfo.ccodesymbols then
                diResult.ccode_symbols = {}
                for i, sym in ipairs(disableInfo.ccodesymbols) do
                    table_insert(diResult.ccode_symbols, sym)
                end
            end
            if disableInfo.exceptionlist then
                diResult.exception_list = {}
                for i, exc in ipairs(disableInfo.exceptionlist) do
                    table_insert(diResult.exception_list, {
                        address = Utils.formatHex(exc.address or 0),
                    })
                end
            end
        end)
        result.disableInfo = diResult
    end

    return result
end

Handlers.enum_modules = function()
    Utils.checkProcess()
    local mods = enumModules()
    local r = {}
    local usedFallback = false

    -- Normal enumeration
    if mods and #mods > 0 then
        for _, m in ipairs(mods) do
            table_insert(r, {
                name = m.Name,
                address = Utils.formatHex(m.Address),
                size = m.Size or getModuleSize(m.Name) or 0,
                path = m.PathToFile,
                source = "enumModules"
            })
        end
    end

    -- Anti-cheat fallback: AOB scan for MZ headers + read PE Export Directory name
    if #r == 0 then
        usedFallback = true
        local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")  -- MZ PE header
        if mzScan and mzScan.Count > 0 then
            for i = 0, math_min(mzScan.Count - 1, 50) do
                local addr = tonumber(mzScan[i], 16)
                if addr then
                    local peOffset = readInteger(addr + 0x3C)
                    local moduleSize = 0
                    local realName = nil

                    if peOffset and peOffset > 0 and peOffset < 0x1000 then
                        -- Get Size of Image
                        local sizeOfImage = readInteger(addr + peOffset + 0x50)
                        if sizeOfImage then moduleSize = sizeOfImage end

                        -- Read internal name from Export Directory
                        local exportRVA = readInteger(addr + peOffset + 0x78)
                        if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                            local nameRVA = readInteger(addr + exportRVA + 0x0C)
                            if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                                local name = readString(addr + nameRVA, 64)
                                if name and #name > 0 and #name < 60 then
                                    realName = name
                                end
                            end
                        end
                    end

                    -- Determine module name
                    local modName
                    if realName then
                        modName = realName
                    elseif i == 0 then
                        modName = (process ~= "" and process) or "main.exe"
                    else
                        modName = "Module_" .. string_format("%X", addr)
                    end

                    table_insert(r, {
                        name = modName,
                        address = Utils.formatHex(addr),
                        size = moduleSize,
                        path = "",
                        source = realName and "export_directory" or "aob_fallback"
                    })
                end
            end
        end
        if mzScan then
            mzScan.destroy()
        end
    end

    return {
        modules = r,
        count = #r,
        used_fallback = usedFallback
    }
end

Handlers.get_address_list = function(p)
    Utils.checkProcess()
    local al = getAddressList()
    if not al then error("Cannot get address list") end

    local results = {}
    local includeScript = p.include_script or false

    local function processRecord(mr, depth)
        local record = {
            id = mr.ID,
            description = mr.Description or "",
            address = "",
            addressStr = mr.Address or "",
            value = "",
            valueType = "",
            isGroup = mr.IsGroupHeader or false,
            active = mr.Active or false,
            depth = depth,
            isPointer = false,
            pointerOffsets = nil,
            baseAddress = nil
        }

        if not mr.IsGroupHeader then
            local addr = mr.CurrentAddress
            if addr and addr ~= 0 then
                record.address = Utils.formatHex(addr)
            end

            -- Check if pointer type, extract full pointer chain
            local ok, offsetCount = pcall(function() return mr.OffsetCount end)
            if ok and offsetCount and offsetCount > 0 then
                record.isPointer = true
                record.pointerOffsets = {}
                record.pointerOffsetsHex = {}

                -- Get base address (string form, may be symbol or value)
                local baseOk, baseAddr = pcall(function() return mr.Address end)
                if baseOk and baseAddr then
                    record.baseAddress = baseAddr
                end

                -- Get all offsets (CE order: Offset[0] is last level, Offset[n-1] is first level)
                -- Example: [[base+28]+19300] -> Offset[0]=19300, Offset[1]=28
                for i = 0, offsetCount - 1 do
                    local offsetOk, offset = pcall(function() return mr.Offset[i] end)
                    if offsetOk and offset then
                        table_insert(record.pointerOffsets, offset)
                        if offset >= 0 then
                            table_insert(record.pointerOffsetsHex, string_format("0x%X", offset))
                        else
                            table_insert(record.pointerOffsetsHex, string_format("-0x%X", math_abs(offset)))
                        end
                    end
                end

                -- Build readable pointer chain (from base to final address)
                -- Reverse offset order: Offset[n-1] is first level, Offset[0] is last level
                local chainParts = {}
                local baseStr = record.baseAddress or "?"
                table_insert(chainParts, baseStr)

                -- Start from last offset (first level)
                for i = #record.pointerOffsets, 1, -1 do
                    local off = record.pointerOffsets[i]
                    local offStr = off >= 0 and string_format("+0x%X", off) or string_format("-0x%X", math_abs(off))
                    local prev = table_concat(chainParts)
                    chainParts = { "[" .. prev .. "]" .. offStr }
                end

                record.pointerChain = table_concat(chainParts)
            end

            local vt = mr.Type
            record.valueType = VtToNameMap[vt] or "unknown"

            local ok, val = pcall(function() return mr.Value end)
            if ok and val then record.value = tostring(val) end
        end

        if includeScript and mr.Type == vtAutoAssembler then
            local ok, script = pcall(function() return mr.Script end)
            if ok and script then record.script = script end
        end

        table_insert(results, record)

        if mr.Count and mr.Count > 0 then
            for i = 0, mr.Count - 1 do
                local child = mr.Child[i]
                if child then processRecord(child, depth + 1) end
            end
        end
    end

    for i = 0, al.Count - 1 do
        local mr = al[i]
        if mr then processRecord(mr, 0) end
    end

    return { count = #results, records = results }
end

Handlers.add_address_record = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"description", "address"})
    local al = getAddressList()
    if not al then error("Cannot get address list") end

    local mr = al.createMemoryRecord()
    mr.Description = p.description
    mr.Address = p.address

    mr.Type = ValueTypeMap[p.value_type or "dword"] or vtDword

    if p.value_type == "script" and p.script then
        mr.Script = p.script
    end

    return { id = mr.ID, description = mr.Description, address = mr.Address, success = true }
end


-- ============ Handlers: Symbols ============
Handlers.get_address = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"expression"})
    local addr = getAddress(p.expression)
    if not addr then error("Could not resolve: " .. p.expression) end
    return {
        expression = p.expression,
        address = Utils.formatHex(addr),
        addressDec = addr
    }
end

-- Cache for get_symbol results to avoid repeated expensive lookups
local SymbolCache = {
    cache = {},
    accessTime = {},
    maxSize = 1000,
    hits = 0,
    misses = 0
}

function SymbolCache.getKey(addr, includeModule)
    return string_format("%X_%s", addr, tostring(includeModule))
end

function SymbolCache.get(addr, includeModule)
    local key = SymbolCache.getKey(addr, includeModule)
    local entry = SymbolCache.cache[key]
    if entry then
        SymbolCache.hits = SymbolCache.hits + 1
        SymbolCache.accessTime[key] = os_clock()
        return entry
    end
    SymbolCache.misses = SymbolCache.misses + 1
    return nil
end

function SymbolCache.set(addr, includeModule, result)
    local key = SymbolCache.getKey(addr, includeModule)

    -- True LRU eviction: remove oldest entry when full
    local count = 0
    for _ in pairs(SymbolCache.cache) do count = count + 1 end
    if count >= SymbolCache.maxSize then
        local oldestKey = nil
        local oldestTime = math.huge
        for k, _ in pairs(SymbolCache.cache) do
            local t = SymbolCache.accessTime[k] or 0
            if t < oldestTime then
                oldestTime = t
                oldestKey = k
            end
        end
        if oldestKey then
            SymbolCache.cache[oldestKey] = nil
            SymbolCache.accessTime[oldestKey] = nil
        end
    end

    SymbolCache.cache[key] = result
    SymbolCache.accessTime[key] = os_clock()
end

function SymbolCache.getStats()
    local total = SymbolCache.hits + SymbolCache.misses
    return {
        hits = SymbolCache.hits,
        misses = SymbolCache.misses,
        hit_rate = total > 0 and (SymbolCache.hits / total) or 0,
        size = Utils.tableCount(SymbolCache.cache),
        max_size = SymbolCache.maxSize
    }
end

Handlers.get_symbol = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)
    local includeModule = p.include_module ~= false
    local skipCache = p.skip_cache == true

    if not skipCache then
        local cached = SymbolCache.get(addr, includeModule)
        if cached then
            return cached
        end
    end

    local symbol = getNameFromAddress(addr, includeModule)

    local rttiName = nil
    pcall(function()
        rttiName = getRTTIClassName(addr)
    end)

    local isInModule = inModule(addr)
    local isInSystemModule = inSystemModule(addr)
    local moduleInfo = nil
    if isInModule then
        pcall(function()
            local mods = enumModules()
            if mods then
                for _, m in ipairs(mods) do
                    local modBase = m.Address
                    local modSize = m.Size or getModuleSize(m.Name) or 0
                    if addr >= modBase and addr < (modBase + modSize) then
                        moduleInfo = {
                            name = m.Name,
                            base = Utils.formatHex(modBase),
                            size = modSize,
                            offset = Utils.formatHex(addr - modBase),
                            is64bit = m.Is64Bit or false,
                            path = m.PathToFile or ""
                        }
                        break
                    end
                end
            end
        end)
    end

    local result = {
        address = Utils.formatHex(addr),
        symbol = symbol or "",
        hasSymbol = symbol ~= nil and symbol ~= "",
        rttiClassName = rttiName,
        hasRTTI = rttiName ~= nil and rttiName ~= "",
        inModule = isInModule,
        inSystemModule = isInSystemModule,
        moduleInfo = moduleInfo
    }
    
    -- Cache the result
    if not skipCache then
        SymbolCache.set(addr, includeModule, result)
    end

    return result
end

Handlers.get_region_info = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)

    local prot = getMemoryProtection(addr)
    local base, size, regionProt = nil, nil, nil

    local regions = enumMemoryRegions()
    if regions and type(regions) == "table" then
        for _, region in ipairs(regions) do
            if region and region.BaseAddress then
                local rBase = region.BaseAddress
                local rSize = region.RegionSize or 0
                if addr >= rBase and addr < (rBase + rSize) then
                    base, size, regionProt = rBase, rSize, region.Protect
                    break
                end
            end
        end
    end

    local protStr = ""
    if prot then
        if prot.r then protStr = protStr .. "R" end
        if prot.w then protStr = protStr .. "W" end
        if prot.x then protStr = protStr .. "X" end
    end
    if protStr == "" then protStr = "---" end

    return {
        address = Utils.formatHex(addr),
        baseAddress = base and Utils.formatHex(base) or "unknown",
        regionSize = size or 0,
        protection = regionProt or 0,
        protectionStr = protStr
    }
end

-- ValueType enum mapping
local ValueTypeNames = {
    [0] = "byte", [1] = "word", [2] = "dword", [3] = "qword",
    [4] = "float", [5] = "double", [6] = "string",
    [8] = "byte_array", [9] = "binary", [10] = "all",
    [11] = "auto_assembler", [12] = "pointer", [13] = "custom", [14] = "grouped"
}

Handlers.auto_guess = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)

    -- Check if address is readable first
    local readable = readBytes(addr, 1) ~= nil
    if not readable then
        error("Address not readable: " .. Utils.formatHex(addr))
    end

    -- Call autoGuess
    local ok, vt = pcall(autoGuess, addr)
    if not ok or vt == nil then
        error("autoGuess failed: " .. Utils.formatHex(addr))
    end

    local typeName = ValueTypeNames[vt] or "unknown"

    -- Read the value based on guessed type
    local value = nil
    local valueHex = nil
    if vt == 0 then -- byte
        value = readBytes(addr, 1); if type(value) == "table" then value = value[1] end
        if value then valueHex = string_format("0x%02X", value) end
    elseif vt == 1 then -- word
        value = readSmallInteger(addr)
        if value then valueHex = string_format("0x%04X", value) end
    elseif vt == 2 then -- dword
        value = readInteger(addr)
        if value then valueHex = string_format("0x%08X", value) end
    elseif vt == 3 then -- qword
        value = readQword(addr)
        if value then valueHex = string_format("0x%X", value) end
    elseif vt == 4 then -- float
        value = readFloat(addr)
    elseif vt == 5 then -- double
        value = readDouble(addr)
    elseif vt == 6 then -- string
        value = readString(addr, 100)
    elseif vt == 12 then -- pointer
        value = readPointer(addr)
        if value then valueHex = string_format("0x%X", value) end
    end

    return {
        address = Utils.formatHex(addr),
        readable = true,
        type_id = vt,
        type_name = typeName,
        value = value,
        value_hex = valueHex
    }
end

Handlers.resolve_pointer = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"base", "offsets"})
    local base = Utils.safeGetAddress(p.base)
    local offsets = p.offsets or {}
    local is64 = targetIs64Bit()
    local readValue = p.read_value or false
    local valueType = p.value_type or "dword"

    local baseSymbol = getNameFromAddress(base, true) or p.base

    -- Build CE pointer notation: [[[base]+off1]+off2]+off3
    local function buildCENotation(symbol, offs)
        if #offs == 0 then return symbol end
        local notation = "[" .. symbol .. "]"
        for i, off in ipairs(offs) do
            if i < #offs then
                notation = "[" .. notation .. string_format("+0x%X]", off)
            else
                notation = notation .. string_format("+0x%X", off)
            end
        end
        return notation
    end

    local currentAddr = base
    local chain = {{
        level = 0,
        address = Utils.formatHex(currentAddr),
        symbol = baseSymbol,
        offset = "base"
    }}

    local failedAtLevel = nil
    local errorMsg = nil

    for i, offset in ipairs(offsets) do
        local ptrValue = readPointer(currentAddr)

        if not ptrValue or ptrValue == 0 then
            failedAtLevel = i
            errorMsg = string_format("Null pointer at level %d: read from %s returned %s",
                i, Utils.formatHex(currentAddr), ptrValue == 0 and "0" or "nil")
            break
        end

        currentAddr = ptrValue + offset
        local addrSymbol = getNameFromAddress(currentAddr, true) or Utils.formatHex(currentAddr)

        table_insert(chain, {
            level = i,
            address = Utils.formatHex(currentAddr),
            symbol = addrSymbol,
            ptrValue = Utils.formatHex(ptrValue),
            offset = string_format("+0x%X", offset)
        })
    end

    local result = {
        success = (failedAtLevel == nil),
        base = Utils.formatHex(base),
        baseSymbol = baseSymbol,
        offsets = offsets,
        offsetsHex = {},
        finalAddress = Utils.formatHex(currentAddr),
        finalSymbol = getNameFromAddress(currentAddr, true) or Utils.formatHex(currentAddr),
        ceNotation = buildCENotation(baseSymbol, offsets),
        chain = chain
    }

    for _, off in ipairs(offsets) do
        table_insert(result.offsetsHex, string_format("0x%X", off))
    end

    if failedAtLevel then
        result.failedAtLevel = failedAtLevel
        result.error = errorMsg
        local partialOffsets = {}
        for i = 1, failedAtLevel - 1 do
            partialOffsets[i] = offsets[i]
        end
        result.partialCENotation = buildCENotation(baseSymbol, partialOffsets)
    end

    -- Optional: read value at final address
    if readValue and result.success then
        local val
        if valueType == "byte" then
            local t = readBytes(currentAddr, 1, true)
            val = t and t[1]
        elseif valueType == "word" then
            val = readSmallInteger(currentAddr)
        elseif valueType == "dword" then
            val = readInteger(currentAddr)
        elseif valueType == "qword" then
            val = readQword(currentAddr)
        elseif valueType == "float" then
            val = readFloat(currentAddr)
        elseif valueType == "double" then
            val = readDouble(currentAddr)
        elseif valueType == "pointer" then
            val = readPointer(currentAddr)
        end

        if val then
            result.value = val
            if type(val) == "number" and math_floor(val) == val then
                result.valueHex = Utils.formatHex(val)
            end
        end
    end

    return result
end

-- ============ Handlers: Debug ============
Handlers.disassemble = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)
    local count = p.count or 10
    local direction = p.direction or "forward"
    local detailed = p.detailed == true
    local instrs = {}

    local function getDetailedInfo(address)
        local info = {}
        pcall(function()
            local d = createDisassembler()
            d.disassemble(address)
            local ld = d.getLastDisassembleData()
            if ld then
                info.modrmValueType = ld.modrmValueType or 0
                info.modrmValue = ld.modrmValue or 0
                info.parameterValueType = ld.parameterValueType or 0
                info.parameterValue = ld.parameterValue or 0
                info.isJump = ld.isJump or false
                info.isCall = ld.isCall or false
                info.isRet = ld.isRet or false
                info.isConditionalJump = ld.isConditionalJump or false
                info.isRep = ld.isRep or false
                if info.modrmValueType == 1 then info.modrmValue = Utils.formatHex(info.modrmValue) end
                if info.parameterValueType == 1 then info.parameterValue = Utils.formatHex(info.parameterValue) end
            end
            d:destroy()
        end)
        return info
    end

    if direction == "backward" then
        for _ = 1, count do
            local prevAddr = getPreviousOpcode(addr)
            if not prevAddr or prevAddr == 0 or prevAddr >= addr then
                break
            end
            addr = prevAddr
            local dis = disassemble(addr)
            local addrStr, opcodeStr, bytesStr, extra = splitDisassembledString(dis)
            -- splitDisassembledString returns: addrStr, opcode, bytes, extra (celua.txt docs have this wrong)
            local sz = getInstructionSize(addr)
            local entry = {
                address = Utils.formatHex(addr),
                bytes = bytesStr or "",
                opcode = opcodeStr or "",
                extra = extra or "",
                size = sz
            }
            if detailed then
                local dInfo = getDetailedInfo(addr)
                for k, v in pairs(dInfo) do entry[k] = v end
            end
            table_insert(instrs, 1, entry)
        end
        return { instructions = instrs, previousAddress = Utils.formatHex(addr) }
    else
        for _ = 1, count do
            local dis = disassemble(addr)
            local addrStr, opcodeStr, bytesStr, extra = splitDisassembledString(dis)
            -- splitDisassembledString returns: addrStr, opcode, bytes, extra (celua.txt docs have this wrong)
            local sz = getInstructionSize(addr)
            local entry = {
                address = Utils.formatHex(addr),
                bytes = bytesStr or "",
                opcode = opcodeStr or "",
                extra = extra or "",
                size = sz
            }
            if detailed then
                local dInfo = getDetailedInfo(addr)
                for k, v in pairs(dInfo) do entry[k] = v end
            end
            table_insert(instrs, entry)
            addr = addr + sz
        end
        return { instructions = instrs, nextAddress = Utils.formatHex(addr) }
    end
end

Handlers.get_instruction_info = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)

    -- Use RAII wrapper to ensure disassembler is properly destroyed
    return Utils.withDisassembler(function(d)
        d.disassemble(addr)
        local data = d.LastDisassembleData

        local bytesHex = {}
        for _, b in ipairs(data.bytes) do
            table_insert(bytesHex, string_format("%02X", b))
        end

        return {
            address = Utils.formatHex(data.address),
            opcode = data.opcode,
            params = data.parameters,
            size = #data.bytes,
            bytes = bytesHex,
            bytesStr = table_concat(bytesHex, " "),
            isCall = data.isCall or false,
            isJump = data.isJump or false,
            isConditionalJump = data.isConditionalJump or false,
            isRet = data.isRet or false,
            parameterValue = data.parameterValue and Utils.formatHex(data.parameterValue) or nil
        }
    end)
end

Handlers.set_breakpoint = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address, "set_breakpoint")
    local bpType = p.type or "execute"
    local size = p.size or 1

    -- Check if breakpoint already exists (avoid duplicate)
    local existing = Context.activeBreakpoints[addr]
    if existing and existing.active then
        Utils.debugPrint("Breakpoint already exists at " .. Utils.formatHex(addr))
        return {
            address = Utils.formatHex(addr),
            type = bpType,
            success = true,
            reused = true,
            slot = existing.slot
        }
    end

    -- Find free hardware breakpoint slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not Context.hwBreakpointSlots[i] then
            slot = i
            break
        end
    end

    if not slot then
        error(ErrorContextBuilder.breakpointError("set_breakpoint", addr,
            "No free hardware breakpoint slots (max 4 debug registers). Use ce_cleanup to remove existing breakpoints."))
    end

    local ceType = bptExecute
    if bpType == "write" then ceType = bptWrite
    elseif bpType == "access" then ceType = bptAccess end

    -- Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    local ok, err = pcall(debug_setBreakpoint, addr, size, ceType, bpmDebugRegister)
    if not ok then
        error(ErrorContextBuilder.breakpointError("set_breakpoint", addr, tostring(err)))
    end

    -- Track the breakpoint
    Context.hwBreakpointSlots[slot] = addr
    Context.activeBreakpoints[addr] = { type = bpType, active = true, slot = slot }

    return {
        address = Utils.formatHex(addr),
        type = bpType,
        success = true,
        slot = slot,
        method = "hardware_debug_register"
    }
end

Handlers.remove_breakpoint = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address, "remove_breakpoint")

    local ok, err = pcall(debug_removeBreakpoint, addr)
    if not ok then
        error(ErrorContextBuilder.breakpointError("remove_breakpoint", addr, tostring(err)))
    end

    -- Remove from active breakpoints table and free slot
    local bp = Context.activeBreakpoints[addr]
    if bp then
        if bp.slot then
            Context.hwBreakpointSlots[bp.slot] = nil
        end
        Context.activeBreakpoints[addr] = nil
    end

    pcall(debug_continueFromBreakpoint, co_run)
    return { address = Utils.formatHex(addr), success = true }
end

Handlers.get_breakpoints = function()
    Utils.checkProcess()
    local bpList = debug_getBreakpointList() or {}
    local results = {}
    for _, bp in ipairs(bpList) do
        table_insert(results, Utils.formatHex(bp))
    end

    -- Sync Context.activeBreakpoints with actual breakpoint list
    local actualBPs = {}
    for _, bp in ipairs(bpList) do
        actualBPs[bp] = true
    end
    for addr, _ in pairs(Context.activeBreakpoints) do
        if not actualBPs[addr] then
            Context.activeBreakpoints[addr] = nil
        end
    end

    -- Build detailed breakpoint info
    local detailedResults = {}
    for _, bp in ipairs(bpList) do
        local info = Context.activeBreakpoints[bp]
        table_insert(detailedResults, {
            address = Utils.formatHex(bp),
            type = info and info.type or "unknown",
            active = info and info.active or true
        })
    end

    return {
        breakpoints = results,
        details = detailedResults,
        count = #results
    }
end


-- ============ Handlers: Advanced Debug ============

Handlers.break_and_get_regs = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address, "break_and_get_regs")
    local timeout = p.timeout or 5000
    local stackDepth = p.stack_depth or 16
    local includeXmm = p.include_xmm or false

    Context.bpResult = nil
    Context.bpTriggered = false

    -- Set breakpoint on main thread (CE API requirement)
    local setOk, setErr = pcall(function()
        synchronize(function()
            debug_setBreakpoint(addr, 1, bptExecute, function()
                local callStack = {}
                local spVal = Utils.getStackPointer()
                local is64 = targetIs64Bit()
                local ptrSize = is64 and 8 or 4

                for i = 0, stackDepth - 1 do
                    local stackAddr = spVal + (i * ptrSize)
                    local retAddr = is64 and readQword(stackAddr) or readInteger(stackAddr)

                    if retAddr and retAddr ~= 0 then
                        local symbol = nil
                        pcall(function()
                            local symInfo = getNameFromAddress(retAddr, true)
                            if symInfo and symInfo ~= "" then symbol = symInfo end
                        end)

                        table_insert(callStack, {
                            stackOffset = string_format("+0x%X", i * ptrSize),
                            address = Utils.formatHex(retAddr),
                            symbol = symbol
                        })
                    end
                end

                local regs = Utils.getRegisters()
                regs.address = Utils.formatHex(addr)
                regs.callStack = callStack
                regs.returnAddress = callStack[1] and callStack[1].address or nil

                -- Add XMM registers if requested (useful for floating point analysis)
                if includeXmm then
                    regs.xmm = Utils.getXMMRegisters()
                end

                Context.bpResult = regs
                Context.bpTriggered = true
                Context.bpTimestamp = os_clock()  -- Record timestamp for watchdog
                debug_removeBreakpoint(addr)
                debug_continueFromBreakpoint(co_run)
                return 0
            end)
        end)
    end)

    if not setOk then
        error(ErrorContextBuilder.breakpointError("break_and_get_regs", addr, tostring(setErr)))
    end

    -- Wait in worker thread (non-blocking for GUI)
    Utils.adaptiveWait(function() return Context.bpTriggered end, timeout)

    -- Cleanup on main thread
    synchronize(function()
        pcall(debug_removeBreakpoint, addr)
        pcall(debug_continueFromBreakpoint, co_run)
    end)

    -- Get results and clear state
    local result = Context.bpResult
    local triggered = Context.bpTriggered
    Context.bpResult = nil
    Context.bpTriggered = false

    if not triggered then
        error(ErrorContextBuilder.breakpointError("break_and_get_regs", addr,
            "Breakpoint not triggered within timeout"))
    end

    return result
end

Handlers.break_and_trace = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address, "break_and_trace")
    local maxSteps = p.max_steps or 100
    local timeout = p.timeout or 10000
    local stopOnRet = p.stop_on_ret ~= false
    local traceIntoCalls = p.trace_into_call or false
    local initialRegs = p.initial_regs or {}
    local endAddr = p.end_address and Utils.safeGetAddress(p.end_address, "break_and_trace") or nil

    -- Reset trace state
    Context.traceLog = {}
    Context.traceComplete = false
    Context.traceStepCount = 0
    Context.traceStopReason = nil
    Context.traceMaxSteps = maxSteps
    Context.traceStopOnRet = stopOnRet
    Context.traceIntoCalls = traceIntoCalls
    Context.traceEndAddr = endAddr

    -- Save original debugger_onBreakpoint
    local originalOnBreakpoint = debugger_onBreakpoint

    -- Step handler - called on each single step via debugger_onBreakpoint
    local function stepHandler()
        local currentIP = targetIs64Bit() and RIP or EIP

        -- Check max steps
        if Context.traceStepCount >= Context.traceMaxSteps then
            Context.traceComplete = true
            Context.traceStopReason = "max_steps"
            debugger_onBreakpoint = originalOnBreakpoint
            debug_continueFromBreakpoint(co_run)
            return 0
        end

        -- Check end address
        if Context.traceEndAddr and currentIP == Context.traceEndAddr then
            Context.traceComplete = true
            Context.traceStopReason = "end_address"
            debugger_onBreakpoint = originalOnBreakpoint
            debug_continueFromBreakpoint(co_run)
            return 0
        end

        -- Capture current instruction
        local step = Utils.withDisassembler(function(d)
            d.disassemble(currentIP)
            local data = d.LastDisassembleData

            local bytesHex = {}
            for _, b in ipairs(data.bytes) do
                table_insert(bytesHex, string_format("%02X", b))
            end

            return {
                step = Context.traceStepCount + 1,
                address = Utils.formatHex(currentIP),
                bytes = table_concat(bytesHex, " "),
                instruction = data.opcode .. " " .. (data.parameters or ""),
                size = #data.bytes,
                isCall = data.isCall or false,
                isJump = data.isJump or false,
                isRet = data.isRet or false,
                registers = Utils.getRegisters(),
                _isCall = data.isCall,
                _isRet = data.isRet
            }
        end)

        table_insert(Context.traceLog, step)
        Context.traceStepCount = Context.traceStepCount + 1

        -- Check ret instruction
        if Context.traceStopOnRet and step._isRet then
            Context.traceComplete = true
            Context.traceStopReason = "ret"
            debugger_onBreakpoint = originalOnBreakpoint
            debug_continueFromBreakpoint(co_run)
            return 0
        end

        -- Continue single-stepping
        local continueMethod = co_stepinto
        if step._isCall and not Context.traceIntoCalls then
            continueMethod = co_stepover
        end

        debug_continueFromBreakpoint(continueMethod)
        return 0
    end

    -- Initial breakpoint callback
    local function initialCallback()
        local currentIP = targetIs64Bit() and RIP or EIP

        -- Set initial registers if provided
        if next(initialRegs) then
            for regName, value in pairs(initialRegs) do
                local upperName = regName:upper()
                local numValue
                if type(value) == "string" then
                    numValue = getAddress(value)
                else
                    numValue = tonumber(value)
                end
                if numValue then
                    if upperName == "RAX" then RAX = numValue
                    elseif upperName == "RBX" then RBX = numValue
                    elseif upperName == "RCX" then RCX = numValue
                    elseif upperName == "RDX" then RDX = numValue
                    elseif upperName == "RSI" then RSI = numValue
                    elseif upperName == "RDI" then RDI = numValue
                    elseif upperName == "RBP" then RBP = numValue
                    elseif upperName == "R8" then R8 = numValue
                    elseif upperName == "R9" then R9 = numValue
                    elseif upperName == "R10" then R10 = numValue
                    elseif upperName == "R11" then R11 = numValue
                    elseif upperName == "R12" then R12 = numValue
                    elseif upperName == "R13" then R13 = numValue
                    elseif upperName == "R14" then R14 = numValue
                    elseif upperName == "R15" then R15 = numValue
                    end
                end
            end
            pcall(debug_setContext)
        end

        -- Remove the initial breakpoint
        pcall(debug_removeBreakpoint, addr)

        -- Set up debugger_onBreakpoint for single stepping
        debugger_onBreakpoint = stepHandler

        -- Start single-stepping (this will trigger stepHandler on next instruction)
        debug_continueFromBreakpoint(co_stepinto)
        return 0
    end

    -- Set breakpoint on main thread
    synchronize(function()
        debug_setBreakpoint(addr, 1, bptExecute, initialCallback)
    end)

    -- Wait in worker thread (non-blocking for GUI)
    Utils.adaptiveWait(function() return Context.traceComplete end, timeout)

    -- Cleanup on main thread - IMPORTANT: restore callback BEFORE clearing state
    -- to prevent stepHandler from accessing nil values
    local traceLog, traceComplete, traceStepCount, stopReason
    synchronize(function()
        -- First, restore original callback to stop stepHandler from being called
        -- Use pcall to ensure restoration even if originalOnBreakpoint is invalid
        pcall(function() debugger_onBreakpoint = originalOnBreakpoint end)
        pcall(debug_removeBreakpoint, addr)
        pcall(debug_continueFromBreakpoint, co_run)

        -- Now safely capture and clear state (stepHandler won't be called anymore)
        traceLog = Context.traceLog
        traceComplete = Context.traceComplete
        traceStepCount = Context.traceStepCount
        stopReason = Context.traceStopReason

        -- Clear all trace state atomically
        Context.traceLog = nil
        Context.traceComplete = nil
        Context.traceStepCount = nil
        Context.traceStopReason = nil
        Context.traceMaxSteps = nil
        Context.traceStopOnRet = nil
        Context.traceIntoCalls = nil
        Context.traceEndAddr = nil
    end)

    local result = {
        address = Utils.formatHex(addr),
        steps = traceStepCount,
        complete = traceComplete,
        timeout = not traceComplete,
        stop_reason = stopReason or (traceComplete and "complete" or "timeout"),
        trace = traceLog
    }

    if endAddr then
        result.end_address = Utils.formatHex(endAddr)
    end

    if next(initialRegs) then
        result.initial_regs_set = (function()
            local t = {}
            for k, v in pairs(initialRegs) do
                t[k] = type(v) == "number" and Utils.formatHex(v) or tostring(v)
            end
            return t
        end)()
    end

    if not traceComplete then
        result.hint = "Manually trigger the relevant action in game (e.g. attack, take damage, use item), then trace again"
    end

    return result
end


-- ============ Handlers: Analysis ============
Handlers.analyze_code = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)
    local count = p.count or 20

    -- Use RAII wrapper
    return Utils.withDisassembler(function(d)
        local instructions = {}
        local calls, jumps, memAccess = {}, {}, {}
        local curAddr = addr

        for i = 1, count do
            d.disassemble(curAddr)
            local data = d.LastDisassembleData
            local sz = #data.bytes

            local bytesHex = {}
            for _, b in ipairs(data.bytes) do
                table_insert(bytesHex, string_format("%02X", b))
            end

            local instr = {
                address = Utils.formatHex(data.address),
                opcode = data.opcode,
                params = data.parameters,
                size = sz,
                bytes = table_concat(bytesHex, " ")
            }

            if data.isCall and data.parameterValue and data.parameterValue ~= 0 then
                table_insert(calls, { from = instr.address, to = Utils.formatHex(data.parameterValue) })
            end

            if data.isJump and data.parameterValue and data.parameterValue ~= 0 then
                table_insert(jumps, {
                    from = instr.address,
                    to = Utils.formatHex(data.parameterValue),
                    type = data.isConditionalJump and "cond" or "uncond"
                })
            end

            if data.parameters and data.parameters:find("%[") then
                table_insert(memAccess, { address = instr.address, op = data.opcode, pattern = data.parameters })
            end

            table_insert(instructions, instr)
            curAddr = curAddr + sz
        end

        return {
            range = { start = Utils.formatHex(addr), stop = Utils.formatHex(curAddr) },
            instructions = instructions,
            analysis = { calls = calls, jumps = jumps, memory = memAccess }
        }
    end)
end

-- ============ Handlers: CFG Builder ============
--[[
  Build Control Flow Graph (CFG) for a function
  Returns basic blocks with connections, loop detection, and complexity metrics
]]
Handlers.build_cfg = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})

    local startAddr = Utils.safeGetAddress(p.address)
    local maxInstructions = math_min(p.max_instructions or 500, 2000)
    local maxBlocks = math_min(p.max_blocks or 100, 500)
    local detectLoops = p.detect_loops ~= false
    local includeDisasm = p.include_disasm ~= false

    return Utils.withDisassembler(function(d)
        -- Phase 1: Collect all instructions and identify block boundaries
        local instructions = {}      -- addr -> {opcode, params, size, isJump, isCall, isRet, jumpTarget, isConditional}
        local blockStarts = {}       -- set of addresses that start a block
        local blockEnds = {}         -- set of addresses that end a block
        local jumpTargets = {}       -- addr -> list of source addresses
        local callTargets = {}       -- addr -> list of source addresses
        local visited = {}           -- set of visited addresses
        local workQueue = {startAddr}
        local instrCount = 0

        blockStarts[startAddr] = true

        -- BFS to discover all reachable code
        while #workQueue > 0 and instrCount < maxInstructions do
            local addr = table_remove(workQueue, 1)

            if visited[addr] then goto continue end
            visited[addr] = true

            d.disassemble(addr)
            local data = d.LastDisassembleData
            local sz = #data.bytes

            if sz == 0 then goto continue end

            instrCount = instrCount + 1

            local instr = {
                address = addr,
                opcode = data.opcode,
                params = data.parameters,
                size = sz,
                isJump = data.isJump or false,
                isCall = data.isCall or false,
                isRet = data.isRet or false,
                isConditional = data.isConditionalJump or false,
                jumpTarget = nil
            }

            -- Get jump/call target
            if (data.isJump or data.isCall) and data.parameterValue and data.parameterValue ~= 0 then
                instr.jumpTarget = data.parameterValue
            end

            instructions[addr] = instr

            -- Handle control flow
            if data.isRet then
                -- Return instruction ends a block
                blockEnds[addr] = true

            elseif data.isJump then
                blockEnds[addr] = true

                if instr.jumpTarget then
                    -- Mark jump target as block start
                    blockStarts[instr.jumpTarget] = true
                    jumpTargets[instr.jumpTarget] = jumpTargets[instr.jumpTarget] or {}
                    table_insert(jumpTargets[instr.jumpTarget], addr)

                    -- Add target to work queue
                    if not visited[instr.jumpTarget] then
                        table_insert(workQueue, instr.jumpTarget)
                    end
                end

                -- For conditional jumps, also follow fall-through
                if data.isConditionalJump then
                    local nextAddr = addr + sz
                    blockStarts[nextAddr] = true
                    if not visited[nextAddr] then
                        table_insert(workQueue, nextAddr)
                    end
                end

            elseif data.isCall then
                -- Calls don't end blocks, but we track targets
                if instr.jumpTarget then
                    callTargets[instr.jumpTarget] = callTargets[instr.jumpTarget] or {}
                    table_insert(callTargets[instr.jumpTarget], addr)
                end

                -- Continue to next instruction
                local nextAddr = addr + sz
                if not visited[nextAddr] then
                    table_insert(workQueue, nextAddr)
                end
            else
                -- Normal instruction, continue to next
                local nextAddr = addr + sz

                -- Check if next instruction is a block start (someone jumps here)
                if blockStarts[nextAddr] then
                    blockEnds[addr] = true
                end

                if not visited[nextAddr] then
                    table_insert(workQueue, nextAddr)
                end
            end

            ::continue::
        end

        -- Phase 2: Build basic blocks
        local blocks = {}
        local blockByAddr = {}  -- start_addr -> block_index
        local sortedAddrs = {}

        for addr in pairs(instructions) do
            table_insert(sortedAddrs, addr)
        end
        table_sort(sortedAddrs)

        local currentBlock = nil
        local blockIndex = 0

        for _, addr in ipairs(sortedAddrs) do
            local instr = instructions[addr]

            -- Start new block if needed
            if blockStarts[addr] or currentBlock == nil then
                if currentBlock then
                    -- Finalize previous block
                    currentBlock.stop = currentBlock.instructions[#currentBlock.instructions].address
                    local lastInstr = instructions[currentBlock.stop]
                    if lastInstr then
                        currentBlock.stopSize = lastInstr.size
                    end
                end

                blockIndex = blockIndex + 1
                if blockIndex > maxBlocks then break end

                currentBlock = {
                    id = blockIndex,
                    start = addr,
                    stop = addr,
                    stopSize = 0,
                    instructions = {},
                    successors = {},
                    predecessors = {},
                    isEntry = (addr == startAddr),
                    isExit = false,
                    jumpType = nil,  -- "unconditional", "conditional", "return", "fallthrough"
                    loopHeader = false,
                    loopBackEdge = false
                }
                blocks[blockIndex] = currentBlock
                blockByAddr[addr] = blockIndex
            end

            -- Add instruction to current block
            if includeDisasm then
                table_insert(currentBlock.instructions, {
                    address = Utils.formatHex(addr),
                    opcode = instr.opcode,
                    params = instr.params,
                    size = instr.size
                })
            else
                table_insert(currentBlock.instructions, addr)
            end

            -- Check if this ends the block
            if blockEnds[addr] or instr.isRet then
                currentBlock.stop = addr
                currentBlock.stopSize = instr.size

                if instr.isRet then
                    currentBlock.isExit = true
                    currentBlock.jumpType = "return"
                elseif instr.isJump then
                    currentBlock.jumpType = instr.isConditional and "conditional" or "unconditional"
                    currentBlock.jumpTarget = instr.jumpTarget and Utils.formatHex(instr.jumpTarget) or nil
                end

                currentBlock = nil
            end
        end

        -- Finalize last block if needed
        if currentBlock then
            currentBlock.stop = currentBlock.instructions[#currentBlock.instructions]
            if type(currentBlock.stop) == "table" then
                currentBlock.stop = tonumber(currentBlock.stop.address:sub(3), 16)
            end
        end

        -- Phase 3: Build edges (successors/predecessors)
        local edges = {}

        for i, block in ipairs(blocks) do
            local lastAddr = block.stop
            local lastInstr = instructions[lastAddr]

            if lastInstr then
                -- Jump edge
                if lastInstr.jumpTarget and blockByAddr[lastInstr.jumpTarget] then
                    local targetIdx = blockByAddr[lastInstr.jumpTarget]
                    table_insert(block.successors, targetIdx)
                    table_insert(blocks[targetIdx].predecessors, i)
                    table_insert(edges, {
                        from = i,
                        to = targetIdx,
                        type = lastInstr.isConditional and "conditional_taken" or "unconditional"
                    })
                end

                -- Fall-through edge (for conditional jumps)
                if lastInstr.isConditional then
                    local fallAddr = lastAddr + lastInstr.size
                    if blockByAddr[fallAddr] then
                        local fallIdx = blockByAddr[fallAddr]
                        table_insert(block.successors, fallIdx)
                        table_insert(blocks[fallIdx].predecessors, i)
                        table_insert(edges, {
                            from = i,
                            to = fallIdx,
                            type = "conditional_fallthrough"
                        })
                    end
                end

                -- Implicit fall-through (no jump at end)
                if not lastInstr.isJump and not lastInstr.isRet then
                    local nextAddr = lastAddr + lastInstr.size
                    if blockByAddr[nextAddr] then
                        local nextIdx = blockByAddr[nextAddr]
                        table_insert(block.successors, nextIdx)
                        table_insert(blocks[nextIdx].predecessors, i)
                        block.jumpType = "fallthrough"
                        table_insert(edges, {
                            from = i,
                            to = nextIdx,
                            type = "fallthrough"
                        })
                    end
                end
            end
        end

        -- Phase 4: Detect loops (back edges)
        local loops = {}
        if detectLoops then
            for _, edge in ipairs(edges) do
                local fromBlock = blocks[edge.from]
                local toBlock = blocks[edge.to]

                -- Back edge: target block starts before or at source block
                if toBlock and fromBlock and toBlock.start <= fromBlock.start then
                    toBlock.loopHeader = true
                    fromBlock.loopBackEdge = true
                    table_insert(loops, {
                        header = edge.to,
                        headerAddr = Utils.formatHex(toBlock.start),
                        backEdgeFrom = edge.from,
                        backEdgeAddr = Utils.formatHex(fromBlock.stop)
                    })
                end
            end
        end

        -- Phase 5: Calculate metrics
        local exitBlocks = 0
        for _, block in ipairs(blocks) do
            if block.isExit then exitBlocks = exitBlocks + 1 end
        end

        -- Cyclomatic complexity: E - N + 2P (edges - nodes + 2*connected_components)
        local cyclomaticComplexity = #edges - #blocks + 2

        -- Format blocks for output
        local outputBlocks = {}
        for i, block in ipairs(blocks) do
            outputBlocks[i] = {
                id = block.id,
                start = Utils.formatHex(block.start),
                stop = Utils.formatHex(block.stop),
                instruction_count = #block.instructions,
                instructions = includeDisasm and block.instructions or nil,
                successors = block.successors,
                predecessors = block.predecessors,
                jump_type = block.jumpType,
                jump_target = block.jumpTarget,
                is_entry = block.isEntry or nil,
                is_exit = block.isExit or nil,
                is_loop_header = block.loopHeader or nil,
                has_back_edge = block.loopBackEdge or nil
            }
        end

        return {
            function_start = Utils.formatHex(startAddr),
            block_count = #blocks,
            edge_count = #edges,
            instruction_count = instrCount,
            blocks = outputBlocks,
            edges = edges,
            loops = loops,
            metrics = {
                cyclomatic_complexity = cyclomaticComplexity,
                exit_points = exitBlocks,
                loop_count = #loops,
                max_depth_reached = instrCount >= maxInstructions
            },
            call_targets = (function()
                local targets = {}
                for addr, sources in pairs(callTargets) do
                    table_insert(targets, {
                        target = Utils.formatHex(addr),
                        call_count = #sources
                    })
                end
                return targets
            end)()
        }
    end)
end

-- ============ Handlers: Pattern Detection ============
--[[
  Detect common code patterns in a function
  Patterns: switch tables, virtual calls, string refs, crypto constants, anti-debug
]]
Handlers.detect_patterns = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})

    local startAddr = Utils.safeGetAddress(p.address)
    local maxInstructions = math_min(p.max_instructions or 200, 1000)
    local requestedPatterns = p.patterns  -- nil = detect all

    return Utils.withDisassembler(function(d)
        local patterns = {
            switch_tables = {},      -- jump tables for switch/case
            virtual_calls = {},      -- indirect calls through vtable
            string_refs = {},        -- references to string data
            crypto_constants = {},   -- known crypto magic numbers
            anti_debug = {},         -- anti-debugging patterns
            comparisons = {},        -- cmp/test patterns (useful for finding checks)
            memory_patterns = {}     -- repeated memory access patterns
        }

        -- Known crypto constants
        local cryptoMagic = {
            [0x67452301] = "MD5/SHA1 init A",
            [0xEFCDAB89] = "MD5/SHA1 init B",
            [0x98BADCFE] = "MD5/SHA1 init C",
            [0x10325476] = "MD5/SHA1 init D",
            [0xC3D2E1F0] = "SHA1 init E",
            [0x6A09E667] = "SHA256 init",
            [0xBB67AE85] = "SHA256 init",
            [0x3C6EF372] = "SHA256 init",
            [0x5BE0CD19] = "SHA256 init",
            [0x9E3779B9] = "TEA/XTEA delta",
            [0x61C88647] = "TEA delta variant",
            [0x243F6A88] = "Blowfish P-array",
            [0x85A308D3] = "Blowfish P-array",
        }

        -- Anti-debug API patterns
        local antiDebugAPIs = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString",
            "GetTickCount", "QueryPerformanceCounter", "rdtsc"
        }

        local curAddr = startAddr
        local prevInstr = nil

        for i = 1, maxInstructions do
            d.disassemble(curAddr)
            local data = d.LastDisassembleData
            local sz = #data.bytes
            if sz == 0 then break end

            local opcode = data.opcode:lower()
            local params = data.parameters or ""
            local paramVal = data.parameterValue

            -- Pattern 1: Switch/Jump tables (jmp [reg*4+table] or jmp [rip+...])
            if opcode == "jmp" and params:find("%[") then
                local isJumpTable = params:find("%*4") or params:find("%*8") or
                                   params:find("rip%+") or params:find("eip%+")
                if isJumpTable then
                    table_insert(patterns.switch_tables, {
                        address = Utils.formatHex(curAddr),
                        instruction = opcode .. " " .. params,
                        type = "indirect_jump"
                    })
                end
            end

            -- Pattern 2: Virtual calls (call [reg+offset] pattern)
            if opcode == "call" and params:find("%[") then
                local base, offset = params:match("%[([%w]+)%+([%w]+)%]")
                if base and offset then
                    table_insert(patterns.virtual_calls, {
                        address = Utils.formatHex(curAddr),
                        instruction = opcode .. " " .. params,
                        base_reg = base,
                        offset = offset,
                        likely_vtable = true
                    })
                end
            end

            -- Pattern 3: String references (lea with RIP-relative or direct address)
            if (opcode == "lea" or opcode == "mov") and paramVal and paramVal > 0x10000 then
                local ok, strVal = pcall(readString, paramVal, 50)
                if ok and strVal and #strVal > 3 then
                    -- Check if it looks like a readable string
                    local isPrintable = true
                    for j = 1, math_min(#strVal, 20) do
                        local b = string_byte(strVal, j)
                        if b < 32 or b > 126 then
                            if b ~= 0 then isPrintable = false end
                            break
                        end
                    end
                    if isPrintable then
                        table_insert(patterns.string_refs, {
                            address = Utils.formatHex(curAddr),
                            string_addr = Utils.formatHex(paramVal),
                            value = strVal:sub(1, 50),
                            instruction = opcode .. " " .. params
                        })
                    end
                end
            end

            -- Pattern 4: Crypto constants
            if paramVal then
                local cryptoName = cryptoMagic[paramVal]
                if cryptoName then
                    table_insert(patterns.crypto_constants, {
                        address = Utils.formatHex(curAddr),
                        constant = Utils.formatHex(paramVal),
                        algorithm = cryptoName,
                        instruction = opcode .. " " .. params
                    })
                end
            end

            -- Pattern 5: Anti-debug checks
            if opcode == "call" then
                local symbol = nil
                pcall(function()
                    if paramVal and paramVal ~= 0 then
                        symbol = getNameFromAddress(paramVal, false)
                    end
                end)
                if symbol then
                    for _, api in ipairs(antiDebugAPIs) do
                        if symbol:find(api) then
                            table_insert(patterns.anti_debug, {
                                address = Utils.formatHex(curAddr),
                                api = symbol,
                                type = "api_call"
                            })
                            break
                        end
                    end
                end
            end

            -- rdtsc instruction (timing check)
            if opcode == "rdtsc" then
                table_insert(patterns.anti_debug, {
                    address = Utils.formatHex(curAddr),
                    api = "rdtsc",
                    type = "timing_check"
                })
            end

            -- Pattern 6: Comparisons (useful for finding validation checks)
            if opcode == "cmp" or opcode == "test" then
                table_insert(patterns.comparisons, {
                    address = Utils.formatHex(curAddr),
                    instruction = opcode .. " " .. params,
                    value = paramVal and Utils.formatHex(paramVal) or nil
                })
            end

            -- Pattern 7: Memory access patterns (struct field access)
            if params:find("%[") then
                local base, offset = params:match("%[([%w]+)%+0x([%x]+)%]")
                if not base then
                    base, offset = params:match("%[([%w]+)%+([%d]+)%]")
                end
                if base and offset then
                    local offsetNum = tonumber(offset, 16) or tonumber(offset)
                    if offsetNum then
                        table_insert(patterns.memory_patterns, {
                            address = Utils.formatHex(curAddr),
                            base_reg = base,
                            offset = Utils.formatHex(offsetNum),
                            access_type = opcode:find("mov") and
                                         (params:find("^%[") and "write" or "read") or "unknown"
                        })
                    end
                end
            end

            prevInstr = {addr = curAddr, opcode = opcode, params = params}
            curAddr = curAddr + sz
        end

        -- Summarize findings
        local summary = {
            has_switch = #patterns.switch_tables > 0,
            has_virtual_calls = #patterns.virtual_calls > 0,
            has_strings = #patterns.string_refs > 0,
            has_crypto = #patterns.crypto_constants > 0,
            has_anti_debug = #patterns.anti_debug > 0,
            comparison_count = #patterns.comparisons,
            unique_offsets = {}
        }

        -- Find unique struct offsets
        local offsetSet = {}
        for _, mp in ipairs(patterns.memory_patterns) do
            offsetSet[mp.offset] = (offsetSet[mp.offset] or 0) + 1
        end
        for offset, count in pairs(offsetSet) do
            if count >= 2 then
                table_insert(summary.unique_offsets, {offset = offset, access_count = count})
            end
        end

        return {
            function_start = Utils.formatHex(startAddr),
            instructions_scanned = maxInstructions,
            patterns = patterns,
            summary = summary
        }
    end)
end

-- ============ Handlers: Function Comparison ============
--[[
  Compare two functions for similarity
  Returns matching blocks, differences, and similarity score
]]
Handlers.compare_functions = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address1", "address2"})

    local addr1 = Utils.safeGetAddress(p.address1)
    local addr2 = Utils.safeGetAddress(p.address2)
    local maxInstructions = math_min(p.max_instructions or 200, 500)

    return Utils.withDisassembler(function(d)
        -- Helper: collect instructions from a function
        local function collectInstructions(startAddr)
            local instrs = {}
            local curAddr = startAddr

            for i = 1, maxInstructions do
                d.disassemble(curAddr)
                local data = d.LastDisassembleData
                local sz = #data.bytes
                if sz == 0 then break end

                -- Normalize: remove absolute addresses from params
                local normalizedParams = data.parameters or ""
                normalizedParams = normalizedParams:gsub("0x[%x]+", "ADDR")
                normalizedParams = normalizedParams:gsub("%d+", "NUM")

                table_insert(instrs, {
                    address = curAddr,
                    opcode = data.opcode,
                    params = data.parameters,
                    normalized = data.opcode .. " " .. normalizedParams,
                    size = sz,
                    isRet = data.isRet
                })

                if data.isRet then break end
                curAddr = curAddr + sz
            end

            return instrs
        end

        local func1 = collectInstructions(addr1)
        local func2 = collectInstructions(addr2)

        -- LCS-based comparison for similarity
        local matches = {}
        local diffs1 = {}  -- in func1 but not func2
        local diffs2 = {}  -- in func2 but not func1

        -- Simple matching: compare normalized opcodes
        local matched1 = {}
        local matched2 = {}

        for i, instr1 in ipairs(func1) do
            for j, instr2 in ipairs(func2) do
                if not matched2[j] and instr1.normalized == instr2.normalized then
                    matched1[i] = true
                    matched2[j] = true
                    table_insert(matches, {
                        func1_addr = Utils.formatHex(instr1.address),
                        func2_addr = Utils.formatHex(instr2.address),
                        opcode = instr1.opcode,
                        func1_params = instr1.params,
                        func2_params = instr2.params
                    })
                    break
                end
            end
        end

        -- Collect differences
        for i, instr in ipairs(func1) do
            if not matched1[i] then
                table_insert(diffs1, {
                    address = Utils.formatHex(instr.address),
                    instruction = instr.opcode .. " " .. (instr.params or "")
                })
            end
        end

        for j, instr in ipairs(func2) do
            if not matched2[j] then
                table_insert(diffs2, {
                    address = Utils.formatHex(instr.address),
                    instruction = instr.opcode .. " " .. (instr.params or "")
                })
            end
        end

        -- Calculate similarity score
        local totalInstrs = math.max(#func1, #func2)
        local similarity = totalInstrs > 0 and (#matches / totalInstrs * 100) or 0

        return {
            function1 = {
                address = Utils.formatHex(addr1),
                instruction_count = #func1
            },
            function2 = {
                address = Utils.formatHex(addr2),
                instruction_count = #func2
            },
            similarity_percent = math_floor(similarity * 100) / 100,
            matching_instructions = #matches,
            matches = #matches <= 50 and matches or nil,  -- Only include if not too many
            differences = {
                only_in_func1 = diffs1,
                only_in_func2 = diffs2
            },
            verdict = similarity >= 90 and "nearly_identical" or
                     similarity >= 70 and "similar" or
                     similarity >= 40 and "partially_similar" or "different"
        }
    end)
end

-- ============ Handlers: Data Flow Tracing ============
--[[
  Trace data flow for a register within a function
  Shows definitions (where value comes from) and uses (where value goes)
]]
Handlers.trace_dataflow = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address", "register"})

    local startAddr = Utils.safeGetAddress(p.address)
    local targetReg = p.register:lower()
    local maxInstructions = math_min(p.max_instructions or 100, 500)
    local direction = p.direction or "both"

    return Utils.withDisassembler(function(d)
        local definitions = {}  -- Where the register gets its value
        local uses = {}         -- Where the register value is used
        local dataFlow = {}     -- Ordered flow of the register

        -- Register aliases (e.g., rax includes eax, ax, al, ah)
        local regAliases = {
            rax = {"rax", "eax", "ax", "al", "ah"},
            rbx = {"rbx", "ebx", "bx", "bl", "bh"},
            rcx = {"rcx", "ecx", "cx", "cl", "ch"},
            rdx = {"rdx", "edx", "dx", "dl", "dh"},
            rsi = {"rsi", "esi", "si", "sil"},
            rdi = {"rdi", "edi", "di", "dil"},
            rbp = {"rbp", "ebp", "bp", "bpl"},
            rsp = {"rsp", "esp", "sp", "spl"},
            r8 = {"r8", "r8d", "r8w", "r8b"},
            r9 = {"r9", "r9d", "r9w", "r9b"},
            r10 = {"r10", "r10d", "r10w", "r10b"},
            r11 = {"r11", "r11d", "r11w", "r11b"},
            r12 = {"r12", "r12d", "r12w", "r12b"},
            r13 = {"r13", "r13d", "r13w", "r13b"},
            r14 = {"r14", "r14d", "r14w", "r14b"},
            r15 = {"r15", "r15d", "r15w", "r15b"},
        }

        -- Find base register
        local baseReg = targetReg
        for base, aliases in pairs(regAliases) do
            for _, alias in ipairs(aliases) do
                if alias == targetReg then
                    baseReg = base
                    break
                end
            end
        end

        local aliases = regAliases[baseReg] or {targetReg}

        -- Helper: check if instruction involves our register
        local function involvesReg(params, checkAliases)
            if not params then return false, false end
            local paramsLower = params:lower()
            for _, alias in ipairs(checkAliases) do
                if paramsLower:find(alias) then
                    -- Check if it's destination (definition) or source (use)
                    local parts = {}
                    for part in paramsLower:gmatch("[^,]+") do
                        table_insert(parts, part:match("^%s*(.-)%s*$"))
                    end

                    local isDef = false
                    local isUse = false

                    if #parts >= 1 then
                        -- First operand is usually destination
                        if parts[1]:find(alias) then
                            isDef = true
                        end
                    end
                    if #parts >= 2 then
                        -- Second operand is usually source
                        if parts[2]:find(alias) then
                            isUse = true
                        end
                    end

                    -- Memory operand with register is a use
                    if paramsLower:find("%[.*" .. alias .. ".*%]") then
                        isUse = true
                    end

                    return isDef, isUse
                end
            end
            return false, false
        end

        local curAddr = startAddr

        for i = 1, maxInstructions do
            d.disassemble(curAddr)
            local data = d.LastDisassembleData
            local sz = #data.bytes
            if sz == 0 then break end

            local opcode = data.opcode:lower()
            local params = data.parameters

            local isDef, isUse = involvesReg(params, aliases)

            -- Special cases
            if opcode == "xor" or opcode == "sub" then
                -- xor reg, reg or sub reg, reg is a definition (zeroing)
                local parts = {}
                for part in (params or ""):gmatch("[^,]+") do
                    table_insert(parts, part:match("^%s*(.-)%s*$"):lower())
                end
                if #parts == 2 and parts[1] == parts[2] then
                    isDef = true
                    isUse = false
                end
            end

            if opcode == "push" then
                isDef = false
                isUse = involvesReg(params, aliases)
            end

            if opcode == "pop" then
                isDef = involvesReg(params, aliases)
                isUse = false
            end

            if opcode == "call" then
                -- Calls may clobber certain registers (ABI dependent)
                -- RAX is typically return value
                if baseReg == "rax" or baseReg == "eax" then
                    isDef = true
                end
            end

            if isDef and (direction == "backward" or direction == "both") then
                table_insert(definitions, {
                    address = Utils.formatHex(curAddr),
                    instruction = opcode .. " " .. (params or ""),
                    type = opcode == "mov" and "assignment" or
                           opcode == "lea" and "address_calc" or
                           opcode == "call" and "return_value" or
                           (opcode == "xor" or opcode == "sub") and "zeroing" or
                           opcode == "pop" and "stack_pop" or
                           "computation"
                })
            end

            if isUse and (direction == "forward" or direction == "both") then
                table_insert(uses, {
                    address = Utils.formatHex(curAddr),
                    instruction = opcode .. " " .. (params or ""),
                    type = opcode == "mov" and "copy" or
                           opcode == "push" and "stack_push" or
                           opcode == "cmp" and "comparison" or
                           opcode == "test" and "test" or
                           opcode == "call" and "argument" or
                           params:find("%[") and "memory_access" or
                           "computation"
                })
            end

            if isDef or isUse then
                table_insert(dataFlow, {
                    address = Utils.formatHex(curAddr),
                    instruction = opcode .. " " .. (params or ""),
                    is_definition = isDef,
                    is_use = isUse
                })
            end

            if data.isRet then break end
            curAddr = curAddr + sz
        end

        return {
            function_start = Utils.formatHex(startAddr),
            traced_register = targetReg,
            base_register = baseReg,
            aliases_checked = aliases,
            definitions = definitions,
            uses = uses,
            data_flow = dataFlow,
            summary = {
                definition_count = #definitions,
                use_count = #uses,
                total_references = #dataFlow
            }
        }
    end)
end

-- ============ Handlers: Program Slicing ============
--[[
  Program Slicing - Find all instructions that affect or are affected by a criterion
  Backward slice: "What instructions contribute to this value?"
  Forward slice: "What instructions are affected by this value?"
]]
Handlers.program_slice = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address", "criterion"})

    local startAddr = Utils.safeGetAddress(p.address)
    local criterion = p.criterion:lower()
    local direction = p.direction or "backward"
    local maxInstructions = math_min(p.max_instructions or 200, 1000)
    local followCalls = p.follow_calls or false

    return Utils.withDisassembler(function(d)
        -- All x64 registers and their aliases
        local allRegs = {
            "rax", "eax", "ax", "al", "ah",
            "rbx", "ebx", "bx", "bl", "bh",
            "rcx", "ecx", "cx", "cl", "ch",
            "rdx", "edx", "dx", "dl", "dh",
            "rsi", "esi", "si", "sil",
            "rdi", "edi", "di", "dil",
            "rbp", "ebp", "bp", "bpl",
            "rsp", "esp", "sp", "spl",
            "r8", "r8d", "r8w", "r8b",
            "r9", "r9d", "r9w", "r9b",
            "r10", "r10d", "r10w", "r10b",
            "r11", "r11d", "r11w", "r11b",
            "r12", "r12d", "r12w", "r12b",
            "r13", "r13d", "r13w", "r13b",
            "r14", "r14d", "r14w", "r14b",
            "r15", "r15d", "r15w", "r15b",
        }

        -- Map sub-registers to base register
        local regToBase = {}
        local baseRegs = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
        for _, base in ipairs(baseRegs) do
            regToBase[base] = base
            if base:sub(1,1) == "r" and #base == 3 then
                -- rax -> eax, ax, al, ah
                local short = base:sub(2)  -- ax
                regToBase["e" .. short] = base
                regToBase[short] = base
                regToBase[short:sub(1,1) .. "l"] = base
                regToBase[short:sub(1,1) .. "h"] = base
            elseif base:match("^r%d+$") then
                -- r8 -> r8d, r8w, r8b
                regToBase[base .. "d"] = base
                regToBase[base .. "w"] = base
                regToBase[base .. "b"] = base
            end
        end

        -- Parse instruction to get defined and used registers/memory
        local function parseInstruction(opcode, params)
            local defs = {}  -- registers/memory written
            local uses = {}  -- registers/memory read

            if not params or params == "" then
                return defs, uses
            end

            local paramsLower = params:lower()

            -- Split by comma
            local operands = {}
            for op in paramsLower:gmatch("[^,]+") do
                table_insert(operands, op:match("^%s*(.-)%s*$"))
            end

            -- Helper: extract registers from operand
            local function extractRegs(operand)
                local regs = {}
                for _, reg in ipairs(allRegs) do
                    if operand:find(reg) then
                        local base = regToBase[reg]
                        if base then regs[base] = true end
                    end
                end
                return regs
            end

            -- Helper: check if operand is memory
            local function isMemory(operand)
                return operand:find("%[") ~= nil
            end

            -- Helper: extract memory pattern
            local function extractMemPattern(operand)
                return operand:match("%[([^%]]+)%]")
            end

            local op = opcode:lower()

            -- Special handling for different instruction types
            if op == "mov" or op == "movzx" or op == "movsx" or op == "movsxd" or op == "lea" then
                -- First operand is destination (def), second is source (use)
                if #operands >= 2 then
                    if isMemory(operands[1]) then
                        -- Memory write: uses base/index regs, uses source
                        for reg in pairs(extractRegs(operands[1])) do uses[reg] = true end
                        defs["mem:" .. extractMemPattern(operands[1])] = true
                    else
                        for reg in pairs(extractRegs(operands[1])) do defs[reg] = true end
                    end

                    if op == "lea" then
                        -- LEA doesn't read memory, just computes address
                        for reg in pairs(extractRegs(operands[2])) do uses[reg] = true end
                    elseif isMemory(operands[2]) then
                        for reg in pairs(extractRegs(operands[2])) do uses[reg] = true end
                        uses["mem:" .. extractMemPattern(operands[2])] = true
                    else
                        for reg in pairs(extractRegs(operands[2])) do uses[reg] = true end
                    end
                end

            elseif op == "push" then
                if #operands >= 1 then
                    for reg in pairs(extractRegs(operands[1])) do uses[reg] = true end
                    if isMemory(operands[1]) then
                        uses["mem:" .. extractMemPattern(operands[1])] = true
                    end
                end
                uses["rsp"] = true
                defs["rsp"] = true

            elseif op == "pop" then
                if #operands >= 1 then
                    for reg in pairs(extractRegs(operands[1])) do defs[reg] = true end
                end
                uses["rsp"] = true
                defs["rsp"] = true

            elseif op == "xor" or op == "sub" then
                -- xor reg, reg or sub reg, reg is just a def (zeroing)
                if #operands >= 2 and operands[1] == operands[2] then
                    for reg in pairs(extractRegs(operands[1])) do defs[reg] = true end
                else
                    if #operands >= 1 then
                        for reg in pairs(extractRegs(operands[1])) do
                            defs[reg] = true
                            uses[reg] = true
                        end
                    end
                    if #operands >= 2 then
                        for reg in pairs(extractRegs(operands[2])) do uses[reg] = true end
                    end
                end

            elseif op == "add" or op == "and" or op == "or" or op == "shl" or op == "shr" or
                   op == "sar" or op == "rol" or op == "ror" or op == "imul" or op == "mul" then
                -- First operand is both read and written
                if #operands >= 1 then
                    for reg in pairs(extractRegs(operands[1])) do
                        defs[reg] = true
                        uses[reg] = true
                    end
                end
                if #operands >= 2 then
                    for reg in pairs(extractRegs(operands[2])) do uses[reg] = true end
                end

            elseif op == "cmp" or op == "test" then
                -- Only reads, no writes (except flags)
                for _, operand in ipairs(operands) do
                    for reg in pairs(extractRegs(operand)) do uses[reg] = true end
                    if isMemory(operand) then
                        uses["mem:" .. extractMemPattern(operand)] = true
                    end
                end

            elseif op == "call" then
                -- Calls clobber volatile registers (simplified)
                defs["rax"] = true  -- return value
                defs["rcx"] = true
                defs["rdx"] = true
                defs["r8"] = true
                defs["r9"] = true
                defs["r10"] = true
                defs["r11"] = true
                -- Arguments are uses
                uses["rcx"] = true
                uses["rdx"] = true
                uses["r8"] = true
                uses["r9"] = true

            elseif op == "ret" then
                uses["rax"] = true  -- return value
                uses["rsp"] = true

            elseif op:sub(1,1) == "j" then
                -- Jumps use flags (implicit)
                -- No explicit register defs/uses

            else
                -- Generic: assume first operand is def if 2+ operands, all are uses
                for i, operand in ipairs(operands) do
                    for reg in pairs(extractRegs(operand)) do
                        if i == 1 and #operands >= 2 then
                            defs[reg] = true
                        end
                        uses[reg] = true
                    end
                    if isMemory(operand) then
                        local memPat = extractMemPattern(operand)
                        if i == 1 and #operands >= 2 then
                            defs["mem:" .. memPat] = true
                        else
                            uses["mem:" .. memPat] = true
                        end
                    end
                end
            end

            return defs, uses
        end

        -- Collect instructions
        local instructions = {}
        local curAddr = startAddr

        for i = 1, maxInstructions do
            d.disassemble(curAddr)
            local data = d.LastDisassembleData
            local sz = #data.bytes
            if sz == 0 then break end

            local defs, uses = parseInstruction(data.opcode, data.parameters)

            table_insert(instructions, {
                index = i,
                address = curAddr,
                opcode = data.opcode,
                params = data.parameters,
                size = sz,
                defs = defs,
                uses = uses,
                isRet = data.isRet,
                isCall = data.isCall,
                isJump = data.isJump
            })

            if data.isRet then break end
            curAddr = curAddr + sz
        end

        -- Find criterion instruction (where the criterion is defined/used)
        local criterionBase = regToBase[criterion] or criterion
        local isCriterionMem = criterion:find("%[") ~= nil
        local criterionMemPat = isCriterionMem and criterion:match("%[([^%]]+)%]") or nil

        local slice = {}
        local sliceSet = {}
        local workSet = {}  -- Variables we're tracking

        if direction == "backward" then
            -- Backward slice: find what affects the criterion
            -- Start from the end, track what defines our criterion

            -- Initialize workset with criterion
            if isCriterionMem then
                workSet["mem:" .. criterionMemPat] = true
            else
                workSet[criterionBase] = true
            end

            -- Process instructions in reverse
            for i = #instructions, 1, -1 do
                local instr = instructions[i]
                local inSlice = false

                -- Check if this instruction defines something we're tracking
                for def in pairs(instr.defs) do
                    if workSet[def] then
                        inSlice = true
                        workSet[def] = nil  -- No longer need to track this

                        -- Add all uses of this instruction to workset
                        for use in pairs(instr.uses) do
                            workSet[use] = true
                        end
                    end
                end

                if inSlice and not sliceSet[instr.address] then
                    sliceSet[instr.address] = true
                    table_insert(slice, 1, {
                        address = Utils.formatHex(instr.address),
                        instruction = instr.opcode .. " " .. (instr.params or ""),
                        defines = instr.defs,
                        uses = instr.uses,
                        reason = "defines tracked variable"
                    })
                end
            end

        else
            -- Forward slice: find what is affected by the criterion
            -- Start from beginning, track what uses our criterion

            -- Find where criterion is first defined
            local startIdx = 1
            for i, instr in ipairs(instructions) do
                if isCriterionMem then
                    if instr.defs["mem:" .. criterionMemPat] then
                        startIdx = i
                        break
                    end
                else
                    if instr.defs[criterionBase] then
                        startIdx = i
                        break
                    end
                end
            end

            -- Initialize workset
            if isCriterionMem then
                workSet["mem:" .. criterionMemPat] = true
            else
                workSet[criterionBase] = true
            end

            -- Process instructions forward from definition
            for i = startIdx, #instructions do
                local instr = instructions[i]
                local inSlice = false

                -- Check if this instruction uses something we're tracking
                for use in pairs(instr.uses) do
                    if workSet[use] then
                        inSlice = true

                        -- Add all defs of this instruction to workset
                        for def in pairs(instr.defs) do
                            workSet[def] = true
                        end
                        break
                    end
                end

                if inSlice and not sliceSet[instr.address] then
                    sliceSet[instr.address] = true
                    table_insert(slice, {
                        address = Utils.formatHex(instr.address),
                        instruction = instr.opcode .. " " .. (instr.params or ""),
                        defines = instr.defs,
                        uses = instr.uses,
                        reason = "uses tracked variable"
                    })
                end
            end
        end

        -- Convert defs/uses to arrays for JSON
        for _, s in ipairs(slice) do
            local defList, useList = {}, {}
            for k in pairs(s.defines or {}) do table_insert(defList, k) end
            for k in pairs(s.uses or {}) do table_insert(useList, k) end
            s.defines = defList
            s.uses = useList
        end

        -- Remaining tracked variables (unresolved dependencies)
        local unresolved = {}
        for var in pairs(workSet) do
            table_insert(unresolved, var)
        end

        return {
            function_start = Utils.formatHex(startAddr),
            criterion = criterion,
            direction = direction,
            slice_size = #slice,
            total_instructions = #instructions,
            slice = slice,
            unresolved_dependencies = unresolved,
            coverage_percent = #instructions > 0 and math_floor(#slice / #instructions * 100) or 0
        }
    end)
end

-- ============ Handlers: Reference Analysis ============

Handlers.find_references = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local targetAddr = Utils.safeGetAddress(p.address)
    local limit = p.limit or 50
    local is64 = targetIs64Bit()

    -- Convert to little-endian AOB pattern
    local pattern
    if is64 and targetAddr > 0xFFFFFFFF then
        local bytes = {}
        local tempAddr = targetAddr
        for i = 1, 8 do
            bytes[i] = tempAddr % 256
            tempAddr = math_floor(tempAddr / 256)
        end
        pattern = string_format("%02X %02X %02X %02X %02X %02X %02X %02X",
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8])
    else
        -- 32-bit address: 4 bytes little-endian
        local b1 = targetAddr % 256
        local b2 = math_floor(targetAddr / 256) % 256
        local b3 = math_floor(targetAddr / 65536) % 256
        local b4 = math_floor(targetAddr / 16777216) % 256
        pattern = string_format("%02X %02X %02X %02X", b1, b2, b3, b4)
    end

    -- Scan executable memory
    local scanResult = AOBScan(pattern, "+X")
    if not scanResult then
        return {
            target = Utils.formatHex(targetAddr),
            count = 0,
            references = {},
            arch = is64 and "x64" or "x86"
        }
    end

    local refs = {}
    local count = math_min(scanResult.Count, limit)

    for i = 0, count - 1 do
        local refAddrStr = scanResult[i]
        local refAddr = tonumber(refAddrStr, 16)
        if refAddr then
            local disasm = ""
            local symbol = nil
            pcall(function()
                disasm = disassemble(refAddr) or "???"
                symbol = getNameFromAddress(refAddr, true)
            end)
            table_insert(refs, {
                address = Utils.formatHex(refAddr),
                instruction = disasm,
                symbol = symbol
            })
        end
    end

    local totalCount = scanResult.Count
    scanResult.destroy()

    return {
        target = Utils.formatHex(targetAddr),
        count = #refs,
        total_found = totalCount,
        truncated = totalCount > limit,
        references = refs,
        arch = is64 and "x64" or "x86",
        pattern_used = pattern
    }
end

-- Find all CALL instructions that target a specific function
-- Optimized: Uses precise AOB patterns based on calculated rel32 offsets
Handlers.find_call_references = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local funcAddr = Utils.safeGetAddress(p.address)
    local limit = p.limit or 100
    local moduleName = p.module

    local callers = {}
    local scannedModule = nil

    -- Find module containing target function
    local targetModule = nil
    local mods = enumModules()
    for _, m in ipairs(mods) do
        local modEnd = m.Address + (m.Size or getModuleSize(m.Name) or 0)
        if funcAddr >= m.Address and funcAddr < modEnd then
            targetModule = m
            scannedModule = m.Name
            break
        end
    end

    -- Override with user-specified module
    if moduleName then
        local m = Utils.findModule(moduleName)
        if m then
            targetModule = m
            scannedModule = m.Name
        else
            error("Module not found: " .. moduleName)
        end
    end

    if not targetModule then
        error("Could not determine module for target address")
    end

    local moduleStart = targetModule.Address
    local moduleSize = targetModule.Size or getModuleSize(targetModule.Name) or 0
    local moduleEnd = moduleStart + moduleSize

    -- Segment size for precise AOB search (16MB segments)
    local SEGMENT_SIZE = 0x1000000  -- 16MB
    local totalSegments = math.ceil(moduleSize / SEGMENT_SIZE)
    local totalMatches = 0

    -- Helper: convert signed 32-bit to bytes (little-endian)
    local function rel32ToBytes(rel)
        if rel < 0 then rel = rel + 0x100000000 end
        local b1 = rel % 256
        local b2 = math.floor(rel / 256) % 256
        local b3 = math.floor(rel / 65536) % 256
        local b4 = math.floor(rel / 16777216) % 256
        return b1, b2, b3, b4
    end

    -- Helper: format byte as hex
    local function byteToHex(b)
        return string_format("%02X", b)
    end

    -- Reuse MemScan and FoundList objects across segments (avoid repeated create/destroy)
    local ms = createMemScan()
    local fl = createFoundList(ms)

    -- Scan each segment with precise AOB pattern
    for segIdx = 0, totalSegments - 1 do
        if #callers >= limit then break end

        local segStart = moduleStart + segIdx * SEGMENT_SIZE
        local segEnd = math.min(segStart + SEGMENT_SIZE, moduleEnd)
        local segMid = math.floor((segStart + segEnd) / 2)

        -- Calculate rel32 for segment midpoint
        -- rel32 = target - call_addr - 5
        local rel32Mid = funcAddr - segMid - 5
        local b1, b2, b3, b4 = rel32ToBytes(rel32Mid)

        -- Create AOB pattern: E8 ?? ?? b3 b4 (fix high 2 bytes, wildcard low 2)
        -- This works because within 16MB, high 2 bytes change by at most 1
        local aobPattern = string_format("E8 ?? ?? %s %s", byteToHex(b3), byteToHex(b4))

        -- Also search with b3-1 and b3+1 to handle segment boundaries
        local patterns = { aobPattern }
        if b3 > 0 then
            table_insert(patterns, string_format("E8 ?? ?? %s %s", byteToHex(b3 - 1), byteToHex(b4)))
        end
        if b3 < 255 then
            table_insert(patterns, string_format("E8 ?? ?? %s %s", byteToHex(b3 + 1), byteToHex(b4)))
        end

        for _, pattern in ipairs(patterns) do
            if #callers >= limit then break end

            -- Reuse MemScan object (firstScan resets previous scan automatically)
            local scanOk = false
            
            pcall(function()
                ms.firstScan(0, 7, 0, pattern, "", segStart, segEnd, "+X", 
                            0, "", true, false, false, false)
                ms.waitTillDone()
                scanOk = true
            end)

            if scanOk then
                fl.initialize()
                local count = fl.Count or 0
                if count > 0 then
                    totalMatches = totalMatches + count

                    for i = 0, count - 1 do
                        if #callers >= limit then break end

                        local callAddrStr = fl.Address[i]
                        local callAddr = type(callAddrStr) == "string" and tonumber(callAddrStr, 16) or callAddrStr

                        if callAddr then
                            local relOffset = readInteger(callAddr + 1)
                            if relOffset then
                                if relOffset > 0x7FFFFFFF then
                                    relOffset = relOffset - 0x100000000
                                end
                                local target = callAddr + 5 + relOffset

                                if target == funcAddr then
                                    local disasm = ""
                                    local symbol = nil
                                    pcall(function()
                                        disasm = disassemble(callAddr) or "???"
                                        symbol = getNameFromAddress(callAddr, true)
                                    end)

                                    local isDup = false
                                    for _, c in ipairs(callers) do
                                        if c.address == Utils.formatHex(callAddr) then
                                            isDup = true
                                            break
                                        end
                                    end

                                    if not isDup then
                                        table_insert(callers, {
                                            address = Utils.formatHex(callAddr),
                                            instruction = disasm,
                                            symbol = symbol
                                        })
                                    end
                                end
                            end
                        end
                    end
                end
                fl.deinitialize()
            end
        end
    end

    -- Cleanup reused objects
    fl.deinitialize()
    ms.destroy()

    return {
        function_address = Utils.formatHex(funcAddr),
        count = #callers,
        total_matches = totalMatches,
        segments_scanned = totalSegments,
        callers = callers,
        module = scannedModule or "unknown"
    }
end

-- Find function start and end boundaries
Handlers.find_function_boundaries = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)
    local maxSearch = p.max_search or 4096

    local is64 = targetIs64Bit()
    local funcStart = nil
    local prologueType = nil

    -- Batch read memory for prologue search (much faster than per-byte reads)
    local readSize = math_min(maxSearch + 4, 0x10000)
    local searchBase = addr - maxSearch
    if searchBase < 0 then searchBase = 0 end
    local rawBytes = readBytes(searchBase, readSize, true)

    if rawBytes then
        local searchLen = #rawBytes - 3
        for offset = 0, searchLen do
            local b1 = rawBytes[offset + 1]
            local b2 = rawBytes[offset + 2]
            local b3 = rawBytes[offset + 3]
            local b4 = rawBytes[offset + 4] or 0

            -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
            if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
                funcStart = searchBase + offset
                prologueType = "x86_standard"
                break
            end

            -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
            if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
                funcStart = searchBase + offset
                prologueType = "x64_standard"
                break
            end

            -- 64-bit alternative: sub rsp, imm8 (48 83 EC xx) - common in leaf functions
            if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
                funcStart = searchBase + offset
                prologueType = "x64_leaf"
                break
            end
        end
    end

    -- Search forwards for return instruction (batch read for performance)
    local funcEnd = nil
    local searchStart = funcStart or addr
    local fwdSize = math_min(maxSearch, 0x10000)
    local fwdBytes = readBytes(searchStart, fwdSize, true)

    if fwdBytes then
        for offset = 0, #fwdBytes - 1 do
            local b = fwdBytes[offset + 1]
            -- C3 = ret, C2 xx xx = ret imm16
            if b == 0xC3 or b == 0xC2 then
                funcEnd = searchStart + offset
                break
            end
        end
    end

    local found = funcStart ~= nil

    return {
        found = found,
        query_address = Utils.formatHex(addr),
        function_start = funcStart and Utils.formatHex(funcStart) or nil,
        function_end = funcEnd and Utils.formatHex(funcEnd) or nil,
        function_size = (funcStart and funcEnd) and (funcEnd - funcStart + 1) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        note = not found and "No standard function prologue found within search range" or nil
    }
end

-- Calculate MD5 hash of a memory region
Handlers.checksum_memory = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)
    local size = p.size or 256

    -- Limit size to prevent excessive memory reads
    size = math_min(size, Config.MAX_CHECKSUM_SIZE)  -- Max 1MB

    local ok, hash = pcall(md5memory, addr, size)

    if ok and hash then
        return {
            address = Utils.formatHex(addr),
            size = size,
            md5_hash = hash
        }
    else
        error("Failed to calculate MD5: " .. tostring(hash))
    end
end

-- Generate unique AOB signature for an address
Handlers.generate_signature = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)

    -- getUniqueAOB returns: AOBString, Offset
    local ok, signature, offset = pcall(getUniqueAOB, addr)

    if not ok then
        error("getUniqueAOB failed: " .. tostring(signature))
    end

    if not signature or signature == "" then
        error("Could not generate unique signature - pattern not unique enough")
    end

    -- Count bytes in signature
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end

    return {
        address = Utils.formatHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string_format("Use aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end

Handlers.analyze_struct_access = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"base_address"})
    local baseAddr = Utils.safeGetAddress(p.base_address)
    local scanRange = math_min(p.scan_range or 0x200, 0x1000)

    local rawBytes = readBytes(baseAddr, scanRange, true)
    if not rawBytes or #rawBytes == 0 then
        error("Could not read memory at base address")
    end

    local function getInt32(offset)
        local idx = offset + 1
        if idx + 3 > #rawBytes then return nil end
        return rawBytes[idx] | (rawBytes[idx+1] << 8) | (rawBytes[idx+2] << 16) | (rawBytes[idx+3] << 24)
    end

    local function getInt64(offset)
        local idx = offset + 1
        if idx + 7 > #rawBytes then return nil end
        local low = rawBytes[idx] | (rawBytes[idx+1] << 8) | (rawBytes[idx+2] << 16) | (rawBytes[idx+3] << 24)
        local high = rawBytes[idx+4] | (rawBytes[idx+5] << 8) | (rawBytes[idx+6] << 16) | (rawBytes[idx+7] << 24)
        return (high << 32) | low
    end

    local function getFloat(offset)
        if not string_unpack then return nil end
        local idx = offset + 1
        if idx + 3 > #rawBytes then return nil end
        local ok, val = pcall(string_unpack, "f", string_char(rawBytes[idx], rawBytes[idx+1], rawBytes[idx+2], rawBytes[idx+3]))
        return ok and val or nil
    end

    local function isPointerLikely(val)
        if not val then return false end
        if targetIs64Bit() then
            return val > 0x10000 and val < 0x7FFFFFFFFFFF
        else
            return val > 0x10000 and val < 0x7FFFFFFF
        end
    end

    local fields = {}
    local step = targetIs64Bit() and 8 or 4

    for offset = 0, scanRange - step, step do
        local iVal32 = getInt32(offset)
        local iVal64 = targetIs64Bit() and getInt64(offset) or nil
        local fVal = getFloat(offset)

        local info = nil

        if targetIs64Bit() and iVal64 and isPointerLikely(iVal64) then
            info = { type = "pointer64", value = Utils.formatHex(iVal64) }
        elseif iVal32 and isPointerLikely(iVal32) then
            info = { type = "pointer32", value = Utils.formatHex(iVal32) }
        elseif fVal and math_abs(fVal) > 0.0001 and math_abs(fVal) < 10000000.0 then
            info = { type = "float", value = fVal }
        elseif iVal32 and iVal32 > 0 and iVal32 < 100000 then
            info = { type = "int32", value = iVal32 }
        end

        if info then
            info.offset = string_format("0x%X", offset)
            info.offsetDec = offset
            table_insert(fields, info)
        end
    end

    return {
        base = Utils.formatHex(baseAddr),
        fields = fields,
        scanned_bytes = scanRange
    }
end

Handlers.trace_struct_access = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    local addr = Utils.safeGetAddress(p.address)
    local duration = p.duration_ms or 1000
    local bptSize = p.size or 4
    local bptType = p.mode == "write" and bptWrite or bptAccess

    -- Cleanup previous trace on main thread
    synchronize(function()
        if Context.traceData then
            pcall(debug_removeBreakpoint, Context.traceAddr)
            Context.traceData = nil
        end
    end)

    Context.traceData = {}
    Context.traceAddr = addr
    Context.traceActive = true
    Context.traceTimestamp = os_clock()  -- Record timestamp for watchdog

    -- Set breakpoint on main thread
    synchronize(function()
        debug_setBreakpoint(addr, bptSize, bptType, function()
            if not Context.traceActive then
                debug_continueFromBreakpoint(co_run)
                return 0
            end

            local entry = {
                offset = 0,
                rip = Utils.formatHex(RIP),
                val_rax = RAX,
                val_rbx = RBX
            }

            if RIP then
                local dis = disassemble(RIP)
                entry.instr = dis
                local off = dis:match("%+([0-9A-Fa-f]+)%]")
                if off then entry.offset = tonumber(off, 16) end
            end

            table_insert(Context.traceData, entry)
            if #Context.traceData > Config.MAX_TRACE_ENTRIES then
                Context.traceActive = false
            end

            debug_continueFromBreakpoint(co_run)
            return 1
        end)
    end)

    -- Wait in worker thread (non-blocking for GUI)
    Utils.adaptiveWait(function() return not Context.traceActive end, duration)

    -- Cleanup on main thread
    synchronize(function()
        Context.traceActive = false
        pcall(debug_removeBreakpoint, addr)
        pcall(debug_continueFromBreakpoint, co_run)
    end)

    local results = Context.traceData
    Context.traceData = nil
    Context.traceAddr = nil

    return { address = Utils.formatHex(addr), count = #results, log = results }
end

Handlers.cleanup_breakpoints = function()
    -- Use the centralized cleanup function
    local cleaned = Utils.cleanupZombieState()

    return {
        cleaned = cleaned.breakpoints + cleaned.traces + cleaned.find_what,
        success = true,
        slots_freed = 4,
        details = cleaned
    }
end

-- ============ Handlers: Function Hooking ============

-- Hook storage: { [name] = { address, originalBytes, trampolineAddr, log, ... } }
local HookRegistry = {}

-- Generate trampoline code for function hooking
-- Enhanced to support return value capture (Requirements 7.1, 7.2)
-- When captureReturn=true, the hook will:
-- 1. Replace the return address on the stack with our return hook address
-- 2. Save the original return address
-- 3. When the function returns, capture RAX/EAX and restore original return address
local function generateHookTrampoline(targetAddr, hookName, captureArgs, captureReturn, maxRecords)
    local is64 = targetIs64Bit()

    -- Calculate how many bytes we need to copy (must be complete instructions)
    -- Use 5 bytes for both x86 and x64 since CE's alloc() with nearAddr
    -- will allocate memory within 2GB range, allowing rel32 jmp
    local minJumpSize = 5
    local origBytesCount = 0
    local currentAddr = targetAddr

    while origBytesCount < minJumpSize do
        local instrSize = getInstructionSize(currentAddr)
        if not instrSize or instrSize <= 0 then instrSize = 1 end
        origBytesCount = origBytesCount + instrSize
        currentAddr = currentAddr + instrSize
    end

    -- Read original bytes
    local originalBytes = readBytes(targetAddr, origBytesCount, true)
    if not originalBytes or #originalBytes < origBytesCount then
        error("Failed to read original bytes")
    end

    -- Convert to hex string
    local origBytesHex = {}
    for _, b in ipairs(originalBytes) do
        table_insert(origBytesHex, string_format("%02X", b))
    end
    local origBytesStr = table_concat(origBytesHex, " ")

    -- Generate NOP padding for bytes after jmp (jmp is 5 bytes, we may have copied more)
    local nopCount = origBytesCount - 5
    local nopStr = ""
    if nopCount > 0 then
        local nops = {}
        for i = 1, nopCount do
            table_insert(nops, "90")
        end
        nopStr = "\n  db " .. table_concat(nops, " ")
    end

    -- Force max_records to 64 (power of 2 for fast modulo with AND)
    local actualMaxRecords = Config.MAX_HOOK_RECORDS

    -- Enhanced log entry size to include return value (Requirements 7.2)
    -- x64: 40 bytes (4 args * 8 + return_value * 8)
    -- x32: 20 bytes (4 args * 4 + return_value * 4)
    local logEntrySize = is64 and 40 or 20
    local logHeaderSize = is64 and Config.HOOK_HEADER_SIZE_X64 or Config.HOOK_HEADER_SIZE_X32
    local logBufferSize = logHeaderSize + logEntrySize * actualMaxRecords

    -- Need more space for return hook code when captureReturn is enabled
    local trampolineCodeSize = captureReturn and 512 or 256

    -- Return address stack for tracking which entry to update (only when captureReturn=true)
    -- x64: 64 entries * 16 bytes (original_ret_addr + entry_index) = 1024 bytes
    -- x32: 64 entries * 8 bytes = 512 bytes
    local retStackSize = captureReturn and (is64 and 1024 or 512) or 0
    local totalSize = logBufferSize + trampolineCodeSize + retStackSize

    -- Build AA script - thread-safe version using lock xadd
    local aaScript
    if is64 then
        -- x64 log buffer layout (enhanced for return value capture):
        -- offset 0: total_count (qword)
        -- offset 8: write_index (qword) - atomically incremented
        -- offset 16: max_records (qword) = 64
        -- offset 24: ret_stack_index (qword) - for return address tracking
        -- offset 32+: log entries (40 bytes each: 4 qword args + 1 qword return_value)

        if captureReturn then
            -- Version with return value capture
            -- Strategy: Replace return address, save original, capture RAX on return
            --
            -- x64 fastcall: RCX=arg1, RDX=arg2, R8=arg3, R9=arg4
            -- Stack on entry to trampoline: [rsp] = return address
            --
            -- FIXED VERSION: Use simple global variables for entry/ret storage
            -- Note: This is NOT fully thread-safe, but works for most scenarios
            -- The return_hook uses push/pop + sub rsp,8; xchg; ret pattern
            aaScript = [[
alloc(hook_]] .. hookName .. [[_mem, ]] .. totalSize .. [[, ]] .. Utils.formatHex(targetAddr) .. [[)

hook_]] .. hookName .. [[_mem:
hook_]] .. hookName .. [[_trampoline:
  sub rsp, 28
  mov [rsp], rax
  mov [rsp+8], rbx
  mov [rsp+10], rcx
  mov [rsp+18], rdx

  mov rax, hook_]] .. hookName .. [[_logbuffer

  mov rbx, 1
  lock xadd qword ptr [rax+8], rbx
  lock inc qword ptr [rax]

  and rbx, 3F
  imul rbx, rbx, #40
  add rbx, 20
  add rbx, rax

  mov rcx, [rsp+10]
  mov [rbx], rcx
  mov rdx, [rsp+18]
  mov [rbx+8], rdx
  mov [rbx+10], r8
  mov [rbx+18], r9
  mov qword ptr [rbx+20], 0

  mov [hook_]] .. hookName .. [[_saved_entry], rbx

  mov rcx, [rsp+28]
  mov [hook_]] .. hookName .. [[_saved_ret], rcx

  lea rdx, [hook_]] .. hookName .. [[_return_hook]
  mov [rsp+28], rdx

  mov rcx, [rsp+10]
  mov rdx, [rsp+18]
  mov rbx, [rsp+8]
  mov rax, [rsp]
  add rsp, 28

  db ]] .. origBytesStr .. [[

  jmp ]] .. Utils.formatHex(targetAddr + origBytesCount) .. [[

hook_]] .. hookName .. [[_return_hook:
  push rbx
  mov rbx, [hook_]] .. hookName .. [[_saved_entry]
  mov [rbx+20], rax
  pop rbx

  sub rsp, 8
  mov [rsp], rax
  mov rax, [hook_]] .. hookName .. [[_saved_ret]
  xchg rax, [rsp]
  ret

hook_]] .. hookName .. [[_logbuffer:
  dq 0
  dq 0
  dq #64
  dq 0

hook_]] .. hookName .. [[_saved_entry:
  dq 0

hook_]] .. hookName .. [[_saved_ret:
  dq 0

]] .. Utils.formatHex(targetAddr) .. [[:
  jmp hook_]] .. hookName .. [[_trampoline]] .. nopStr .. [[

registersymbol(hook_]] .. hookName .. [[_mem)
registersymbol(hook_]] .. hookName .. [[_logbuffer)
registersymbol(hook_]] .. hookName .. [[_trampoline)
]]
        else
            -- Original version without return value capture (simpler, faster)
            -- Use sub rsp to allocate our own space, avoid shadow space conflicts
            -- Use db with pre-read bytes instead of readmem (readmem fails if executed after jmp is written)
            aaScript = [[
alloc(hook_]] .. hookName .. [[_mem, ]] .. totalSize .. [[, ]] .. Utils.formatHex(targetAddr) .. [[)

hook_]] .. hookName .. [[_mem:
hook_]] .. hookName .. [[_trampoline:
  sub rsp, 28
  mov [rsp], rax
  mov [rsp+8], rbx
  mov [rsp+10], rcx
  mov [rsp+18], rdx

  mov rax, hook_]] .. hookName .. [[_logbuffer

  mov rbx, 1
  lock xadd qword ptr [rax+8], rbx
  lock inc qword ptr [rax]

  and rbx, 3F
  imul rbx, rbx, #40
  add rbx, 20
  add rbx, rax

  mov rcx, [rsp+10]
  mov [rbx], rcx
  mov rdx, [rsp+18]
  mov [rbx+8], rdx
  mov [rbx+10], r8
  mov [rbx+18], r9
  mov qword ptr [rbx+20], 0

  mov rcx, [rsp+10]
  mov rdx, [rsp+18]
  mov rbx, [rsp+8]
  mov rax, [rsp]
  add rsp, 28

  db ]] .. origBytesStr .. [[

  jmp ]] .. Utils.formatHex(targetAddr + origBytesCount) .. [[

hook_]] .. hookName .. [[_logbuffer:
  dq 0
  dq 0
  dq #64
  dq 0

]] .. Utils.formatHex(targetAddr) .. [[:
  jmp hook_]] .. hookName .. [[_trampoline]] .. nopStr .. [[

registersymbol(hook_]] .. hookName .. [[_mem)
registersymbol(hook_]] .. hookName .. [[_logbuffer)
registersymbol(hook_]] .. hookName .. [[_trampoline)
]]
        end
    else
        -- 32-bit version
        if captureReturn then
            -- Version with return value capture for x32
            -- FIXED: Correct stack offsets, use readmem, simplified return_hook
            --
            -- x32 cdecl/stdcall: args on stack
            -- Stack on entry: [esp] = return address, [esp+4] = arg1, [esp+8] = arg2, etc.
            aaScript = [[
alloc(hook_]] .. hookName .. [[_mem, ]] .. totalSize .. [[, ]] .. Utils.formatHex(targetAddr) .. [[)

hook_]] .. hookName .. [[_mem:
hook_]] .. hookName .. [[_trampoline:
  // Save registers
  push eax
  push ebx
  push ecx
  push edx
  // Stack: [esp]=edx, [esp+4]=ecx, [esp+8]=ebx, [esp+C]=eax, [esp+10]=retaddr, [esp+14]=arg1...

  mov eax, hook_]] .. hookName .. [[_logbuffer

  // Atomically get and increment write_index
  mov ebx, 1
  lock xadd dword ptr [eax+4], ebx
  lock inc dword ptr [eax]

  // Calculate entry offset: (write_index & 0x3F) * 20 + 16
  and ebx, 3F
  imul ebx, ebx, #20
  add ebx, 10
  add ebx, eax
  // ebx = entry pointer

  // Store arguments from stack
  mov edx, [esp+14]   // arg1
  mov [ebx], edx
  mov edx, [esp+18]   // arg2
  mov [ebx+4], edx
  mov edx, [esp+1C]   // arg3
  mov [ebx+8], edx
  mov edx, [esp+20]   // arg4
  mov [ebx+C], edx
  mov dword ptr [ebx+10], 0  // return_value = 0 (filled later)

  // ===== SETUP RETURN HOOK =====
  mov edx, hook_]] .. hookName .. [[_retstack
  mov eax, 1
  lock xadd dword ptr [hook_]] .. hookName .. [[_logbuffer+C], eax
  and eax, 3F

  // Calculate ret_stack entry: base + index * 8
  shl eax, 3
  add eax, edx
  // eax = ret_stack entry pointer

  // Save original return address and entry pointer
  mov edx, [esp+10]   // original return address
  mov [eax], edx
  mov [eax+4], ebx    // entry pointer

  // Replace return address with our return hook
  lea edx, [hook_]] .. hookName .. [[_return_hook]
  mov [esp+10], edx

  // Restore registers
  pop edx
  pop ecx
  pop ebx
  pop eax

  // Use readmem for proper instruction relocation
  readmem(]] .. Utils.formatHex(targetAddr) .. [[, ]] .. origBytesCount .. [[)

  jmp ]] .. Utils.formatHex(targetAddr + origBytesCount) .. [[

hook_]] .. hookName .. [[_return_hook:
  // ===== RETURN HOOK =====
  // Function has returned, EAX contains return value
  // Preserve EAX!
  push ebx
  push ecx
  // Stack: [esp]=ecx, [esp+4]=ebx, [esp+8]=garbage_retaddr

  // Decrement ret_stack_index to get our entry
  mov ebx, hook_]] .. hookName .. [[_logbuffer
  mov ecx, -1
  lock xadd dword ptr [ebx+C], ecx
  dec ecx
  and ecx, 3F

  // Get ret_stack entry
  mov ebx, hook_]] .. hookName .. [[_retstack
  shl ecx, 3
  add ebx, ecx
  // ebx = ret_stack entry pointer

  // Store return value to log entry
  mov ecx, [ebx+4]    // get entry pointer
  mov [ecx+10], eax   // store return value (preserve eax!)

  // Get original return address
  mov ecx, [ebx]

  // Setup for return
  mov [esp+4], ecx    // put original ret addr where we'll ret to
  pop ecx             // restore ecx
  // Now: [esp]=original_ret_addr, need to restore ebx
  xchg ebx, [esp]     // ebx = original_ret_addr, [esp] = saved_ebx
  xchg ebx, [esp+4]   // ebx = saved_ebx (restored!), [esp+4] = original_ret_addr
  add esp, 4
  ret

hook_]] .. hookName .. [[_logbuffer:
  dd 0               // total_count
  dd 0               // write_index
  dd #64             // max_records
  dd 0               // ret_stack_index

hook_]] .. hookName .. [[_retstack:
  // 64 entries * 8 bytes = 512 bytes
]] .. string.rep("  dd 0\n  dd 0\n", 64) .. [[

]] .. Utils.formatHex(targetAddr) .. [[:
  jmp hook_]] .. hookName .. [[_trampoline]] .. nopStr .. [[

registersymbol(hook_]] .. hookName .. [[_mem)
registersymbol(hook_]] .. hookName .. [[_logbuffer)
registersymbol(hook_]] .. hookName .. [[_trampoline)
registersymbol(hook_]] .. hookName .. [[_retstack)
]]
        else
            -- Original 32-bit version without return capture
            -- FIXED: Use readmem for instruction relocation
            aaScript = [[
alloc(hook_]] .. hookName .. [[_mem, ]] .. totalSize .. [[, ]] .. Utils.formatHex(targetAddr) .. [[)

hook_]] .. hookName .. [[_mem:
hook_]] .. hookName .. [[_trampoline:
  push eax
  push ebx
  push ecx
  // Stack: [esp]=ecx, [esp+4]=ebx, [esp+8]=eax, [esp+C]=retaddr, [esp+10]=arg1...

  mov eax, hook_]] .. hookName .. [[_logbuffer

  mov ebx, 1
  lock xadd dword ptr [eax+4], ebx
  lock inc dword ptr [eax]

  // Calculate entry offset: (write_index & 0x3F) * 20 + 16
  and ebx, 3F
  imul ebx, ebx, #20
  add ebx, 10
  add ebx, eax

  mov ecx, [esp+10]   // arg1
  mov [ebx], ecx
  mov ecx, [esp+14]   // arg2
  mov [ebx+4], ecx
  mov ecx, [esp+18]   // arg3
  mov [ebx+8], ecx
  mov ecx, [esp+1C]   // arg4
  mov [ebx+C], ecx
  mov dword ptr [ebx+10], 0  // return_value = 0 (not captured)

  pop ecx
  pop ebx
  pop eax

  // Use readmem for proper instruction relocation
  readmem(]] .. Utils.formatHex(targetAddr) .. [[, ]] .. origBytesCount .. [[)

  jmp ]] .. Utils.formatHex(targetAddr + origBytesCount) .. [[

hook_]] .. hookName .. [[_logbuffer:
  dd 0
  dd 0
  dd #64
  dd 0

]] .. Utils.formatHex(targetAddr) .. [[:
  jmp hook_]] .. hookName .. [[_trampoline]] .. nopStr .. [[

registersymbol(hook_]] .. hookName .. [[_mem)
registersymbol(hook_]] .. hookName .. [[_logbuffer)
registersymbol(hook_]] .. hookName .. [[_trampoline)
]]
        end
    end

    local success, err = autoAssemble(aaScript)
    if not success then
        error("Failed to assemble hook: " .. tostring(err))
    end

    local logBufferAddr = getAddress("hook_" .. hookName .. "_logbuffer")
    local trampolineAddr = getAddress("hook_" .. hookName .. "_trampoline")
    local memAddr = getAddress("hook_" .. hookName .. "_mem")
    local retStackAddr = captureReturn and getAddress("hook_" .. hookName .. "_retstack") or nil

    -- Log buffer is initialized by AA script with dq/dd directives
    -- No need to initialize again via Lua

    return {
        logBuffer = logBufferAddr,
        trampolineAddr = trampolineAddr,
        memAddr = memAddr,
        retStackAddr = retStackAddr,
        originalBytes = originalBytes,
        origBytesCount = origBytesCount,
        totalSize = totalSize,
        logEntrySize = logEntrySize,
        logHeaderSize = logHeaderSize,
        maxRecords = maxRecords,
        captureReturn = captureReturn
    }
end

Handlers.hook_function = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address", "name"})

    local addr = Utils.safeGetAddress(p.address, "hook_function")
    local name = p.name

    -- Validate hook name to prevent AA script injection
    -- Must start with letter/underscore, contain only alphanumeric/underscore
    if not name:match("^[a-zA-Z_][a-zA-Z0-9_]*$") then
        error(ErrorContextBuilder.build("hook_function",
            "Invalid hook name '" .. name .. "'. Must match pattern: ^[a-zA-Z_][a-zA-Z0-9_]*$",
            { address = Utils.formatHex(addr) }))
    end

    local captureArgs = math_min(p.capture_args or 4, 4)  -- max 4 args
    -- Re-enabled after fixing setMemoryProtection crash
    -- Note: captureReturn assumes approximate LIFO return order
    -- In heavy multi-threaded scenarios, return values may be mismatched
    local captureReturn = p.capture_return ~= false
    -- Force max_records to 64 (power of 2 for thread-safe modulo)
    local maxRecords = 64

    -- Check if hook already exists
    if HookRegistry[name] then
        error(ErrorContextBuilder.build("hook_function",
            "Hook '" .. name .. "' already exists. Use ce_unhook_function first.",
            { address = Utils.formatHex(addr) }))
    end

    -- Get symbol for better identification
    local symbol = nil
    pcall(function()
        symbol = getNameFromAddress(addr, true)
    end)

    -- Generate and install hook with error handling
    local ok, hookData = pcall(generateHookTrampoline, addr, name, captureArgs, captureReturn, maxRecords)
    if not ok then
        error(ErrorContextBuilder.breakpointError("hook_function", addr, tostring(hookData)))
    end

    -- Store hook info
    HookRegistry[name] = {
        name = name,
        address = addr,
        addressHex = Utils.formatHex(addr),
        symbol = symbol,
        captureArgs = captureArgs,
        captureReturn = captureReturn,
        maxRecords = maxRecords,
        hookData = hookData,
        createdAt = os.time(),
        callCount = 0
    }

    return {
        success = true,
        name = name,
        address = Utils.formatHex(addr),
        symbol = symbol,
        capture_args = captureArgs,
        capture_return = captureReturn,
        max_records = maxRecords,
        trampoline = Utils.formatHex(hookData.trampolineAddr),
        log_buffer = Utils.formatHex(hookData.logBuffer),
        warning = captureReturn and "x64 return capture uses global saved_entry/saved_ret (NOT thread-safe for concurrent callers). If the hooked function is called from multiple threads simultaneously, return values may be mismatched with args." or nil
    }
end

Handlers.unhook_function = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"name"})
    local name = p.name

    local hook = HookRegistry[name]
    if not hook then
        error("Hook '" .. name .. "' not found")
    end

    -- Get call count before cleanup
    local callCount = 0
    pcall(function()
        local is64 = targetIs64Bit()
        callCount = is64 and (readQword(hook.hookData.logBuffer) or 0) or (readInteger(hook.hookData.logBuffer) or 0)
    end)

    -- Restore original bytes
    local addr = hook.address
    local origBytes = hook.hookData.originalBytes
    local count = hook.hookData.origBytesCount

    synchronize(function()
        for i = 1, count do
            writeBytes(addr + i - 1, origBytes[i])
        end
    end)

    -- Unregister symbols via AA
    -- Note: x64 captureReturn uses saved_entry and saved_ret instead of retstack
    pcall(function()
        local unregScript = string_format([[
unregistersymbol(hook_%s_mem)
unregistersymbol(hook_%s_logbuffer)
unregistersymbol(hook_%s_trampoline)
unregistersymbol(hook_%s_saved_entry)
unregistersymbol(hook_%s_saved_ret)
]], name, name, name, name, name)
        autoAssemble(unregScript)
    end)

    -- Free memory using AA dealloc (AA alloc must be freed by AA dealloc, not Lua deAlloc)
    pcall(function()
        if hook.hookData.memAddr and hook.hookData.memAddr ~= 0 then
            autoAssemble(string_format("dealloc(%s)", Utils.formatHex(hook.hookData.memAddr)))
        end
    end)

    HookRegistry[name] = nil

    return {
        success = true,
        name = name,
        address = Utils.formatHex(addr),
        total_calls = callCount
    }
end

Handlers.list_hooks = function()
    Utils.checkProcess()
    local hooks = {}

    for name, hook in pairs(HookRegistry) do
        local callCount = 0
        pcall(function()
            local is64 = targetIs64Bit()
            callCount = is64 and (readQword(hook.hookData.logBuffer) or 0) or (readInteger(hook.hookData.logBuffer) or 0)
        end)

        table_insert(hooks, {
            name = name,
            address = hook.addressHex,
            symbol = hook.symbol,
            capture_args = hook.captureArgs,
            capture_return = hook.captureReturn,
            max_records = hook.maxRecords,
            call_count = callCount,
            created_at = hook.createdAt
        })
    end

    return {
        count = #hooks,
        hooks = hooks
    }
end

Handlers.get_hook_log = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"name"})
    local name = p.name
    local clear = p.clear or false
    local limit = math_min(p.limit or 50, 64)  -- max 64 entries

    local hook = HookRegistry[name]
    if not hook then
        error("Hook '" .. name .. "' not found")
    end

    local logBuffer = hook.hookData.logBuffer
    local is64 = targetIs64Bit()
    local captureReturn = hook.captureReturn

    -- Enhanced log format with return value capture (Requirements 7.3):
    -- offset 0: total_count (qword/dword)
    -- offset 8/4: write_index (qword/dword)
    -- offset 16/8: max_records = 64
    -- offset 24/12: ret_stack_index (for return capture)
    -- offset 32/16+: log entries (40/20 bytes each: 4 args + return_value)

    local totalCalls, writeIndex
    local headerSize, entrySize, maxRecords

    if is64 then
        totalCalls = readQword(logBuffer) or 0
        writeIndex = readQword(logBuffer + 8) or 0
        maxRecords = 64
        headerSize = 32
        entrySize = 40  -- 4 qwords args + 1 qword return_value
    else
        totalCalls = readInteger(logBuffer) or 0
        writeIndex = readInteger(logBuffer + 4) or 0
        maxRecords = 64
        headerSize = 16
        entrySize = 20  -- 4 dwords args + 1 dword return_value
    end

    -- Read log entries
    local entries = {}
    local readCount = math_min(totalCalls, maxRecords, limit)

    -- Read from most recent to oldest
    -- Use proper modulo handling for negative numbers
    for i = 0, readCount - 1 do
        local rawIdx = writeIndex - 1 - i
        local idx = ((rawIdx % maxRecords) + maxRecords) % maxRecords
        local entryAddr = logBuffer + headerSize + idx * entrySize

        local entry = { args = {} }

        -- Read 4 arguments
        for j = 0, 3 do
            local argVal
            if is64 then
                argVal = readQword(entryAddr + j * 8) or 0
            else
                argVal = readInteger(entryAddr + j * 4) or 0
            end
            entry.args[j + 1] = Utils.formatHex(argVal)
        end

        -- Read return value (Requirements 7.3)
        -- Return value is stored at offset 32 (x64) or 16 (x32) within the entry
        local returnVal
        if is64 then
            returnVal = readQword(entryAddr + 32) or 0
        else
            returnVal = readInteger(entryAddr + 16) or 0
        end
        entry.return_value = Utils.formatHex(returnVal)

        -- Indicate if return capture was enabled for this hook
        entry.return_captured = captureReturn

        table_insert(entries, entry)
    end

    -- Clear log if requested
    if clear then
        if is64 then
            writeQword(logBuffer, 0)
            writeQword(logBuffer + 8, 0)
        else
            writeInteger(logBuffer, 0)
            writeInteger(logBuffer + 4, 0)
        end
    end

    return {
        name = name,
        address = hook.addressHex,
        symbol = hook.symbol,
        capture_return = captureReturn,
        total_calls = totalCalls,
        entries_returned = #entries,
        entries = entries,
        cleared = clear
    }
end

Handlers.clear_hook_log = function(p)
    Utils.checkProcess()
    local name = p.name
    local cleared = {}

    if name then
        -- Clear specific hook
        local hook = HookRegistry[name]
        if not hook then
            error("Hook '" .. name .. "' not found")
        end

        local is64 = targetIs64Bit()
        local prevCount = is64 and (readQword(hook.hookData.logBuffer) or 0) or (readInteger(hook.hookData.logBuffer) or 0)
        if is64 then
            writeQword(hook.hookData.logBuffer, 0)
            writeQword(hook.hookData.logBuffer + 8, 0)
        else
            writeInteger(hook.hookData.logBuffer, 0)
            writeInteger(hook.hookData.logBuffer + 4, 0)
        end

        table_insert(cleared, { name = name, previous_count = prevCount })
    else
        -- Clear all hooks
        for hookName, hook in pairs(HookRegistry) do
            local is64 = targetIs64Bit()
            local prevCount = is64 and (readQword(hook.hookData.logBuffer) or 0) or (readInteger(hook.hookData.logBuffer) or 0)
            if is64 then
                writeQword(hook.hookData.logBuffer, 0)
                writeQword(hook.hookData.logBuffer + 8, 0)
            else
                writeInteger(hook.hookData.logBuffer, 0)
                writeInteger(hook.hookData.logBuffer + 4, 0)
            end

            table_insert(cleared, { name = hookName, previous_count = prevCount })
        end
    end

    return {
        success = true,
        cleared = cleared
    }
end

-- Add hook cleanup to zombie cleanup
local originalCleanupZombieState = Utils.cleanupZombieState
Utils.cleanupZombieState = function()
    local result = originalCleanupZombieState()

    -- Cleanup all hooks
    local hookCount = 0
    for name, hook in pairs(HookRegistry) do
        pcall(function()
            -- Restore original bytes
            local addr = hook.address
            local origBytes = hook.hookData.originalBytes
            local count = hook.hookData.origBytesCount
            for i = 1, count do
                writeBytes(addr + i - 1, origBytes[i])
            end
            -- Free memory using AA dealloc (AA alloc must be freed by AA dealloc)
            autoAssemble(string_format("dealloc(%s)", Utils.formatHex(hook.hookData.memAddr)))
        end)
        hookCount = hookCount + 1
    end
    HookRegistry = {}

    result.hooks = hookCount
    return result
end

-- ============ Handlers: Find What Accesses/Writes ============

local function findWhatImpl(p, bpType, modeName)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    if not p.user_prompted then error("You must confirm user interaction first") end
    local commandName = "find_what_" .. modeName
    local addr = Utils.safeGetAddress(p.address, commandName)
    local duration = p.duration_ms or 10000  -- 10 seconds for user to trigger access
    local bpSize = p.size or 4
    local maxRecords = p.max_records or 1000

    synchronize(function()
        if Context.findWhatAddr then
            pcall(debug_removeBreakpoint, Context.findWhatAddr)
            Context.findWhatAddr = nil
        end
    end)

    Context.findWhatData = {}
    Context.findWhatAddr = addr
    Context.findWhatActive = true
    Context.findWhatTimestamp = os_clock()  -- Record timestamp for watchdog
    Context.findWhatHits = 0

    -- Set breakpoint on main thread with error handling
    local setOk, setErr = pcall(function()
        synchronize(function()
            debug_setBreakpoint(addr, bpSize, bpType, function()
                if not Context.findWhatActive then
                    debug_continueFromBreakpoint(co_run)
                    return 0
                end

                Context.findWhatHits = Context.findWhatHits + 1

                -- Get instruction pointer
                -- For bptAccess/bptWrite breakpoints, the behavior differs from bptExecute:
                -- - On x64: RIP points to the instruction AFTER the one that triggered
                -- - We need to find the actual triggering instruction
                local rip = targetIs64Bit() and RIP or EIP
                local triggerAddr = rip

                -- For data breakpoints (access/write), try to find the actual instruction
                -- that caused the access by looking at the previous instruction
                if bpType == bptAccess or bpType == bptWrite then
                    local prevAddr = getPreviousOpcode(rip)
                    if prevAddr and prevAddr ~= 0 and prevAddr < rip then
                        -- Verify the previous instruction actually accesses our monitored address
                        -- by checking if it contains a memory operand
                        local ok, instrInfo = pcall(function()
                            local d = createDisassembler()
                            d.disassemble(prevAddr)
                            local data = d.LastDisassembleData
                            d.destroy()
                            return data
                        end)

                        if ok and instrInfo and instrInfo.parameters then
                            -- Check if instruction has memory operand (contains '[')
                            if instrInfo.parameters:find("%[") then
                                triggerAddr = prevAddr
                            end
                        end
                    end
                end

            local ripHex = Utils.formatHex(triggerAddr)

            -- Get or create entry for this instruction
            local entry = Context.findWhatData[ripHex]
            if not entry then
                -- New instruction, get details using disassembler
                local instrStr = ""
                local bytesStr = ""
                pcall(function()
                    local d = createDisassembler()
                    d.disassemble(triggerAddr)
                    local data = d.LastDisassembleData
                    instrStr = (data.opcode or "") .. " " .. (data.parameters or "")
                    -- Get bytes as hex string
                    local bytesHex = {}
                    for _, b in ipairs(data.bytes or {}) do
                        table_insert(bytesHex, string_format("%02X", b))
                    end
                    bytesStr = table_concat(bytesHex, " ")
                    d.destroy()
                end)

                -- Get symbol for address
                local symbol = nil
                pcall(function()
                    symbol = getNameFromAddress(triggerAddr, true)
                end)

                entry = {
                    address = ripHex,
                    symbol = symbol,
                    instruction = instrStr,
                    bytes = bytesStr,
                    count = 0,
                    registers = nil,
                    lastValue = nil
                }
                Context.findWhatData[ripHex] = entry
            end

            -- Update count and registers
            entry.count = entry.count + 1
            entry.registers = Utils.getRegisters()

            -- Try to read current value at monitored address
            pcall(function()
                if bpSize == 1 then
                    local rb = readBytes(addr, 1); entry.lastValue = Utils.formatHex(type(rb) == "table" and rb[1] or rb)
                elseif bpSize == 2 then
                    entry.lastValue = Utils.formatHex(readSmallInteger(addr))
                elseif bpSize == 4 then
                    entry.lastValue = Utils.formatHex(readInteger(addr))
                elseif bpSize == 8 then
                    entry.lastValue = Utils.formatHex(readQword(addr))
                end
            end)

            -- Check limits
            if Context.findWhatHits >= maxRecords then
                Context.findWhatActive = false
            end

            debug_continueFromBreakpoint(co_run)
            return 1  -- Continue monitoring
        end)
    end)
    end)

    if not setOk then
        error(ErrorContextBuilder.breakpointError(commandName, addr, tostring(setErr)))
    end

    -- Wait in worker thread (non-blocking for GUI)
    Utils.adaptiveWait(function() return not Context.findWhatActive end, duration)

    -- Cleanup on main thread
    synchronize(function()
        Context.findWhatActive = false
        pcall(debug_removeBreakpoint, addr)
        pcall(debug_continueFromBreakpoint, co_run)
    end)

    -- Collect and sort results by count (descending)
    local results = {}
    local uniqueCount = 0
    for _, entry in pairs(Context.findWhatData or {}) do
        uniqueCount = uniqueCount + 1
        table_insert(results, entry)
    end

    table_sort(results, function(a, b) return a.count > b.count end)

    -- Clear state
    local totalHits = Context.findWhatHits or 0
    Context.findWhatData = nil
    Context.findWhatAddr = nil
    Context.findWhatHits = nil

    local response = {
        address = Utils.formatHex(addr),
        mode = modeName,
        size = bpSize,
        duration_ms = duration,
        total_hits = totalHits,
        unique_instructions = uniqueCount,
        results = results
    }

    return response
end

Handlers.find_what_accesses = function(p)
    return findWhatImpl(p, bptAccess, "access")
end

Handlers.find_what_writes = function(p)
    return findWhatImpl(p, bptWrite, "write")
end

-- ============ Pointer Path Helpers (module-level for performance) ============

local PTR_REGS64 = {"RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP",
                    "R8","R9","R10","R11","R12","R13","R14","R15"}
local PTR_REGS32 = {"EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP"}

local function parseInstructionOffset(instr)
    if not instr then return nil, nil end
    local bracket = instr:match("%[([^%]]+)%]")
    if not bracket then return nil, nil end

    local upperBracket = bracket:upper()
    local foundReg = nil

    for _, reg in ipairs(PTR_REGS64) do
        if upperBracket:find(reg, 1, true) == 1 then
            foundReg = reg
            break
        end
    end
    if not foundReg then
        for _, reg in ipairs(PTR_REGS32) do
            if upperBracket:find(reg, 1, true) == 1 then
                foundReg = reg
                break
            end
        end
    end

    if not foundReg then return nil, nil end

    local offset = 0
    local sign, offStr = bracket:match("([%+%-])([0-9A-Fa-f]+)$")
    if offStr and not bracket:match("%*[0-9]+$") then
        offset = tonumber(offStr, 16) or 0
        if sign == "-" then offset = -offset end
    end

    return foundReg, offset
end

local function getRegValue(regs, regName)
    if not regs or not regName then return nil end
    return regs[regName:lower()]
end

local function isStaticAddress(addr)
    local addrNum = type(addr) == "string" and tonumber(addr:gsub("^0[xX]", ""), 16) or addr
    if not addrNum or addrNum == 0 then return false, nil end

    local symbol = nil
    pcall(function()
        symbol = getNameFromAddress(addrNum, true)
    end)

    if symbol then
        local lowerSym = symbol:lower()
        if lowerSym:find("%.exe%+") or lowerSym:find("%.dll%+") or
           lowerSym:find("%.sys%+") or lowerSym:find("%.ocx%+") or
           lowerSym:find("%.drv%+") or lowerSym:find("%.efi%+") then
            return true, symbol
        end
    end

    local inMod = false
    pcall(function() inMod = inModule(addrNum) end)

    if inMod then
        return true, symbol or Utils.formatHex(addrNum)
    end

    return false, symbol
end

-- ============ Handlers: Find Pointer Path ============

Handlers.find_pointer_path = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})
    if not p.user_prompted then error("You must confirm user interaction first") end

    local startAddr = Utils.safeGetAddress(p.address)
    local maxDepth = math_min(p.max_depth or 7, Config.MAX_POINTER_DEPTH)
    local durationPerLevel = p.duration_ms or Config.POINTER_TRACE_DURATION
    local maxResults = p.max_results or 10
    local strategy = p.strategy or "hybrid"

    local steps = {}
    local currentAddr = startAddr
    local offsets = {}
    local foundStatic = false
    local staticBase = nil
    local cycleDetected = false
    local suggestions = {}

    local visitedAddresses = {}
    local visitedPointers = {}

    local function searchPointerToValue(targetValue, excludeAddrs)
        excludeAddrs = excludeAddrs or {}
        local results = {}
        local scanOk, scanResult = pcall(function()
            return Handlers.value_scan({
                value = Utils.formatHex(targetValue),
                type = "qword",
                max_results = maxResults * 3,  -- Search more for multi-path exploration
                protection = "+W-C"
            })
        end)

        if scanOk and scanResult and scanResult.results then
            for _, r in ipairs(scanResult.results) do
                local ptrAddr = tonumber(tostring(r.address):gsub("^0[xX]", ""), 16)
                -- Exclude visited addresses and nearby addresses
                local excluded = false
                for _, excl in ipairs(excludeAddrs) do
                    if ptrAddr and math_abs(ptrAddr - excl) < 0x100 then
                        excluded = true
                        break
                    end
                end
                if not excluded and not visitedPointers[ptrAddr] then
                    table_insert(results, r)
                end
            end
            -- Prioritize static pointers
            table_sort(results, function(a, b)
                if a.isStatic and not b.isStatic then return true end
                if not a.isStatic and b.isStatic then return false end
                return false
            end)
        end
        return results
    end

    -- Helper: Quick check if an address has code accessing it (for candidate scoring)
    -- Single address version - kept for compatibility
    local function hasCodeAccess(addr, duration)
        duration = duration or 500  -- Quick check with short duration
        local result = nil
        local ok = pcall(function()
            result = findWhatImpl({
                address = Utils.formatHex(addr),
                size = 8,
                duration_ms = duration,
                max_records = 10
            }, bptAccess, "access")
        end)
        if ok and result and result.total_hits and result.total_hits > 0 then
            return true, result
        end
        return false, nil
    end

    -- Helper: Batch check multiple addresses for code access
    -- Uses sequential quick checks (more reliable than parallel breakpoints)
    -- Returns: table mapping address -> {hasAccess, hits}
    local function batchCheckCodeAccess(addresses, duration)
        duration = duration or 500
        local results = {}
        local quickDuration = math_floor(duration / math_min(#addresses, 4))  -- Split time among addresses
        quickDuration = math_max(quickDuration, 200)  -- Minimum 200ms per address

        for _, addr in ipairs(addresses) do
            local addrNum = type(addr) == "number" and addr or
                tonumber(tostring(addr):gsub("^0[xX]", ""), 16)
            if addrNum then
                local hasAccess = false
                local hits = 0
                local accessResult = nil

                -- Quick check using existing findWhatImpl
                local ok = pcall(function()
                    accessResult = findWhatImpl({
                        address = Utils.formatHex(addrNum),
                        size = 8,
                        duration_ms = quickDuration,
                        max_records = 5
                    }, bptAccess, "access")
                end)

                if ok and accessResult and accessResult.total_hits and accessResult.total_hits > 0 then
                    hasAccess = true
                    hits = accessResult.total_hits
                end

                results[addrNum] = {
                    hasAccess = hasAccess,
                    hits = hits
                }
            end
        end

        return results
    end

    -- Helper: Score candidates with batch access checking
    -- Checks up to 4 candidates for code access (hardware breakpoint limit)
    -- Selects candidates from different memory regions for better coverage
    local function scoreAndRankCandidates(pointers, targetAddr, checkDuration)
        checkDuration = checkDuration or 1000

        -- First pass: collect all candidates and group by memory region
        local candidates = {}
        local regionGroups = {}  -- Group by high bits of address (memory region)

        for _, ptr in ipairs(pointers) do
            local ptrAddr = tonumber(tostring(ptr.address):gsub("^0[xX]", ""), 16)
            if ptrAddr then
                local baseScore = 0

                -- Static pointers get highest priority - no need to check access
                if ptr.isStatic then
                    baseScore = 100000
                end

                local candidate = {
                    ptr = ptr,
                    addr = ptrAddr,
                    baseScore = baseScore,
                    score = baseScore,
                    hasAccess = false,
                    checked = ptr.isStatic  -- Static ones don't need access check
                }
                table_insert(candidates, candidate)

                -- Group by memory region (top 24 bits)
                if not ptr.isStatic then
                    local region = math_floor(ptrAddr / 0x1000000)
                    if not regionGroups[region] then
                        regionGroups[region] = {}
                    end
                    table_insert(regionGroups[region], candidate)
                end
            end
        end

        -- Select up to 4 candidates from different regions for access check
        local toCheck = {}
        local checkedRegions = {}

        -- First, pick one from each unique region
        for region, group in pairs(regionGroups) do
            if #toCheck < 4 and not checkedRegions[region] then
                table_insert(toCheck, group[1].addr)
                group[1].willCheck = true
                checkedRegions[region] = true
            end
        end

        -- If we have slots left, add more from largest groups
        if #toCheck < 4 then
            for _, candidate in ipairs(candidates) do
                if #toCheck >= 4 then break end
                if not candidate.checked and not candidate.willCheck then
                    table_insert(toCheck, candidate.addr)
                    candidate.willCheck = true
                end
            end
        end

        -- Check code access
        if #toCheck > 0 then
            local accessResults = batchCheckCodeAccess(toCheck, checkDuration)

            -- Update scores: addresses with code access get huge bonus
            for _, candidate in ipairs(candidates) do
                local accessInfo = accessResults[candidate.addr]
                if accessInfo then
                    candidate.checked = true
                    candidate.hasAccess = accessInfo.hasAccess
                    candidate.accessHits = accessInfo.hits
                    if accessInfo.hasAccess then
                        candidate.score = candidate.score + 50000  -- Huge bonus for active access
                    end
                end
            end
        end

        -- Sort by final score descending
        table_sort(candidates, function(a, b)
            return a.score > b.score
        end)

        return candidates
    end

    -- Helper: Score a candidate pointer for prioritization (kept for simple cases)
    -- Higher score = better candidate for tracing
    local function scoreCandidatePointer(ptr, targetAddr)
        local score = 0
        local ptrAddr = tonumber(tostring(ptr.address):gsub("^0[xX]", ""), 16)

        -- Static pointers get highest priority
        if ptr.isStatic then
            score = score + 100000
        end

        -- Addresses far from target are usually better (not in same struct)
        if ptrAddr then
            local distance = math_abs(ptrAddr - targetAddr)
            if distance > 0x10000 then
                score = score + 1000
            elseif distance > 0x1000 then
                score = score + 500
            elseif distance > 0x100 then
                score = score + 100
            end
        end

        return score
    end

    -- Helper: Try to find a valid path from a candidate address (with backtracking)
    -- Returns: success, steps, offsets, staticBase
    local function tryPathFromCandidate(candidateAddr, remainingDepth, localVisited, localOffsets)
        if remainingDepth <= 0 then
            return false, {}, {}, nil
        end

        -- Check if already visited in this path
        if localVisited[candidateAddr] then
            return false, {}, {}, nil
        end
        localVisited[candidateAddr] = true

        -- Check if this address is static
        local isStatic, symbol = isStaticAddress(candidateAddr)
        if isStatic then
            return true, {{
                level = 1,
                address = Utils.formatHex(candidateAddr),
                method = "static_found",
                isStatic = true,
                symbol = symbol
            }}, localOffsets, symbol
        end

        -- Try to find code accessing this address
        local hasAccess, accessResult = hasCodeAccess(candidateAddr, 1000)
        if hasAccess and accessResult.results and #accessResult.results > 0 then
            -- Found code accessing this address - good candidate!
            for _, entry in ipairs(accessResult.results) do
                local reg, offset = parseInstructionOffset(entry.instruction)
                if reg then
                    local regValue = getRegValue(entry.registers, reg)
                    if regValue then
                        local regValueNum = tonumber(tostring(regValue):gsub("^0[xX]", ""), 16)
                        if regValueNum and regValueNum ~= 0 then
                            -- Search for pointers storing this register value
                            local nextPointers = searchPointerToValue(regValueNum, {candidateAddr, regValueNum})

                            -- Try each next candidate
                            for _, nextPtr in ipairs(nextPointers) do
                                local nextAddr = tonumber(tostring(nextPtr.address):gsub("^0[xX]", ""), 16)
                                if nextAddr and not localVisited[nextAddr] then
                                    -- Record offset for this level
                                    local newOffsets = {}
                                    for _, o in ipairs(localOffsets) do table_insert(newOffsets, o) end
                                    table_insert(newOffsets, offset or 0)

                                    if nextPtr.isStatic then
                                        -- Found static base!
                                        return true, {{
                                            level = 1,
                                            address = Utils.formatHex(candidateAddr),
                                            method = "f5_then_value_scan",
                                            instruction = entry.instruction,
                                            register = reg,
                                            registerValue = regValue,
                                            offset = offset or 0,
                                            nextAddress = nextPtr.address,
                                            pointerFound = nextPtr.address,
                                            pointerSymbol = nextPtr.symbol,
                                            isStatic = true
                                        }}, newOffsets, nextPtr.symbol
                                    end

                                    -- Recursively try this path
                                    local success, subSteps, subOffsets, subBase = tryPathFromCandidate(
                                        nextAddr, remainingDepth - 1, localVisited, newOffsets
                                    )
                                    if success then
                                        -- Prepend current step
                                        local currentStep = {
                                            level = 1,
                                            address = Utils.formatHex(candidateAddr),
                                            method = "f5_then_value_scan",
                                            instruction = entry.instruction,
                                            register = reg,
                                            registerValue = regValue,
                                            offset = offset or 0,
                                            nextAddress = nextPtr.address,
                                            pointerFound = nextPtr.address,
                                            pointerSymbol = nextPtr.symbol,
                                            isStatic = false
                                        }
                                        local allSteps = {currentStep}
                                        for _, s in ipairs(subSteps) do
                                            s.level = s.level + 1
                                            table_insert(allSteps, s)
                                        end
                                        return true, allSteps, subOffsets, subBase
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end

        return false, {}, {}, nil
    end

    -- Helper: Monitor address and get access instructions
    local function monitorAddress(addr, size, duration)
        local result = nil
        local ok = pcall(function()
            result = findWhatImpl({
                address = Utils.formatHex(addr),
                size = size,
                duration_ms = duration,
                max_records = 200
            }, bptAccess, "access")
        end)
        return ok and result or nil
    end

    -- Main loop
    for depth = 1, maxDepth do
        local step = {
            level = depth,
            address = Utils.formatHex(currentAddr),
            method = nil,
            instruction = nil,
            register = nil,
            registerValue = nil,
            offset = nil,
            nextAddress = nil,
            isStatic = false,
            symbol = nil
        }

        -- Cycle detection
        if visitedAddresses[currentAddr] then
            step.error = "Cycle detected: address already visited"
            step.method = "cycle_detected"
            cycleDetected = true
            table_insert(suggestions, "Cycle detected at " .. Utils.formatHex(currentAddr) .. ". Try manual value_scan with different search parameters.")
            table_insert(steps, step)
            break
        end
        visitedAddresses[currentAddr] = true

        -- 1. Check if current address is already static
        local isStatic, symbol = isStaticAddress(currentAddr)
        if isStatic then
            step.isStatic = true
            step.symbol = symbol
            step.method = "static_found"
            staticBase = symbol
            foundStatic = true
            table_insert(steps, step)
            break
        end

        local foundNext = false

        -- 2. Method A: Try direct search for static pointer to current address (fast path)
        if strategy ~= "f5" then
            local staticPointers = searchPointerToValue(currentAddr, {currentAddr})
            for _, ptr in ipairs(staticPointers) do
                if ptr.isStatic then
                    step.method = "direct_static_pointer"
                    step.pointerFound = ptr.address
                    step.pointerSymbol = ptr.symbol
                    step.offset = 0
                    step.isStatic = true
                    staticBase = ptr.symbol or ptr.address
                    foundStatic = true
                    table_insert(offsets, 0)
                    table_insert(steps, step)
                    foundNext = true
                    break
                end
            end
        end

        if foundStatic then break end

        -- 3. Method B: Use find_what_accesses to monitor address (core improvement)
        if not foundNext and strategy ~= "value_scan" then
            local accessResult = monitorAddress(currentAddr, 4, durationPerLevel)

            if accessResult and accessResult.results and #accessResult.results > 0 then
                -- Select best instruction: prioritize those with offset, then by access count
                local bestEntry = nil
                local bestScore = -1

                for _, entry in ipairs(accessResult.results) do
                    local reg, offset = parseInstructionOffset(entry.instruction)
                    if reg then
                        local score = (entry.count or 1)
                        if offset and offset ~= 0 then
                            score = score + 10000  -- Boost score for instructions with offset
                        end
                        if score > bestScore then
                            bestScore = score
                            bestEntry = entry
                            bestEntry.parsedReg = reg
                            bestEntry.parsedOffset = offset or 0
                        end
                    end
                end

                if bestEntry then
                    step.method = "find_what_accesses"
                    step.instruction = bestEntry.instruction
                    step.instructionAddress = bestEntry.address
                    step.hitCount = bestEntry.count
                    step.register = bestEntry.parsedReg
                    step.offset = bestEntry.parsedOffset

                    local regValue = getRegValue(bestEntry.registers, bestEntry.parsedReg)
                    if regValue then
                        step.registerValue = regValue
                        local regValueNum = tonumber(tostring(regValue):gsub("^0[xX]", ""), 16)

                        if regValueNum and regValueNum ~= 0 then
                            -- Core improvement: use value_scan to search for register value
                            -- Correct flow: find register value → search for pointer storing that value → continue tracing

                            if strategy == "hybrid" or strategy == "value_scan" then
                                -- Search for pointers storing the register value
                                local pointers = searchPointerToValue(regValueNum, {currentAddr, regValueNum})

                                if #pointers > 0 then
                                    -- NEW: Batch parallel scoring using up to 4 hardware breakpoints
                                    local scoredCandidates = scoreAndRankCandidates(pointers, currentAddr, 800)

                                    step.candidatesFound = #scoredCandidates
                                    step.candidateScores = {}
                                    for i, c in ipairs(scoredCandidates) do
                                        if i <= 5 then  -- Log top 5 candidates
                                            table_insert(step.candidateScores, {
                                                address = c.ptr.address,
                                                score = c.score,
                                                isStatic = c.ptr.isStatic,
                                                hasAccess = c.hasAccess
                                            })
                                        end
                                    end

                                    -- Try candidates in order of score
                                    local selectedCandidate = nil
                                    for _, candidate in ipairs(scoredCandidates) do
                                        if candidate.ptr.isStatic then
                                            -- Static pointer found - best case!
                                            selectedCandidate = candidate
                                            break
                                        elseif candidate.hasAccess then
                                            -- Has code access - good candidate, use it
                                            selectedCandidate = candidate
                                            break
                                        end
                                    end

                                    -- Fallback: use first candidate if none have access
                                    if not selectedCandidate and #scoredCandidates > 0 then
                                        selectedCandidate = scoredCandidates[1]
                                        step.fallbackUsed = true
                                    end

                                    if selectedCandidate then
                                        local bestPtr = selectedCandidate.ptr
                                        local ptrAddr = selectedCandidate.addr

                                        step.method = "f5_then_value_scan"
                                        step.pointerFound = bestPtr.address
                                        step.pointerSymbol = bestPtr.symbol
                                        step.pointerIsStatic = bestPtr.isStatic
                                        step.nextAddress = bestPtr.address
                                        step.selectedScore = selectedCandidate.score
                                        step.hasCodeAccess = selectedCandidate.hasAccess

                                        table_insert(offsets, bestEntry.parsedOffset)
                                        visitedPointers[ptrAddr] = true

                                        if bestPtr.isStatic then
                                            -- Found static pointer, done!
                                            step.isStatic = true
                                            staticBase = bestPtr.symbol or bestPtr.address
                                            foundStatic = true
                                        else
                                            -- Continue tracing this pointer address
                                            currentAddr = ptrAddr
                                        end
                                        foundNext = true
                                    end
                                end

                                if not foundNext then
                                    -- value_scan found nothing, fallback to using register value directly
                                    step.method = "f5_direct"
                                    step.note = "value_scan found no pointers, using register value directly"
                                    step.nextAddress = Utils.formatHex(regValueNum)
                                    table_insert(offsets, bestEntry.parsedOffset)
                                    currentAddr = regValueNum
                                    foundNext = true
                                end
                            else
                                -- Pure F5 mode: use register value directly
                                step.method = "f5_direct"
                                step.nextAddress = Utils.formatHex(regValueNum)
                                table_insert(offsets, bestEntry.parsedOffset)
                                currentAddr = regValueNum
                                foundNext = true
                            end
                        end
                    end
                end
            end
        end

        -- 4. Method C: If monitoring failed, search for any pointer to current address
        if not foundNext then
            local pointers = searchPointerToValue(currentAddr, {currentAddr})

            if #pointers > 0 then
                -- Filter out nearby and visited addresses first
                local filteredPointers = {}
                for _, ptr in ipairs(pointers) do
                    local ptrAddr = tonumber(tostring(ptr.address):gsub("^0[xX]", ""), 16)
                    if ptrAddr and math_abs(ptrAddr - currentAddr) > 0x100 and not visitedAddresses[ptrAddr] then
                        table_insert(filteredPointers, ptr)
                    end
                end

                if #filteredPointers > 0 then
                    -- Use batch scoring for efficiency
                    local scoredCandidates = scoreAndRankCandidates(filteredPointers, currentAddr, 800)

                    -- Select best candidate (prefer those with code access)
                    for _, candidate in ipairs(scoredCandidates) do
                        local ptr = candidate.ptr
                        local ptrAddr = candidate.addr

                        step.method = "pointer_search_fallback"
                        step.pointerFound = ptr.address
                        step.pointerSymbol = ptr.symbol
                        step.offset = 0
                        step.nextAddress = ptr.address
                        step.hasCodeAccess = candidate.hasAccess
                        step.candidateScore = candidate.score
                        step.candidatesChecked = #scoredCandidates

                        table_insert(offsets, 0)
                        visitedPointers[ptrAddr] = true
                        currentAddr = ptrAddr
                        foundNext = true

                        if ptr.isStatic then
                            step.isStatic = true
                            staticBase = ptr.symbol or ptr.address
                            foundStatic = true
                        end
                        break
                    end
                end
            end

            if not foundNext then
                step.error = "No pointer path found at this level"
                table_insert(suggestions, string_format(
                    "Manual step: Use ce_value_scan to search for value %s, then continue tracing the found pointer address.",
                    Utils.formatHex(currentAddr)
                ))
            end
        end

        table_insert(steps, step)

        if not foundNext then
            break
        end

        if foundStatic then break end

        sleep(Config.POINTER_STEP_DELAY)  -- Configurable delay between steps
    end

    -- Reverse offsets array (from base to target order)
    local reversedOffsets = {}
    for i = #offsets, 1, -1 do
        table_insert(reversedOffsets, offsets[i])
    end
    offsets = reversedOffsets

    -- Build pointer path string
    local pointerPath = nil
    local ceNotation = nil

    if foundStatic and staticBase then
        -- pointer_path: "base+off1+off2"
        local parts = { staticBase }
        for _, off in ipairs(offsets) do
            table_insert(parts, string_format(off >= 0 and "+%X" or "-%X", math_abs(off)))
        end
        pointerPath = table_concat(parts, "")

        -- CE notation: [[base]+off1]+off2
        ceNotation = staticBase
        for _, off in ipairs(offsets) do
            ceNotation = string_format("[%s]%s%X", ceNotation, off >= 0 and "+" or "-", math_abs(off))
        end
    end

    -- Add suggestions if no static base found
    if not foundStatic and #suggestions == 0 then
        local lastStep = steps[#steps]
        if lastStep then
            if lastStep.registerValue then
                table_insert(suggestions, string_format(
                    "Try: ce_value_scan('%s', 'qword') to find pointers storing this register value",
                    lastStep.registerValue
                ))
            end
            if lastStep.nextAddress then
                table_insert(suggestions, string_format(
                    "Try: ce_find_what_accesses('%s') to continue tracing manually",
                    lastStep.nextAddress
                ))
            end
        end
    end

    return {
        success = foundStatic,
        target_address = Utils.formatHex(startAddr),
        base_address = staticBase,
        pointer_path = pointerPath,
        offsets = offsets,
        offsets_hex = (function()
            local t = {}
            for _, off in ipairs(offsets) do
                table_insert(t, string_format("0x%X", off))
            end
            return t
        end)(),
        depth = #steps,
        steps = steps,
        ce_pointer_notation = ceNotation,
        cycle_detected = cycleDetected,
        strategy_used = strategy,
        suggestions = #suggestions > 0 and suggestions or nil,
        partial_path = not foundStatic and #offsets > 0 and {
            last_address = steps[#steps] and steps[#steps].address or nil,
            offsets_so_far = offsets,
            message = "Partial path found. Use suggestions to continue manually."
        } or nil
    }
end


-- ============ Symbolic Trace Helpers (module-level for performance) ============

local SYM_REG_ALIASES = {
    eax = "rax", ax = "rax", al = "rax", ah = "rax",
    ebx = "rbx", bx = "rbx", bl = "rbx", bh = "rbx",
    ecx = "rcx", cx = "rcx", cl = "rcx", ch = "rcx",
    edx = "rdx", dx = "rdx", dl = "rdx", dh = "rdx",
    esi = "rsi", si = "rsi", sil = "rsi",
    edi = "rdi", di = "rdi", dil = "rdi",
    ebp = "rbp", bp = "rbp", bpl = "rbp",
    esp = "rsp", sp = "rsp", spl = "rsp",
    r8d = "r8", r8w = "r8", r8b = "r8",
    r9d = "r9", r9w = "r9", r9b = "r9",
    r10d = "r10", r10w = "r10", r10b = "r10",
    r11d = "r11", r11w = "r11", r11b = "r11",
    r12d = "r12", r12w = "r12", r12b = "r12",
    r13d = "r13", r13w = "r13", r13b = "r13",
    r14d = "r14", r14w = "r14", r14b = "r14",
    r15d = "r15", r15w = "r15", r15b = "r15"
}

local SYM_DEFAULT_SYMBOLS = {
    rcx = "arg0", rdx = "arg1", r8 = "arg2", r9 = "arg3",
    rsp = "rsp", rbp = "rbp"
}

local CMOV_OPS = {"cmove", "cmovne", "cmovz", "cmovnz", "cmovg", "cmovge",
                  "cmovl", "cmovle", "cmova", "cmovae", "cmovb", "cmovbe",
                  "cmovs", "cmovns"}

local function symCanonicalReg(reg)
    if not reg then return nil end
    reg = reg:lower():gsub("%s+", "")
    return SYM_REG_ALIASES[reg] or reg
end

-- ============ Handlers: Code Emulation ============
--[[
  Phase 1: ce_call_function - Call a function in target process
  Uses executeCodeEx to call functions with arguments
]]
Handlers.call_function = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})

    local funcAddr = Utils.safeGetAddress(p.address)
    local args = p.args or {}
    local timeout = p.timeout or 5000
    local returnType = p.return_type or "qword"

    -- Resolve argument values (can be numbers or address expressions)
    local resolvedArgs = {}
    for i, arg in ipairs(args) do
        if type(arg) == "string" then
            local resolved = getAddress(arg)
            if not resolved then
                error(string_format("Cannot resolve argument %d: %s", i, arg))
            end
            resolvedArgs[i] = resolved
        elseif type(arg) == "number" then
            resolvedArgs[i] = arg
        else
            error(string_format("Invalid argument %d type: %s", i, type(arg)))
        end
    end

    -- Pad to 4 arguments (x64 fastcall)
    while #resolvedArgs < 4 do
        table_insert(resolvedArgs, 0)
    end

    -- Execute function using CE's executeCodeEx.
    -- If call_method is explicitly provided, use new signature:
    --   executeCodeEx(callmethod, timeout, address, ...)
    -- If omitted, try old signature first for backward compatibility:
    --   executeCodeEx(timeout, address, ...)
    -- then fallback to new signature.
    local callMethod = p.call_method
    local ok, result = false, nil
    if callMethod ~= nil then
        ok, result = pcall(executeCodeEx, callMethod, timeout, funcAddr,
            resolvedArgs[1], resolvedArgs[2], resolvedArgs[3], resolvedArgs[4])
    else
        callMethod = 0
        ok, result = pcall(executeCodeEx, callMethod, timeout, funcAddr,
            resolvedArgs[1], resolvedArgs[2], resolvedArgs[3], resolvedArgs[4])
    end

    if not ok then
        error(tostring(result))
    end

    -- Format return value based on type
    local formattedResult = result
    if returnType == "float" then
        -- Reinterpret as float
        local bytes = {}
        local val = result
        for i = 1, 4 do
            bytes[i] = val % 256
            val = math_floor(val / 256)
        end
        formattedResult = byteTableToFloat(bytes)
    elseif returnType == "double" then
        -- Reinterpret as double
        local bytes = {}
        local val = result
        for i = 1, 8 do
            bytes[i] = val % 256
            val = math_floor(val / 256)
        end
        formattedResult = byteTableToDouble(bytes)
    elseif returnType == "pointer" then
        formattedResult = Utils.formatHex(result)
    end

    return {
        success = true,
        function_address = Utils.formatHex(funcAddr),
        return_value = result,
        return_value_hex = Utils.formatHex(result),
        return_value_formatted = formattedResult,
        return_type = returnType,
        args_passed = (function()
            local t = {}
            for i, v in ipairs(resolvedArgs) do
                if i <= #args then
                    t[i] = Utils.formatHex(v)
                end
            end
            return t
        end)()
    }
end

--[[
  Phase 2: ce_symbolic_trace - Lightweight symbolic execution
  Interprets instruction semantics without actual execution
  Produces human/AI-readable expressions
]]
Handlers.symbolic_trace = function(p)
    Utils.checkProcess()
    Utils.validateParams(p, {"address"})

    local startAddr = Utils.safeGetAddress(p.address)
    local count = math_min(p.count or 30, 200)
    local initialState = p.initial_state or {}
    local stopOnCall = p.stop_on_call ~= false
    local stopOnRet = p.stop_on_ret ~= false
    local simplify = p.simplify ~= false

    return Utils.withDisassembler(function(d)
        -- State: register -> value (number or string expression)
        local state = {}

        for reg, sym in pairs(SYM_DEFAULT_SYMBOLS) do
            state[reg] = sym
        end

        for reg, val in pairs(initialState) do
            state[reg:lower()] = val
        end

        local function resolve(operand)
            if not operand then return nil end
            operand = operand:gsub("^%s+", ""):gsub("%s+$", "")

            local canonReg = symCanonicalReg(operand)
            if state[canonReg] then
                return state[canonReg]
            end

            -- Check if it's a hex number
            local hexVal = operand:match("^([0-9A-Fa-f]+)$")
            if hexVal then
                local num = tonumber(hexVal, 16)
                if num then return num end
            end

            -- Check if it's a decimal number
            local decVal = tonumber(operand)
            if decVal then return decVal end

            -- Memory reference [...]
            local memRef = operand:match("^%[(.+)%]$")
            if memRef then
                return string_format("mem[%s]", resolve(memRef) or memRef)
            end

            -- Unknown - return as symbol
            return operand
        end

        -- Format value for output
        local function formatVal(val)
            if type(val) == "number" then
                if val >= 0 and val <= 0xFFFF then
                    return tostring(val)
                else
                    return string_format("0x%X", val)
                end
            end
            return tostring(val)
        end

        -- Simplify expression
        local function simplifyExpr(expr)
            if not simplify or type(expr) ~= "string" then return expr end

            -- x + 0 = x
            expr = expr:gsub("%(%s*([^()]+)%s*%+%s*0%s*%)", "%1")
            -- x - 0 = x
            expr = expr:gsub("%(%s*([^()]+)%s*%-%s*0%s*%)", "%1")
            -- x * 1 = x
            expr = expr:gsub("%(%s*([^()]+)%s*%*%s*1%s*%)", "%1")
            -- x ^ x = 0 (xor with self)
            expr = expr:gsub("%(%s*([%w_]+)%s*%^%s*%1%s*%)", "0")
            -- x & x = x
            expr = expr:gsub("%(%s*([%w_]+)%s*&%s*%1%s*%)", "%1")
            -- x | x = x
            expr = expr:gsub("%(%s*([%w_]+)%s*|%s*%1%s*%)", "%1")
            -- 0 + x = x
            expr = expr:gsub("%(%s*0%s*%+%s*([^()]+)%s*%)", "%1")

            return expr
        end

        -- Build expression for binary operation
        local function binOp(op, left, right)
            if type(left) == "number" and type(right) == "number" then
                if op == "+" then return left + right
                elseif op == "-" then return left - right
                elseif op == "*" then return left * right
                elseif op == "&" then return bit32 and bit32.band(left, right) or left
                elseif op == "|" then return bit32 and bit32.bor(left, right) or left
                elseif op == "^" then return bit32 and bit32.bxor(left, right) or left
                elseif op == "<<" then return bit32 and bit32.lshift(left, right) or left
                elseif op == ">>" then return bit32 and bit32.rshift(left, right) or left
                end
            end
            return simplifyExpr(string_format("(%s %s %s)", formatVal(left), op, formatVal(right)))
        end

        -- Instruction semantics interpreter
        local semantics = {}

        semantics["mov"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                state[dstReg] = resolve(src)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return string_format("%s = %s", dst, formatVal(resolve(src)))
        end

        semantics["movzx"] = function(dst, src)
            return semantics["mov"](dst, src)
        end

        semantics["movsxd"] = function(dst, src)
            return semantics["mov"](dst, src)
        end

        semantics["lea"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            -- LEA computes address, not dereference
            local memRef = src:match("^%[(.+)%]$")
            if memRef and dstReg then
                -- Parse address expression: [base + index*scale + disp]
                local expr = memRef
                -- Simple case: [reg + offset]
                local base, op, offset = expr:match("^(%w+)%s*([%+%-])%s*([0-9A-Fa-fx]+)$")
                if base then
                    local baseVal = resolve(base)
                    local offVal = tonumber(offset, 16) or tonumber(offset) or 0
                    if op == "-" then offVal = -offVal end
                    state[dstReg] = binOp("+", baseVal, offVal)
                else
                    -- Complex expression - just store symbolically
                    state[dstReg] = string_format("&[%s]", expr)
                end
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["add"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                local srcVal = resolve(src)
                state[dstReg] = binOp("+", dstVal, srcVal)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["sub"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                local srcVal = resolve(src)
                state[dstReg] = binOp("-", dstVal, srcVal)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["xor"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            local srcReg = symCanonicalReg(src)
            if dstReg then
                if dstReg == srcReg then
                    state[dstReg] = 0
                else
                    local dstVal = state[dstReg] or dst
                    local srcVal = resolve(src)
                    state[dstReg] = binOp("^", dstVal, srcVal)
                end
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["and"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                local srcVal = resolve(src)
                state[dstReg] = binOp("&", dstVal, srcVal)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["or"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                local srcVal = resolve(src)
                state[dstReg] = binOp("|", dstVal, srcVal)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["shl"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                local srcVal = resolve(src)
                state[dstReg] = binOp("<<", dstVal, srcVal)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["shr"] = function(dst, src)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                local srcVal = resolve(src)
                state[dstReg] = binOp(">>", dstVal, srcVal)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["imul"] = function(dst, src, src2)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local srcVal = resolve(src)
                if src2 then
                    -- imul dst, src, imm
                    local immVal = resolve(src2)
                    state[dstReg] = binOp("*", srcVal, immVal)
                else
                    -- imul dst, src
                    local dstVal = state[dstReg] or dst
                    state[dstReg] = binOp("*", dstVal, srcVal)
                end
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["inc"] = function(dst)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                state[dstReg] = binOp("+", dstVal, 1)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["dec"] = function(dst)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                state[dstReg] = binOp("-", dstVal, 1)
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["neg"] = function(dst)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                state[dstReg] = string_format("(-%s)", formatVal(dstVal))
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["not"] = function(dst)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                local dstVal = state[dstReg] or dst
                state[dstReg] = string_format("(~%s)", formatVal(dstVal))
                return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
            end
            return nil
        end

        semantics["push"] = function(src)
            local srcVal = resolve(src)
            return string_format("push %s", formatVal(srcVal))
        end

        semantics["pop"] = function(dst)
            local dstReg = symCanonicalReg(dst)
            if dstReg then
                state[dstReg] = string_format("stack_pop_%s", dstReg)
                return string_format("%s = pop()", dstReg)
            end
            return nil
        end

        semantics["cmp"] = function(dst, src)
            local dstVal = resolve(dst)
            local srcVal = resolve(src)
            return string_format("cmp(%s, %s)", formatVal(dstVal), formatVal(srcVal))
        end

        semantics["test"] = function(dst, src)
            local dstVal = resolve(dst)
            local srcVal = resolve(src)
            return string_format("test(%s, %s)", formatVal(dstVal), formatVal(srcVal))
        end

        for _, op in ipairs(CMOV_OPS) do
            semantics[op] = function(dst, src)
                local dstReg = symCanonicalReg(dst)
                if dstReg then
                    local srcVal = resolve(src)
                    local cond = op:sub(5)  -- Extract condition
                    state[dstReg] = string_format("(%s if %s else %s)",
                        formatVal(srcVal), cond, formatVal(state[dstReg] or dstReg))
                    return string_format("%s = %s", dstReg, formatVal(state[dstReg]))
                end
                return nil
            end
        end

        -- Trace execution
        local trace = {}
        local currentAddr = startAddr
        local stopReason = nil

        for i = 1, count do
            d.disassemble(currentAddr)
            local data = d.LastDisassembleData
            local instrText = data.opcode .. " " .. (data.parameters or "")
            instrText = instrText:gsub("%s+$", "")

            local entry = {
                address = Utils.formatHex(currentAddr),
                instruction = instrText,
                effect = nil
            }

            -- Parse instruction
            local mnemonic = data.opcode:lower()
            if mnemonic then

                -- Check for stop conditions
                if mnemonic == "ret" and stopOnRet then
                    entry.effect = "return"
                    stopReason = "ret"
                    table_insert(trace, entry)
                    break
                end

                if mnemonic == "call" and stopOnCall then
                    local target = instrText:match("call%s+(.+)")
                    entry.effect = string_format("call %s", target or "?")
                    stopReason = "call"
                    table_insert(trace, entry)
                    break
                end

                -- Parse operands
                local operands = instrText:match("^%S+%s+(.+)$")
                local dst, src, src2 = nil, nil, nil
                if operands then
                    -- Split by comma, handling memory references with commas inside brackets
                    local parts = {}
                    local current = ""
                    local bracketDepth = 0
                    for c in operands:gmatch(".") do
                        if c == "[" then bracketDepth = bracketDepth + 1
                        elseif c == "]" then bracketDepth = bracketDepth - 1
                        elseif c == "," and bracketDepth == 0 then
                            local trimmed = current:gsub("^%s+", ""):gsub("%s+$", "")
                            table_insert(parts, trimmed)
                            current = ""
                            goto continue_parse
                        end
                        current = current .. c
                        ::continue_parse::
                    end
                    if #current > 0 then
                        local trimmed = current:gsub("^%s+", ""):gsub("%s+$", "")
                        table_insert(parts, trimmed)
                    end

                    dst = parts[1]
                    src = parts[2]
                    src2 = parts[3]
                end

                -- Execute semantic handler
                local handler = semantics[mnemonic]
                if handler then
                    local effect = handler(dst, src, src2)
                    entry.effect = effect
                end

                -- Handle jumps (just note them, don't follow)
                if mnemonic:match("^j") then
                    local target = instrText:match("^%S+%s+(.+)")
                    entry.effect = string_format("jump %s (not followed)", target or "?")
                end
            end

            table_insert(trace, entry)

            -- Move to next instruction
            currentAddr = currentAddr + #data.bytes
        end

        -- Build final state summary
        local finalState = {}
        for reg, val in pairs(state) do
            if type(val) ~= "string" or not val:match("^" .. reg .. "$") then
                finalState[reg] = formatVal(val)
            end
        end

        return {
            start_address = Utils.formatHex(startAddr),
            instructions_traced = #trace,
            stop_reason = stopReason or "count_reached",
            trace = trace,
            final_state = finalState,
            initial_state = (function()
                local t = {}
                for k, v in pairs(initialState) do
                    t[k] = formatVal(v)
                end
                return t
            end)()
        }
    end)
end

-- ============ New Tool Handlers ============

Handlers.allocate_memory = function(p)
    Utils.checkProcess()
    local size = tonumber(p.size)
    if not size or size <= 0 then
        error("Invalid size")
    end
    local baseAddr = p.base_address and Utils.safeGetAddress(p.base_address) or nil
    local protStr = p.protection or "rw"
    local prot = 0x40 -- PAGE_EXECUTE_READWRITE default
    if protStr:find("r") and protStr:find("w") and not protStr:find("x") then
        prot = 0x04 -- PAGE_READWRITE
    elseif protStr:find("r") and not protStr:find("w") and not protStr:find("x") then
        prot = 0x02 -- PAGE_READONLY
    elseif protStr:find("x") then
        prot = 0x40 -- PAGE_EXECUTE_READWRITE
    end

    local ok, addr = pcall(allocateMemory, size, baseAddr or nil, prot)
    if ok and addr and addr ~= 0 then
        return {
            success = true,
            address = Utils.formatHex(addr),
            size = size
        }
    end
    error("Failed to allocate memory")
end

Handlers.deallocate_memory = function(p)
    Utils.checkProcess()
    local addr = Utils.safeGetAddress(p.address)
    if not addr then
        error("Invalid address")
    end
    local size = tonumber(p.size) or 0
    local ok, err = pcall(deAlloc, addr, size ~= 0 and size or nil)
    if ok then
        return { success = true, address = Utils.formatHex(addr) }
    end
    error(tostring(err))
end

Handlers.get_memory_protection = function(p)
    Utils.checkProcess()
    local addr = Utils.safeGetAddress(p.address)
    if not addr then
        error("Invalid address")
    end
    local ok, prot = pcall(getMemoryProtection, addr)
    if ok and prot then
        return {
            address = Utils.formatHex(addr),
            protection = {
                r = prot.r or false,
                w = prot.w or false,
                x = prot.x or false,
            }
        }
    end
    error("Failed to get memory protection")
end

Handlers.set_memory_protection = function(p)
    Utils.checkProcess()
    local addr = Utils.safeGetAddress(p.address)
    if not addr then
        error("Invalid address")
    end
    local size = tonumber(p.size)
    if not size or size <= 0 then
        error("Invalid size")
    end
    local readable = p.readable ~= false
    local writable = p.writable ~= false
    local executable = p.executable == true

    local ok, err = pcall(setMemoryProtection, addr, size, {
        r = readable,
        w = writable,
        x = executable
    })
    if ok then
        return {
            success = true,
            address = Utils.formatHex(addr),
            protection = { r = readable, w = writable, x = executable }
        }
    end
    error(tostring(err))
end

Handlers.copy_memory = function(p)
    Utils.checkProcess()
    local srcAddr = Utils.safeGetAddress(p.source_address)
    if not srcAddr then
        error("Invalid source address")
    end
    local size = tonumber(p.size)
    if not size or size <= 0 then
        error("Invalid size")
    end
    local method = tonumber(p.method) or 0
    local dstAddr = p.destination_address and Utils.safeGetAddress(p.destination_address) or nil

    local ok, result = pcall(copyMemory, srcAddr, size, dstAddr or nil, method)
    if ok and result then
        return {
            success = true,
            source = Utils.formatHex(srcAddr),
            destination = Utils.formatHex(result),
            size = size,
            method = method
        }
    end
    error("Copy failed")
end

Handlers.compare_memory = function(p)
    Utils.checkProcess()
    local addr1 = Utils.safeGetAddress(p.address1)
    if not addr1 then error("Invalid address1") end
    local addr2 = Utils.safeGetAddress(p.address2)
    if not addr2 then error("Invalid address2") end
    local size = tonumber(p.size)
    if not size or size <= 0 then error("Invalid size") end
    local method = tonumber(p.method) or 0

    local ok, result, diffIdx = pcall(compareMemory, addr1, addr2, size, method)
    if ok then
        return {
            match = result == true,
            firstDifferenceOffset = diffIdx or nil
        }
    end
    error("Compare failed")
end

Handlers.enum_memory_regions = function(p)
    local ok, regions = pcall(enumMemoryRegions)
    if not ok then
        error("Failed to enumerate memory regions")
    end
    local result = {}
    local count = 0
    if regions then
        for i, r in ipairs(regions) do
            count = count + 1
            table_insert(result, {
                baseAddress = Utils.formatHex(r.BaseAddress or 0),
                allocationBase = Utils.formatHex(r.AllocationBase or 0),
                allocationProtect = r.AllocationProtect or 0,
                regionSize = r.RegionSize or 0,
                state = r.State or 0,
                protect = r.Protect or 0,
                type = r.Type or 0,
            })
        end
    end
    return { count = count, regions = result }
end

Handlers.register_symbol = function(p)
    Utils.checkProcess()
    local symbolName = p.symbol
    if not symbolName or symbolName == "" then
        error("Symbol name required")
    end
    local addr = Utils.safeGetAddress(p.address)
    if not addr then
        error("Invalid address")
    end
    local doNotSave = p.do_not_save == true
    local ok, err = pcall(registerSymbol, symbolName, addr, doNotSave)
    if ok then
        return {
            success = true,
            symbol = symbolName,
            address = Utils.formatHex(addr)
        }
    end
    error(tostring(err))
end

Handlers.unregister_symbol = function(p)
    Utils.checkProcess()
    local symbolName = p.symbol
    if not symbolName or symbolName == "" then
        error("Symbol name required")
    end
    local ok, err = pcall(unregisterSymbol, symbolName)
    if ok then
        return { success = true, symbol = symbolName }
    end
    error(tostring(err))
end

Handlers.write_memory_batch = function(p)
    Utils.checkProcess()
    local requests = p.requests
    if not requests or #requests == 0 then
        error("No write requests provided")
    end
    if #requests > 100 then
        error("Too many requests (max 100)")
    end

    local results = {}
    for i, req in ipairs(requests) do
        local addr = Utils.safeGetAddress(req.address)
        if not addr then
            table_insert(results, { address = req.address, success = false, error = "Invalid address" })
            goto continue_write_batch
        end

        local vtype = req.type or "dword"
        local vt = ValueTypeMap[vtype]
        if not vt then
            table_insert(results, { address = req.address, success = false, error = "Invalid type" })
            goto continue_write_batch
        end

        local ok, err
        if vtype == "byte" then
            ok, err = pcall(writeBytes, addr, tonumber(req.value))
        elseif vtype == "word" then
            ok, err = pcall(writeSmallInteger, addr, tonumber(req.value))
        elseif vtype == "dword" then
            ok, err = pcall(writeInteger, addr, tonumber(req.value))
        elseif vtype == "qword" then
            ok, err = pcall(writeQword, addr, tonumber(req.value))
        elseif vtype == "float" then
            ok, err = pcall(writeFloat, addr, tonumber(req.value))
        elseif vtype == "double" then
            ok, err = pcall(writeDouble, addr, tonumber(req.value))
        elseif vtype == "string" then
            ok, err = pcall(writeString, addr, tostring(req.value))
        elseif vtype == "bytes" then
            local bytes = {}
            for b in tostring(req.value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            ok, err = pcall(writeBytes, addr, table_unpack(bytes))
        else
            ok = false
            err = "Unsupported type"
        end

        table_insert(results, {
            address = Utils.formatHex(addr),
            success = ok and err ~= false,
            error = (not ok) and tostring(err) or nil
        })
        ::continue_write_batch::
    end
    return { results = results }
end

Handlers.pause_process = function(p)
    Utils.checkProcess()
    local wasPaused = false
    pcall(function() wasPaused = debug_isBroken() or false end)
    local ok, err = pcall(pause)
    if ok then
        return { success = true, wasPaused = wasPaused }
    end
    error(tostring(err))
end

Handlers.resume_process = function(p)
    Utils.checkProcess()
    local wasPaused = false
    pcall(function() wasPaused = debug_isBroken() or false end)
    local ok, err = pcall(unpause)
    if ok then
        return { success = true, wasPaused = wasPaused }
    end
    error(tostring(err))
end

Handlers.speedhack = function(p)
    Utils.checkProcess()
    local speed = tonumber(p.speed)
    if not speed or speed <= 0 then
        error("Invalid speed (must be > 0)")
    end
    local wasEnabled = false
    pcall(function() wasEnabled = (speedhack_getSpeed() ~= 1.0) end)
    local ok, err = pcall(speedhack_setSpeed, speed)
    if ok then
        return {
            success = true,
            speed = speed,
            wasEnabled = wasEnabled
        }
    end
    error(tostring(err))
end

Handlers.enum_threads = function(p)
    Utils.checkProcess()
    local list = createStringlist()
    local ok = pcall(getThreadlist, list)
    if not ok then
        list:destroy()
        error("Failed to enumerate threads")
    end
    local threads = {}
    for i = 0, list.getCount() - 1 do
        local line = list.getString(i)
        local id = tonumber(line:match("(%x+)") or "0", 16)
        if id and id > 0 then
            table_insert(threads, { id = id })
        end
    end
    list:destroy()
    return { count = #threads, threads = threads }
end

Handlers.enum_handles = function(p)
    Utils.checkProcess()
    local filter = tonumber(p.filter) or 2
    local ok, handles = pcall(getHandleList, filter)
    if not ok then
        error("Failed to enumerate handles")
    end
    local result = {}
    if handles then
        for i, h in ipairs(handles) do
            table_insert(result, {
                processID = h.ProcessID or 0,
                objectTypeIndex = h.ObjectTypeIndex or 0,
                handleAttributes = h.HandleAttributes or 0,
                handleValue = h.HandleValue or 0,
                object = h.Object or 0,
                grantedAccess = h.GrantedAccess or 0,
            })
        end
    end
    return { count = #result, handles = result }
end

Handlers.inject_dll = function(p)
    Utils.checkProcess()
    local dllPath = p.dll_path
    if not dllPath or dllPath == "" then
        error("DLL path required")
    end
    local skipReload = p.skip_symbol_reload == true
    local ok, result = pcall(injectDLL, dllPath, skipReload)
    if ok and result then
        return { success = true, dllPath = dllPath }
    end
    error("DLL injection failed: " .. tostring(result))
end

Handlers.inject_dotnet_dll = function(p)
    Utils.checkProcess()
    local dllPath = p.dll_path
    if not dllPath or dllPath == "" then
        error("DLL path required")
    end
    local className = p.class_name or ""
    local methodName = p.method_name or ""
    local parameters = p.parameters or ""
    local timeout = tonumber(p.timeout) or 30000

    local ok, result = pcall(injectDotNetDLL, dllPath, className, methodName, parameters, timeout)
    if ok then
        return {
            success = true,
            returnValue = result,
            dllPath = dllPath,
            className = className,
            methodName = methodName
        }
    end
    error("DotNet DLL injection failed: " .. tostring(result))
end

Handlers.compile_c_code = function(p)
    local code = p.code
    if not code or code == "" then
        error("C code required")
    end
    local addr = p.address and Utils.safeGetAddress(p.address) or nil
    local targetSelf = p.target_self == true

    local ok, symbols, err
    if addr then
        ok, symbols, err = pcall(compile, code, addr, targetSelf)
    else
        ok, symbols, err = pcall(compile, code, nil, targetSelf)
    end

    if ok and symbols then
        local symResult = {}
        for name, address in pairs(symbols) do
            symResult[name] = Utils.formatHex(address)
        end
        return { success = true, symbols = symResult }
    end
    error("Compilation failed: " .. tostring(err or "unknown"))
end

Handlers.load_table = function(p)
    local filename = p.filename
    if not filename or filename == "" then
        error("Filename required")
    end
    local merge = p.merge == true
    local ok, err = pcall(loadTable, filename, merge)
    if ok then
        return { success = true, filename = filename, merged = merge }
    end
    error("Failed to load table: " .. tostring(err))
end

Handlers.save_table = function(p)
    local filename = p.filename
    if not filename or filename == "" then
        error("Filename required")
    end
    local protect = p.protect == true
    local ok, err = pcall(saveTable, filename, protect)
    if ok then
        return { success = true, filename = filename }
    end
    error("Failed to save table: " .. tostring(err))
end

-- New tool handlers for second phase enhancement
Handlers.aob_scan_unique = function(p)
    Utils.checkProcess()
    local aobString = p.aob_string
    if not aobString then
        error("aob_string required")
    end

    local cleanAob = string_gsub(aobString, "%s+", " ")
    cleanAob = string_gsub(cleanAob, "^%s*(.-)%s*$", "%1")
    local protection = p.protection or "-C+X"

    local startAddr, stopAddr = nil, nil
    if p.module then
        local m = Utils.findModule(p.module)
        if m then
            startAddr = m.Address
            stopAddr = m.Address + (m.Size or getModuleSize(m.Name) or 0)
        else
            error("Module not found: " .. p.module)
        end
    elseif p.start then
        startAddr = Utils.safeGetAddress(p.start, "aob_scan_unique")
        if p.stop then
            stopAddr = Utils.safeGetAddress(p.stop, "aob_scan_unique")
        end
    end

    if startAddr and stopAddr then
        local memscan = createMemScan()
        local foundList = createFoundList(memscan)
        local scanOk = false
        pcall(function()
            memscan.firstScan(
                soExactValue or 1, vtByteArray or 7, rtRounded or 0,
                cleanAob, "",
                startAddr, stopAddr,
                protection, fsmNotAligned or 0, "",
                true, false, false, false
            )
            memscan.waitTillDone()
            scanOk = true
        end)
        if not scanOk then
            pcall(function() foundList.deinitialize() end)
            pcall(function() memscan.destroy() end)
            return { found = false }
        end
        foundList.initialize()
        local count = foundList.Count or 0
        if count > 0 then
            local addr = foundList.getAddress(0)
            pcall(function() foundList.deinitialize() end)
            pcall(function() memscan.destroy() end)
            return { found = true, address = Utils.formatHex(addr) }
        end
        pcall(function() foundList.deinitialize() end)
        pcall(function() memscan.destroy() end)
        return { found = false }
    end

    local ok, result = pcall(AOBScanUnique, cleanAob, protection)
    if ok and result then
        return { found = true, address = Utils.formatHex(result) }
    end
    return { found = false }
end

Handlers.check_assemble = function(p)
    Utils.checkProcess()
    local script = p.script
    if not script then
        error("script required")
    end

    local valid = false
    local errMsg = ""
    local enable = p.enable ~= false
    local targetSelf = p.target_self or false
    local ok, result = pcall(function()
        return autoAssembleCheck(script, enable, targetSelf)
    end)

    if ok then
        valid = result == true
        if not valid then
            errMsg = type(result) == "string" and result or "Validation failed"
        end
    else
        errMsg = tostring(result)
    end

    return { valid = valid, error_message = errMsg }
end

Handlers.generate_script = function(p)
    local template = p.template
    if not template then
        error("template required")
    end

    local templates = {
        globalalloc = function(p)
            local name = p.name or "myMemory"
            local size = p.size or 1024
            return string_format([[
globalalloc(%s, %d)

[%s]
// your code here
]], name, size, name)
        end,
        alloc = function(p)
            local name = p.name or "myAlloc"
            local size = p.size or 1024
            return string_format([[
alloc(%s, %d)

[%s]
// your code here
]], name, size, name)
        end,
        writebytes = function(p)
            local address = p.address
            local value = p.value
            if not address then
                error("address required for writebytes template")
            end
            return string_format([[
define(address,%s)
define(bytes,%s)

// write bytes to address
writebytes(address, bytes)
]], address, value or "?? ?? ?? ??")
        end,
        registersymbol = function(p)
            local name = p.name or "mySymbol"
            local address = p.address
            if not address then
                error("address required for registersymbol template")
            end
            return string_format([[
define(%s,%s)
registersymbol(%s)
]], name, address, name)
        end,
        createalloc = function(p)
            local name = p.name or "myAlloc"
            local size = p.size or 1024
            return string_format([[
define(%s)
alloc(%s, %d)

[%s]
// your code here
]], name, name, size, name)
        end,
    }

    local templateFunc = templates[template]
    if not templateFunc then
        error("Unknown template: " .. template)
    end

    local script = templateFunc(p)
    return { script = script, template = template, usage_hint = "Use this script as a starting point for your modifications" }
end

Handlers.memory_record_control = function(p)
    Utils.checkProcess()
    local recordId = p.record_id
    local active = p.active
    if not recordId then
        error("record_id required")
    end
    if active == nil then
        error("active required (true/false)")
    end

    local addressList = getAddressList()
    if not addressList then
        error("No address list available")
    end

    local record = addressList.getMemoryRecordByID(tonumber(recordId))
    if not record then
        error("Record not found: " .. tostring(recordId))
    end

    record.Active = active
    return { success = true, record_id = recordId, active = active }
end

Handlers.rip_scan = function(p)
    Utils.checkProcess()
    local address = p.address
    local scanRange = p.scan_range or 50

    if not address then
        error("address required")
    end

    local addr = Utils.safeGetAddress(address, "rip_scan")

    local startAddr, stopAddr = nil, nil
    if p.module then
        local m = Utils.findModule(p.module)
        if m then
            startAddr = m.Address
            stopAddr = m.Address + (m.Size or getModuleSize(m.Name) or 0)
            if addr < startAddr or addr >= stopAddr then
                error("Address is outside the specified module range")
            end
        end
    end

    local results = {}
    local count = 0
    local currentAddr = addr
    local scanEnd = stopAddr or (addr + scanRange * 15)

    local disassembler = createDisassembler()
    local maxBytes = scanRange * 15

    for i = 1, scanRange do
        if currentAddr >= scanEnd then break end

        local ok, instr = pcall(function()
            disassembler.disassemble(currentAddr)
            return getLastDisassembleData()
        end)

        if not ok or not instr then break end

        local params = instr.parameters or ""
        if string_find(params, "rip", 1, true) then
            local ripOffset = nil
            local targetAddr = nil
            pcall(function()
                local offsetStr = params:match("%[rip%+([^%]]+)%]") or params:match("%[rip%-([^%]]+)%]")
                if offsetStr then
                    local offsetVal = tonumber(offsetStr, 16) or tonumber(offsetStr)
                    if offsetVal then
                        if params:match("%[rip%-") then
                            ripOffset = -offsetVal
                        else
                            ripOffset = offsetVal
                        end
                    end
                end
            end)
            pcall(function()
                if ripOffset then
                    local instrSize = instr.OpcodeSize or instr.size or 0
                    if instrSize > 0 then
                        targetAddr = Utils.formatHex(currentAddr + instrSize + ripOffset)
                    end
                end
            end)

            table_insert(results, {
                address = Utils.formatHex(currentAddr),
                instruction = (instr.opcode or "") .. " " .. params,
                offset = ripOffset and string_format("0x%X", ripOffset > 0 and ripOffset or -ripOffset) or "unknown",
                target_address = targetAddr or "unknown"
            })
            count = count + 1
        end

        local nextAddr = nil
        pcall(function()
            nextAddr = currentAddr + (instr.OpcodeSize or instr.size or 1)
        end)
        if not nextAddr or nextAddr <= currentAddr then break end
        currentAddr = nextAddr
    end

    pcall(function() disassembler.destroy() end)
    return { count = count, references = results }
end

Handlers.pointer_size = function(p)
    Utils.checkProcess()
    local ps = targetIs64Bit() and 8 or 4

    if p.size then
        local size = tonumber(p.size)
        if size ~= 4 and size ~= 8 then
            error("Pointer size must be 4 or 8")
        end
        local previousSize = ps
        pcall(function() setPointerSize(size) end)
        return { pointerSize = size, previousSize = previousSize }
    end

    return { pointerSize = ps }
end

Handlers.symbol_control = function(p)
    Utils.checkProcess()
    local operation = p.operation
    if not operation then
        error("operation required")
    end

    local ops = {
        wait_dotnet = function()
            pcall(function() waitForDotNet() end)
            return { success = true, operation = operation, result = "DotNet symbols loaded" }
        end,
        wait_pdb = function()
            pcall(function() waitForPDB() end)
            return { success = true, operation = operation, result = "PDB symbols loaded" }
        end,
        wait_exports = function()
            pcall(function() waitForExports() end)
            return { success = true, operation = operation, result = "Exports loaded" }
        end,
        reinit_dotnet = function()
            local mod = p.module
            pcall(function() reinitDotNet(mod) end)
            return { success = true, operation = operation, result = "DotNet reinitialized" }
        end,
        enable_windows = function()
            pcall(function() loadWindowsSymbols() end)
            return { success = true, operation = operation, result = "Windows PDB loading enabled" }
        end,
        load_new = function()
            pcall(function() loadModuleSymbols() end)
            return { success = true, operation = operation, result = "New module symbols loaded" }
        end,
        done = function()
            local isDone = false
            pcall(function() isDone = symbolLoadingDone() end)
            return { success = true, operation = operation, result = isDone and "done" or "still_loading" }
        end,
    }

    local opFunc = ops[operation]
    if not opFunc then
        error("Unknown operation: " .. operation)
    end

    return opFunc()
end

Handlers.get_rtti = function(p)
    Utils.checkProcess()
    local address = p.address
    if not address then
        error("address required")
    end

    local addr = Utils.safeGetAddress(address, "get_rtti")

    local className = nil
    local ok, name = pcall(function()
        return getRTTIClassName(addr)
    end)

    if ok and name and name ~= "" then
        className = name
    end

    return {
        address = Utils.formatHex(addr),
        className = className or "",
        hasRTTI = className ~= nil and className ~= ""
    }
end

Handlers.comment = function(p)
    Utils.checkProcess()
    local address = p.address
    if not address then
        error("address required")
    end

    local addr = Utils.safeGetAddress(address, "comment")

    if p.text then
        local ok, err = pcall(function()
            setComment(addr, p.text)
        end)
        if not ok then
            error("Failed to set comment: " .. tostring(err))
        end
        return { success = true, address = Utils.formatHex(addr), comment = p.text }
    else
        local comment = nil
        local ok = pcall(function()
            comment = getComment(addr)
        end)
        return { address = Utils.formatHex(addr), comment = comment or "" }
    end
end

Handlers.enum_symbols = function(p)
    Utils.checkProcess()
    local operation = p.operation
    if not operation then
        error("operation required")
    end

    if operation == "registered" then
        local symbols = {}
        local ok, enumResult = pcall(function()
            return enumRegisteredSymbols()
        end)
        if ok and enumResult then
            for i, s in ipairs(enumResult) do
                table_insert(symbols, {
                    name = s.name or s.Name or s.symbolname or "",
                    address = Utils.formatHex(s.address or s.Address or 0),
                    size = s.size or s.Size or 0,
                })
            end
        end
        return { operation = operation, symbols = symbols }
    elseif operation == "pdb_struct" then
        local structName = p.structure_name
        if not structName then
            error("structure_name required for pdb_struct")
        end
        local elements = {}
        local ok, structResult = pcall(function()
            return getPDBStructureElements(structName)
        end)
        if ok and structResult then
            for i, e in ipairs(structResult) do
                table_insert(elements, {
                    offset = e.offset or e.Offset or 0,
                    name = e.name or e.Name or "",
                    vartype = e.vartype or e.VarType or "",
                })
            end
        end
        return { operation = operation, elements = elements }
    end

    error("Unknown operation: " .. operation)
end

Handlers.full_access = function(p)
    Utils.checkProcess()
    local address = p.address
    local size = p.size
    if not address then
        error("address required")
    end
    if not size then
        error("size required")
    end

    local addr = Utils.safeGetAddress(address, "full_access")
    size = tonumber(size)

    local ok, result = pcall(function()
        return fullAccess(addr, size)
    end)

    if not ok then
        error("Failed to set full access: " .. tostring(result))
    end

    return {
        success = result ~= false,
        address = Utils.formatHex(addr),
        protection = { r = true, w = true, x = true }
    }
end

Handlers.dump_memory = function(p)
    Utils.checkProcess()
    local address = p.address
    local size = p.size
    local filePath = p.file_path
    local mode = p.mode

    if not address or not size or not filePath or not mode then
        error("address, size, file_path, and mode required")
    end

    local addr = Utils.safeGetAddress(address, "dump_memory")
    size = tonumber(size)

    if mode == "dump" then
        local ok, err = pcall(function()
            local dataTable = readBytes(addr, size, true)
            if dataTable then
                local file = io.open(filePath, "wb")
                if file then
                    -- Convert table to string
                    local dataStr = string_char(table_unpack(dataTable))
                    file:write(dataStr)
                    file:close()
                else
                    error("Cannot open file for writing")
                end
            else
                error("Cannot read memory")
            end
        end)
        if not ok then
            error("Dump failed: " .. tostring(err))
        end
        local checksum = nil
        pcall(function()
            checksum = md5memory(addr, size)
        end)
        return { success = true, file_path = filePath, checksum = checksum }

    elseif mode == "load" then
        local ok, err = pcall(function()
            local file = io.open(filePath, "rb")
            if not file then error("Cannot open file for reading") end
            local data = file:read("*a")
            file:close()
            if #data ~= size then
                error("File size mismatch: expected " .. size .. ", got " .. #data)
            end
            writeBytes(addr, data)
        end)
        if not ok then
            error("Load failed: " .. tostring(err))
        end
        return { success = true, file_path = filePath }

    elseif mode == "compare" then
        local fileData = nil
        local ok, err = pcall(function()
            local file = io.open(filePath, "rb")
            if not file then error("Cannot open file") end
            fileData = file:read("*a")
            file:close()
        end)
        if not ok then
            error("Compare failed: " .. tostring(err))
        end
        local memData = nil
        pcall(function()
            memData = readBytes(addr, size, true)
        end)
        if not memData or not fileData then
            error("Failed to read data for comparison")
        end
        local match = (memData == fileData)
        return { success = true, match = match, file_path = filePath }
    end

    error("Unknown mode: " .. mode)
end

Handlers.structure_manage = function(p)
    Utils.checkProcess()
    local operation = p.operation
    if not operation then
        error("operation required")
    end

    if operation == "list" then
        local structures = {}
        local count = getStructureCount()
        for i = 0, count - 1 do
            local ok, s = pcall(function() return getStructure(i) end)
            if ok and s then
                local fields = {}
                pcall(function()
                    for j = 0, s.getElementCount() - 1 do
                        local elem = s.getElement(j)
                        if elem then
                            local vt = elem.getVartype()
                            local vtName = ""
                            if vt == vtByte then vtName = "byte"
                            elseif vt == vtWord then vtName = "word"
                            elseif vt == vtDword then vtName = "dword"
                            elseif vt == vtQword then vtName = "qword"
                            elseif vt == vtSingle then vtName = "float"
                            elseif vt == vtDouble then vtName = "double"
                            elseif vt == vtString then vtName = "string"
                            elseif type(vt) == "string" then vtName = vt
                            end
                            table_insert(fields, {
                                offset = elem.getOffset() or 0,
                                name = elem.getName() or "",
                                type = vtName,
                            })
                        end
                    end
                end)
                table_insert(structures, {
                    name = s.getName() or "",
                    fields = fields
                })
            end
        end
        return { success = true, operation = operation, structures = structures }

    elseif operation == "get" then
        local name = p.name
        if not name then error("name required for get") end
        local ok, s = pcall(function()
            return getStructure(name)
        end)
        if not ok or not s then
            error("Structure not found: " .. name)
        end
        local fields = {}
        pcall(function()
            for j = 0, s.getElementCount() - 1 do
                local elem = s.getElement(j)
                if elem then
                    local vt = elem.getVartype()
                    local vtName = ""
                    if vt == vtByte then vtName = "byte"
                    elseif vt == vtWord then vtName = "word"
                    elseif vt == vtDword then vtName = "dword"
                    elseif vt == vtQword then vtName = "qword"
                    elseif vt == vtSingle then vtName = "float"
                    elseif vt == vtDouble then vtName = "double"
                    elseif vt == vtString then vtName = "string"
                    elseif type(vt) == "string" then vtName = vt
                    end
                    table_insert(fields, {
                        offset = elem.getOffset() or 0,
                        name = elem.getName() or "",
                        type = vtName,
                    })
                end
            end
        end)
        return {
            success = true,
            operation = operation,
            structure = {
                name = name,
                size = s.size or 0,
                fields = fields,
            }
        }

    elseif operation == "create" then
        local name = p.name
        local sz = p.size or 0
        if not name then error("name required for create") end
        local ok, err = pcall(function()
            local s = createStructure(name)
            if sz > 0 then s.size = sz end
            s.addToGlobalStructureList()
        end)
        if not ok then error("Create failed: " .. tostring(err)) end
        return { success = true, operation = operation }

    elseif operation == "delete" then
        local name = p.name
        if not name then error("name required for delete") end
        local ok, err = pcall(function()
            local s = getStructure(name)
            if s then s.destroy() end
        end)
        if not ok then error("Delete failed: " .. tostring(err)) end
        return { success = true, operation = operation }

    elseif operation == "add_field" then
        local name = p.name
        local fieldName = p.field_name
        local fieldOffset = p.field_offset
        local fieldType = p.field_type or "dword"
        if not name or not fieldName or not fieldOffset then
            error("name, field_name, and field_offset required")
        end
        local ok, err = pcall(function()
            local s = getStructure(name)
            if not s then error("Structure not found") end
            local vtMap = {
                byte = vtByte, word = vtWord, dword = vtDword,
                qword = vtQword, float = vtSingle, double = vtDouble,
                string = vtString, bytes = vtByte,
            }
            local vt = vtMap[fieldType] or vtDword
            s.addElement(fieldOffset)
            -- Find the newly added unconfigured element (default byte, no name)
            -- IMPORTANT: setName BEFORE setVartype to avoid CE re-sorting issues
            for j = 0, s.getElementCount() - 1 do
                local elem = s.getElement(j)
                if elem.getVartype() == 0 and elem.getName() == "" then
                    elem.setName(fieldName)
                    elem.setVartype(vt)
                    elem.setOffset(fieldOffset)
                    break
                end
            end
        end)
        if not ok then error("Add field failed: " .. tostring(err)) end
        return { success = true, operation = operation }
    end

    error("Unknown operation: " .. operation)
end

Handlers.dissect_code = function(p)
    Utils.checkProcess()
    local module = p.module
    local analyzeFunctions = p.analyze_functions ~= false

    if not module then
        error("module required")
    end

    local modAddr, modSize, modName = nil, nil, nil

    if string_find(module, "-") then
        local startStr, stopStr = module:match("^(0x%x+)%-(0x%x+)$")
        if not startStr then
            startStr, stopStr = module:match("^(%x+)%-(%x+)$")
        end
        if not startStr or not stopStr then
            error("Invalid address range format, use 0xSTART-0xSTOP")
        end
        modAddr = tonumber(startStr, 16) or Utils.safeGetAddress(startStr, "dissect_code")
        local stopAddr = tonumber(stopStr, 16) or Utils.safeGetAddress(stopStr, "dissect_code")
        if not modAddr or not stopAddr then
            error("Invalid address range")
        end
        modSize = stopAddr - modAddr
        modName = string_format("0x%X-0x%X", modAddr, stopAddr)
    else
        local m = Utils.findModule(module)
        if not m then
            error("Module not found: " .. module)
        end
        modAddr = m.Address
        modSize = m.Size or getModuleSize(m.Name) or 0
        modName = m.Name
    end

    local result = {
        module = modName,
        functions = {},
        referenced_strings = {},
        stats = { total_functions = 0, code_size = modSize }
    }

    if analyzeFunctions then
        pcall(function()
            local dc = getDissectCode()
            if modName and not string_find(module, "-") then
                dc.dissect(modName)
            else
                dc.dissect(modAddr, modSize)
            end
            local refs = dc.getReferencedFunctions()
            if refs then
                for i, f in ipairs(refs) do
                    table_insert(result.functions, {
                        address = Utils.formatHex(type(f) == "table" and (f.address or f.Address or 0) or f),
                        name = type(f) == "table" and (f.name or f.Name or "") or "",
                    })
                end
                result.stats.total_functions = #refs
            end
            local strings = dc.getReferencedStrings()
            if strings then
                for i, s in ipairs(strings) do
                    table_insert(result.referenced_strings, {
                        address = Utils.formatHex(type(s) == "table" and (s.address or s.Address or 0) or s),
                        value = type(s) == "table" and (s.string or s.String or s.value or "") or tostring(s),
                    })
                end
            end
        end)
    end

    return result
end

Handlers.thread_breakpoint = function(p)
    Utils.checkProcess()
    local address = p.address
    local threadId = p.thread_id
    local bpType = p.type or "execute"
    local size = p.size or 1

    if not address then
        error("address required")
    end
    if not threadId then
        error("thread_id required")
    end

    local addr = Utils.safeGetAddress(address, "thread_breakpoint")
    threadId = tonumber(threadId)
    size = tonumber(size)

    local typeMap = { execute = bptExecute, write = bptWrite, access = bptAccess }
    local bpTypeNum = typeMap[bpType]
    if not bpTypeNum then
        error("Unknown breakpoint type: " .. bpType)
    end

    local ok, err = pcall(function()
        debug_setThreadBreakpoint(threadId, addr, bpTypeNum, size)
    end)

    if not ok then
        error("Failed to set thread breakpoint: " .. tostring(err))
    end

    Context.activeBreakpoints[addr] = {
        type = bpType,
        size = size,
        thread_id = threadId,
    }

    return { success = true, address = Utils.formatHex(addr), thread_id = threadId }
end

Handlers.dotnet_analyze = function(p)
    Utils.checkProcess()
    local operation = p.operation
    if not operation then
        error("Operation required")
    end

    local ok, collector = pcall(getDotNetDataCollector)
    if not ok or not collector then
        error("Failed to get DotNet data collector (is target a .NET process?)")
    end

    if not collector.Attached then
        error("DotNet collector not attached to process")
    end

    if operation == "domains" then
        local ok2, domains = pcall(function() return collector.enumDomains() end)
        if ok2 and domains then
            local result = {}
            for i, d in ipairs(domains) do
                table_insert(result, {
                    domainHandle = d.DomainHandle,
                    name = d.Name or "",
                })
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to enumerate domains")

    elseif operation == "modules" then
        local domainHandle = tonumber(p.domain_handle)
        if not domainHandle then error("domain_handle required for modules") end
        local ok2, modules = pcall(function() return collector.enumModuleList(domainHandle) end)
        if ok2 and modules then
            local result = {}
            for i, m in ipairs(modules) do
                table_insert(result, {
                    moduleHandle = m.ModuleHandle,
                    baseAddress = Utils.formatHex(m.BaseAddress or 0),
                    name = m.Name or "",
                })
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to enumerate modules")

    elseif operation == "typedefs" then
        local moduleHandle = tonumber(p.module_handle)
        if not moduleHandle then error("module_handle required for typedefs") end
        local ok2, typedefs = pcall(function() return collector.enumTypeDefs(moduleHandle) end)
        if ok2 and typedefs then
            local result = {}
            for i, t in ipairs(typedefs) do
                table_insert(result, {
                    typedefToken = t.TypeDefToken,
                    name = t.Name or "",
                    flags = t.Flags or 0,
                    extends = t.Extends or 0,
                })
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to enumerate typedefs")

    elseif operation == "methods" then
        local moduleHandle = tonumber(p.module_handle)
        local typedefToken = tonumber(p.typedef_token)
        if not moduleHandle or not typedefToken then
            error("module_handle and typedef_token required")
        end
        local ok2, methods = pcall(function() return collector.getTypeDefMethods(moduleHandle, typedefToken) end)
        if ok2 and methods then
            local result = {}
            for i, m in ipairs(methods) do
                table_insert(result, {
                    methodToken = m.MethodToken,
                    name = m.Name or "",
                    attributes = m.Attributes or 0,
                    implementationFlags = m.ImplementationFlags or 0,
                    ilCode = Utils.formatHex(m.ILCode or 0),
                    nativeCode = Utils.formatHex(m.NativeCode or 0),
                })
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to enumerate methods")

    elseif operation == "fields" then
        local moduleHandle = tonumber(p.module_handle)
        local typedefToken = tonumber(p.typedef_token)
        if not moduleHandle or not typedefToken then
            error("module_handle and typedef_token required")
        end
        local ok2, data = pcall(function() return collector.getTypeDefData(moduleHandle, typedefToken) end)
        if ok2 and data then
            local result = {
                className = data.ClassName or "",
                elementType = data.ElementType or 0,
                firstElementOffset = data.FirstElementOffset or 0,
                elementSize = data.ElementSize or 0,
                fields = {},
            }
            if data.Fields then
                for i, f in ipairs(data.Fields) do
                    table_insert(result.fields, {
                        offset = f.Offset or 0,
                        fieldType = f.FieldType or 0,
                        name = f.Name or "",
                    })
                end
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to enumerate fields")

    elseif operation == "objects" then
        local moduleHandle = tonumber(p.module_handle)
        local typedefToken = tonumber(p.typedef_token)
        if not moduleHandle or not typedefToken then
            error("module_handle and typedef_token required")
        end
        local ok2, objects = pcall(function() return collector.enumAllObjectsOfType(moduleHandle, typedefToken) end)
        if ok2 and objects then
            local result = {}
            for i, addr in ipairs(objects) do
                table_insert(result, Utils.formatHex(addr))
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to enumerate objects")

    elseif operation == "address_data" then
        local addr = Utils.safeGetAddress(p.address)
        if not addr then error("address required for address_data") end
        local ok2, data = pcall(function() return collector.getAddressData(addr) end)
        if ok2 and data then
            local result = {
                startAddress = Utils.formatHex(data.StartAddress or 0),
                className = data.ClassName or "",
                elementType = data.ElementType or 0,
                firstElementOffset = data.FirstElementOffset or 0,
                elementSize = data.ElementSize or 0,
                fields = {},
            }
            if data.Fields then
                for i, f in ipairs(data.Fields) do
                    table_insert(result.fields, {
                        offset = f.Offset or 0,
                        fieldType = f.FieldType or 0,
                        name = f.Name or "",
                    })
                end
            end
            return { success = true, operation = operation, data = result }
        end
        error("Failed to get address data")
    end

    error("Unknown operation: " .. operation)
end

-- ============ Phase 3: New tool handlers ============

Handlers.debug_start = function(p)
    Utils.checkProcess()
    local interface = tonumber(p["interface"]) or 0
    local ok, err = pcall(function()
        debugProcess(interface)
    end)
    if not ok then
        error("Failed to start debugger: " .. tostring(err))
    end
    return { success = true, ["interface"] = interface }
end

Handlers.debug_status = function(p)
    Utils.checkProcess()
    local status = {
        isDebugging = false,
        isBroken = false,
        canBreak = false,
        ["interface"] = 0,
    }
    pcall(function()
        status.isDebugging = debug_isDebugging() or false
        status.isBroken = debug_isBroken() or false
        status.canBreak = debug_canBreak() or false
        status["interface"] = debug_getCurrentDebuggerInterface() or 0
    end)
    return status
end

Handlers.debug_continue = function(p)
    Utils.checkProcess()
    local method = p.method
    if not method then error("method required") end

    local methodMap = { run = 0, stepinto = 1, stepover = 2 }
    local coMethod = methodMap[method]
    if not coMethod then error("Unknown method: " .. method) end

    local ok, err = pcall(function()
        debug_continueFromBreakpoint(coMethod)
    end)
    if not ok then
        error("Failed to continue: " .. tostring(err))
    end
    return { success = true, method = method }
end

Handlers.get_set_context = function(p)
    Utils.checkProcess()
    local setRegs = p.register_values
    local includeXmm = p.include_xmm or false

    local ALLOWED_REGS = {
        RAX=true, RBX=true, RCX=true, RDX=true, RSI=true, RDI=true,
        RBP=true, RSP=true, RIP=true, R8=true, R9=true, R10=true,
        R11=true, R12=true, R13=true, R14=true, R15=true, EFLAGS=true
    }

    if setRegs then
        for reg, val in pairs(setRegs) do
            local regName = reg:upper()
            if not ALLOWED_REGS[regName] then
                error("Invalid register: " .. reg .. " (allowed: RAX-R15, RIP, RSP, RBP, EFLAGS)")
            end
            pcall(function()
                _G[regName] = tonumber(val, 16) or tonumber(val) or 0
            end)
        end
        if includeXmm then
            pcall(function() debug_setContext(true) end)
        else
            pcall(function() debug_setContext(false) end)
        end
    end

    local regs = {}
    pcall(function()
        if includeXmm then
            debug_getContext(true)
        else
            debug_getContext(false)
        end
        local regNames = {"RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP","R8","R9","R10","R11","R12","R13","R14","R15","EFLAGS"}
        for _, name in ipairs(regNames) do
            local v = _G[name]
            if v then regs[name] = Utils.formatHex(v) end
        end
    end)

    local result = { registers = regs }
    if includeXmm then
        result.xmm_registers = {}
        for i = 0, 15 do
            local ok, ptr = pcall(function() return debug_getXMMPointer(i) end)
            if ok and ptr then
                result.xmm_registers["XMM" .. i] = Utils.formatHex(ptr)
            end
        end
    end

    return result
end

Handlers.thread_no_break = function(p)
    Utils.checkProcess()
    local operation = p.operation
    if not operation then error("operation required") end

    if operation == "add" then
        local tid = p.thread_id
        if not tid then error("thread_id required") end
        pcall(function() debug_addThreadToNoBreakList(tonumber(tid)) end)
        return { success = true, operation = operation, thread_id = tid }
    elseif operation == "remove" then
        local tid = p.thread_id
        if not tid then error("thread_id required") end
        pcall(function() debug_removeThreadFromNoBreakList(tonumber(tid)) end)
        return { success = true, operation = operation, thread_id = tid }
    elseif operation == "list" then
        error("No-break exclusion list retrieval is not supported by CE API. Use 'list_threads' to list all process threads instead")
    elseif operation == "list_threads" then
        local tids = {}
        pcall(function()
            local tl = getThreadList()
            if tl then
                for i = 0, tl.Count - 1 do
                    table_insert(tids, tonumber(tl.getString(i)))
                end
            end
        end)
        return { success = true, operation = operation, threads = tids }
    end

    error("Unknown operation: " .. operation)
end

Handlers.debug_break_thread = function(p)
    Utils.checkProcess()
    local tid = p.thread_id
    if not tid then error("thread_id required") end
    tid = tonumber(tid)

    local ok, err = pcall(function()
        debug_breakThread(tid)
    end)
    if not ok then
        error("Failed to break thread: " .. tostring(err))
    end
    return { success = true, thread_id = tid }
end

Handlers.detach_debugger = function(p)
    Utils.checkProcess()
    local ok, err = pcall(function()
        detachIfPossible()
    end)
    return { success = ok }
end

Handlers.open_file_as_process = function(p)
    local filename = p.filename
    if not filename then error("filename required") end
    local is64bit = p.is64bit or false
    local startAddr = p.start_address and Utils.safeGetAddress(p.start_address, "open_file_as_process") or nil

    local ok, err = pcall(function()
        openFileAsProcess(filename, is64bit, startAddr or 0)
    end)
    if not ok then
        error("Failed to open file as process: " .. tostring(err))
    end
    return { success = true, filename = filename, is64bit = is64bit }
end

Handlers.create_process = function(p)
    local path = p.path
    if not path then error("path required") end
    local params = p.parameters or ""
    local dbg = p.debug or false
    local breakEntry = p.break_on_entry or false

    local ok, err = pcall(function()
        createProcess(path, params, dbg, breakEntry)
    end)
    if not ok then
        error("Failed to create process: " .. tostring(err))
    end

    local pid = getOpenedProcessID() or 0
    return { success = true, pid = pid, name = path }
end

Handlers.get_foreground_process = function(p)
    local pid = nil
    pcall(function() pid = getForegroundProcess() end)
    local name = ""
    if pid and pid > 0 then
        pcall(function()
            local procs = getProcessList()
            for procPid, procName in pairs(procs) do
                if procPid == pid then
                    name = procName or ""
                    break
                end
            end
        end)
    end
    return { pid = pid or 0, name = name }
end

Handlers.close_remote_handle = function(p)
    local handle = p.handle
    if not handle then error("handle required") end
    local pid = p.process_id

    local ok, err = pcall(function()
        closeRemoteHandle(tonumber(handle), pid and tonumber(pid) or nil)
    end)
    if not ok then
        error("Failed to close handle: " .. tostring(err))
    end
    return { success = true }
end

Handlers.duplicate_handle = function(p)
    local handle = p.handle
    if not handle then error("handle required") end
    local mode = p.mode
    local fromPid = p.from_pid
    local toPid = p.to_pid

    local newHandle = nil
    local ok, err = pcall(function()
        if fromPid and toPid then
            newHandle = duplicateHandle(tonumber(handle), tonumber(fromPid), tonumber(toPid))
        elseif mode then
            newHandle = duplicateHandle(tonumber(handle), tonumber(mode))
        else
            newHandle = duplicateHandle(tonumber(handle))
        end
    end)
    if not ok then
        error("Failed to duplicate handle: " .. tostring(err))
    end
    return { success = true, new_handle = newHandle }
end

Handlers.target_info = function(p)
    Utils.checkProcess()
    local info = {
        is64bit = false,
        isX86 = true,
        isArm = false,
        isAndroid = false,
        isRosetta = false,
        abi = 0,
        ceIs64bit = false,
        pointerSize = 4,
    }
    pcall(function()
        info.is64bit = targetIs64Bit() or false
        info.isX86 = targetIsX86() or false
        info.isArm = targetIsArm() or false
        info.isAndroid = targetIsAndroid() or false
        info.isRosetta = targetIsRosetta() or false
        info.abi = getABI() or 0
        info.ceIs64bit = cheatEngineIs64Bit() or false
        info.pointerSize = getPointerSize() or 4
    end)
    return info
end

Handlers.md5_file = function(p)
    local filePath = p.file_path
    if not filePath then error("file_path required") end
    local hash = nil
    local ok, err = pcall(function()
        hash = md5file(filePath)
    end)
    if not ok then error("Failed to hash file: " .. tostring(err)) end
    return { file_path = filePath, md5 = hash or "" }
end

Handlers.file_version = function(p)
    local filePath = p.file_path
    if not filePath then error("file_path required") end
    local version = nil
    local parts = nil
    pcall(function()
        version, parts = getFileVersion(filePath)
    end)
    local result = { file_path = filePath, version = version or 0 }
    if parts then
        result.major = parts.major or 0
        result.minor = parts.minor or 0
        result.release = parts.release or 0
        result.build = parts.build or 0
    end
    return result
end

Handlers.file_ops = function(p)
    local operation = p.operation
    if not operation then error("operation required") end
    local path = p.path
    if not path then error("path required") end

    if operation == "exists" then
        local exists = false
        pcall(function() exists = fileExists(path) end)
        return { operation = operation, result = exists }
    elseif operation == "delete" then
        local ok = false
        pcall(function() ok = deleteFile(path) end)
        return { operation = operation, result = ok }
    elseif operation == "list_files" then
        local files = {}
        pcall(function()
            local mask = p.search_mask or "*.*"
            local subdirs = p.search_subdirs or false
            local list = getFileList(path, mask, subdirs)
            if list then
                for i, f in ipairs(list) do
                    table_insert(files, f)
                end
            end
        end)
        return { operation = operation, result = files }
    elseif operation == "list_dirs" then
        local dirs = {}
        pcall(function()
            local subdirs = p.search_subdirs or false
            local list = getDirectoryList(path, subdirs)
            if list then
                for i, d in ipairs(list) do
                    table_insert(dirs, d)
                end
            end
        end)
        return { operation = operation, result = dirs }
    end

    error("Unknown operation: " .. operation)
end

Handlers.write_region_to_file = function(p)
    Utils.checkProcess()
    local address = p.address
    local size = p.size
    local filePath = p.file_path
    if not address or not size or not filePath then
        error("address, size, and file_path required")
    end
    local addr = Utils.safeGetAddress(address, "write_region_to_file")
    size = tonumber(size)

    local bytesWritten = 0
    local ok, err = pcall(function()
        bytesWritten = writeRegionToFile(filePath, addr, size)
    end)
    if not ok then error("Write failed: " .. tostring(err)) end
    return { success = true, file_path = filePath, bytes_written = bytesWritten or 0 }
end

Handlers.read_region_from_file = function(p)
    Utils.checkProcess()
    local address = p.address
    local filePath = p.file_path
    if not address or not filePath then
        error("address and file_path required")
    end
    local addr = Utils.safeGetAddress(address, "read_region_from_file")

    local ok, err = pcall(function()
        readRegionFromFile(filePath, addr)
    end)
    if not ok then error("Read failed: " .. tostring(err)) end
    return { success = true, file_path = filePath, address = Utils.formatHex(addr) }
end

Handlers.find_window = function(p)
    Utils.checkProcess()
    local className = p.class_name or nil
    local caption = p.caption or nil

    local handle = nil
    pcall(function()
        handle = findWindow(className, caption)
    end)

    if not handle or handle == 0 then
        return { found = false }
    end

    local result = { found = true, handle = handle }
    pcall(function() result.caption = getWindowCaption(handle) or "" end)
    pcall(function() result.class_name = getWindowClassName(handle) or "" end)
    pcall(function() result.process_id = getWindowProcessID(handle) or 0 end)
    return result
end

Handlers.enum_windows = function(p)
    Utils.checkProcess()
    local windows = {}
    pcall(function()
        local sl = createStringList()
        getWindowList(sl)
        for i = 0, sl.Count - 1 do
            local entry = sl.getString(i)
            -- Format: "PID-Caption" (hex PID, then dash, then caption)
            local pidStr, caption = entry:match("^(%x+)%-(.+)$")
            if pidStr and caption then
                local pid = tonumber(pidStr, 16) or 0
                local hwnd = 0
                pcall(function()
                    local h = findWindow(nil, caption)
                    if h and h ~= 0 then hwnd = h end
                end)
                table_insert(windows, {
                    handle = Utils.formatHex(hwnd),
                    caption = caption,
                    process_id = pid,
                })
            end
        end
        sl.destroy()
    end)
    return { count = #windows, windows = windows }
end

Handlers.allocate_shared_memory = function(p)
    Utils.checkProcess()
    local name = p.name
    if not name then error("name required") end
    local size = tonumber(p.size) or 4096

    local addr = nil
    local ok, err = pcall(function()
        addr = allocateSharedMemory(name, size)
    end)
    if not ok then error("Allocate shared memory failed: " .. tostring(err)) end
    return { success = addr ~= nil, name = name, address = Utils.formatHex(addr or 0), size = size }
end

Handlers.get_physical_address = function(p)
    Utils.checkProcess()
    local address = p.address
    if not address then error("address required") end
    local addr = Utils.safeGetAddress(address, "get_physical_address")

    local physAddr = nil
    pcall(function()
        physAddr = dbk_getPhysicalAddress(addr)
    end)
    return {
        virtual_address = Utils.formatHex(addr),
        physical_address = physAddr and Utils.formatHex(physAddr) or "unavailable"
    }
end

Handlers.dbvm_cloak = function(p)
    Utils.checkProcess()
    local operation = p.operation
    if not operation then error("operation required") end

    if operation == "activate" then
        local address = p.address
        if not address then error("address required for activate") end
        local addr = Utils.safeGetAddress(address, "dbvm_cloak")
        local virtualAddr = p.virtual_address and Utils.safeGetAddress(p.virtual_address, "dbvm_cloak") or nil
        local ok, err = pcall(function()
            dbvm_cloak_activate(addr, virtualAddr)
        end)
        if not ok then error("Cloak activate failed: " .. tostring(err)) end
        return { success = true, operation = operation }
    elseif operation == "deactivate" then
        local address = p.address
        if not address then error("address required for deactivate") end
        local addr = Utils.safeGetAddress(address, "dbvm_cloak")
        local ok, err = pcall(function()
            dbvm_cloak_deactivate(addr)
        end)
        if not ok then error("Cloak deactivate failed: " .. tostring(err)) end
        return { success = true, operation = operation }
    elseif operation == "read_original" then
        local address = p.address
        if not address then error("address required") end
        local addr = Utils.safeGetAddress(address, "dbvm_cloak")
        local data = nil
        pcall(function() data = dbvm_cloak_readOriginal(addr) end)
        return { success = true, operation = operation, data = data }
    elseif operation == "write_original" then
        local address = p.address
        if not address then error("address required") end
        local addr = Utils.safeGetAddress(address, "dbvm_cloak")
        local ok, err = pcall(function()
            dbvm_cloak_writeOriginal(addr)
        end)
        if not ok then error("Write original failed: " .. tostring(err)) end
        return { success = true, operation = operation }
    end

    error("Unknown operation: " .. operation)
end

Handlers.type_conversion = function(p)
    local conversion = p.conversion
    local value = p.value
    local signed = p.signed or false
    if not conversion or not value then error("conversion and value required") end

    local result = nil
    local ok, err = pcall(function()
        if conversion == "word_to_bytes" then
            result = wordToByteTable(tonumber(value) or 0)
        elseif conversion == "dword_to_bytes" then
            result = dwordToByteTable(tonumber(value) or 0)
        elseif conversion == "qword_to_bytes" then
            result = qwordToByteTable(tonumber(value) or 0)
        elseif conversion == "float_to_bytes" then
            result = floatToByteTable(tonumber(value) or 0)
        elseif conversion == "double_to_bytes" then
            result = doubleToByteTable(tonumber(value) or 0)
        elseif conversion == "string_to_bytes" then
            result = stringToByteTable(tostring(value))
        elseif conversion == "bytes_to_word" then
            local bytes = {}
            for b in tostring(value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            result = byteTableToWord(bytes, signed)
        elseif conversion == "bytes_to_dword" then
            local bytes = {}
            for b in tostring(value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            result = byteTableToDword(bytes, signed)
        elseif conversion == "bytes_to_qword" then
            local bytes = {}
            for b in tostring(value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            result = byteTableToQword(bytes)
        elseif conversion == "bytes_to_float" then
            local bytes = {}
            for b in tostring(value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            result = byteTableToFloat(bytes)
        elseif conversion == "bytes_to_double" then
            local bytes = {}
            for b in tostring(value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            result = byteTableToDouble(bytes)
        elseif conversion == "bytes_to_string" then
            local bytes = {}
            for b in tostring(value):gmatch("%S+") do
                table_insert(bytes, tonumber(b) or 0)
            end
            result = byteTableToString(bytes)
        else
            error("Unknown conversion: " .. conversion)
        end
    end)
    if not ok then error("Conversion failed: " .. tostring(err)) end

    local output = result
    if type(result) == "table" then
        local parts = {}
        for i, v in ipairs(result) do
            table_insert(parts, string_format("%02X", v))
        end
        output = table_concat(parts, " ")
    end

    return {
        input_type = conversion:match("^(%w+)_to_"),
        output_type = conversion:match("_to_(%w+)$"),
        value = value,
        result = output,
    }
end

Handlers.get_address_safe = function(p)
    Utils.checkProcess()
    local expression = p.expression
    if not expression then error("expression required") end
    local addr = nil
    local oldState = nil
    pcall(function()
        oldState = errorOnLookupFailure(false)
    end)
    pcall(function()
        addr = getAddressSafe(expression)
    end)
    pcall(function()
        if oldState ~= nil then errorOnLookupFailure(oldState) end
    end)
    return { expression = expression, address = addr and Utils.formatHex(addr) or "0x0", found = addr ~= nil and addr ~= 0 }
end

Handlers.get_symbol_info = function(p)
    Utils.checkProcess()
    local symbolName = p.symbol_name
    if not symbolName then error("symbol_name required") end
    local info = nil
    pcall(function()
        info = getSymbolInfo(symbolName)
    end)
    if not info then
        return { modulename = "", searchkey = symbolName, address = "0x0", size = 0, found = false }
    end
    return {
        modulename = info.modulename or info.ModuleName or "",
        searchkey = info.searchkey or info.SearchKey or symbolName,
        address = Utils.formatHex(info.address or info.Address or 0),
        size = info.size or info.Size or 0,
        found = true,
    }
end

Handlers.add_symbol_module = function(p)
    local path = p.path
    local baseAddr = p.base_address
    if not path or not baseAddr then error("path and base_address required") end
    local addr = Utils.safeGetAddress(baseAddr, "add_symbol_module")

    local ok, err = pcall(function()
        symbolHandlerAddModule(path, addr)
    end)
    if not ok then error("Add symbol module failed: " .. tostring(err)) end
    return { success = true, path = path, base_address = Utils.formatHex(addr) }
end

Handlers.get_name_from_address = function(p)
    Utils.checkProcess()
    local address = p.address
    if not address then error("address required") end
    local addr = Utils.safeGetAddress(address, "get_name_from_address")
    local includeModules = p.include_modules ~= false
    local includeSymbols = p.include_symbols ~= false
    local includeSections = p.include_sections or false

    local name = ""
    pcall(function()
        name = getNameFromAddress(addr, includeModules, includeSymbols, includeSections)
    end)
    return {
        address = Utils.formatHex(addr),
        name = name or "",
        has_module = inModule(addr) or false,
        has_symbol = name and name ~= "" and not name:match("^%x+$") or false,
        has_section = includeSections,
    }
end

Handlers.disassemble_bytes = function(p)
    Utils.checkProcess()
    local bytes = p.bytes
    if not bytes then error("bytes required") end
    local baseAddr = p.base_address and Utils.safeGetAddress(p.base_address, "disassemble_bytes") or 0
    local count = tonumber(p.count) or 20

    local instructions = {}
    local ok, err = pcall(function()
        -- Parse hex bytes string into byte array for disassembleBytes
        -- Input: "48 83 EC 28" -> {0x48, 0x83, 0xEC, 0x28}
        local byteArray = {}
        for hexByte in string_gmatch(bytes, "%x%x") do
            table_insert(byteArray, tonumber(hexByte, 16))
        end
        if #byteArray == 0 then error("No valid hex bytes found in input") end
        
        local currentAddr = baseAddr
        local byteOffset = 1  -- 1-based index for Lua
        local processedCount = 0
        
        while byteOffset <= #byteArray and processedCount < count do
            -- Get remaining bytes from current offset
            local remainingBytes = {}
            for i = byteOffset, #byteArray do
                table_insert(remainingBytes, byteArray[i])
            end
            
            -- Use disassembleBytes with remaining byte array
            local disasmStr = disassembleBytes(remainingBytes, currentAddr)
            if not disasmStr or disasmStr == "" then break end
            
            -- Parse: "address - bytes - opcode"
            local addrStr, instrBytes, instrOpcode = disasmStr:match("^(%x+)%s*-%s*(%x[%x%s]*)%s*-%s*(.+)$")
            if not addrStr then break end
            
            -- Calculate instruction size from bytes string
            local byteCount = 0
            for _ in string_gmatch(instrBytes, "%x%x") do byteCount = byteCount + 1 end
            if byteCount == 0 then break end
            
            table_insert(instructions, {
                address = Utils.formatHex(tonumber(addrStr, 16) or currentAddr),
                opcode = string_gsub(string_gsub(instrOpcode, "^%s+", ""), "%s+$", ""),
                bytes = string_gsub(string_gsub(instrBytes, "^%s+", ""), "%s+$", ""),
                size = byteCount,
            })
            
            currentAddr = currentAddr + byteCount
            byteOffset = byteOffset + byteCount
            processedCount = processedCount + 1
        end
    end)
    if not ok then error("Disassemble bytes failed: " .. tostring(err)) end
    return { instructions = instructions }
end

Handlers.assemble_instruction = function(p)
    Utils.checkProcess()
    local instruction = p.instruction
    if not instruction then error("instruction required") end
    local addr = p.address and Utils.safeGetAddress(p.address, "assemble_instruction") or 0
    local preference = tonumber(p.preference) or 0

    local byteTable = nil
    local ok, err = pcall(function()
        byteTable = assemble(instruction, addr, preference)
    end)
    if not ok then error("Assemble failed: " .. tostring(err)) end
    if not byteTable then error("Assemble returned nil") end

    local byteStr = {}
    for i, b in ipairs(byteTable) do
        table_insert(byteStr, string_format("%02X", b))
    end
    return {
        instruction = instruction,
        bytes = table_concat(byteStr, " "),
        size = #byteTable,
    }
end

Handlers.execute_method = function(p)
    Utils.checkProcess()
    local address = p.address
    local classInstance = p.class_instance
    if not address or not classInstance then error("address and class_instance required") end

    local addr = Utils.safeGetAddress(address, "execute_method")
    local instance = Utils.safeGetAddress(classInstance, "execute_method")
    local args = p.args or {}
    local callMethod = tonumber(p.call_method) or 0
    local instanceReg = tonumber(p.instance_register) or 1
    local timeout = tonumber(p.timeout) or 5000

    local returnValue = nil
    local ok, err = pcall(function()
        returnValue = executeMethod(callMethod, timeout, addr,
            {regnr = instanceReg, classinstance = instance},
            unpack(args))
    end)
    if not ok then error("Execute method failed: " .. tostring(err)) end
    return { success = true, return_value = Utils.formatHex(returnValue or 0) }
end

Handlers.create_remote_thread = function(p)
    Utils.checkProcess()
    local address = p.address
    if not address then error("address required") end
    local addr = Utils.safeGetAddress(address, "create_remote_thread")
    local parameter = tonumber(p.parameter) or 0

    local ok, err = pcall(function()
        createRemoteThread(addr, parameter)
    end)
    if not ok then error("Create remote thread failed: " .. tostring(err)) end
    return { success = true }
end

Handlers.compile_c_sharp = function(p)
    Utils.checkProcess()
    local code = p.code
    if not code then error("code required") end
    local references = p.references or {}

    local filename = nil
    local ok, err = pcall(function()
        filename = compileCS(code, references)
    end)
    if not ok then error("Compile C# failed: " .. tostring(err)) end
    return { success = filename ~= nil, filename = filename or "" }
end

Handlers.generate_api_hook_script = function(p)
    Utils.checkProcess()
    local address = p.address
    local jumpAddress = p.jump_address
    if not address or not jumpAddress then error("address and jump_address required") end

    local addr = Utils.safeGetAddress(address, "generate_api_hook_script")
    local jumpAddr = Utils.safeGetAddress(jump_address, "generate_api_hook_script")
    local newCallAddr = p.new_call_address and Utils.safeGetAddress(p.new_call_address, "generate_api_hook_script") or nil
    local targetSelf = p.target_self or false

    local script = nil
    pcall(function()
        script = generateAPIHookScript(
            Utils.formatHex(addr),
            Utils.formatHex(jumpAddr),
            newCallAddr and Utils.formatHex(newCallAddr) or nil,
            nil,
            targetSelf
        )
    end)
    return { script = script or "", address = Utils.formatHex(addr), jump_address = Utils.formatHex(jumpAddr) }
end

local Pipe = {}

-- Commands requiring main thread sync
local SYNC_COMMANDS = {
    write_memory = true,
    write_memory_batch = true,
    auto_assemble = true,
    set_breakpoint = true,
    remove_breakpoint = true,
    cleanup_breakpoints = true,
    add_address_record = true,
    register_symbol = true,
    unregister_symbol = true,
    allocate_memory = true,
    deallocate_memory = true,
    set_memory_protection = true,
    execute_lua = true,
    -- Hook commands
    hook_function = true,
    unhook_function = true,
    -- Emulation commands
    call_function = true,
    -- Scan session commands (CE objects must be created/destroyed on main thread)
    scan_new = true,
    scan_next = true,
    scan_close = true,
    scan_results = true,
    -- Process control
    pause_process = true,
    resume_process = true,
    speedhack = true,
    -- Injection
    inject_dll = true,
    inject_dotnet_dll = true,
    compile_c_code = true,
    -- Table operations
    load_table = true,
    save_table = true,
    -- New tools requiring main thread sync
    memory_record_control = true,
    full_access = true,
    dump_memory = true,
    thread_breakpoint = true,
    structure_manage = true,
    check_assemble = true,
    pointer_size = true,
    comment = true,
    symbol_control = true,
    rip_scan = true,
    -- Phase 3 new tools
    debug_start = true,
    debug_continue = true,
    get_set_context = true,
    thread_no_break = true,
    debug_break_thread = true,
    detach_debugger = true,
    open_file_as_process = true,
    create_process = true,
    close_remote_handle = true,
    duplicate_handle = true,
    allocate_shared_memory = true,
    write_region_to_file = true,
    read_region_from_file = true,
    add_symbol_module = true,
    execute_method = true,
    create_remote_thread = true,
    compile_c_sharp = true,
    generate_api_hook_script = true,
    -- Scan operations (CE objects must be created/destroyed on main thread)
    aob_scan = true,
    value_scan = true,
    aob_scan_unique = true,
    -- Breakpoint/debugger analysis (sets breakpoints, modifies debugger state)
    break_and_get_regs = true,
    break_and_trace = true,
    find_what_accesses = true,
    find_what_writes = true,
    trace_struct_access = true,
    -- Process attachment (opens process)
    attach_process = true,
    -- Write operations
    copy_memory = true,
    clear_hook_log = true,
    find_pointer_path = true,
}

function Pipe.handleRequest(req)
    if not req or not req.command then
        return { error = "Invalid request structure" }
    end


    local handler = Handlers[req.command]
    if not handler then
        return { error = "Unknown command: " .. tostring(req.command) }
    end

    -- Record execution start time for metrics
    local startTime = os_clock()

    local status, result = pcall(handler, req.params or {})

    -- Record execution metrics
    local duration = os_clock() - startTime
    Metrics.recordCommand(req.command, duration, status)

    if not status then
        Utils.debugPrint("Error in " .. req.command .. ": " .. tostring(result))
        return { error = tostring(result) }
    end
    return { result = result }
end

function Pipe.executeRequest(req)
    if SYNC_COMMANDS[req.command] then
        local resp = nil
        synchronize(function()
            resp = Pipe.handleRequest(req)
        end)
        return resp
    else
        -- Read-only operations can execute directly without sync
        return Pipe.handleRequest(req)
    end
end

-- Helper function to send error response without breaking connection
local function sendErrorResponse(errorMsg)
    local resp = { error = errorMsg }
    local respStr = JSON.encode(resp)
    local respLen = #respStr
    
    pcall(function()
        Context.pipeServer.lock()
        pcall(function()
            Context.pipeServer.writeDword(respLen)
            Context.pipeServer.writeString(respStr, false)
        end)
        Context.pipeServer.unlock()
    end)
end

function Pipe.workerLoop()
    Utils.debugPrint("Worker started")
    local consecutiveErrors = 0

    while Context.serverRunning do
        if not Context.pipeServer then
            Utils.debugPrint("Pipe server is nil, attempting to recreate...")
            local pipeOk, pipeObj = pcall(createPipe, Config.PIPE_NAME, Config.PIPE_BUFFER_SIZE, Config.PIPE_BUFFER_SIZE, Config.PIPE_MAX_INSTANCES)
            if pipeOk and pipeObj and pipeObj.Valid then
                Context.pipeServer = pipeObj
                Context.pipeServer.Timeout = 30
                consecutiveErrors = 0
            else
                sleep(1000)
            end
            goto worker_continue
        end

        local acceptOk, acceptErr = pcall(function()
            Context.pipeServer.acceptConnection()
        end)

        if not acceptOk then
            consecutiveErrors = consecutiveErrors + 1
            if consecutiveErrors > Config.MAX_CONSECUTIVE_ERRORS then
                Utils.debugPrint("Too many consecutive errors, restarting pipe...")
                pcall(function() Context.pipeServer.destroy() end)
                Context.pipeServer = createPipe(Config.PIPE_NAME, Config.PIPE_BUFFER_SIZE, Config.PIPE_BUFFER_SIZE, Config.PIPE_MAX_INSTANCES)
                consecutiveErrors = 0
            end
            if Context.serverRunning then
                sleep(Config.HEARTBEAT_INTERVAL)
            end
        else
            consecutiveErrors = 0
            Context.connectionCount = Context.connectionCount + 1
            Context.lastActivityTime = os_clock()  -- Heartbeat: record connection time
            Utils.debugPrint("Client connected (#" .. Context.connectionCount .. ")")
            
            local sessionErrors = 0

            while Context.serverRunning and Context.pipeServer and Context.pipeServer.Valid do
                Utils.periodicCleanup()

                -- Read size
                local ok, size = false, nil
                pcall(function()
                    Context.pipeServer.lock()
                    ok, size = pcall(Context.pipeServer.readDword)
                    Context.pipeServer.unlock()
                end)

                if not ok or not size or size == 0 then
                    sessionErrors = sessionErrors + 1
                    if sessionErrors >= Config.MAX_SESSION_ERRORS then
                        Utils.debugPrint("Too many session errors, disconnecting client")
                        -- Send error before disconnecting
                        sendErrorResponse("Too many consecutive read errors")
                        break
                    end
                    sleep(10)
                    goto continue
                end

                if size >= Config.MAX_MESSAGE_SIZE then
                    Utils.debugPrint("Message too large: " .. size)
                    sendErrorResponse("Message too large: " .. size .. " bytes (max: " .. Config.MAX_MESSAGE_SIZE .. ")")
                    break
                end

                sessionErrors = 0

                -- Read payload
                local ok2, payload = false, nil
                pcall(function()
                    Context.pipeServer.lock()
                    ok2, payload = pcall(Context.pipeServer.readString, size)
                    Context.pipeServer.unlock()
                end)

                if ok2 and payload and #payload == size then
                    local decodeOk, req = pcall(JSON.decode, payload)
                    if not decodeOk or not req then
                        Utils.debugPrint("Failed to decode JSON payload")
                        sendErrorResponse("Invalid JSON payload")
                        goto continue
                    end
                    
                    local resp = nil

                    -- Use optimized request execution (sync on demand)
                    resp = Pipe.executeRequest(req)

                    local respStr = JSON.encode(resp)
                    local respLen = #respStr

                    if respLen > Config.MAX_MESSAGE_SIZE then
                        respStr = JSON.encode({ error = "Response too large" })
                        respLen = #respStr
                    end

                    local writeOk = false
                    pcall(function()
                        Context.pipeServer.lock()
                        writeOk = pcall(function()
                            Context.pipeServer.writeDword(respLen)
                            Context.pipeServer.writeString(respStr, false)
                        end)
                        Context.pipeServer.unlock()
                    end)

                    if writeOk then
                        Context.lastActivityTime = os_clock()  -- Heartbeat: update on successful communication
                    else
                        Utils.debugPrint("Failed to write response")
                        break
                    end
                else
                    Utils.debugPrint("Failed to read payload: expected " .. size .. " bytes")
                    sendErrorResponse("Failed to read payload: expected " .. size .. " bytes, got " .. tostring(#(payload or "")))
                    -- Don't break, allow client to retry
                    sleep(50)
                end

                ::continue::
            end

            pcall(function()
                if Context.pipeServer and Context.pipeServer.Valid then
                    Context.pipeServer.disconnect()
                end
            end)
            Context.lastActivityTime = 0  -- Heartbeat: reset on disconnect
            Utils.debugPrint("Client disconnected, recreating pipe for next connection...")
            
            -- Recreate pipe instance for next client (Windows named pipes are single-client)
            pcall(function()
                if Context.pipeServer then
                    Context.pipeServer.destroy()
                end
            end)
            local pipeOk, pipeObj = pcall(createPipe, Config.PIPE_NAME, Config.PIPE_BUFFER_SIZE, Config.PIPE_BUFFER_SIZE, Config.PIPE_MAX_INSTANCES)
            if pipeOk and pipeObj and pipeObj.Valid then
                Context.pipeServer = pipeObj
                Context.pipeServer.Timeout = 30
                Utils.debugPrint("Pipe recreated, ready for next connection")
            else
                Context.pipeServer = nil
                Utils.debugPrint("Failed to recreate pipe, retrying next iteration...")
                sleep(500)
            end
        end
        ::worker_continue::
    end
    Utils.debugPrint("Worker stopped")
end

-- ============ Server Lifecycle ============
local Server = {}

function Server.stop()
    Utils.debugPrint("Stopping server...")
    Context.serverRunning = false

    -- Cleanup UI status timer/label to avoid leaked timers across stop/start cycles
    if CE_MCP_STATUS_LABEL then
        pcall(function()
            if CE_MCP_STATUS_LABEL.timer then
                CE_MCP_STATUS_LABEL.timer.Enabled = false
                CE_MCP_STATUS_LABEL.timer.destroy()
                CE_MCP_STATUS_LABEL.timer = nil
            end
            if CE_MCP_STATUS_LABEL.label then
                CE_MCP_STATUS_LABEL.label.destroy()
                CE_MCP_STATUS_LABEL.label = nil
            end
        end)
    end

    -- Cleanup all zombie resources (breakpoints, traces, etc.)
    Utils.cleanupZombieState()

    -- Clear address cache
    Utils.clearAddressCache()
    Context.traceData = nil

    if Context.pipeServer then
        pcall(function()
            if Context.pipeServer.Valid then
                Context.pipeServer.disconnect()
            end
            Context.pipeServer.destroy()
        end)
        Context.pipeServer = nil
    end

    Utils.debugPrint("Server stopped (handled " .. Context.connectionCount .. " connections)")
end

function Server.start()
    Server.stop()  -- This calls cleanupZombieState()

    -- Additional cleanup for fresh start
    Utils.debugPrint("Starting MCP Bridge")

    Context.pipeServer = createPipe(Config.PIPE_NAME, Config.PIPE_BUFFER_SIZE, Config.PIPE_BUFFER_SIZE, Config.PIPE_MAX_INSTANCES)
    if not Context.pipeServer or not Context.pipeServer.Valid then
        print("[CE-MCP] Failed to create pipe: " .. Config.PIPE_NAME)
        return false
    end

    -- Set pipe timeout to prevent indefinite blocking on read/write if client disconnects
    Context.pipeServer.Timeout = 30

    Context.serverRunning = true
    Context.connectionCount = 0
    createThread(Pipe.workerLoop)

    --print("[CE-MCP] Server started on pipe: " .. Config.PIPE_NAME)
    return true
end

function Server.stats()
    -- Count cached symbols
    local symbolCacheCount = 0
    for _ in pairs(AddressCache.symbols) do
        symbolCacheCount = symbolCacheCount + 1
    end

    -- Count cached module bases
    local moduleCacheCount = 0
    for _ in pairs(AddressCache.moduleBase) do
        moduleCacheCount = moduleCacheCount + 1
    end

    -- Count active breakpoints
    local bpCount = 0
    for _ in pairs(Context.activeBreakpoints) do
        bpCount = bpCount + 1
    end

    return {
        running = Context.serverRunning,
        connections = Context.connectionCount,
        cached_symbols = symbolCacheCount,
        cached_modules = moduleCacheCount,
        active_breakpoints = bpCount
    }
end

-- ============ Global API ============
-- Cleanup old instance
if CE_MCP_BRIDGE_INSTANCE then
    CE_MCP_BRIDGE_INSTANCE.stop()
end
if CE_MCP_STATUS_LABEL then
    pcall(function()
        if CE_MCP_STATUS_LABEL.timer then
            CE_MCP_STATUS_LABEL.timer.Enabled = false
            CE_MCP_STATUS_LABEL.timer.destroy()
        end
        if CE_MCP_STATUS_LABEL.label then
            CE_MCP_STATUS_LABEL.label.destroy()
        end
    end)
end

CE_MCP = {
    start = Server.start,
    stop = Server.stop,
    stats = Server.stats,
    -- Logger API
    Logger = Logger,
    LogLevel = LogLevel,
    -- Expose for debugging
    _config = Config,
    _context = Context,
    _handlers = Handlers,
}

CE_MCP_BRIDGE_INSTANCE = CE_MCP

-- ============ Status Label ============
local StatusLabel = {
    label = nil,
    timer = nil,
}

function StatusLabel.create()
    local mainForm = getMainForm()
    if not mainForm then return end

    -- Find "附加注释" button (CommentButton)
    local commentBtn = mainForm.findComponentByName("CommentButton")

    -- Create status label
    local label = createLabel(mainForm)
    label.Caption = "MCP"
    label.Font.Size = 9
    label.Font.Style = "fsBold"
    label.Cursor = crHandPoint

    if commentBtn then
        -- Use pcall to safely set properties, in case of unexpected parent/control issues
        local ok = pcall(function()
            label.Parent = commentBtn.Parent
            -- Anchor to CommentButton's left side
            label.AnchorSideRight.Control = commentBtn
            label.AnchorSideRight.Side = asrLeft
            label.AnchorSideTop.Control = commentBtn
            label.AnchorSideTop.Side = asrTop
            label.Anchors = "[akTop,akRight]"
            label.BorderSpacing.Right = 5
            label.BorderSpacing.Top = 2
        end)
        
        if not ok then
            -- Fallback if anchoring failed
            label.Parent = mainForm
            label.Anchors = "[akRight, akTop]"
            label.Left = mainForm.ClientWidth - 120
            label.Top = 5
        end
    else
        -- Fallback: top right
        label.Parent = mainForm
        label.Anchors = "[akRight, akTop]"
        label.Left = mainForm.ClientWidth - 120
        label.Top = 5
    end

    -- Click to show stats
    label.OnClick = function()
        local stats = Server.stats()
        local connected = Context.lastActivityTime > 0 and
                         (os_clock() - Context.lastActivityTime) < Config.HEARTBEAT_TIMEOUT
        showMessage(string_format("CE MCP\nStatus: %s\nConnections: %d",
            connected and "Connected" or "Waiting",
            stats.connections or 0))
    end

    StatusLabel.label = label
    StatusLabel.updateColor(false)
end

function StatusLabel.updateColor(connected)
    if not StatusLabel.label then return end
    if connected then
        StatusLabel.label.Font.Color = 0x00AA00  -- Green
    else
        StatusLabel.label.Font.Color = 0x0000AA  -- Red
    end
end

function StatusLabel.startMonitor()
    local timer = createTimer(nil, false)
    timer.Interval = 1000
    timer.OnTimer = function()
        -- Green when client is connected (pipe busy), Red when waiting
        local connected = Context.pipeServer and Context.pipeServer.Valid and Context.pipeServer.Connected
        StatusLabel.updateColor(connected)
    end
    timer.Enabled = true
    StatusLabel.timer = timer
end

-- Store globally for cleanup on reload
CE_MCP_STATUS_LABEL = StatusLabel

-- Auto-start
local startOk = Server.start()
if startOk then
    StatusLabel.create()
    StatusLabel.startMonitor()
end
