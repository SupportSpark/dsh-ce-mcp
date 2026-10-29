# Vendored patches

`mcp/` is the upstream `ce_mcp` 6.0.0 tree, with the minimum local changes needed
to run against Cheat Engine 7.5. Each patch is listed here so it can be dropped
or upstreamed once the source project fixes it.

## 1. `ce_mcp_bridge.lua` — `getProcessNameFromID` does not exist

*Symptom*

```
zz_ce_mcp_bridge.lua:2414: attempt to call a nil value (global 'getProcessNameFromID')
```

`ce_attach_process` failed for every target, so no other tool could run.

*Cause*

Cheat Engine's Lua API has `getProcessIDFromProcessName(name)` and
`getProcessList()` — which returns a `pid -> name` table — but no
`getProcessNameFromID(pid)`. The bridge called the latter.

*Fix*

A local helper resolves the name from `getProcessList()`, and the call site uses it:

```lua
local function mcpProcessNameFromID(pid)
    if not pid or pid == 0 then return nil end
    local pl = getProcessList()
    if type(pl) ~= "table" then return nil end
    return pl[pid]
end
```
