[English](README.md) | 中文

# Cheat Engine MCP - AI 辅助逆向工程

MCP 桥接器，让 AI 助手直接控制 Cheat Engine 进行游戏修改和逆向工程。**提供 127 个工具**，覆盖 14 个分类。

## 目录

- [架构](#架构)
- [安装](#安装)
- [连接特性](#连接特性)
- [安全特性](#安全特性)
- [工具参考](#工具参考)
  - [系统与连接](#系统与连接)
  - [内存读写](#内存读写)
  - [扫描与搜索](#扫描与搜索)
  - [扫描会话](#扫描会话)
  - [符号与地址](#符号与地址)
  - [反汇编与代码分析](#反汇编与代码分析)
  - [调试与断点](#调试与断点)
  - [分析工具](#分析工具)
  - [高级分析](#高级分析)
  - [代码模拟](#代码模拟)
  - [内存管理](#内存管理)
  - [进程控制](#进程控制)
  - [注入](#注入)
  - [高级调试](#高级调试)
  - [文件操作](#文件操作)
  - [窗口操作](#窗口操作)
  - [内核操作](#内核操作)
  - [类型转换](#类型转换)
  - [函数 Hook](#函数-hook)
  - [作弊表](#作弊表)
- [推荐工作流](#推荐工作流)
- [故障排除](#故障排除)
- [版本](#版本)

## 架构

```
AI <--MCP/JSON-RPC--> ce_mcp_server.js <--命名管道--> ce_mcp_bridge.lua (CE)
                           ↑
                  后台自动重连
```

## 安装

### 快速开始 (NPX) - 推荐

1. **前提条件**: Node.js 14+ (无需其他依赖项)

2. **在 CE 中加载** (二选一):
   - **自动加载**: 将 `ce_mcp_bridge.lua` 复制到 CE 的 `autorun` 文件夹 (如 `D:\Cheat Engine\autorun\`)
   - **手动加载**: 按 `Ctrl+Alt+L`，执行:
     ```lua
     dofile([[D:\path\to\ce_mcp_bridge.lua]])
     ```

3. **配置 MCP**:
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

### 手动安装 (本地运行)

如果你希望从源码运行:

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

## 连接特性

- **自动重连**: CE 重启后 MCP Server 自动重连
- **后台重试**: 连接尝试在后台进行，使用指数退避
- **失败诊断**: `ce_ping` 在连接失败时返回详细诊断信息
- **线程安全**: 所有管道操作都有锁保护

## 安全特性

### Hook 名称验证

Hook 名称会验证以防止 AA 脚本注入:
- 必须以字母或下划线开头
- 只能包含字母数字和下划线
- 模式: `^[a-zA-Z_][a-zA-Z0-9_]*$`

无效名称如 `"my hook"` 或 `"hook;inject"` 将被拒绝。

---

## 工具参考

### 系统与连接

| 工具 | 说明 |
|------|------|
| `ce_ping` | 测试连接。连接失败时返回诊断信息和故障排除建议。 |
| `ce_get_process_info(refresh_symbols?)` | 获取已附加进程信息: `{name, pid, is64bit, ce_version, debugger, symbols_ready, module_count}`。使用 `ce_get_symbol` 前设 `refresh_symbols=true`（首次调用大型进程可能需要 60-120 秒）。 |
| `ce_attach_process(target)` | 通过 PID 或名称附加到进程。附加后清除缓存和扫描会话。 |
| `ce_auto_assemble(script, target_self?, disable?, disable_info?)` | 执行 AA 脚本。默认执行 `[ENABLE]` 段。设 `disable=true` + 上次返回的 `disable_info` 可执行 `[DISABLE]` 段。返回 `{success, target_self, disableInfo?, action?}`。 |
| `ce_execute_lua(code)` | 在 CE 中执行任意 Lua 代码。 |
| `ce_get_stats` | 桥接统计: `{uptime, commands, summary, cache, scanSessions, connections, debugger}`。 |
| `ce_get_logs(count?, min_level?)` | 日志条目，用于调试。`count` 默认 50，`min_level` 默认 `INFO`。 |

### 内存读写

| 工具 | 说明 |
|------|------|
| `ce_read_memory(address, type, size?, signed?)` | 读取单个值。`type`: byte/word/dword/qword/float/double/string/bytes。`signed` 用于 word/dword 有符号解读。 |
| `ce_read_memory_batch(requests)` | 一次调用读取多个地址。**始终优先使用此方法而非多次调用 ce_read_memory。** `requests`: `[{address, type, id?, size?}]` |
| `ce_write_memory(address, type, value)` | 向内存写入值。返回 `{success, address}`。 |

### 扫描与搜索

| 工具 | 说明 |
|------|------|
| `ce_aob_scan(aob_string, module?, protection?, start?, stop?, max_results?)` | 扫描字节数组模式，支持 `??` 通配符。默认保护: `"+X-C-W"`。 |
| `ce_aob_scan_unique(aob_string, module?, protection?, start?, stop?)` | 扫描唯一字节模式 - 仅返回首个匹配。期望唯一结果时比 `ce_aob_scan` 快得多。返回 `{found, address}` 或 `{found: false}`。 |
| `ce_check_assemble(script, enable?)` | 验证 AA 脚本语法而不执行。返回 `{valid, error_message}`。 |
| `ce_dissect_code(module, analyze_functions?)` | 使用 CE DissectCode 分析模块内所有代码。返回 `{module, functions, referenced_strings, stats}`。 |
| `ce_dbvm_cloak(operation, address, virtual_address?)` | 使用 DBVM 隐藏已修改代码页以绕过反作弊完整性检查。操作: `activate/deactivate/read_original/write_original`。 |
| `ce_value_scan(value, type, module?, protection?, start?, stop?, max_results?, is_hex?)` | 一次性值扫描，用于指针追踪。默认保护: `"+W-C"`。**迭代扫描请使用扫描会话。** |

### 扫描会话

实现 CE 核心的 "首次扫描 → 再次扫描" 工作流。会话在 5 分钟不活动后自动过期。最多 5 个并发会话。

| 工具 | 说明 |
|------|------|
| `ce_scan_new(value, type, module?, protection?)` | 开始新的扫描会话。按类型自动对齐（dword/float 用 4 字节，qword/double 用 8 字节）。 |
| `ce_scan_next(session_id, value, scan_type?, value2?)` | 继续过滤现有会话。`scan_type`: exact/increased/decreased/changed/unchanged/bigger_than/smaller_than/between。 |
| `ce_scan_results(session_id, start_index?, limit?)` | 获取分页结果。 |
| `ce_scan_close(session_id)` | 关闭会话并释放资源。 |
| `ce_scan_list` | 列出所有活动的扫描会话。 |
| `ce_enum_modules` | 列出已加载的模块: `{count, modules: [{name, address, size, path, source}], used_fallback}`。 |

### 符号与地址

| 工具 | 说明 |
|------|------|
| `ce_get_address(expression)` | 将地址表达式解析为数字地址。支持嵌套: `"[[game.exe+100]+20]+8"`。 |
| `ce_get_symbol(address, include_module?)` | 获取符号名称，包含 RTTI 类信息。 |
| `ce_resolve_pointer(base, offsets, read_value?, value_type?)` | 解析多级指针链。返回 `ceNotation` 可直接用于 CE 地址列表。 |
| `ce_auto_guess(address)` | 猜测地址处的值类型。 |

### 反汇编与代码分析

| 工具 | 说明 |
|------|------|
| `ce_disassemble(address, count?, direction?)` | 反汇编指令。`count` 默认 10，`direction`: forward/backward。 |
| `ce_get_instruction_info(address)` | 单条指令详细信息: `{address, opcode, params, bytes, bytesStr, size, isCall, isJump, isRet, isConditionalJump, parameterValue}`。 |
| `ce_analyze_code(address, count?)` | 代码块静态分析 (调用、跳转、引用)。 |

### 调试与断点

| 工具 | 说明 |
|------|------|
| `ce_set_breakpoint(address, type?, size?)` | 设置硬件断点。`type`: execute/write/access。 |
| `ce_break_and_get_regs(address, timeout?, include_xmm?, stack_depth?)` | 断点 + 捕获寄存器 + 调用栈。 |
| `ce_break_and_trace(address, max_steps?, timeout?, stop_on_ret?, trace_into_call?, end_address?, initial_regs?)` | **多步执行跟踪。** 最强大的调试工具。停止原因: ret/end_address/max_steps/timeout。 |
| `ce_cleanup` | 移除所有断点和跟踪。游戏卡住时使用。 |

### 分析工具

| 工具 | 说明 |
|------|------|
| `ce_find_what_accesses(address, size?, duration_ms?, max_records?)` | 查找访问此地址的代码 (CE 的 F5)。监控读写。 |
| `ce_find_what_writes(address, size?, duration_ms?, max_records?)` | 查找写入此地址的代码 (CE 的 F6)。仅监控写入。 |
| `ce_find_pointer_path(address, max_depth?, strategy?)` | **自动指针链追踪。** `max_depth` 1-10 (默认 7)，`strategy`: hybrid/f5/value_scan。 |
| `ce_find_references(address, limit?)` | 查找引用特定地址的所有代码位置。 |
| `ce_find_call_references(address, module?, limit?)` | 查找目标为特定函数的所有 CALL 指令。 |
| `ce_find_function_boundaries(address, max_search?)` | 通过序言/尾声模式检测函数起止。 |
| `ce_generate_signature(address)` | 生成唯一 AOB 特征码。返回 `{address, signature, offset_from_start, byte_count, usage_hint}`。 |

### 高级分析

| 工具 | 说明 |
|------|------|
| `ce_build_cfg(address, max_blocks?, max_instructions?, detect_loops?)` | 构建控制流图。 |
| `ce_detect_patterns(address, max_instructions?, patterns?)` | 检测模式: switch 表、虚函数调用、字符串引用、加密常量。 |
| `ce_compare_functions(address1, address2, max_instructions?)` | 比较两个函数的相似度。 |
| `ce_trace_dataflow(address, register, direction?, max_instructions?)` | 追踪寄存器的数据流。 |
| `ce_program_slice(address, criterion, direction?, max_instructions?)` | 计算程序切片 - 查找影响或受变量影响的所有指令。 |

### 代码模拟

| 工具 | 说明 |
|------|------|
| `ce_symbolic_trace(address, count?, initial_state?, stop_on_call?, stop_on_ret?)` | 轻量级符号执行。`initial_state`: 如 `{"rcx": "this_ptr", "rdx": "arg1"}`。 |
| `ce_call_function(address, args?, call_method?, return_type?, timeout?)` | 在目标进程中调用函数。**警告: 执行真实代码!** 最多 4 个参数。 |

### 内存管理

| 工具 | 说明 |
|------|------|
| `ce_allocate_memory(size, base_address?, protection?)` | 分配内存。`protection`: rw/rwx。返回 `{success, address, size}`。 |
| `ce_deallocate_memory(address, size?)` | 释放已分配的内存。 |
| `ce_get_memory_protection(address)` | 获取页面保护: `{address, protection: {r, w, x}, base, regionSize}`。 |
| `ce_set_memory_protection(address, size, readable?, writable?, executable?)` | 设置页面保护标志。 |
| `ce_copy_memory(source_address, size, destination_address?, method?)` | 在内存区域间复制。 |
| `ce_compare_memory(address1, address2, size, method?)` | 比较两个内存区域。 |
| `ce_full_access(address, size)` | 设置内存保护为 RWX。 |
| `ce_dump_memory(address, size, file_path, mode, verify?)` | 将内存转储到文件/从文件加载/比较。 |

### 进程控制

| 工具 | 说明 |
|------|------|
| `ce_pause_process` | 暂停/挂起目标进程。 |
| `ce_resume_process` | 恢复/取消暂停目标进程。 |
| `ce_speedhack(speed)` | 设置游戏速度。1.0=正常, 0.5=半速, 2.0=双倍。 |
| `ce_enum_threads` | 枚举目标进程中的线程。 |
| `ce_enum_handles(filter?)` | 枚举系统句柄。 |

### 注入

| 工具 | 说明 |
|------|------|
| `ce_inject_dll(dll_path, skip_symbol_reload?)` | 向目标进程注入 DLL。 |
| `ce_inject_dotnet_dll(dll_path, class_name, method_name, parameters?, timeout?)` | 注入 .NET DLL 并执行静态方法。 |
| `ce_compile_c_code(code, address?, target_self?)` | 使用 CE 的 TCC 编译器编译 C 代码并注入。 |
| `ce_compile_c_sharp(code, references?)` | 编译 C# 代码，获取用于注入的文件名。 |

### 高级调试

| 工具 | 说明 |
|------|------|
| `ce_debug_start(interface)` | 启动调试器。`interface`: 0=默认, 1=Windows, 2=VEH, 3=Kernel。 |
| `ce_debug_status` | 调试器状态: `{isDebugging, isBroken, canBreak, interface}`。 |
| `ce_debug_continue(method)` | 从断点继续。`method`: run/stepinto/stepover。 |
| `ce_get_set_context(register_values?, include_xmm?)` | 调试器中断时获取或设置完整寄存器上下文。 |
| `ce_thread_no_break(operation, thread_id?)` | 排除/包含线程的断点触发。`operation`: add/remove/list_threads。 |
| `ce_debug_break_thread(thread_id)` | 强制中断指定线程。 |
| `ce_detach_debugger` | 干净地分离调试器。 |

### 文件操作

| 工具 | 说明 |
|------|------|
| `ce_md5_file(file_path)` | 计算文件的 MD5 哈希。 |
| `ce_file_version(file_path)` | 获取文件版本信息。 |
| `ce_file_ops(operation, path, search_mask?, search_subdirs?)` | 文件操作: exists/delete/list_files/list_dirs。 |
| `ce_write_region_to_file(address, size, file_path)` | 将内存区域写入文件。 |
| `ce_read_region_from_file(address, file_path)` | 将文件加载到目标进程内存。 |

### 窗口操作

| 工具 | 说明 |
|------|------|
| `ce_find_window(class_name?, caption?)` | 按类名和/或标题查找窗口。 |
| `ce_enum_windows` | 列出所有顶层窗口及其 PID 和标题。 |

### 内核操作

| 工具 | 说明 |
|------|------|
| `ce_allocate_shared_memory(name, size?)` | 创建映射到目标进程的命名共享内存。 |
| `ce_get_physical_address(address)` | 将虚拟地址转换为物理地址。 |

### 类型转换

| 工具 | 说明 |
|------|------|
| `ce_type_conversion(conversion, value, signed?)` | 在类型间转换。转换: word_to_bytes, dword_to_bytes, qword_to_bytes, float_to_bytes, double_to_bytes, string_to_bytes, bytes_to_word, bytes_to_dword, bytes_to_qword, bytes_to_float, bytes_to_double, bytes_to_string。 |

### 函数 Hook

| 工具 | 说明 |
|------|------|
| `ce_hook_function(address, name, capture_args?, capture_return?)` | Hook 函数以拦截调用。`capture_args` 0-4 (默认 4)，`capture_return` (默认 true)。返回 `{success, name, address, symbol, capture_args, capture_return, trampoline}`。 |
| `ce_get_hook_log(name, limit?, clear?)` | 获取捕获的函数调用参数。 |
| `ce_unhook_function(name)` | 移除函数 Hook。 |
| `ce_list_hooks` | 列出所有活动的 Hook。 |

### 作弊表

| 工具 | 说明 |
|------|------|
| `ce_get_address_list(include_script?)` | 获取作弊表中的所有记录。 |
| `ce_add_address_record(description, address, value_type?, script?)` | 向作弊表添加新记录。 |

---

## 推荐工作流

### 指针追踪

```json
// 自动 (首选)
{"name": "ce_find_pointer_path", "arguments": {"address": "0x255D5E758"}}
// 返回: base_address, offsets, ce_pointer_notation

// 手动 (自动失败时)
// 1. 查找访问该地址的代码
{"name": "ce_find_what_accesses", "arguments": {"address": "0x255D5E758"}}
// 2. 从结果获取寄存器值 (如 RBX=0x255D5E658)
// 3. 搜索存储该值的指针
{"name": "ce_value_scan", "arguments": {"value": "0x255D5E658", "type": "qword"}}
// 4. 重复直到找到 game.exe+offset
```

### 函数分析

```json
// 1. 查找函数边界
{"name": "ce_find_function_boundaries", "arguments": {"address": "0x14587EDB0"}}
// 2. 跟踪执行
{"name": "ce_break_and_trace", "arguments": {"address": "0x14587EDB0", "max_steps": 100}}
// 3. 生成特征码用于更新
{"name": "ce_generate_signature", "arguments": {"address": "0x14587EDB0"}}
```

### 逆向未知代码

```json
// 1. 反汇编
{"name": "ce_disassemble", "arguments": {"address": "0x14587EDB0", "count": 20}}
// 2. 符号跟踪理解逻辑
{"name": "ce_symbolic_trace", "arguments": {"address": "0x14587EDB0", "initial_state": {"rcx": "this"}}}
// 3. 为复杂函数构建 CFG
{"name": "ce_build_cfg", "arguments": {"address": "0x14587EDB0"}}
// 4. 检测模式
{"name": "ce_detect_patterns", "arguments": {"address": "0x14587EDB0"}}
```

---

## 故障排除

| 问题 | 解决方案 |
|------|----------|
| 连接失败 | 使用 `ce_ping` - 返回诊断信息和具体建议 |
| CE 重启 | MCP Server 自动重连，只需在 CE 中重新加载 Lua 脚本 |
| 管道错误 | 在 CE 中运行 `CE_MCP.stop()` 然后 `CE_MCP.start()` |
| 权限拒绝 | 以管理员身份运行 CE |
| 游戏卡住 | 使用 `ce_cleanup()` 移除所有断点 |
| 断点未触发 | 确保代码路径在游戏中被执行 |

## 状态检查

```lua
CE_MCP.stats()  -- 在 CE 中检查桥接状态
reloadMcpBridge()  -- 代码更改后重新加载桥接
```

## 参考

- [CE Wiki](https://wiki.cheatengine.org/)
- [CE Lua API](https://wiki.cheatengine.org/index.php?title=Lua)

## 版本

- **MCP 工具**: 127 个
- **分类**: 14 个 (System, Memory, Scanning, Symbols, Debug, Analysis, Injection, Table, DotNet, Process, FileIO, Window, Kernel, Type Conversion)
- **Lua 桥接**: ~10,400 行

---

*最后更新: 2026-04-20*
