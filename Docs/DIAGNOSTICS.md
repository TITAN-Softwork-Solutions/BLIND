# BLIND Diagnostics

BLIND has two supported diagnostic modes:

- `BlindRunner.exe` starts an owned child in a new console, loads `BLIND.dll`, hosts the selected pipe, and writes a decoded diagnostic bundle.
- `BlindTestTarget.exe` run directly self-hosts the same pipe when `BLIND.dll` is next to it, loads the DLL in-process, and writes a direct diagnostic bundle.

It also has a CLI mode for quick owned-process hook debugging. CLI mode uses the same runner and IPC pipe, starts the target in its own console, installs only the requested NT/module/Winsock hook policy, and disables diagnostic file logging unless `--debug` is present.

## Commands

```powershell
.\bin\Debug\x64\BlindRunner.exe
.\bin\Debug\x64\BlindRunner.exe --verbose
.\bin\Debug\x64\BlindRunner.exe --pipe \\.\pipe\BLINDDemoPipe --verbose
.\bin\Debug\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDLaunchGateDemo
.\bin\Debug\x64\BlindTestTarget.exe
```

`--verbose` only changes BLIND runner console output. Target stdout/stderr appears in the target's separate console. The JSONL, TSV, summary, and runtime log files are written either way.

CLI examples:

```powershell
.\blind.cmd .\sample.exe --lhook NtAllocateVirtualMemory --deny
.\blind.cmd .\sample.exe --lhook NtAllocateVirtualMemory --stack-trace --sym --r --hook NtCreateThreadEx --deny
.\blind.cmd .\sample.exe --behavior --when alloc.total>1MB
.\blind.cmd .\sample.exe --lhook NtProtectVirtualMemory --stack-trace --sym
.\blind.cmd .\sample.exe --lhook amsi --stack-trace --sym
.\blind.cmd .\sample.exe --lhook etw
.\blind.cmd .\sample.exe --lhook winsock
.\blind.cmd --lhook NtAllocateVirtualMemory --ignore-dll ntdll -- .\sample.exe --target-flag
.\blind.cmd --timeout 12s --behavior=all --behavior-stacks 6 --summary-interval 0 --lhooks loader,etw,amsi,winsock,http,crypto,credentials,exceptions,NtProtectVirtualMemory,NtCreateThreadEx,NtAllocateVirtualMemory --stack-trace --sym -- .\ab_secure.exe
```

CLI options:

- `--hook <api|group>` installs an explicit hook without console logging by default. Prefixes are accepted as `nt:`, `module:`, `winsock:`, or `group:`.
- `--lhook <api|group>` installs an explicit log-hook and prints de-duplicated hits. `NtProtectVirtualMemory` log-hooks auto-enable behavior folding unless `--raw` is used.
- `--hooks <list>` and `--lhooks <list>` install comma/semicolon-separated hooks or groups, so `--lhooks NtAllocateVirtualMemory,NtProtectVirtualMemory,loader` applies later rule options to the whole list.
- `--groups <list>` and `--lgroups <list>` install named group lists. Groups include `behavior`, `memory`, `remote`, `injection`, `process`, `thread`, `file`, `token`, `anti-analysis`, `loader`, `etw`, `amsi`, `winsock`, `http`, `network`, `crypto`, `credentials`, `sspi`, `vault`, `dpapi`, `com`, `jobs`, `cloud`, and `exceptions`.
- `--timeout <duration>` terminates long-lived samples after values like `15000`, `30s`, or `2m`; use `0`/`none` for no target timeout.
- `--hook-group <name>` and `--lhook-group <name>` install one named group. The group set matches `--groups` and `--lgroups`.
- `--deny` blocks the previous hook rule with `STATUS_ACCESS_DENIED`.
- `--silent-deny` drops the previous hook rule with `STATUS_SUCCESS`.
- `--stack-trace` prints stack frames for the previous hook rule. Frames are role-tagged as `[internal]`, `[system]`, `[runtime]`, `[app]`, `[module]`, or `[private]` so BLIND/runtime/system frames are easier to separate from target behavior. Folded `NtProtectVirtualMemory` streams keep grouped caller/callsite summaries instead of per-event frames.
- `--sym` and `--syms` try DbgHelp symbol resolution for frames printed by `--stack-trace`.
- `--sym-path <path>` overrides DbgHelp's symbol search path. Use `_NT_SYMBOL_PATH` or a path such as `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols` when you want Windows/CLR public symbols.
- `--r`, `--regs`, and `--registers` print a hook-time register snapshot for the previous hook rule.
- `--behavior[=areas]` prints behavior summaries for allocations, VAD state, protections, writes, thread starts, APCs, and maps instead of raw spam.
- `--behavior-stacks[=N|all]` prints one representative folded stack for each printed behavior region/protect/thread group; default is all captured frames. The spaced form `--behavior-stacks N` works too.
- `--behavior-protect-stacks` also collects folded stacks for `NtProtectVirtualMemory`; enable it deliberately because protect loops can be hot.
- `--raw` prints raw hook lines alongside behavior summaries or auto-folded protect summaries.
- `--summary-interval <ms>` prints periodic behavior summaries; `0` means final summary only.
- `--when <condition>` prints behavior alerts for `rwx`, `remote`, `start.private`, `protect.flips>=N`, `thread.count>=N`, or `alloc.total>NMB`.
- Built-in `[blind:detection]` lines always print for BLIND hook patching, AMSI/ETW export patching, double-loaded `ntdll.dll`, guarded `ntdll.dll` export-table reads that look like SSN resolution, and private pages containing direct-syscall stubs. Direct-syscall pages are dumped under `logs\` when diagnostics are enabled. Add `--guard-direct-syscalls` to PAGE_GUARD those pages and capture follow-up reads/executes; leave it off for protected targets that rely on guard pages or single-step-sensitive code.
- `--color[=auto|always|never]` and `--no-color` control stdout coloring. Color is automatic for real consoles; redirected output and diagnostic files remain plain.
- `--ignore-dll <name>` and `--ignore-private` suppress caller noise.
- `--verbose` prints all CLI NT hook events; `--debug` also writes the normal diagnostic bundle.

Non-NT hook groups are lazy. BLIND keeps the loader path hooked, but it does not import or `LoadLibrary` optional DLLs just because a group was requested. When the target loads `amsi.dll`, `ws2_32.dll`, eventing DLLs, or other covered modules, the loader hook refreshes module/winsock hooks immediately.

## Bundle Layout

Runner bundles:

```text
.\bin\<Configuration>\<Platform>\BlindDiagnostics\run-YYYYMMDD-HHMMSS-<runner-pid>\
```

Direct self-host bundles:

```text
.\bin\<Configuration>\<Platform>\BlindDiagnostics\direct-YYYYMMDD-HHMMSS-<target-pid>\
```

Files:

- `summary.txt`: run-level status, ready mask, event totals, event kind counts, self-map kind counts, and important paths.
- `events.jsonl`: one hook/event record per line with pid, tid, kind, operation, API/module, caller, context fields, arguments, and printable data sample.
- `selfmap.tsv`: decoded BLIND self-map entries showing runtime state, owned ranges, indirection handles, syscall stubs, hook patch metadata, and memory attributes.
- `logs\blind-runtime-<pid>.log`: BLIND runtime log covering `DllMain`, bootstrap thread creation, init path, IPC readiness, hook controller setup, self-map publication, and process detach.

Behavior summaries are runner console output today. They aggregate the live event stream into target-aware memory regions, protection histories, write totals, and thread/APC start groups while preserving raw events in `events.jsonl` when diagnostics are enabled. Protection summaries group `NtProtectVirtualMemory` by target, caller, old/new protection, page count, address span, VAD facts, caller memory region, risk labels such as `private_rwx` or `rwx_transition`, and sampled private/RWX stack-frame evidence so page-flip loops show up as behavior instead of console spam. `--behavior-stacks` prints representative grouped frames underneath those folded summaries; `--behavior-protect-stacks` or a hook-level `--stack-trace` enables the same behavior for protect groups.

Launch-gate runs add `launch_gate_mode=1` and `launch_gate_traps=<count>` to `summary.txt`. The runtime log should show `DllMain: PROCESS_ATTACH launchGate=1`, `LaunchGatePrepare: prepared`, `LaunchGateHandleFault: redirected`, and `LaunchGateInitializeThunk: resuming original thread`.

## Self-Map Columns

`selfmap.tsv` columns:

- `index`, `total`, `truncated`: snapshot ordering and whether BLIND had more entries than the fixed publication budget.
- `kind`: `runtime`, `indirect_handle`, `hook_patch`, `syscall_stub`, `launch_gate_page`, `launch_gate_context`, `callback`, or `summary`.
- `owner`, `name`: component and local structure/function name.
- `address`, `size`: address range or object location.
- `flags`: BLIND ownership, executable/write/guard/reference, and memory classification flags.
- `ref0`, `ref1`: kind-specific references, such as handle slot metadata or original target details.
- `allocation_base`, `region_size`, `protect`, `state`, `type`: `VirtualQuery` memory facts for the address.

## Environment

- `BLIND_PIPE_NAME`: optional named-pipe override. Default is `\\.\pipe\BLINDHookIngest`.
- `BLIND_LOG_DIR`: forces the BLIND runtime log directory.
- `BLIND_RUNNER_OWNS_PIPE=1`: tells the test target not to self-host because the runner owns the pipe.

Expected core readiness for a complete local run is `ready_mask=0x0000000D`, matching `BLIND_SDK_READY_CORE_MASK`: IPC, NT, and KI coverage are active. CLI runs that enable module hooks commonly publish `0x0000001D` after module initialization. `BLIND_SDK_READY_FULL_MASK` is `0x0000001F` when IPC, Winsock, NT, KI, and module coverage are all active.

## Example Run Logs

The README contains short examples captured from Release runs against `ab_secure.exe`, `RefractionMirage.exe`, and `edgeSnapper.exe`. The full local run logs used for that documentation pass were written under:

```text
analysis-output\blind-showcases\
```

Those logs are local analysis artifacts, not release payloads.
