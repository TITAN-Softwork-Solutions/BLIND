# BLIND Diagnostics

BLIND has two supported diagnostic modes:

- `BlindRunner.exe` starts an owned child, loads `BLIND.dll`, hosts the selected pipe, and writes a decoded diagnostic bundle.
- `BlindTestTarget.exe` run directly self-hosts the same pipe when `BLIND.dll` is next to it, loads the DLL in-process, and writes a direct diagnostic bundle.

## Commands

```powershell
.\bin\Debug\x64\BlindRunner.exe
.\bin\Debug\x64\BlindRunner.exe --verbose
.\bin\Debug\x64\BlindRunner.exe --pipe \\.\pipe\BLINDDemoPipe --verbose
.\bin\Debug\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDLaunchGateDemo
.\bin\Debug\x64\BlindTestTarget.exe
```

`--verbose` only changes console output. The JSONL, TSV, summary, and runtime log files are written either way.

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
- `events.jsonl`: one hook/event telemetry record per line with pid, tid, kind, operation, API/module, caller, context fields, arguments, and printable data sample.
- `selfmap.tsv`: decoded BLIND self-map entries showing runtime state, owned ranges, indirection handles, syscall stubs, hook patch metadata, and memory attributes.
- `logs\blind-runtime-<pid>.log`: BLIND runtime log covering `DllMain`, bootstrap thread creation, init path, IPC readiness, hook controller setup, self-map publication, and process detach.

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

Expected readiness for a complete local run is `ready_mask=0x0000000F`, matching `BLIND_SDK_READY_CORE_MASK`: IPC, NT, KI, and Winsock coverage are active. The ABI also defines a module readiness flag for builds that publish module coverage separately.
