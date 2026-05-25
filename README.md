# BLIND

BLIND is a standalone, user-mode EDR sensor runtime for owned-process telemetry. The runtime DLL publishes readiness, hook telemetry, self-map metadata, and exception telemetry to a host-controlled IPC service.

The integration model is intentionally plug-in oriented:

- IPC services are pluggable: host the default `\\.\pipe\BLINDHookIngest`, pass `--pipe \\.\pipe\Name` to the runner or SDK host, or set `BLIND_PIPE_NAME` before loading `BLIND.dll`.
- Collection services are pluggable: hosts consume the packet ABI in `sdk/include/blind/blind_ipc.h` and can route events to files, queues, UI, or a larger sensor backend.
- Hook surfaces are pluggable: NT, Winsock, KI, exception, integrity, and self-map surfaces publish through the same event envelope.
- DLL exports provide explicit local API arguments: see `sdk/include/blind/blind_veh.h` and the `IxBlindTelemetryArguments` helpers.
- Runner scaffolding is included: `BlindRunner.exe` is the full diagnostic harness and `BlindSdkHost.exe` is the minimal SDK host sample.

Standalone boundaries:

- no kernel-driver control plane or privileged device transport;
- no protected-range read/write result rewriting;
- no PEB unlinking or hidden-thread filtering;
- no arbitrary PID attach, persistence, service deployment, or third-party monitoring path;
- no generic module-inline trampoline layer in standalone builds.

## Projects

- `vcxproj/BLIND.vcxproj` builds `BLIND.dll`.
- `vcxproj/BlindRunner.vcxproj` builds the diagnostic runner and IPC endpoint.
- `vcxproj/BlindSdkHost.vcxproj` builds the minimal SDK integration host.
- `vcxproj/BlindTestTarget.vcxproj` builds a benign owned test process.

Build from this directory:

```powershell
msbuild .\vcxproj\BLIND.vcxproj /p:Configuration=Debug /p:Platform=x64
msbuild .\vcxproj\BlindTestTarget.vcxproj /p:Configuration=Debug /p:Platform=x64
msbuild .\vcxproj\BlindRunner.vcxproj /p:Configuration=Debug /p:Platform=x64
msbuild .\vcxproj\BlindSdkHost.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## Harness Demo

Run the full harness:

```powershell
.\bin\Debug\x64\BlindRunner.exe
```

Run with verbose event printing and a custom pipe:

```powershell
.\bin\Debug\x64\BlindRunner.exe --pipe \\.\pipe\BLINDDemoPipe --verbose
```

Run the early launch-gate harness:

```powershell
.\bin\Debug\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDLaunchGateDemo
```

`--launch-gate` creates the owned target suspended, loads `BLIND.dll` with `IX_HOOK_LAUNCH_GATE=1`, resumes the primary thread, and fails unless a launch-gate trap event is observed and the target exits cleanly.

The runner starts an owned child target, loads `BLIND.dll`, hosts the pipe, waits for `BLIND_SDK_READY_CORE_MASK`, and exits successfully only when the child exits cleanly and at least one hook event was received.

Each runner execution writes:

```text
.\bin\<Configuration>\<Platform>\BlindDiagnostics\run-YYYYMMDD-HHMMSS-<runner-pid>\
```

The bundle includes `summary.txt`, `events.jsonl`, `selfmap.tsv`, and `logs\blind-runtime-<target-pid>.log`.

## SDK Host

The SDK host is the smallest plug-in IPC service example:

```powershell
.\bin\Debug\x64\BlindSdkHost.exe
.\bin\Debug\x64\BlindSdkHost.exe --pipe \\.\pipe\BLINDSdkPipe --verbose
```

The target can also self-host the pipe for direct local diagnostics when `BLIND.dll` is next to it:

```powershell
.\bin\Debug\x64\BlindTestTarget.exe
```

See `docs\SDK.md`, `docs\INTEGRATION.md`, `docs\DIAGNOSTICS.md`, and `docs\RELEASE.md` for packet details, host responsibilities, diagnostic formats, and push readiness.

## Security Boundary

BLIND is for internal EDR-sensor engineering, regression testing, and secure-systems analysis against owned processes. Do not deploy it as a bypass, persistence, stealth, or third-party monitoring component. See `LICENSE.md`.
