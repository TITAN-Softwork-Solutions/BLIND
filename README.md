<h1 align="center">BLIND</h1>

<p align="center"><b>Standalone user-mode EDR sensor runtime for owned-process telemetry, hook diagnostics, launch-gate validation, and SDK host integration.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/-00599C?logo=c%2B%2B&logoColor=white&style=for-the-badge" />
</p>

**BLIND** is a standalone Windows user-mode EDR sensor component. It loads into an owned child process, initializes local hook surfaces, publishes readiness and telemetry over a host-controlled IPC pipe, and emits diagnostic self-map metadata for runtime validation.

## REQUIREMENTS

Windows 10 22H2 or higher, 64-bit, with Visual Studio 2022+ and the MSVC C++ toolchain.

> [!IMPORTANT]
> BLIND is intended for controlled EDR-sensor engineering, regression testing, and secure-systems analysis against owned processes.
> Do not deploy it as a persistence, stealth, bypass, or third-party monitoring component.

## FEATURES

- Standalone `BLIND.dll` user-mode sensor runtime with no kernel-driver control plane
- Host-controlled named-pipe telemetry over the public `IXIPC` packet ABI
- Custom pipe selection through `BLIND_PIPE_NAME`, `--pipe`, or host-side SDK configuration
- Readiness reporting for IPC, Winsock, NT, KI, and optional full hook state
- Usermode hook telemetry for NT, Winsock, KI/PIC, exception, integrity, and runtime self-map surfaces
- Launch-gate mode for suspended owned-process startup, first-entry trap capture, runtime initialization, and controlled resume
- Hook event batching, asynchronous publication, readiness acknowledgement, and diagnostic fallback paths
- Self-map telemetry for runtime state, indirect handles, hook patches, syscall stubs, launch-gate pages, and launch-gate park contexts
- Exported local VEH telemetry API through `IxRegisterVectoredExceptionHandler`, `IxPromoteVectoredExceptionHandlerToFront`, and `IxUnregisterVectoredExceptionHandler`
- Diagnostic runner that injects the DLL, hosts the IPC service, captures events, writes logs, and fails closed when expected telemetry is missing
- Minimal SDK host sample that shows how to integrate BLIND into another local sensor or collection service
- Benign owned test targets for normal injection smoke testing and early launch-gate validation

## PROJECTS

- `vcxproj/BLIND.vcxproj` builds `BLIND.dll`
- `vcxproj/BlindRunner.vcxproj` builds the diagnostic runner and IPC endpoint
- `vcxproj/BlindSdkHost.vcxproj` builds the minimal SDK integration host
- `vcxproj/BlindTestTarget.vcxproj` builds the normal benign owned test process
- `vcxproj/BlindLaunchGateTarget.vcxproj` builds the no-CRT launch-gate target

## HARNESS DEMO

Run the normal diagnostic harness:

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

Each runner execution writes a diagnostic bundle:

```text
.\bin\<Configuration>\<Platform>\BlindDiagnostics\run-YYYYMMDD-HHMMSS-<runner-pid>\
```

The bundle includes `summary.txt`, `events.jsonl`, `selfmap.tsv`, and `logs\blind-runtime-<target-pid>.log`.

## SDK INTEGRATION

The SDK surface is intentionally small:

- `sdk/include/blind/blind_ipc.h`: host-facing IPC packet ABI, pipe constants, event records, batches, and readiness masks
- `sdk/include/blind/blind_veh.h`: exported in-process VEH telemetry helper API
- `sdk/samples/host/BlindSdkHost.cpp`: minimal host that creates the pipe, starts an owned target, loads `BLIND.dll`, and consumes telemetry

Run the SDK host:

```powershell
.\bin\Debug\x64\BlindSdkHost.exe
.\bin\Debug\x64\BlindSdkHost.exe --pipe \\.\pipe\BLINDSdkPipe --verbose
```

Consumers that link against `BLIND.dll` should define `IX_BLIND_IMPORTS` and link the matching `BLIND.lib`.

## COMPILATION

Build from this directory with Visual Studio 2022+ MSBuild:

```powershell
msbuild .\vcxproj\BLIND.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\vcxproj\BlindTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\vcxproj\BlindLaunchGateTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\vcxproj\BlindRunner.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\vcxproj\BlindSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64
```

Expected artifacts:

```text
.\bin\Release\x64\BLIND.dll
.\bin\Release\x64\BLIND.lib
.\bin\Release\x64\BlindRunner.exe
.\bin\Release\x64\BlindSdkHost.exe
.\bin\Release\x64\BlindTestTarget.exe
.\bin\Release\x64\BlindLaunchGateTarget.exe
```

Release preflight:

```powershell
.\bin\Release\x64\BlindRunner.exe
.\bin\Release\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDReleaseLaunchGate
.\bin\Release\x64\BlindSdkHost.exe
```

A passing launch-gate run reports `ready_mask=0x0000000F`, `child_exit=0x00000000`, and `launch_gate_traps > 0`.

## DOCUMENTATION

- `docs/SDK.md`: SDK headers, packet ABI, and host expectations
- `docs/INTEGRATION.md`: integration boundary and host responsibilities
- `docs/DIAGNOSTICS.md`: runner output, event JSONL, self-map TSV, and runtime logs
- `docs/RELEASE.md`: controlled handoff and preflight checklist

## DISCLAIMER

BLIND is provided for authorized internal security engineering, defensive validation, and controlled research only. Unauthorized monitoring, deployment, evasion, persistence, or use against systems you do not own or administer may violate law and policy.

## LICENSE

Copyright (c) TITAN Softwork Solutions. All rights reserved.

BLIND is governed by `LICENSE.md`: PolyForm Noncommercial 1.0.0 with a BLIND Defensive Use Addendum and DSGL/export-control notice.
