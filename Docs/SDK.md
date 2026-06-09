# BLIND SDK

BLIND exposes two supported SDK surfaces:

- `SDK/include/blind/blind_ipc.h`: the stable host-facing packet ABI for the named-pipe event channel.
- `SDK/include/blind/blind_veh.h`: the exported VEH event helper API for explicit in-process tools.

The IPC surface is the primary integration contract. The VEH surface is narrow and intended for advanced local instrumentation tooling.

## Versioning

Current SDK version:

```text
BLIND_SDK_VERSION_MAJOR=0
BLIND_SDK_VERSION_MINOR=2
BLIND_SDK_IPC_VERSION=IXIPC_VERSION
```

SDK `0.x` means the ABI is controlled but still internal-alpha. Consumers must pin to the matching BLIND source or binary release.

## Public Headers

### `blind_ipc.h`

Use this header when implementing a BLIND host:

```cpp
#include <blind/blind_ipc.h>
```

The header defines:

- default pipe name: `IXIPC_HOOK_PIPE_NAME`;
- pipe override environment variable: `IXIPC_PIPE_NAME_ENV`;
- packet magic and version: `IXIPC_MAGIC`, `IXIPC_VERSION`;
- packet envelope: `IXIPC_PACKET`;
- commands: `IXIPC_COMMAND`;
- event record: `IXIPC_HOOK_EVENT`;
- batch record: `IXIPC_HOOK_EVENT_BATCH`;
- CLI hook policy records: `IXIPC_HOOK_POLICY_RULE` and `IXIPC_QUERY_HOOK_POLICY_RESPONSE`;
- CLI rule flags: logging, stack traces, and register snapshots;
- readiness flags and SDK masks.

Readiness masks:

- `BLIND_SDK_READY_CORE_MASK`: IPC, NT, and KI readiness (`0x0000000D`). This is the minimum healthy standalone runtime mask.
- `BLIND_SDK_READY_FULL_MASK`: all ABI-defined readiness flags (`0x0000001F`): IPC, Winsock, NT, KI, and module. Hosts may observe partial/full masks as lazy module and Winsock coverage becomes active.

### `blind_veh.h`

Use this only for in-process VEH event registration:

```cpp
#include <blind/blind_veh.h>
```

Consumers that link against `BLIND.dll` should define `IX_BLIND_IMPORTS` before including the header and link `BLIND.lib` from the matching build.

Exported functions:

```cpp
PVOID IxRegisterVectoredExceptionHandler(IxBlindTelemetryArguments *args) noexcept;
BOOL IxPromoteVectoredExceptionHandlerToFront() noexcept;
void IxUnregisterVectoredExceptionHandler() noexcept;
```

The caller owns the `IxBlindTelemetryArguments` object and any callback context. Keep it valid until `IxUnregisterVectoredExceptionHandler` returns.

## Build

Build the runtime, test target, diagnostic runner, and SDK host from this directory:

```powershell
msbuild .\VCXProj\BLIND.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindLaunchGateTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindRunner.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64
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

## Sample Host

`SDK/samples/host/BlindSdkHost.cpp` is the minimal integration example. It:

- creates the selected pipe;
- starts an owned target process in a new console;
- loads `BLIND.dll` into that process;
- handles handshake and readiness packets;
- receives single events and event batches;
- acknowledges self-map, hook-patch, and instrumentation registration commands;
- exits successfully only when the child exits cleanly, events were received, and the core readiness mask was observed.

Run:

```powershell
.\bin\Release\x64\BlindSdkHost.exe
.\bin\Release\x64\BlindSdkHost.exe --pipe \\.\pipe\BLINDSdkPipe --verbose
```

## Diagnostics

Use `BlindRunner.exe` for full diagnostic bundles. Use `BlindSdkHost.exe` for SDK integration smoke testing.

Runner diagnostic formats are documented in `Docs/DIAGNOSTICS.md`.

The full runner also includes the launch-gate harness:

```powershell
.\bin\Release\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDLaunchGateDemo
```

That mode starts the owned target suspended, loads `BLIND.dll` with launch-gate preparation enabled, resumes the target, and requires a launch-gate trap event before reporting success.
