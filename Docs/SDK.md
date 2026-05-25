# BLIND SDK

BLIND exposes two supported SDK surfaces:

- `sdk/include/blind/blind_ipc.h`: the stable host-facing packet ABI for the named-pipe telemetry channel.
- `sdk/include/blind/blind_veh.h`: the exported VEH telemetry helper API for explicit in-process tools.

The IPC surface is the primary integration contract. The VEH surface is narrow and intended for advanced local tooling.

## Versioning

Current SDK version:

```text
BLIND_SDK_VERSION_MAJOR=0
BLIND_SDK_VERSION_MINOR=1
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
- readiness flags and SDK masks.

Readiness masks:

- `BLIND_SDK_READY_CORE_MASK`: IPC, Winsock, NT, and KI readiness. This is the expected complete standalone mask today.
- `BLIND_SDK_READY_FULL_MASK`: all ABI-defined readiness flags, including the module flag. Hosts may observe this when module coverage is active.

### `blind_veh.h`

Use this only for in-process VEH telemetry registration:

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
msbuild .\vcxproj\BLIND.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\vcxproj\BlindTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64
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
```

## Sample Host

`sdk/samples/host/BlindSdkHost.cpp` is the minimal integration example. It:

- creates the selected pipe;
- starts an owned target process;
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

Runner diagnostic formats are documented in `docs/DIAGNOSTICS.md`.

The full runner also includes the launch-gate harness:

```powershell
.\bin\Release\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDLaunchGateDemo
```

That mode starts the owned target suspended, loads `BLIND.dll` with launch-gate preparation enabled, resumes the target, and requires a launch-gate trap event before reporting success.
