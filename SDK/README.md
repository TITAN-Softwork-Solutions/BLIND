# BLIND SDK

The BLIND SDK is the controlled integration surface for the standalone BLIND runtime. It is intended for Titan-owned hosts that load `BLIND.dll` into owned child processes and receive instrumentation events over the BLIND IPC pipe.

Current SDK version: `0.2` (`BLIND_SDK_IPC_VERSION == IXIPC_VERSION`).

## Layout

```text
SDK/
  include/blind/blind_ipc.h
  include/blind/blind_veh.h
  samples/host/BlindSdkHost.cpp
```

- `blind_ipc.h`: public named-pipe packet ABI, pipe override constants, CLI hook policy records, rule flags, and readiness masks.
- `blind_veh.h`: public in-process VEH event registration API. Most hosts should not need this.
- `samples/host/BlindSdkHost.cpp`: minimal host example that creates the pipe, starts an owned target in a new console, loads `BLIND.dll`, and consumes events.

`blind_veh.h` consumers should define `IX_BLIND_IMPORTS` and link the matching `BLIND.lib`. IPC-only hosts do not need the import library.

## Build The Sample Host

```powershell
msbuild .\VCXProj\BlindSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64
```

The sample expects `BLIND.dll` and the owned target executable next to `BlindSdkHost.exe`:

```powershell
.\bin\Release\x64\BlindSdkHost.exe
.\bin\Release\x64\BlindSdkHost.exe --verbose
.\bin\Release\x64\BlindSdkHost.exe --pipe \\.\pipe\BLINDSdkPipe C:\path\to\owned-test.exe
```

## Integration Boundary

The SDK supports owned-process, local-machine integration only:

- host `\\.\pipe\BLINDHookIngest` or set `BLIND_PIPE_NAME`;
- create or otherwise own the target process;
- load `BLIND.dll` only into that owned process;
- process handshake, optional CLI hook policy queries, readiness, hook events, batches, self-map records, and registration records;
- treat `BLIND_SDK_READY_CORE_MASK` (`0x0000000D`: IPC, NT, KI) as the minimum healthy runtime mask, and `BLIND_SDK_READY_FULL_MASK` (`0x0000001F`) as all ABI-defined hook readiness flags;
- preserve audit logs and release artifacts under the BLIND license and Titan DSGL/export-control policy.

Do not add arbitrary-PID attach, persistence, stealth loading, third-party monitoring, or remote deployment paths without a formal Titan security review.

See `Docs/SDK.md` and `Docs/INTEGRATION.md` for the complete host contract.
