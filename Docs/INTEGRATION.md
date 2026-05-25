# BLIND Integration Guide

This guide defines the supported host contract for integrating BLIND as a standalone user-mode EDR sensor component.

## Supported Model

BLIND integration is local and owned-process only:

1. The host chooses a pipe name.
2. The host creates or owns the target process.
3. The host sets BLIND environment variables for the child.
4. The host loads `BLIND.dll` into the child.
5. The DLL connects to the pipe, handshakes, publishes readiness, and emits telemetry.
6. The host acknowledges every valid request packet with one response packet using the same sequence number.

The standalone SDK does not provide a kernel-driver control plane, privileged device transport, arbitrary-PID attach, service deployment, or remote collection.

## Environment

Set these before loading the DLL:

- `BLIND_PIPE_NAME`: optional named-pipe override. Default is `\\.\pipe\BLINDHookIngest`.
- `BLIND_LOG_DIR`: directory for `blind-runtime-<pid>.log`.
- `BLIND_RUNNER_OWNS_PIPE=1`: tells the included test target not to create its own pipe when the host owns IPC.

## Pipe Contract

Use `IXIPC_HOOK_PIPE_NAME` for the default pipe or `BLIND_PIPE_NAME` for a host-selected pipe.

```cpp
CreateNamedPipeW(
    pipeName,
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
    1,
    64 * 1024,
    64 * 1024,
    0,
    nullptr);
```

The host reads and writes fixed-size `IXIPC_PACKET` records. A valid request has:

- `Magic == IXIPC_MAGIC`;
- `Version == IXIPC_VERSION`;
- `PacketType == IxIpcPacketRequest`;
- a command-specific payload.

The response must set:

- `PacketType = IxIpcPacketResponse`;
- `Command = request.Command`;
- `Sequence = request.Sequence`;
- `Status = ERROR_SUCCESS` or a Win32 error code.

## Command Handling

### `IxIpcCommandHandshake`

Return:

- `NegotiatedVersion = IXIPC_VERSION`;
- `Capabilities = 1`;
- `ThreatIntelEnabled = 0` unless the host has a separate approved enrichment path.

### `IxIpcCommandNotifyHookReady`

OR the request `ReadyMask` into the host-observed ready mask.

Use `BLIND_SDK_READY_CORE_MASK` as the complete standalone-ready target:

```text
IPC_CONNECTED | WINSOCK | NT | KI = 0x0000000F
```

Return the observed mask in `NotifyHookReadyResponse.ObservedMask`.

### `IxIpcCommandPublishHookEvent`

Consume one `IXIPC_HOOK_EVENT`.

Important fields:

- `Kind`: event class, such as NT, Winsock, KI, integrity, module, or exception.
- `Operation`: event-specific operation id.
- `ProcessId`, `ThreadId`: source process and thread.
- `ApiName`, `ModuleName`: fixed-size, NUL-terminated best-effort labels.
- `Caller`, `Context0..Context3`: event-specific addresses and values.
- `Args[]`: event-specific arguments.
- `Stack[]`, `StackCount`, `CallerFlags`: stack and caller classification.
- `DataSample`, `DataSize`: bounded printable or binary sample bytes.

Do not block in the packet handling path. Queue event processing to a worker if enrichment, disk writes, or UI updates may be slow.

### `IxIpcCommandPublishHookEventBatch`

Validate `Count <= IXIPC_MAX_HOOK_EVENT_BATCH`, then process each event in order.

### Registration Commands

The runtime may send:

- `IxIpcCommandRegisterInstrumentationRange`;
- `IxIpcCommandRegisterHookPatch`;
- `IxIpcCommandRegisterProcessInstrumentationCallback`.

Standalone hosts should acknowledge these and persist them if diagnostics need a map of BLIND-owned memory, hook patches, syscall stubs, or callback locations. These records are metadata only in standalone mode.

## Self-Map Events

Self-map entries arrive as hook events:

```text
Kind == IxIpcHookEventIntegrity
Operation == IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY
```

Decode:

- `Context0`: `IX_SELF_MAP_KIND_*`;
- `Context1`: address;
- `Context2`: size;
- `Context3`: self-map flags;
- `Args[0]`, `Args[1]`: references;
- `Args[2]`: allocation base;
- `Args[3]`: region size;
- `Args[4]`: high 32 bits are protect, low 32 bits are state;
- `Args[5]`: memory type;
- `Args[6]`: entry index;
- `Args[7]`: high 32 bits are total, low 32 bits are truncated count.

`docs/DIAGNOSTICS.md` documents the TSV form written by the full runner.

## Loading The DLL

The included samples use `CreateRemoteThread` with `LoadLibraryW` against a child process they created. Product integrations can replace that loader with a Titan-reviewed owned-process load path, but the same restrictions apply:

- no arbitrary PID attach;
- no third-party target process;
- no persistence or stealth deployment;
- no remote deployment path;
- no uncontrolled privilege escalation.

## Performance Rules

Host-side IPC handling should remain bounded:

- keep pipe reads and writes synchronous and fixed-size;
- validate packet version and command before reading payload fields;
- send a response for every valid request;
- queue heavy work away from the pipe thread;
- rate-limit console or UI printing;
- preserve raw packets or decoded JSONL if later analysis is required.

## Failure Handling

Recommended host outcomes:

- fail startup if the pipe cannot be created;
- fail startup if `BLIND.dll` or the owned target is missing;
- fail the run if the child exits before handshake;
- fail the run if no hook events are received;
- fail or warn if only `IXIPC_HOOK_READY_FLAG_IPC_CONNECTED` is observed;
- warn if self-map events report truncation.

## Security And Release Controls

All SDK use remains under `LICENSE.md`. Do not publish, transfer, demo, or ship source, binaries, symbols, headers, docs, or derived packages outside Titan-approved DSGL/export-control and secure-use policy.
