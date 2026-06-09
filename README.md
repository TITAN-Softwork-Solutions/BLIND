<h1 align="center">BLIND</h1>

<p align="center"><b>Windows user-mode instrumentation that turns hooks, launch-gate injection, direct-syscall probes, and runtime self-maps into readable process behavior.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/-00599C?logo=c%2B%2B&logoColor=white&style=for-the-badge" />
</p>

Ever wondered exactly what an executable is doing? What API's it's calling? If it's "Suspicious", or you don't want it touching something? **BLIND** is the perfect tool for you to find out!

**BLIND** is a Windows user-mode process-instrumentation tool. It injects or manual-maps `BLIND.dll`, arms NT/module/Winsock/VEH hook surfaces before user code gets a head start, and streams structured telemetry that exposes & explains behaviour: API hits, callers, stack/register context, memory protection flips, direct-syscall pages, launch-gate state, and runtime self-mapping metadata.

Use it when you need to validate EDR/endpoint detections, reverse malicious process behaviour, find out exactly what a process is doing, test hook policies, or build a local sensor around concrete Windows runtime evidence.

## REQUIREMENTS

Windows 10 22H2 or higher, 64-bit, with Visual Studio 2022+ and the MSVC C++ toolchain.

## WHAT IT DOES

- Start an owned process, load `BLIND.dll` by `LoadLibrary` or manual map, and verify readiness before the target resumes
- Log NT/module/Winsock API activity with caller offsets, stack role tags, register snapshots, deny policies, and caller filters
- Fold noisy memory, protection, thread, map, handle, and remote-read activity into compact behavior summaries
- Detect direct-syscall pages, guarded `ntdll` export-table reads, hook patch state, syscall stubs, launch-gate pages, and runtime self-map changes
- Export structured events over the public `IXIPC` packet ABI for host tools, SDK integrations, and diagnostic bundles

## REPOSITORY LAYOUT

- `DLL/`: injected runtime, hook implementations, IPC client, VEH/guard logic, and runtime self-map telemetry
- `Injector/`: `BlindRunner.exe` controller code, split by responsibility into `App/`, `Core/`, `Policy/`, `Telemetry/`, `Diagnostics/`, `Ipc/`, and `Launch/`
- `Mapper/`: manual-map loader used by the runner when `--manual-map` / `--mm` is selected
- `SDK/`: public headers and sample host for direct integration
- `Testing/`: owned probe targets compiled into `BlindTestTarget.exe` and `BlindLaunchGateTarget.exe`
- `Scripts/`: local build, verification, cleanup, connectivity, formatting, and mitigation test harnesses
- `Docs/`: SDK, integration, diagnostics, and controlled-release notes

## RELEASE TEST CAPTURES

The examples below are curated Release x64 captures from the local
`BlindRunner.exe` / `BlindTestTarget.exe` tests. PIDs, pipe suffixes, stack
addresses, and ASLR bases are from this capture and will differ on another run;
the event fields, counts, and verdicts are real output, not pseudocode.

### API log-hook smoke

```powershell
.\bin\Release\x64\BlindRunner.exe --cli .\bin\Release\x64\BlindTestTarget.exe --lhook NtQueryInformationProcess
```

```text
[blind] listening on \\.\pipe\BLINDCli-32620
[blind] child pid=35264 target=.\bin\Release\x64\BlindTestTarget.exe launch_gate=1 guarded=0 inject=loadlibrary
[blind] hook client connected
[blind] ready pid=35264 mask=0x00000001 observed=0x00000001
[blind] ready pid=35264 mask=0x00000005 observed=0x00000005
[blind] ready wait=0 mask=0x00000005
[blind] ready pid=35264 mask=0x0000000D observed=0x0000000D
[blind] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x21B8E args=[0xFFFFFFFFFFFFFFFF,0x34,0x58AB7BF2A0,0x8]
[blind] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x4194E args=[0xFFFFFFFFFFFFFFFF,0x25,0x58AB7BF370,0x40]
[blind] child exit=0x00000000 events=25 suppressed=0
[blind] launch-gate traps=0
```

### Stack, symbols, and registers

```powershell
.\bin\Release\x64\BlindRunner.exe --cli .\bin\Release\x64\BlindTestTarget.exe --lhook NtQueryInformationProcess --stack-trace --syms --r
```

```text
[blind] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x21B8E args=[0xFFFFFFFFFFFFFFFF,0x34,0xDDB94FF460,0x8]
    regs rip=0x7FFA645D1B8E rsp=0xDDB94FDF50 rbp=0xDDB94FE570 rax=0x0 rbx=0x7FFA645D1B8E rcx=0xFFFFFFFFFFFFFFFF rdx=0x34 rsi=0xDDB94FEDB0 rdi=0xDDB94FE4A0 r8=0xDDB94FF460 r9=0x8 r10=0x7FFA53840000 r11=0x7FFA5385E62B r12=0x8 r13=0x0 r14=0xDDB94FE4C8 r15=0x0 eflags=0x206
    #00 [internal] BLIND.dll!IX_NT::NtQueryInformationProcess_Hook+0xB2
    #01 [system]   KERNELBASE.dll!GetProcessMitigationPolicy+0x4E
    #02 [system]   ws2_32.dll!getnameinfo+0x1BCA
    #03 [system]   ws2_32.dll!getnameinfo+0x589
    #04 [system]   ws2_32.dll!WSASocketW+0xAC3
    #05 [system]   ws2_32.dll!getnameinfo+0x1AB4
    #06 [system]   ws2_32.dll!getnameinfo+0x8C0
    #07 [system]   ws2_32.dll!WSAStartup+0x4EE
    #08 [system]   ws2_32.dll!WSAStartup+0x30C
    #09 [app]      BlindTestTarget.exe!`anonymous namespace'::ExerciseWinsock+0x131
    #10 [app]      BlindTestTarget.exe!wmain+0x55E
    #11 [app]      BlindTestTarget.exe!__scrt_common_main_seh+0x10F
    #12 [system]   KERNEL32.DLL!BaseThreadInitThunk+0x17
    #13 [system]   ntdll.dll!RtlUserThreadStart+0x2C
```

### Deny policy

```powershell
.\bin\Release\x64\BlindRunner.exe --cli .\bin\Release\x64\BlindTestTarget.exe --lhook NtQueryInformationProcess --deny
```

```text
[blind] NtQueryInformationProcess denied status=0xC0000022 caller=KERNELBASE.dll+0x21B8E args=[0xFFFFFFFFFFFFFFFF,0x34,0x623A6FF350,0x8]
[blind] NtQueryInformationProcess denied status=0xC0000022 caller=KERNELBASE.dll+0x4194E args=[0xFFFFFFFFFFFFFFFF,0x25,0x623A6FF420,0x40]
[blind] child exit=0x00000000 events=25 suppressed=0
```

### Manual-map injection

```powershell
.\bin\Release\x64\BlindRunner.exe --cli --mm .\bin\Release\x64\BlindTestTarget.exe --lhook NtQueryInformationProcess
```

```text
[blind] child pid=41152 target=.\bin\Release\x64\BlindTestTarget.exe launch_gate=1 guarded=0 inject=manual-map
[blind] manual-map visible=0 base=0x0 mapped=0x180000000
[blind] ready wait=0 mask=0x00000005
[blind] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x21B8E args=[0xFFFFFFFFFFFFFFFF,0x34,0xA849AFF410,0x8]
[blind] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x4194E args=[0xFFFFFFFFFFFFFFFF,0x25,0xA849AFF4E0,0x40]
[blind] child exit=0x00000000 events=25 suppressed=0
```

### Behavior folding

```powershell
.\bin\Release\x64\BlindRunner.exe --cli .\bin\Release\x64\BlindTestTarget.exe --behavior
```

```text
[blind] child exit=0x00000000 events=122 suppressed=0
[blind:behavior] final targets=1 regions=10 protect_groups=13 thread_starts=1 handles=0
[blind:behavior] memory target=self allocs=15 total=3.10MB pages=793 maps=5 mapped=2.72MB regions=10 protects=48 queries=0 query_info=0B reads=0 read=0B writes=0 written=0B opens=0/0 rwx=2.72MB threads=1 apc=0 risk=rwx
[blind:behavior] protect target=self count=7 pages=14 size=8.00KB RW->R first=0x24DAFC30000 last=0x24DAFC30000 span=0x24DAFC30000-0x24DAFC30000 vad=MEM_COMMIT/MEM_PRIVATE caller=ntdll.dll+0x40974 stack=0x2B68C4E0DAABA1B5 rwx=0 risk=- caller_region=MEM_IMAGE/RX
[blind:behavior] region target=self base=0x24DAFC30000 size=8.00KB pages=2 protect=R vad=MEM_COMMIT/MEM_PRIVATE alloc_protect=RW alloc_type=0x0 allocs=0 maps=0 protects=13 flips=13 queries=0 last_query=MemoryBasicInformation(0) reads=0 read=0B writes=0 written=0B caller=ntdll.dll+0x40974 stack=0x2B68C4E0DAABA1B5 risk=protect_flips seq=R->RW->R->RW->R->RW->R->R->RW->R->RW->R->RW->R caller_region=MEM_IMAGE/RX
[blind:behavior] thread target=self count=1 suspended=0 start=0x7FFA637475D0 private=0 vad=MEM_COMMIT/MEM_IMAGE/RX start_region=MEM_IMAGE/RX caller=KERNELBASE.dll+0xC8079 stack=0xBD624BEEB1544B29 risk=- caller_region=MEM_IMAGE/RX
```

### Direct-syscall probe and RW-to-RX correlation

```powershell
.\bin\Release\x64\BlindRunner.exe --cli .\bin\Release\x64\BlindTestTarget.exe --cli-probe-direct-syscall --lhook NtProtectVirtualMemory --stack-trace --sym
```

```text
[blind:behavior] auto-enabled protect folding for NtProtectVirtualMemory; add --raw for raw hits
[blind:detection] direct-syscall source=NtProtectVirtualMemory page=0x1F503750000 size=0x1000 stub=0x1F503750000 ssn=0x1234  caller=KERNELBASE.dll+0xBE73B sample=4C8BD1B8341200000F05C300000000000000000000000000000000000000000000000000000000000000000000000000...
    #00 [internal] BLIND.dll!IX_RUNTIME_INTERNAL::RegisterDirectSyscallPage+0xAEB
    #01 [internal] BLIND.dll!IX_NT::TryObserveDirectSyscallRange+0x393
    #02 [internal] BLIND.dll!IX_NT::TryAnnotateProtectTarget+0x64
    #03 [internal] BLIND.dll!IX_NT::NtProtectVirtualMemory_Hook+0x287
    #04 [system]   KERNELBASE.dll!VirtualProtect+0x3B
    #05 [app]      BlindTestTarget.exe!`anonymous namespace'::RunCliProbeDirectSyscallPage+0x9E
    #06 [app]      BlindTestTarget.exe!wmain+0x594
[blind:behavior] protect target=self count=1 pages=1 size=4.00KB RW->RX first=0x1F503750000 last=0x1F503750000 span=0x1F503750000-0x1F503750000 vad=MEM_COMMIT/MEM_UNKNOWN caller=KERNELBASE.dll!VirtualProtect+0x3B stack=0x641EF0EDD4A2B1D5 rwx=0 risk=- caller_region=MEM_IMAGE/RX
[blind:behavior] region target=self base=0x1F503750000 size=4.00KB pages=1 protect=RX vad=MEM_COMMIT/MEM_UNKNOWN alloc_protect=UNKNOWN alloc_type=0x0 allocs=0 maps=0 protects=1 flips=1 queries=0 last_query=MemoryBasicInformation(0) reads=0 read=0B writes=0 written=0B caller=KERNELBASE.dll!VirtualProtect+0x3B stack=0x641EF0EDD4A2B1D5 risk=protect_flips seq=RW->RX caller_region=MEM_IMAGE/RX
```

### Debug diagnostics and self-map

```powershell
.\bin\Release\x64\BlindRunner.exe --cli .\bin\Release\x64\BlindTestTarget.exe --debug --hook NtQueryInformationProcess
```

```text
[blind] diagnostics dir=C:\$ARSENAL\TitanToolchain\BLIND\bin\Release\x64\BlindDiagnostics\run-20260602-171410-38864
[blind] child pid=18088 target=.\bin\Release\x64\BlindTestTarget.exe launch_gate=1 guarded=0 inject=loadlibrary
[blind] runtime log=C:\$ARSENAL\TitanToolchain\BLIND\bin\Release\x64\BlindDiagnostics\run-20260602-171410-38864\logs\blind-runtime-18088.log
[blind] IxSelfMap hit kind=integrity module=Runtime caller=BLIND.dll+0x5D018 args=[0x1,0x1F,0x7FF9F7630000,0x1000] sample="runtime.readyMask"
[blind] IxSelfMap hit kind=integrity module=NtStub caller=0x15D98100000 args=[0x1,0x0,0x15D98100000,0x1000] sample="NtQueryInformationProcess"
[blind] IxSelfMap hit kind=integrity module=HookPatch caller=ntdll.dll+0x160380 args=[0x0,0x1,0x7FFA671A0000,0x12000] sample="NtQueryInformationProcess"
[blind] IxSelfMap hit kind=integrity module=Runtime caller=BLIND.dll+0x19BA0 args=[0x49A646043AF696E0,0x5,0x7FF9F7630000,0x1A000] sample="summary entries=20 truncated=0 ready=0x00000005 signature=0x49A"
[blind] child exit=0x00000000 events=25 suppressed=0
[blind] self-map entries=21
```

Selected `summary.txt` rows from that run:

```text
child_exit=0x00000000
ready_mask=0x0000000D
events=25
launch_gate_mode=1
launch_gate_traps=0
self_map_entries=21

event_counts:
  nt=2
  integrity=23

self_map_by_kind:
  runtime=14
  indirect_handle=4
  hook_patch=1
  syscall_stub=1
  summary=1
```

Selected `selfmap.tsv` rows from that run:

```text
index	total	truncated	kind	owner	name	address	size	flags	ref0	ref1	allocation_base	region_size	protect	state	type
4	21	0	runtime	Runtime	runtime.readyMask	0x7FF9F768D018	0x4	0x00000152	0x1	0x1F	0x7FF9F7630000	0x1000	0x00000004	0x00001000	0x01000000
15	21	0	syscall_stub	NtStub	NtQueryInformationProcess	0x15D98100000	0x10	0x00000037	0x1	0x0	0x15D98100000	0x1000	0x00000020	0x00001000	0x00020000
16	21	0	indirect_handle	IHR	ihr.NtHookTarget slot=1 tag=0xEA2DDA8A gen=0x70000001	0x7FFA67300380	0x10	0x00000059	0x1	0x6EA2DDA8A	0x7FFA671A0000	0x12000	0x00000020	0x00001000	0x01000000
20	21	0	hook_patch	HookPatch	NtQueryInformationProcess	0x7FFA67300380	0x10	0x00000055	0x0	0x1	0x7FFA671A0000	0x12000	0x00000020	0x00001000	0x01000000
21	21	0	summary	Runtime	summary entries=20 truncated=0 ready=0x00000005 signature=0x49A	0x7FF9F7649BA0	0x14	0x00000053	0x49A646043AF696E0	0x5	0x7FF9F7630000	0x1A000	0x00000020	0x00001000	0x01000000
```

## SDK INTEGRATION

The SDK surface is intentionally small:

- `SDK/include/blind/blind_ipc.h`: host-facing IPC packet ABI, pipe constants, event records, batches, and readiness masks
- `SDK/include/blind/blind_veh.h`: exported in-process VEH telemetry helper API
- `SDK/samples/host/BlindSdkHost.cpp`: minimal host that creates the pipe, starts an owned target, loads `BLIND.dll`, and consumes events

Run the SDK host:

```powershell
.\bin\Debug\x64\BlindSdkHost.exe
.\bin\Debug\x64\BlindSdkHost.exe --pipe \\.\pipe\BLINDSdkPipe --verbose
```

Consumers that link against `BLIND.dll` should define `IX_BLIND_IMPORTS` and link the matching `BLIND.lib`.

## COMPILATION

Build from this directory with Visual Studio 2022+ MSBuild:

```powershell
msbuild .\VCXProj\BLIND.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindLaunchGateTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindRunner.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64
```

Products:

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

A passing launch-gate run reports at least `BLIND_SDK_READY_CORE_MASK` (`0x0000000D`: IPC, NT, KI), `child_exit=0x00000000`, and `launch_gate_traps > 0`. CLI runs with module hooks commonly publish `0x0000001D` (core plus module); full readiness is `0x0000001F` when Winsock is also active.

Run the local test harness without spawning extra consoles:

```powershell
.\Scripts\run_blind_tests.ps1 -Configuration Release
```

## DOCUMENTATION

- `Docs/SDK.md`: SDK headers, packet ABI, and host expectations
- `Docs/INTEGRATION.md`: integration boundary and host responsibilities
- `Docs/DIAGNOSTICS.md`: runner output, event JSONL, self-map TSV, and runtime logs
- `Docs/RELEASE.md`: controlled handoff and preflight checklist

## DISCLAIMER

> [!IMPORTANT]
> BLIND is provided for authorized internal security engineering, defensive validation, and controlled research only.
> Unauthorized monitoring, deployment, evasion, persistence, or use against systems you do not own or administer may violate law and policy.

## LICENSE

Copyright (c) TITAN Softwork Solutions. All rights reserved.

BLIND is governed by `LICENSE.md`: PolyForm Noncommercial 1.0.0 with a BLIND Defensive Use Addendum and DSGL/export-control notice.
