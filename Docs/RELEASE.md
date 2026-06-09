# BLIND Controlled Release Checklist

BLIND is not a public release artifact. A "release" means a Titan-controlled internal handoff under the license, DSGL/export-control review, and secure-use policy.

## Required Artifacts

For an SDK-enabled handoff, stage:

```text
BLIND.dll
BLIND.lib                import library for explicit VEH API consumers
BLIND.pdb                optional, controlled symbols only
BlindRunner.exe          diagnostic runner
BlindSdkHost.exe         SDK smoke-test host
BlindTestTarget.exe      benign owned test target
BlindLaunchGateTarget.exe no-CRT launch-gate test target
SDK/include/blind/*
SDK/samples/host/BlindSdkHost.cpp
README.md
LICENSE.md
Docs/SDK.md
Docs/INTEGRATION.md
Docs/DIAGNOSTICS.md
Docs/RELEASE.md
```

Do not stage `bin/`, `obj/`, old diagnostic run folders, temporary disassembler files, editor state, or unmanaged logs.

## Preflight

Run from this directory:

```powershell
msbuild .\VCXProj\BLIND.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindLaunchGateTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindRunner.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\BlindSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64
.\bin\Release\x64\BlindRunner.exe
.\bin\Release\x64\BlindRunner.exe --launch-gate --pipe \\.\pipe\BLINDReleaseLaunchGate
.\bin\Release\x64\BlindSdkHost.exe
```

Expected:

- both executables exit with code `0`;
- readiness includes `BLIND_SDK_READY_CORE_MASK` (`0x0000000D`: IPC, NT, KI);
- at least one hook event is received;
- the launch-gate harness reports `launch_gate_traps > 0`;
- diagnostics include `summary.txt`, `events.jsonl`, `selfmap.tsv`, and runtime log;
- any self-map truncation is documented or remediated before handoff.

## Signing And Provenance

Before handoff:

- record source commit and build machine identity;
- hash every staged binary and header;
- sign binaries when required by Titan policy;
- preserve PDBs only in approved symbol storage;
- record the approving owner and DSGL/export-control decision.

## Publication Gate

Do not publish or transfer the package until:

- `LICENSE.md` controls are included;
- `Docs/SDK.md` and `Docs/INTEGRATION.md` are included;
- the sample host has passed against the exact staged DLL;
- the package owner confirms the recipient, purpose, retention, and deletion requirements.
