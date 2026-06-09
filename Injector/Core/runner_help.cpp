#include "Core/runner_help.h"

namespace blind::injector {
bool IsHelpArgument(const wchar_t *arg) noexcept {
  return arg != nullptr &&
         (wcscmp(arg, L"help") == 0 || wcscmp(arg, L"--help") == 0 ||
          wcscmp(arg, L"-h") == 0 || wcscmp(arg, L"/?") == 0);
}

void PrintUsage() {
  std::wprintf(L"BLIND - owned-process user-mode sensor runner\n\n");
  std::wprintf(L"Usage:\n");
  std::wprintf(L"  blind help\n");
  std::wprintf(L"  blind help <command>\n");
  std::wprintf(L"  blind <target.exe> [target args...] --lhook <api|group> "
               L"[rule options]\n");
  std::wprintf(L"  blind <target.exe> [target args...] --lhooks "
               L"<api,api,group> [rule options]\n");
  std::wprintf(L"  blind [cli options] --lhooks <api,group> [rule options] -- "
               L"<target.exe> [target args...]\n");
  std::wprintf(L"  BlindRunner.exe [runner options] [owned-test-exe]\n");
  std::wprintf(
      L"  BlindRunner.exe --cli <same arguments accepted by blind.cmd>\n\n");

  std::wprintf(L"Commands:\n");
  std::wprintf(L"  run         Launch an owned process with hooks and behavior "
               L"summaries.\n");
  std::wprintf(
      L"  hooks       Hook one function, a comma list, or a named group.\n");
  std::wprintf(L"  groups      Show built-in groups for memory, remote, "
               L"network, credentials, and more.\n");
  std::wprintf(L"  behavior    Fold noisy events into target-aware behavior "
               L"summaries.\n");
  std::wprintf(L"  help        Show this help text, or command-focused help "
               L"with `blind help <command>`.\n\n");

  std::wprintf(L"Help aliases:\n");
  std::wprintf(L"  help, --help, -h, /?\n\n");

  std::wprintf(L"CLI options:\n");
  std::wprintf(L"  --hook <api|group>     Install an explicit hook without "
               L"printing hits by default.\n");
  std::wprintf(L"  --lhook <api|group>    Install an explicit log-hook and "
               L"print matching hits.\n");
  std::wprintf(L"  --hooks <list>         Install a comma/semicolon list "
               L"without printing by default.\n");
  std::wprintf(L"  --lhooks <list>        Install and print a comma/semicolon "
               L"list; [] or {} wrappers are OK.\n");
  std::wprintf(
      L"                         Prefixes: nt:, module:, winsock:, group:.\n");
  std::wprintf(L"                         NT memory/handle lines resolve "
               L"target pid/name, access masks, VADs, and "
               L"byte counts.\n");
  std::wprintf(L"  --hook-group <name>    Install a group without printing by "
               L"default.\n");
  std::wprintf(L"  --group, --lgroup      Install and print a hook group; "
               L"--groups/--lgroups accept lists.\n");
  std::wprintf(L"                         Groups: behavior, memory, remote, "
               L"injection, process, thread, file,\n");
  std::wprintf(L"                         token, anti-analysis, loader, etw, "
               L"amsi, winsock, http, network,\n");
  std::wprintf(L"                         crypto, credentials, sspi, vault, "
               L"dpapi, com, jobs, cloud, exceptions.\n");
  std::wprintf(L"  --pipe <path>          Use a named pipe such as "
               L"\\\\.\\pipe\\BLINDCliDemo.\n");
  std::wprintf(L"  --timeout <duration>   Terminate the target after a "
               L"duration like 15000, 30s, 2m, or 0/none.\n");
  std::wprintf(L"  --verbose              Print every CLI NT hook event.\n");
  std::wprintf(L"  --debug                Enable verbose CLI output plus "
               L"diagnostics files and runtime logs.\n");
  std::wprintf(
      L"  --disable-lg           Disable the default pre-entry launch gate.\n");
  std::wprintf(L"  --mm                   Manually map BLIND.dll without "
               L"LoadLibrary and verify loader-list absence.\n");
  std::wprintf(L"  --sym, --syms          Try DbgHelp symbol names for "
               L"--stack-trace frames.\n");
  std::wprintf(
      L"  --sym-path <path>      Use an explicit DbgHelp symbol path, e.g. "
      L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols.\n");
  std::wprintf(L"  --behavior[=areas]     Aggregate memory/thread/protect "
               L"behavior instead of spamming raw hits.\n");
  std::wprintf(L"                         Areas: "
               L"memory,protect,threads,writes,reads,queries,handles,apc,maps,"
               L"remote,all.\n");
  std::wprintf(L"                         Plain --behavior uses core areas; "
               L"use --behavior=remote for remote "
               L"VAD/read behavior.\n");
  std::wprintf(
      L"                         Remote "
      L"NtQueryVirtualMemory/NtReadVirtualMemory scanner noise folds into "
      L"VAD/read maps.\n");
  std::wprintf(L"                         NtProtectVirtualMemory log-hooks "
               L"auto-fold unless --raw is used.\n");
  std::wprintf(L"  --behavior-stacks[=N|all]\n");
  std::wprintf(L"                         Print representative folded behavior "
               L"stack frames.\n");
  std::wprintf(L"  --behavior-protect-stacks\n");
  std::wprintf(L"                         Also collect folded NtProtect "
               L"stacks; useful but can be hot/noisy.\n");
  std::wprintf(L"  --raw                  With behavior mode or auto-folded "
               L"protect hooks, also print raw events.\n");
  std::wprintf(L"  --summary-interval ms  With behavior mode, print periodic "
               L"live summaries; 0 means final only.\n");
  std::wprintf(L"  --when <condition>     Behavior alert condition: rwx, "
               L"remote, start.private,\n");
  std::wprintf(L"                         protect.flips>=N, thread.count>=N, "
               L"alloc.total>NMB.\n");
  std::wprintf(L"  Built-in detections    Always print own hook patching, "
               L"AMSI/ETW patching,\n");
  std::wprintf(L"                         ntdll EAT SSN-resolution, "
               L"double-loaded ntdll, and direct syscall pages.\n");
  std::wprintf(L"  --guard-direct-syscalls PAGE_GUARD detected direct-syscall "
               L"pages for access traps; higher risk.\n");
  std::wprintf(L"  --color[=mode]         Color console output: auto, always, "
               L"or never; --no-color disables it.\n");
  std::wprintf(L"  --ignore-dll <name>    Suppress hits whose immediate caller "
               L"is in that DLL basename.\n");
  std::wprintf(L"  --ignore-private       Suppress hits from private or "
               L"unmapped executable memory.\n\n");

  std::wprintf(
      L"Rule options, applied to the most recent hook or expanded group:\n");
  std::wprintf(L"  --deny                 Return STATUS_ACCESS_DENIED for the "
               L"hooked call.\n");
  std::wprintf(
      L"  --silent-deny          Drop the call and return STATUS_SUCCESS.\n");
  std::wprintf(L"                         Deny modes are NT-only.\n");
  std::wprintf(L"  --stack-trace          Include resolved stack frames in "
               L"matching output.\n");
  std::wprintf(L"                         Frames are role-tagged: [internal], "
               L"[system], [runtime], [app], [module], "
               L"[private].\n");
  std::wprintf(
      L"  --hook-type <type>     Patch style for recent rules: inline, "
      L"int3, iat, shadow-iat.\n");
  std::wprintf(L"                         Aliases: --inline, --int3, --iat, "
               L"--shadow-iat.\n");
  std::wprintf(L"  --sf                  Sanitize BLIND-owned frames from "
               L"published stack traces.\n");
  std::wprintf(L"  --r, --regs            Include a hook-time register "
               L"snapshot for NT hooks.\n\n");

  std::wprintf(L"Runner options:\n");
  std::wprintf(L"  --verbose              Print diagnostic hook events.\n");
  std::wprintf(
      L"  --disable-lg           Disable the default pre-entry launch gate.\n");
  std::wprintf(L"  --mm                   Manually map BLIND.dll without "
               L"LoadLibrary and verify loader-list absence.\n");
  std::wprintf(L"  --timeout <duration>   Terminate the target after the given "
               L"duration.\n");
  std::wprintf(L"  --pipe <path>          Override the IPC pipe for the runner "
               L"and injected DLL.\n\n");

  std::wprintf(L"Examples:\n");
  std::wprintf(L"  blind .\\sample.exe --lhook NtAllocateVirtualMemory\n");
  std::wprintf(
      L"  blind .\\sample.exe --lhooks "
      L"NtAllocateVirtualMemory,NtProtectVirtualMemory,loader --stack-trace\n");
  std::wprintf(L"  blind .\\sample.exe --lhook amsi --stack-trace --sym\n");
  std::wprintf(L"  blind .\\sample.exe --lgroup network\n");
  std::wprintf(L"  blind .\\sample.exe --lhook NtAllocateVirtualMemory "
               L"--stack-trace --sym --r --deny\n");
  std::wprintf(L"  blind .\\sample.exe --behavior --behavior-stacks --when rwx "
               L"--when protect.flips>=2\n");
  std::wprintf(L"  blind .\\sample.exe --timeout 30s --behavior=all --lhooks "
               L"loader,network\n");
  std::wprintf(L"  blind .\\sample.exe --mm --timeout 30s --behavior=all "
               L"--lhooks loader,network\n");
  std::wprintf(L"  blind --lhook NtQueryInformationProcess --ignore-dll ntdll "
               L"-- .\\sample.exe --target-flag\n");
  std::wprintf(L"  BlindRunner.exe --pipe \\\\.\\pipe\\BLINDLaunchGateDemo "
               L".\\BlindLaunchGateTarget.exe\n\n");

  std::wprintf(L"Notes:\n");
  std::wprintf(L"  BLIND only instruments processes spawned by this runner.\n");
  std::wprintf(L"  Extra module hooks are lazy: BLIND watches loader APIs and "
               L"does not LoadLibrary optional DLLs.\n");
  std::wprintf(L"  Targets are started in a new console so target "
               L"stdout/stderr stay separate from BLIND logs.\n");
  std::wprintf(L"  Use -- before the target when target arguments start with "
               L"-- or when you want unambiguous parsing.\n");
  std::wprintf(L"  Normal CLI mode keeps diagnostics files off; add --debug "
               L"when you need a BlindDiagnostics bundle.\n");
  std::wprintf(L"  Exit 0 means the runner and target completed successfully; "
               L"exit 2 is argument or setup failure.\n");
}

void PrintHelpTopic(const wchar_t *topic) {
  std::wstring key = topic != nullptr ? topic : L"";
  for (auto &ch : key) {
    ch = static_cast<wchar_t>(std::towlower(ch));
  }
  if (key.empty() || key == L"help" || key == L"commands") {
    PrintUsage();
    return;
  }

  if (key == L"run" || key == L"cli") {
    std::wprintf(L"BLIND help: run\n\n");
    std::wprintf(L"Usage:\n");
    std::wprintf(L"  blind <target.exe> [target args...] [cli options]\n");
    std::wprintf(L"  blind [cli options] -- <target.exe> [target args...]\n\n");
    std::wprintf(L"Key options:\n");
    std::wprintf(L"  launch-gate            Enabled by default before normal "
                 L"target entry.\n");
    std::wprintf(
        L"  --disable-lg           Disable the default launch gate.\n");
    std::wprintf(L"  --mm                   Manually map BLIND.dll and verify "
                 L"it is absent from loader lists.\n");
    std::wprintf(L"  --timeout <duration>   Stop long-lived targets after "
                 L"15000, 30s, 2m, or 0/none.\n");
    std::wprintf(
        L"  --pipe <path>          Override the host/injected DLL IPC pipe.\n");
    std::wprintf(
        L"  --debug                Keep diagnostics files and runtime logs.\n");
    std::wprintf(L"  --color[=mode]         auto, always, never; --no-color "
                 L"disables ANSI output.\n");
    return;
  }

  if (key == L"hooks" || key == L"hook" || key == L"functions" ||
      key == L"function") {
    std::wprintf(L"BLIND help: hooks\n\n");
    std::wprintf(L"Usage:\n");
    std::wprintf(L"  blind .\\sample.exe --lhook NtQueryInformationProcess "
                 L"--stack-trace\n");
    std::wprintf(L"  blind .\\sample.exe --lhooks "
                 L"NtAllocateVirtualMemory,NtProtectVirtualMemory,loader\n");
    std::wprintf(
        L"  blind .\\sample.exe --hooks "
        L"[nt:NtOpenProcess,module:CoCreateInstance,winsock:connect]\n\n");
    std::wprintf(L"Hook selectors:\n");
    std::wprintf(L"  --hook <api|group>     Install one hook without printing "
                 L"by default.\n");
    std::wprintf(L"  --lhook <api|group>    Install one hook and print "
                 L"de-duplicated hits.\n");
    std::wprintf(L"  --hooks <list>         Install comma/semicolon-separated "
                 L"selectors.\n");
    std::wprintf(L"  --lhooks <list>        Install and print "
                 L"comma/semicolon-separated selectors.\n");
    std::wprintf(L"  --group/--lgroup       Select a built-in group; "
                 L"--groups/--lgroups accept lists.\n\n");
    std::wprintf(L"Prefixes:\n");
    std::wprintf(L"  nt:<name>              NT/native syscall-family hook.\n");
    std::wprintf(L"  module:<name>          User-mode export hook such as "
                 L"CoCreateInstance.\n");
    std::wprintf(L"  winsock:<name>         Winsock/DNS hook such as send or "
                 L"GetAddrInfoW.\n");
    std::wprintf(L"  group:<name>           Built-in group, same as "
                 L"--lgroup/--group.\n\n");
    std::wprintf(L"Rule options apply to every selector added by the previous "
                 L"hook/list/group flag:\n");
    std::wprintf(L"  --stack-trace, --sym, --r/--regs, --deny, --silent-deny, "
                 L"--ignore-dll, --ignore-private.\n");
    std::wprintf(L"  --hook-type <inline|int3|iat|shadow-iat>, --inline, "
                 L"--int3, --iat, --shadow-iat, --sf.\n");
    return;
  }

  if (key == L"groups" || key == L"group") {
    std::wprintf(L"BLIND help: groups\n\n");
    std::wprintf(L"Core groups:\n");
    std::wprintf(L"  "
                 L"behavior/memory/protect/thread/process/file/token/remote/"
                 L"injection/anti-analysis\n");
    std::wprintf(L"Module groups:\n");
    std::wprintf(L"  "
                 L"loader/etw/amsi/http/network/crypto/credentials/sspi/vault/"
                 L"dpapi/com/jobs/cloud/exceptions\n");
    std::wprintf(L"Winsock group:\n");
    std::wprintf(L"  winsock covers WSASend, WSARecv, send, recv, connect, "
                 L"WSAConnect, GetAddrInfo*, and "
                 L"DnsQuery*.\n\n");
    std::wprintf(L"Examples:\n");
    std::wprintf(L"  blind .\\sample.exe --lgroups loader,anti-analysis,remote "
                 L"--stack-trace\n");
    std::wprintf(
        L"  blind .\\sample.exe --lgroup credentials --sym --stack-trace\n");
    std::wprintf(L"  blind .\\sample.exe --lhooks "
                 L"group:network,nt:NtQueryInformationProcess\n");
    return;
  }

  if (key == L"behavior" || key == L"behaviour" || key == L"smart") {
    std::wprintf(L"BLIND help: behavior\n\n");
    std::wprintf(L"Usage:\n");
    std::wprintf(L"  blind .\\sample.exe --behavior\n");
    std::wprintf(L"  blind .\\sample.exe --behavior=all --behavior-stacks 8 "
                 L"--when rwx\n");
    std::wprintf(
        L"  blind .\\sample.exe --behavior=remote --summary-interval 0\n\n");
    std::wprintf(L"Areas:\n");
    std::wprintf(L"  memory, protect, threads, writes, reads, queries, "
                 L"handles, apc, maps, remote, all.\n");
    std::wprintf(L"Options:\n");
    std::wprintf(L"  --behavior-stacks[=N|all]       Print representative "
                 L"folded stacks.\n");
    std::wprintf(L"  --behavior-protect-stacks       Capture "
                 L"protect-transition stacks.\n");
    std::wprintf(L"  --raw                           Also print raw events.\n");
    std::wprintf(L"  --summary-interval <ms>         Print live summaries; 0 "
                 L"prints final only.\n");
    std::wprintf(L"  --when <condition>              rwx, remote, "
                 L"start.private, protect.flips>=N,\n");
    std::wprintf(L"                                  thread.count>=N, "
                 L"alloc.total>NMB.\n");
    return;
  }

  std::wprintf(L"[blind] unknown help topic: %ls\n\n",
               topic != nullptr ? topic : L"<null>");
  PrintUsage();
}
bool CopyWideToAnsi(const wchar_t *input, char *out,
                    std::size_t outChars) noexcept {
  if (input == nullptr || out == nullptr || outChars == 0) {
    return false;
  }
  out[0] = '\0';
  int written = WideCharToMultiByte(
      CP_UTF8, 0, input, -1, out, static_cast<int>(outChars), nullptr, nullptr);
  if (written <= 0) {
    return false;
  }
  out[outChars - 1] = '\0';
  return true;
}

const wchar_t *ComponentDisplayName(UINT32 component) noexcept {
  switch (component) {
  case IXIPC_HOOK_POLICY_COMPONENT_NT:
    return L"nt";
  case IXIPC_HOOK_POLICY_COMPONENT_MODULE:
    return L"module";
  case IXIPC_HOOK_POLICY_COMPONENT_WINSOCK:
    return L"winsock";
  default:
    return L"hook";
  }
}

} // namespace blind::injector
