#include "Core/runner_console.h"
#include "Core/runner_help.h"
#include "Diagnostics/diagnostics.h"
#include "Ipc/pipe_server.h"
#include "Launch/injection.h"
#include "Mapper/mapper.h"
#include "Policy/option_parsing.h"
#include "Telemetry/cli_events.h"
#include "Telemetry/process_cache.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/smart_summary.h"

using namespace blind::injector;

int wmain(int argc, wchar_t **argv) {
  ConfigureConsoleColor(ConsoleColorMode::Auto);
  std::wstring baseDir = ModuleDirectory();
  std::wstring dllPath = baseDir + L"\\BLIND.dll";
  RunnerOptions options{};
  options.TargetPath = baseDir + L"\\BlindTestTarget.exe";

  int parseStart = 1;
  if (argc > 1 && wcscmp(argv[1], L"--cli") == 0) {
    if (argc >= 3 && wcscmp(argv[2], L"help") == 0) {
      PrintHelpTopic(argc >= 4 ? argv[3] : nullptr);
      return 0;
    }
    if (argc == 2 || (argc == 3 && IsHelpArgument(argv[2]))) {
      PrintUsage();
      return 0;
    }
    if (!ParseCliMode(argc, argv, 2, options)) {
      return options.HelpRequested ? 0 : 2;
    }
  } else {
    for (int argIndex = parseStart; argIndex < argc; ++argIndex) {
      if (IsHelpArgument(argv[argIndex])) {
        PrintHelpTopic(wcscmp(argv[argIndex], L"help") == 0 &&
                               argIndex + 1 < argc
                           ? argv[argIndex + 1]
                           : nullptr);
        return 0;
      }
      if (wcscmp(argv[argIndex], L"--verbose") == 0) {
        options.Verbose = true;
        continue;
      }
      if (wcscmp(argv[argIndex], L"--launch-gate") == 0) {
        options.LaunchGateMode = true;
        options.GuardedLaunchGate = true;
        continue;
      }
      if (wcscmp(argv[argIndex], L"--disable-lg") == 0 ||
          wcscmp(argv[argIndex], L"--no-launch-gate") == 0) {
        options.LaunchGateMode = false;
        options.GuardedLaunchGate = false;
        continue;
      }
      if (wcscmp(argv[argIndex], L"--mm") == 0 ||
          wcscmp(argv[argIndex], L"--manual-map") == 0) {
        options.ManualMap = true;
        continue;
      }
      if (wcscmp(argv[argIndex], L"--timeout") == 0 ||
          wcscmp(argv[argIndex], L"--target-timeout") == 0) {
        if (argIndex + 1 >= argc) {
          std::wprintf(L"[blind] %ls requires a duration such as 15000, 30s, "
                       L"2m, or none\n",
                       argv[argIndex]);
          return 2;
        }
        if (!ParseDurationMs(argv[++argIndex], options.ChildTimeoutMs)) {
          std::wprintf(L"[blind] invalid timeout duration: %ls\n",
                       argv[argIndex]);
          return 2;
        }
        continue;
      }
      if (wcscmp(argv[argIndex], L"--no-color") == 0 ||
          wcscmp(argv[argIndex], L"--no-colour") == 0 ||
          wcscmp(argv[argIndex], L"--color") == 0 ||
          wcscmp(argv[argIndex], L"--colour") == 0 ||
          wcsncmp(argv[argIndex], L"--color=", 8) == 0 ||
          wcsncmp(argv[argIndex], L"--colour=", 9) == 0) {
        if (!ParseColorMode(options, argv[argIndex])) {
          return 2;
        }
        continue;
      }
      if (wcscmp(argv[argIndex], L"--pipe") == 0) {
        if (argIndex + 1 >= argc) {
          std::wprintf(L"[blind] --pipe requires a named-pipe path\n");
          return 2;
        }
        (void)SetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, argv[++argIndex]);
        continue;
      }
      if (!options.TargetSet) {
        options.TargetPath = argv[argIndex];
        options.TargetSet = true;
        continue;
      }

      std::wprintf(L"[blind] unexpected argument: %ls\n", argv[argIndex]);
      return 2;
    }
    if (options.GuardedLaunchGate && !options.TargetSet) {
      options.TargetPath = baseDir + L"\\BlindLaunchGateTarget.exe";
    }
  }

  wchar_t existingPipeName[2]{};
  if (options.CliMode &&
      GetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, existingPipeName,
                              RTL_NUMBER_OF(existingPipeName)) == 0) {
    std::wstring cliPipe = BuildUniqueCliPipeName();
    (void)SetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, cliPipe.c_str());
  }
  const std::wstring &targetPath = options.TargetPath;

  if (!FileExists(dllPath)) {
    std::wprintf(L"[blind] missing DLL: %ls\n", dllPath.c_str());
    return 2;
  }
  if (!FileExists(targetPath)) {
    std::wprintf(L"[blind] missing target: %ls\n", targetPath.c_str());
    return 2;
  }

  ServerContext ctx{};
  ctx.Verbose = options.Verbose;
  ctx.CliMode = options.CliMode;
  ctx.ResolveSymbols = options.ResolveSymbols;
  ctx.SymbolSearchPath = options.SymbolSearchPath;
  ctx.SmartMode = options.SmartMode;
  ctx.SmartRawEvents = options.SmartRawEvents;
  ctx.SmartStacks = options.SmartStacks;
  ctx.SmartStackFrameLimit = options.SmartStackFrameLimit;
  ctx.SmartAreas = options.SmartAreas;
  ctx.SmartSummaryIntervalMs = options.SmartSummaryIntervalMs;
  ctx.Conditions = options.Conditions;
  ctx.DebugDiagnostics = options.DebugDiagnostics;
  ctx.LaunchGateMode = options.LaunchGateMode;
  ctx.ChildTimeoutMs = options.ChildTimeoutMs;
  ctx.CliPolicy = options.CliPolicy;
  ctx.PipeName = EffectivePipeName();
  const bool remoteSmart = (ctx.SmartAreas & kSmartAreaRemote) != 0;
  ReserveServerContextStorage(ctx, remoteSmart);
  if (ctx.DebugDiagnostics && !OpenDiagnostics(ctx, baseDir)) {
    CloseDiagnostics(ctx);
    return 2;
  }
  if (ctx.DebugDiagnostics) {
    (void)SetEnvironmentVariableW(L"BLIND_LOG_DIR", ctx.LogDir.c_str());
    (void)SetEnvironmentVariableW(L"BLIND_DISABLE_FILE_LOG", nullptr);
  } else {
    (void)SetEnvironmentVariableW(L"BLIND_LOG_DIR", nullptr);
    (void)SetEnvironmentVariableW(L"BLIND_DISABLE_FILE_LOG", L"1");
  }
  (void)SetEnvironmentVariableW(L"BLIND_RUNNER_OWNS_PIPE", L"1");
  if (options.GuardedLaunchGate) {
    (void)SetEnvironmentVariableW(L"IX_HOOK_LAUNCH_GATE", L"1");
  } else {
    (void)SetEnvironmentVariableW(L"IX_HOOK_LAUNCH_GATE", nullptr);
  }

  ctx.ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (ctx.ReadyEvent == nullptr) {
    ColorPrintf(LogColor::Error, "[blind] CreateEvent failed gle=%lu\n",
                GetLastError());
    CloseDiagnostics(ctx);
    return 2;
  }

  HANDLE serverThread =
      CreateThread(nullptr, 0, PipeServerThread, &ctx, 0, nullptr);
  if (serverThread == nullptr) {
    ColorPrintf(LogColor::Error, "[blind] server thread failed gle=%lu\n",
                GetLastError());
    CloseHandle(ctx.ReadyEvent);
    CloseDiagnostics(ctx);
    return 2;
  }

  STARTUPINFOW si{};
  PROCESS_INFORMATION pi{};
  si.cb = sizeof(si);
  std::wstring commandLine =
      options.CliMode ? BuildTargetCommandLine(targetPath, options.TargetArgs)
                      : QuotePath(targetPath);
  const bool debugPreEntryManualMap =
      options.ManualMap && options.LaunchGateMode;
  const bool startSuspended = options.LaunchGateMode;
  const bool hideChildWindow =
      EnvironmentVariableEnabled(L"BLIND_TEST_NO_NEW_CONSOLE");
  if (hideChildWindow) {
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
  }
  DWORD creationFlags =
      (hideChildWindow ? CREATE_NO_WINDOW : CREATE_NEW_CONSOLE) |
      (startSuspended && !debugPreEntryManualMap ? CREATE_SUSPENDED : 0) |
      (debugPreEntryManualMap ? DEBUG_ONLY_THIS_PROCESS : 0);
  UINT previousErrorMode =
      SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS |
                   SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  BOOL created =
      CreateProcessW(targetPath.c_str(), commandLine.data(), nullptr, nullptr,
                     FALSE, creationFlags, nullptr,
                     options.CliMode ? nullptr : baseDir.c_str(), &si, &pi);
  (void)SetErrorMode(previousErrorMode);
  if (!created) {
    ColorPrintf(LogColor::Error, "[blind] CreateProcess failed gle=%lu\n",
                GetLastError());
    ctx.Stop.store(true, std::memory_order_release);
    WaitForSingleObject(serverThread, 1000);
    CloseHandle(serverThread);
    CloseHandle(ctx.ReadyEvent);
    CloseDiagnostics(ctx);
    return 3;
  }

  std::wprintf(L"[blind] child pid=%lu target=%ls launch_gate=%u guarded=%u "
               L"inject=%ls\n",
               pi.dwProcessId, targetPath.c_str(),
               options.LaunchGateMode ? 1u : 0u,
               options.GuardedLaunchGate ? 1u : 0u,
               options.ManualMap ? L"manual-map" : L"loadlibrary");
  ctx.ChildProcessId = pi.dwProcessId;
  ctx.ChildProcessHandle = pi.hProcess;
  if (debugPreEntryManualMap) {
    if (!blind::mapper::PauseDebuggedChildAtEntrypoint(ctx, pi)) {
      TerminateProcess(pi.hProcess, ERROR_DLL_INIT_FAILED);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      ctx.Stop.store(true, std::memory_order_release);
      WaitForSingleObject(serverThread, 1000);
      CloseHandle(serverThread);
      CloseHandle(ctx.ReadyEvent);
      CloseDiagnostics(ctx);
      return 4;
    }
  }
  RefreshChildModules(ctx);
  if (ctx.DebugDiagnostics) {
    wchar_t logName[64]{};
    (void)StringCchPrintfW(logName, RTL_NUMBER_OF(logName),
                           L"blind-runtime-%lu.log", pi.dwProcessId);
    ctx.RuntimeLogPath = JoinPath(ctx.LogDir, logName);
    std::wprintf(L"[blind] runtime log=%ls\n", ctx.RuntimeLogPath.c_str());
  }
  if (!startSuspended) {
    Sleep(500);
  }
  HostDebugLog(
      ctx,
      "created child pid=%lu suspended=%u launch_gate=%u guarded=%u mapper=%u",
      pi.dwProcessId, startSuspended ? 1u : 0u,
      options.LaunchGateMode ? 1u : 0u, options.GuardedLaunchGate ? 1u : 0u,
      options.ManualMap ? 1u : 0u);
  bool injected =
      options.ManualMap
          ? blind::mapper::MapDllIntoChild(ctx, pi.hProcess, dllPath)
          : InjectDllIntoChild(ctx, pi.hProcess, dllPath);
  if (!injected) {
    TerminateProcess(pi.hProcess, ERROR_DLL_INIT_FAILED);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ctx.Stop.store(true, std::memory_order_release);
    WaitForSingleObject(serverThread, 1000);
    CloseHandle(serverThread);
    CloseHandle(ctx.ReadyEvent);
    CloseDiagnostics(ctx);
    return 4;
  }

  bool readyWaitCompleted = false;
  DWORD readyWait = WAIT_TIMEOUT;
  if (startSuspended && !options.GuardedLaunchGate) {
    readyWait = WaitForSingleObject(ctx.ReadyEvent, kReadyTimeoutMs);
    readyWaitCompleted = true;
    ColorPrintf(LogColor::Info, "[blind] ready wait=%lu mask=0x%08lX\n",
                readyWait,
                static_cast<unsigned long>(
                    ctx.ReadyMask.load(std::memory_order_acquire)));
    RefreshChildModules(ctx);
  }

  if (startSuspended) {
    DWORD previousSuspendCount = ResumeThread(pi.hThread);
    if (previousSuspendCount == static_cast<DWORD>(-1)) {
      ColorPrintf(LogColor::Error, "[blind] ResumeThread failed gle=%lu\n",
                  GetLastError());
      TerminateProcess(pi.hProcess, ERROR_INVALID_STATE);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      ctx.Stop.store(true, std::memory_order_release);
      WaitForSingleObject(serverThread, 1000);
      CloseHandle(serverThread);
      CloseHandle(ctx.ReadyEvent);
      CloseDiagnostics(ctx);
      return 4;
    }
    if (options.GuardedLaunchGate) {
      ColorPrintf(
          LogColor::Lifecycle,
          "[blind] launch-gate child resumed previous_suspend_count=%lu\n",
          static_cast<unsigned long>(previousSuspendCount));
    } else if (options.Verbose) {
      ColorPrintf(LogColor::Info,
                  "[blind] cli child resumed previous_suspend_count=%lu\n",
                  static_cast<unsigned long>(previousSuspendCount));
    }
  }

  if (!readyWaitCompleted) {
    readyWait = WaitForSingleObject(ctx.ReadyEvent, kReadyTimeoutMs);
    ColorPrintf(LogColor::Info, "[blind] ready wait=%lu mask=0x%08lX\n",
                readyWait,
                static_cast<unsigned long>(
                    ctx.ReadyMask.load(std::memory_order_acquire)));
  }

  DWORD childTimeout = options.ChildTimeoutMs != INFINITE
                           ? options.ChildTimeoutMs
                           : (options.CliMode ? INFINITE : 30000);
  DWORD childWait = WaitForSingleObject(pi.hProcess, childTimeout);
  if (childWait == WAIT_TIMEOUT) {
    ColorPrintf(LogColor::Warning,
                "[blind] child wait timed out; terminating pid=%lu\n",
                pi.dwProcessId);
    TerminateProcess(pi.hProcess, WAIT_TIMEOUT);
    WaitForSingleObject(pi.hProcess, 5000);
  }

  DWORD exitCode = 0;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  ColorPrintf(exitCode == 0 ? LogColor::Success : LogColor::Warning,
              "[blind] child exit=0x%08lX events=%lu suppressed=%lu\n",
              exitCode,
              static_cast<unsigned long>(
                  ctx.HookEventCount.load(std::memory_order_acquire)),
              static_cast<unsigned long>(
                  ctx.SuppressedEventCount.load(std::memory_order_acquire)));
  ColorPrintf(LogColor::Lifecycle, "[blind] launch-gate traps=%lu\n",
              static_cast<unsigned long>(
                  ctx.LaunchGateTrapCount.load(std::memory_order_acquire)));
  if (ctx.DebugDiagnostics) {
    ColorPrintf(LogColor::Info, "[blind] self-map entries=%zu\n",
                ctx.SelfMapEntries.size());
    std::wprintf(L"[blind] diagnostics summary=%ls\n",
                 JoinPath(ctx.RunDir, L"summary.txt").c_str());
  }

  CloseHandle(pi.hThread);

  Sleep(500);
  ctx.Stop.store(true, std::memory_order_release);
  WaitForSingleObject(serverThread, 1000);
  PrintSmartSummary(ctx, true);
  if (options.CliMode) {
    PrintCliDetectionFoldSummary(ctx);
  }
  CloseCachedProcessHandles(ctx);
  CloseHandle(pi.hProcess);
  ctx.ChildProcessHandle = nullptr;
  CloseHandle(serverThread);
  CloseHandle(ctx.ReadyEvent);
  if (ctx.EventsFile != nullptr) {
    std::fflush(ctx.EventsFile);
  }
  if (ctx.SelfMapFile != nullptr) {
    std::fflush(ctx.SelfMapFile);
  }
  if (ctx.DebugDiagnostics) {
    WriteSummary(ctx, exitCode, childWait);
  }
  CloseDiagnostics(ctx);
  CleanupSymbols(ctx);

  DWORD finalReadyMask = ctx.ReadyMask.load(std::memory_order_acquire);
  if (options.CliMode) {
    const DWORD cliReadyMask = CliReadyMaskForPolicy(ctx);
    if ((finalReadyMask & cliReadyMask) != cliReadyMask) {
      return 5;
    }
    return static_cast<int>(exitCode);
  }

  bool ok = exitCode == 0 &&
            ctx.HookEventCount.load(std::memory_order_acquire) != 0 &&
            ((finalReadyMask & BLIND_SDK_READY_CORE_MASK) ==
             BLIND_SDK_READY_CORE_MASK);
  if (options.GuardedLaunchGate) {
    ok = ok && ctx.LaunchGateTrapCount.load(std::memory_order_acquire) != 0;
  }
  return ok ? 0 : 5;
}
