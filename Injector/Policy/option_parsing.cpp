#include "Policy/option_parsing.h"
#include "Core/runner_console.h"
#include "Core/runner_help.h"
#include "Policy/hook_catalog.h"

namespace blind::injector {
std::wstring QuoteCommandLineArgument(const std::wstring &arg) {
  if (arg.empty()) {
    return L"\"\"";
  }

  bool needsQuotes = false;
  for (wchar_t ch : arg) {
    if (ch == L' ' || ch == L'\t' || ch == L'"') {
      needsQuotes = true;
      break;
    }
  }
  if (!needsQuotes) {
    return arg;
  }

  std::wstring quoted = L"\"";
  std::size_t backslashes = 0;
  for (wchar_t ch : arg) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    if (ch == L'"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(ch);
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, L'\\');
    backslashes = 0;
    quoted.push_back(ch);
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'"');
  return quoted;
}

std::wstring
BuildTargetCommandLine(const std::wstring &targetPath,
                       const std::vector<std::wstring> &targetArgs) {
  std::wstring commandLine = QuoteCommandLineArgument(targetPath);
  for (const auto &arg : targetArgs) {
    commandLine.push_back(L' ');
    commandLine += QuoteCommandLineArgument(arg);
  }
  return commandLine;
}

std::wstring BuildUniqueCliPipeName() {
  wchar_t pipeName[128]{};
  (void)StringCchPrintfW(pipeName, RTL_NUMBER_OF(pipeName),
                         L"\\\\.\\pipe\\BLINDCli-%lu",
                         static_cast<unsigned long>(GetCurrentProcessId()));
  return pipeName;
}

const wchar_t *HookMethodDisplayName(UINT32 method) noexcept {
  switch (method) {
  case IXIPC_HOOK_METHOD_INLINE:
    return L"inline";
  case IXIPC_HOOK_METHOD_INT3:
    return L"int3";
  case IXIPC_HOOK_METHOD_IAT:
    return L"iat";
  case IXIPC_HOOK_METHOD_SHADOW_IAT:
    return L"shadow-iat";
  case IXIPC_HOOK_METHOD_VMT:
    return L"vmt";
  case IXIPC_HOOK_METHOD_TRAP_FLAG:
    return L"trap-flag";
  case IXIPC_HOOK_METHOD_DEBUG_REGISTER:
    return L"debug-register";
  default:
    return L"unknown";
  }
}

bool ParseHookMethodValue(const wchar_t *value, UINT32 &method) noexcept {
  std::wstring lower = ToLowerWide(value);
  for (auto &ch : lower) {
    if (ch == L'_') {
      ch = L'-';
    }
  }

  if (lower == L"inline" || lower == L"jmp" || lower == L"jump") {
    method = IXIPC_HOOK_METHOD_INLINE;
    return true;
  }
  if (lower == L"int3" || lower == L"breakpoint" || lower == L"bp" ||
      lower == L"veh") {
    method = IXIPC_HOOK_METHOD_INT3;
    return true;
  }
  if (lower == L"iat" || lower == L"import" ||
      lower == L"import-address-table") {
    method = IXIPC_HOOK_METHOD_IAT;
    return true;
  }
  if (lower == L"shadow-iat" || lower == L"shadowiat" ||
      lower == L"shadow-copy" || lower == L"shadowcpy" || lower == L"shadow") {
    method = IXIPC_HOOK_METHOD_SHADOW_IAT;
    return true;
  }
  if (lower == L"vmt" || lower == L"vtable" || lower == L"vtbl") {
    method = IXIPC_HOOK_METHOD_VMT;
    return true;
  }
  if (lower == L"trap-flag" || lower == L"tf" || lower == L"single-step") {
    method = IXIPC_HOOK_METHOD_TRAP_FLAG;
    return true;
  }
  if (lower == L"debug-register" || lower == L"debug-registers" ||
      lower == L"dr" || lower == L"drx") {
    method = IXIPC_HOOK_METHOD_DEBUG_REGISTER;
    return true;
  }
  return false;
}

bool HookMethodSupportedForRule(const IXIPC_HOOK_POLICY_RULE &rule,
                                UINT32 method) noexcept {
  if (rule.Component == IXIPC_HOOK_POLICY_COMPONENT_NT) {
    return method == IXIPC_HOOK_METHOD_INLINE ||
           method == IXIPC_HOOK_METHOD_INT3;
  }
  if (rule.Component == IXIPC_HOOK_POLICY_COMPONENT_MODULE) {
    return method == IXIPC_HOOK_METHOD_INLINE ||
           method == IXIPC_HOOK_METHOD_IAT ||
           method == IXIPC_HOOK_METHOD_SHADOW_IAT;
  }
  if (rule.Component == IXIPC_HOOK_POLICY_COMPONENT_WINSOCK) {
    return method == IXIPC_HOOK_METHOD_INLINE ||
           method == IXIPC_HOOK_METHOD_IAT;
  }
  return false;
}

bool ApplyHookMethodToRecentRules(RunnerOptions &options, UINT32 method,
                                  const wchar_t *arg) noexcept {
  if (options.LastRuleCount == 0 ||
      options.LastRuleStart >= options.CliPolicy.RuleCount) {
    std::wprintf(L"[blind] %ls must follow --hook or --lhook\n", arg);
    return false;
  }

  UINT32 end = options.LastRuleStart + options.LastRuleCount;
  if (end > options.CliPolicy.RuleCount) {
    end = options.CliPolicy.RuleCount;
  }
  for (UINT32 i = options.LastRuleStart; i < end; ++i) {
    IXIPC_HOOK_POLICY_RULE &rule = options.CliPolicy.Rules[i];
    if (!HookMethodSupportedForRule(rule, method)) {
      if (method == IXIPC_HOOK_METHOD_VMT) {
        std::wprintf(L"[blind] --hook-type vmt requires an object/interface "
                     L"vtable target; "
                     L"API hook %S is a %ls hook\n",
                     rule.ApiName, ComponentDisplayName(rule.Component));
      } else if (method == IXIPC_HOOK_METHOD_TRAP_FLAG ||
                 method == IXIPC_HOOK_METHOD_DEBUG_REGISTER) {
        std::wprintf(L"[blind] --hook-type %ls is reserved but not supported "
                     L"for API hook %S yet\n",
                     HookMethodDisplayName(method), rule.ApiName);
      } else {
        std::wprintf(
            L"[blind] --hook-type %ls is not supported for %S (%ls hook)\n",
            HookMethodDisplayName(method), rule.ApiName,
            ComponentDisplayName(rule.Component));
      }
      return false;
    }
  }
  for (UINT32 i = options.LastRuleStart; i < end; ++i) {
    options.CliPolicy.Rules[i].HookMethod = method;
  }
  return true;
}

bool ParseCliMode(int argc, wchar_t **argv, int startIndex,
                  RunnerOptions &options) {
  options.CliMode = true;
  options.DebugDiagnostics = false;
  options.CliPolicy.PolicyVersion = IXIPC_HOOK_POLICY_VERSION;
  options.CliPolicy.Flags = IXIPC_HOOK_POLICY_FLAG_CLI_MODE;

  bool afterSeparator = false;
  for (int argIndex = startIndex; argIndex < argc; ++argIndex) {
    const wchar_t *arg = argv[argIndex];

    if (afterSeparator) {
      if (!options.TargetSet) {
        options.TargetPath = arg;
        options.TargetSet = true;
      } else {
        options.TargetArgs.push_back(arg);
      }
      continue;
    }

    if (wcscmp(arg, L"--") == 0) {
      afterSeparator = true;
      options.TargetSet = false;
      options.TargetPath.clear();
      options.TargetArgs.clear();
      continue;
    }
    if (IsHelpArgument(arg)) {
      options.HelpRequested = true;
      PrintUsage();
      return false;
    }
    if (wcscmp(arg, L"--verbose") == 0) {
      options.Verbose = true;
      continue;
    }
    if (wcscmp(arg, L"--debug") == 0) {
      options.Verbose = true;
      options.DebugDiagnostics = true;
      continue;
    }
    if (wcscmp(arg, L"--launch-gate") == 0) {
      options.LaunchGateMode = true;
      options.GuardedLaunchGate = true;
      continue;
    }
    if (wcscmp(arg, L"--disable-lg") == 0 ||
        wcscmp(arg, L"--no-launch-gate") == 0) {
      options.LaunchGateMode = false;
      options.GuardedLaunchGate = false;
      continue;
    }
    if (wcscmp(arg, L"--mm") == 0 || wcscmp(arg, L"--manual-map") == 0) {
      options.ManualMap = true;
      continue;
    }
    if (wcscmp(arg, L"--timeout") == 0 ||
        wcscmp(arg, L"--target-timeout") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] %ls requires a duration such as 15000, 30s, 2m, "
                     L"or none\n",
                     arg);
        return false;
      }
      if (!ParseDurationMs(argv[++argIndex], options.ChildTimeoutMs)) {
        std::wprintf(L"[blind] invalid timeout duration: %ls\n",
                     argv[argIndex]);
        return false;
      }
      continue;
    }
    if (wcscmp(arg, L"--sym") == 0 || wcscmp(arg, L"--syms") == 0 ||
        wcscmp(arg, L"--symbols") == 0) {
      options.ResolveSymbols = true;
      continue;
    }
    if (wcscmp(arg, L"--sym-path") == 0 || wcscmp(arg, L"--symbol-path") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] %ls requires a DbgHelp symbol path\n", arg);
        return false;
      }
      options.ResolveSymbols = true;
      options.SymbolSearchPath = argv[++argIndex];
      continue;
    }
    if (wcscmp(arg, L"--no-color") == 0 || wcscmp(arg, L"--no-colour") == 0 ||
        wcscmp(arg, L"--color") == 0 || wcscmp(arg, L"--colour") == 0 ||
        wcsncmp(arg, L"--color=", 8) == 0 ||
        wcsncmp(arg, L"--colour=", 9) == 0) {
      if (!ParseColorMode(options, arg)) {
        return false;
      }
      continue;
    }
    if ((wcsncmp(arg, L"--smart", 7) == 0 &&
         (arg[7] == L'\0' || arg[7] == L'=')) ||
        (wcsncmp(arg, L"--behavior", 10) == 0 &&
         (arg[10] == L'\0' || arg[10] == L'=')) ||
        (wcsncmp(arg, L"--behaviour", 11) == 0 &&
         (arg[11] == L'\0' || arg[11] == L'='))) {
      const wchar_t *smartArg = (wcsncmp(arg, L"--behavior", 10) == 0 ||
                                 wcsncmp(arg, L"--behaviour", 11) == 0)
                                    ? L"--smart"
                                    : arg;
      if (arg[0] != L'\0' && wcschr(arg, L'=') != nullptr) {
        smartArg = arg;
      }
      if (!ParseSmartAreas(options, smartArg)) {
        return false;
      }
      continue;
    }
    if ((wcsncmp(arg, L"--smart-stacks", 14) == 0 &&
         (arg[14] == L'\0' || arg[14] == L'=')) ||
        (wcsncmp(arg, L"--behavior-stacks", 17) == 0 &&
         (arg[17] == L'\0' || arg[17] == L'=')) ||
        (wcsncmp(arg, L"--behaviour-stacks", 18) == 0 &&
         (arg[18] == L'\0' || arg[18] == L'='))) {
      if (!ParseSmartStacks(options, arg)) {
        return false;
      }
      const bool needsValue =
          (wcsncmp(arg, L"--smart-stacks", 14) == 0 && arg[14] == L'\0') ||
          (wcsncmp(arg, L"--behavior-stacks", 17) == 0 && arg[17] == L'\0') ||
          (wcsncmp(arg, L"--behaviour-stacks", 18) == 0 && arg[18] == L'\0');
      if (needsValue && argIndex + 1 < argc &&
          IsSmartStackFrameValue(argv[argIndex + 1])) {
        std::wstring synthetic = L"--smart-stacks=";
        synthetic += argv[++argIndex];
        if (!ParseSmartStacks(options, synthetic.c_str())) {
          return false;
        }
      }
      continue;
    }
    if (wcscmp(arg, L"--smart-protect-stacks") == 0 ||
        wcscmp(arg, L"--behavior-protect-stacks") == 0 ||
        wcscmp(arg, L"--behaviour-protect-stacks") == 0) {
      options.SmartMode = true;
      options.SmartStacks = true;
      options.SmartProtectStacks = true;
      continue;
    }
    if (wcscmp(arg, L"--raw") == 0) {
      options.SmartRawEvents = true;
      continue;
    }
    if (wcscmp(arg, L"--summary-interval") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] --summary-interval requires milliseconds\n");
        return false;
      }
      UINT64 interval = 0;
      if (!ParseSizeValue(ToLowerWide(argv[++argIndex]), interval) ||
          interval > 600000ull) {
        std::wprintf(L"[blind] invalid --summary-interval value\n");
        return false;
      }
      options.SmartSummaryIntervalMs = static_cast<DWORD>(interval);
      options.SmartMode = true;
      continue;
    }
    if (wcscmp(arg, L"--when") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] --when requires a condition\n");
        return false;
      }
      if (!ParseSmartCondition(options, argv[++argIndex])) {
        return false;
      }
      options.SmartMode = true;
      continue;
    }
    if (wcscmp(arg, L"--guard-direct-syscalls") == 0) {
      options.CliPolicy.Flags |= IXIPC_HOOK_POLICY_FLAG_GUARD_DIRECT_SYSCALLS;
      continue;
    }
    if (wcscmp(arg, L"--pipe") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] --pipe requires a named-pipe path\n");
        return false;
      }
      (void)SetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, argv[++argIndex]);
      continue;
    }
    if (wcscmp(arg, L"--hook") == 0 || wcscmp(arg, L"--lhook") == 0 ||
        wcscmp(arg, L"--hooks") == 0 || wcscmp(arg, L"--lhooks") == 0 ||
        wcscmp(arg, L"--hook-list") == 0 || wcscmp(arg, L"--lhook-list") == 0 ||
        wcscmp(arg, L"--functions") == 0 || wcscmp(arg, L"--lfunctions") == 0 ||
        wcscmp(arg, L"--hook-group") == 0 ||
        wcscmp(arg, L"--lhook-group") == 0 || wcscmp(arg, L"--group") == 0 ||
        wcscmp(arg, L"--lgroup") == 0 || wcscmp(arg, L"--groups") == 0 ||
        wcscmp(arg, L"--lgroups") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] %ls requires a hook name or group\n", arg);
        return false;
      }
      const bool log =
          wcscmp(arg, L"--lhook") == 0 || wcscmp(arg, L"--lhooks") == 0 ||
          wcscmp(arg, L"--lhook-list") == 0 ||
          wcscmp(arg, L"--lfunctions") == 0 ||
          wcscmp(arg, L"--lhook-group") == 0 || wcscmp(arg, L"--lgroup") == 0 ||
          wcscmp(arg, L"--lgroups") == 0 || wcscmp(arg, L"--group") == 0 ||
          wcscmp(arg, L"--groups") == 0;
      const bool explicitGroup =
          wcscmp(arg, L"--hook-group") == 0 ||
          wcscmp(arg, L"--lhook-group") == 0 || wcscmp(arg, L"--group") == 0 ||
          wcscmp(arg, L"--lgroup") == 0 || wcscmp(arg, L"--groups") == 0 ||
          wcscmp(arg, L"--lgroups") == 0;
      const wchar_t *spec = argv[++argIndex];
      if (!AddHookList(options, spec, log, explicitGroup)) {
        return false;
      }
      continue;
    }
    if (wcscmp(arg, L"--hook-type") == 0 ||
        wcscmp(arg, L"--hook-method") == 0 || wcscmp(arg, L"--ht") == 0 ||
        wcsncmp(arg, L"--hook-type=", 12) == 0 ||
        wcsncmp(arg, L"--hook-method=", 14) == 0 ||
        wcsncmp(arg, L"--ht=", 5) == 0 || wcscmp(arg, L"--inline") == 0 ||
        wcscmp(arg, L"--jmp") == 0 || wcscmp(arg, L"--int3") == 0 ||
        wcscmp(arg, L"--iat") == 0 || wcscmp(arg, L"--shadow-iat") == 0 ||
        wcscmp(arg, L"--shadowcpy") == 0) {
      UINT32 method = IXIPC_HOOK_METHOD_INLINE;
      if (wcscmp(arg, L"--inline") == 0 || wcscmp(arg, L"--jmp") == 0) {
        method = IXIPC_HOOK_METHOD_INLINE;
      } else if (wcscmp(arg, L"--int3") == 0) {
        method = IXIPC_HOOK_METHOD_INT3;
      } else if (wcscmp(arg, L"--iat") == 0) {
        method = IXIPC_HOOK_METHOD_IAT;
      } else if (wcscmp(arg, L"--shadow-iat") == 0 ||
                 wcscmp(arg, L"--shadowcpy") == 0) {
        method = IXIPC_HOOK_METHOD_SHADOW_IAT;
      } else {
        const wchar_t *value = wcschr(arg, L'=');
        if (value != nullptr) {
          ++value;
        } else {
          if (argIndex + 1 >= argc) {
            std::wprintf(
                L"[blind] %ls requires inline, int3, iat, or shadow-iat\n",
                arg);
            return false;
          }
          value = argv[++argIndex];
        }
        if (!ParseHookMethodValue(value, method)) {
          std::wprintf(L"[blind] unknown hook type: %ls\n", value);
          return false;
        }
      }
      if (!ApplyHookMethodToRecentRules(options, method, arg)) {
        return false;
      }
      continue;
    }
    if (wcscmp(arg, L"--deny") == 0 || wcscmp(arg, L"--silent-deny") == 0) {
      if (options.LastRuleCount == 0 ||
          options.LastRuleStart >= options.CliPolicy.RuleCount) {
        std::wprintf(L"[blind] %ls must follow --hook or --lhook\n", arg);
        return false;
      }
      UINT32 end = options.LastRuleStart + options.LastRuleCount;
      if (end > options.CliPolicy.RuleCount) {
        end = options.CliPolicy.RuleCount;
      }
      for (UINT32 i = options.LastRuleStart; i < end; ++i) {
        IXIPC_HOOK_POLICY_RULE &rule = options.CliPolicy.Rules[i];
        if (rule.Component != IXIPC_HOOK_POLICY_COMPONENT_NT) {
          std::wprintf(
              L"[blind] %ls is only supported for NT hooks; %S is a %ls hook\n",
              arg, rule.ApiName, ComponentDisplayName(rule.Component));
          return false;
        }
        if (wcscmp(arg, L"--deny") == 0) {
          rule.Action = IXIPC_HOOK_ACTION_DENY;
          rule.DenyStatus = 0xC0000022u;
        } else {
          rule.Action = IXIPC_HOOK_ACTION_SILENT_DENY;
          rule.DenyStatus = 0;
        }
      }
      continue;
    }
    if (wcscmp(arg, L"--sf") == 0 || wcscmp(arg, L"--stack-fabricate") == 0 ||
        wcscmp(arg, L"--stack-sanitize") == 0) {
      if (options.LastRuleCount == 0 ||
          options.LastRuleStart >= options.CliPolicy.RuleCount) {
        std::wprintf(L"[blind] %ls must follow --hook or --lhook\n", arg);
        return false;
      }
      UINT32 end = options.LastRuleStart + options.LastRuleCount;
      if (end > options.CliPolicy.RuleCount) {
        end = options.CliPolicy.RuleCount;
      }
      for (UINT32 i = options.LastRuleStart; i < end; ++i) {
        options.CliPolicy.Rules[i].Flags |=
            IXIPC_HOOK_RULE_FLAG_STACK_FABRICATE |
            IXIPC_HOOK_RULE_FLAG_STACK_TRACE;
      }
      continue;
    }
    if (wcscmp(arg, L"--stack-trace") == 0) {
      if (options.LastRuleCount == 0 ||
          options.LastRuleStart >= options.CliPolicy.RuleCount) {
        std::wprintf(L"[blind] --stack-trace must follow --hook or --lhook\n");
        return false;
      }
      UINT32 end = options.LastRuleStart + options.LastRuleCount;
      if (end > options.CliPolicy.RuleCount) {
        end = options.CliPolicy.RuleCount;
      }
      for (UINT32 i = options.LastRuleStart; i < end; ++i) {
        options.CliPolicy.Rules[i].Flags |= IXIPC_HOOK_RULE_FLAG_STACK_TRACE;
      }
      continue;
    }
    if (wcscmp(arg, L"--r") == 0 || wcscmp(arg, L"--regs") == 0 ||
        wcscmp(arg, L"--registers") == 0) {
      if (options.LastRuleCount == 0 ||
          options.LastRuleStart >= options.CliPolicy.RuleCount) {
        std::wprintf(L"[blind] %ls must follow --hook or --lhook\n", arg);
        return false;
      }
      UINT32 end = options.LastRuleStart + options.LastRuleCount;
      if (end > options.CliPolicy.RuleCount) {
        end = options.CliPolicy.RuleCount;
      }
      for (UINT32 i = options.LastRuleStart; i < end; ++i) {
        IXIPC_HOOK_POLICY_RULE &rule = options.CliPolicy.Rules[i];
        if (rule.Component != IXIPC_HOOK_POLICY_COMPONENT_NT) {
          std::wprintf(
              L"[blind] %ls is only supported for NT hooks; %S is a %ls hook\n",
              arg, rule.ApiName, ComponentDisplayName(rule.Component));
          return false;
        }
        rule.Flags |= IXIPC_HOOK_RULE_FLAG_REGISTERS;
      }
      continue;
    }
    if (wcscmp(arg, L"--ignore-dll") == 0) {
      if (argIndex + 1 >= argc) {
        std::wprintf(L"[blind] --ignore-dll requires a DLL basename\n");
        return false;
      }
      if (!AddIgnoreDll(options, argv[++argIndex])) {
        return false;
      }
      continue;
    }
    if (wcscmp(arg, L"--ignore-private") == 0) {
      options.CliPolicy.Flags |= IXIPC_HOOK_POLICY_FLAG_IGNORE_PRIVATE;
      continue;
    }

    if (!options.TargetSet) {
      options.TargetPath = arg;
      options.TargetSet = true;
    } else {
      options.TargetArgs.push_back(arg);
    }
  }

  if (!options.TargetSet) {
    std::wprintf(L"[blind] CLI mode requires -- <target.exe> [args...]\n");
    return false;
  }
  FinalizeSmartPolicy(options);
  if (options.SmartMode) {
    if (!AddDefaultSmartRules(options)) {
      return false;
    }
  }
  if (options.CliPolicy.RuleCount == 0) {
    std::wprintf(
        L"[blind] CLI mode requires at least one --hook or --lhook rule\n");
    return false;
  }
  EnableSmartCallsiteStackCollection(options);

  if (options.Verbose || options.DebugDiagnostics || options.SmartMode) {
    for (UINT32 i = 0; i < options.CliPolicy.RuleCount; ++i) {
      options.CliPolicy.Rules[i].Flags |= IXIPC_HOOK_RULE_FLAG_LOG;
    }
  }
  if (options.SmartAutoProtect) {
    std::wprintf(L"[blind:behavior] auto-enabled protect folding for "
                 L"NtProtectVirtualMemory; add --raw for raw hits\n");
  }
  if (options.SmartFoldedProtectStacks) {
    std::wprintf(L"[blind:behavior] folded NtProtectVirtualMemory stack traces "
                 L"into grouped caller summaries\n");
  }
  return true;
}
} // namespace blind::injector
