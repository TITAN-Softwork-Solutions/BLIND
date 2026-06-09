#include "Core/runner_console.h"
#include "Policy/hook_catalog.h"
#include "Policy/option_parsing.h"

namespace blind::injector {
bool ParseSizeValue(const std::wstring &value, UINT64 &out) noexcept {
  out = 0;
  if (value.empty()) {
    return false;
  }

  const wchar_t *cursor = value.c_str();
  wchar_t *end = nullptr;
  unsigned long long number = std::wcstoull(cursor, &end, 10);
  if (end == cursor) {
    return false;
  }

  UINT64 multiplier = 1;
  if (_wcsicmp(end, L"kb") == 0 || _wcsicmp(end, L"k") == 0) {
    multiplier = 1024ull;
  } else if (_wcsicmp(end, L"mb") == 0 || _wcsicmp(end, L"m") == 0) {
    multiplier = 1024ull * 1024ull;
  } else if (_wcsicmp(end, L"gb") == 0 || _wcsicmp(end, L"g") == 0) {
    multiplier = 1024ull * 1024ull * 1024ull;
  } else if (*end != L'\0') {
    return false;
  }

  out = static_cast<UINT64>(number) * multiplier;
  return true;
}

bool ParseDurationMs(const wchar_t *arg, DWORD &out) noexcept {
  out = INFINITE;
  std::wstring value = ToLowerWide(arg);
  if (value.empty()) {
    return false;
  }
  if (value == L"0" || value == L"none" || value == L"infinite" ||
      value == L"inf" || value == L"off") {
    out = INFINITE;
    return true;
  }

  const wchar_t *cursor = value.c_str();
  wchar_t *end = nullptr;
  unsigned long long number = std::wcstoull(cursor, &end, 10);
  if (end == cursor) {
    return false;
  }

  unsigned long long multiplier = 1;
  if (*end == L'\0' || wcscmp(end, L"ms") == 0 || wcscmp(end, L"msec") == 0 ||
      wcscmp(end, L"millis") == 0) {
    multiplier = 1;
  } else if (wcscmp(end, L"s") == 0 || wcscmp(end, L"sec") == 0 ||
             wcscmp(end, L"secs") == 0 || wcscmp(end, L"second") == 0 ||
             wcscmp(end, L"seconds") == 0) {
    multiplier = 1000ull;
  } else if (wcscmp(end, L"m") == 0 || wcscmp(end, L"min") == 0 ||
             wcscmp(end, L"mins") == 0 || wcscmp(end, L"minute") == 0 ||
             wcscmp(end, L"minutes") == 0) {
    multiplier = 60ull * 1000ull;
  } else {
    return false;
  }

  unsigned long long ms = number * multiplier;
  if (ms == 0 || ms >= 0xFFFFFFFFull) {
    return false;
  }
  out = static_cast<DWORD>(ms);
  return true;
}

bool ParseSmartAreas(RunnerOptions &options, const wchar_t *arg) {
  options.SmartMode = true;
  options.SmartAreas = kSmartAreaDefault;

  const wchar_t *equals = wcschr(arg, L'=');
  if (equals == nullptr || equals[1] == L'\0') {
    return true;
  }

  options.SmartAreas = 0;
  std::wstring areas = ToLowerWide(equals + 1);
  std::size_t start = 0;
  while (start <= areas.size()) {
    std::size_t comma = areas.find(L',', start);
    std::wstring token =
        areas.substr(start, comma == std::wstring::npos ? std::wstring::npos
                                                        : comma - start);
    if (token == L"all") {
      options.SmartAreas |= kSmartAreaAll;
    } else if (token == L"remote" || token == L"remotes") {
      options.SmartAreas |= kSmartAreaRemote;
    } else if (token == L"memory" || token == L"alloc" || token == L"allocs") {
      options.SmartAreas |= kSmartAreaMemory;
    } else if (token == L"protect" || token == L"protections") {
      options.SmartAreas |= kSmartAreaProtect;
    } else if (token == L"threads" || token == L"thread") {
      options.SmartAreas |= kSmartAreaThreads;
    } else if (token == L"writes" || token == L"write") {
      options.SmartAreas |= kSmartAreaWrites;
    } else if (token == L"reads" || token == L"read") {
      options.SmartAreas |= kSmartAreaReads;
    } else if (token == L"queries" || token == L"query" || token == L"vads" ||
               token == L"vad") {
      options.SmartAreas |= kSmartAreaQueries;
    } else if (token == L"handles" || token == L"handle") {
      options.SmartAreas |= kSmartAreaHandles;
    } else if (token == L"apc" || token == L"apcs") {
      options.SmartAreas |= kSmartAreaApc;
    } else if (token == L"maps" || token == L"map") {
      options.SmartAreas |= kSmartAreaMaps;
    } else if (!token.empty()) {
      std::wprintf(L"[blind] unknown --behavior area: %ls\n", token.c_str());
      return false;
    }

    if (comma == std::wstring::npos) {
      break;
    }
    start = comma + 1;
  }

  if (options.SmartAreas == 0) {
    std::wprintf(L"[blind] --behavior requires at least one area\n");
    return false;
  }
  return true;
}

bool ParseSmartCondition(RunnerOptions &options, const wchar_t *condition) {
  std::wstring value = ToLowerWide(condition);
  if (value == L"rwx") {
    options.Conditions.Rwx = true;
  } else if (value == L"remote") {
    options.Conditions.Remote = true;
  } else if (value == L"start.private") {
    options.Conditions.StartPrivate = true;
  } else if (value.rfind(L"protect.flips>=", 0) == 0) {
    UINT64 parsed = 0;
    if (!ParseSizeValue(value.substr(wcslen(L"protect.flips>=")), parsed) ||
        parsed > 0xFFFFFFFFull) {
      std::wprintf(L"[blind] invalid --when threshold: %ls\n", condition);
      return false;
    }
    options.Conditions.ProtectFlipsAtLeast = static_cast<UINT32>(parsed);
  } else if (value.rfind(L"thread.count>=", 0) == 0) {
    UINT64 parsed = 0;
    if (!ParseSizeValue(value.substr(wcslen(L"thread.count>=")), parsed) ||
        parsed > 0xFFFFFFFFull) {
      std::wprintf(L"[blind] invalid --when threshold: %ls\n", condition);
      return false;
    }
    options.Conditions.ThreadCountAtLeast = static_cast<UINT32>(parsed);
  } else if (value.rfind(L"alloc.total>", 0) == 0) {
    UINT64 parsed = 0;
    if (!ParseSizeValue(value.substr(wcslen(L"alloc.total>")), parsed)) {
      std::wprintf(L"[blind] invalid --when size: %ls\n", condition);
      return false;
    }
    options.Conditions.AllocTotalGreater = parsed;
  } else {
    std::wprintf(L"[blind] unknown --when condition: %ls\n", condition);
    return false;
  }

  options.Conditions.Any = true;
  return true;
}

bool IsSmartStackFrameValue(const wchar_t *arg) {
  if (arg == nullptr || arg[0] == L'\0') {
    return false;
  }

  std::wstring value = ToLowerWide(arg);
  if (value == L"all" || value == L"full" || value == L"max") {
    return true;
  }

  UINT64 parsed = 0;
  return ParseSizeValue(value, parsed);
}

bool ParseSmartStacks(RunnerOptions &options, const wchar_t *arg) {
  options.SmartMode = true;
  options.SmartStacks = true;
  const wchar_t *equals = wcschr(arg, L'=');
  if (equals == nullptr) {
    return true;
  }

  std::wstring value = ToLowerWide(equals + 1);
  if (value == L"all" || value == L"full" || value == L"max") {
    options.SmartStackFrameLimit = IXIPC_MAX_HOOK_STACK_FRAMES;
    return true;
  }

  UINT64 parsed = 0;
  if (!ParseSizeValue(value, parsed) || parsed == 0 ||
      parsed > IXIPC_MAX_HOOK_STACK_FRAMES) {
    std::wprintf(L"[blind] invalid behavior stack frame count: %ls\n", arg);
    return false;
  }
  options.SmartStackFrameLimit = static_cast<UINT32>(parsed);
  return true;
}

bool ParseColorMode(RunnerOptions &options, const wchar_t *arg) {
  std::wstring value = ToLowerWide(arg);
  if (value == L"--no-color" || value == L"--no-colour" ||
      value == L"--color=never" || value == L"--colour=never") {
    options.ColorMode = ConsoleColorMode::Never;
  } else if (value == L"--color" || value == L"--colour" ||
             value == L"--color=always" || value == L"--colour=always") {
    options.ColorMode = ConsoleColorMode::Always;
  } else if (value == L"--color=auto" || value == L"--colour=auto") {
    options.ColorMode = ConsoleColorMode::Auto;
  } else {
    std::wprintf(L"[blind] invalid color mode: %ls\n", arg);
    return false;
  }
  ConfigureConsoleColor(options.ColorMode);
  return true;
}
} // namespace blind::injector
