#include "Telemetry/process_symbols.h"
#include "Core/runner_console.h"

#include <cctype>

namespace blind::injector {
void CopyDisplaySymbolName(const char *symbolName, char *out,
                           std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  if (symbolName == nullptr || symbolName[0] == '\0') {
    return;
  }

  char *cursor = out;
  std::size_t remaining = outChars;
  const char *input = symbolName;
  while (*input != '\0' && remaining > 1) {
    if (std::strncmp(input, "ix::IX::", 8) == 0) {
      HRESULT hr = StringCchCopyExA(cursor, remaining, "Interceptor::", &cursor,
                                    &remaining, 0);
      if (FAILED(hr)) {
        break;
      }
      input += 8;
      continue;
    }

    const bool tokenBoundary =
        input == symbolName ||
        (!std::isalnum(static_cast<unsigned char>(input[-1])) &&
         input[-1] != '_');
    if (tokenBoundary && std::strncmp(input, "IX_", 3) == 0) {
      HRESULT hr = StringCchCopyExA(cursor, remaining, "Interceptor_", &cursor,
                                    &remaining, 0);
      if (FAILED(hr)) {
        break;
      }
      input += 3;
      continue;
    }

    *cursor++ = *input++;
    --remaining;
    *cursor = '\0';
  }
}

void RefreshChildModules(ServerContext &ctx) {
  if (ctx.ChildProcessId == 0) {
    return;
  }

  HANDLE snapshot = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ctx.ChildProcessId);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return;
  }

  std::vector<ChildModuleEntry> modules;
  modules.reserve(ctx.ChildModules.empty() ? 128
                                           : ctx.ChildModules.size() + 16);
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Module32FirstW(snapshot, &entry)) {
    do {
      ChildModuleEntry module{};
      module.Base = reinterpret_cast<UINT64>(entry.modBaseAddr);
      module.Size = static_cast<UINT64>(entry.modBaseSize);
      (void)WideCharToMultiByte(CP_UTF8, 0, entry.szModule, -1, module.Name,
                                RTL_NUMBER_OF(module.Name), nullptr, nullptr);
      (void)StringCchCopyW(module.Path, RTL_NUMBER_OF(module.Path),
                           entry.szExePath);
      modules.push_back(module);
      entry.dwSize = sizeof(entry);
    } while (Module32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);

  if (!modules.empty()) {
    std::sort(modules.begin(), modules.end(),
              [](const ChildModuleEntry &left, const ChildModuleEntry &right) {
                return left.Base < right.Base;
              });
    ctx.ChildModules.swap(modules);
    ctx.LastModuleSnapshotTick = GetTickCount();
  }
}

DWORD NormalizeTargetPid(const ServerContext &ctx, DWORD pid) noexcept {
  return pid == 0 ? ctx.ChildProcessId : pid;
}

const ChildModuleEntry *FindChildModule(ServerContext &ctx, UINT64 address) {
  if (address == 0) {
    return nullptr;
  }

  if (ctx.ChildModules.empty() ||
      GetTickCount() - ctx.LastModuleSnapshotTick > 1000) {
    RefreshChildModules(ctx);
  }

  auto findInSnapshot = [&](UINT64 value) -> const ChildModuleEntry * {
    auto it = std::upper_bound(
        ctx.ChildModules.begin(), ctx.ChildModules.end(), value,
        [](UINT64 addressValue, const ChildModuleEntry &module) {
          return addressValue < module.Base;
        });
    if (it == ctx.ChildModules.begin()) {
      return nullptr;
    }
    --it;
    UINT64 end = it->Base + it->Size;
    if (end <= it->Base) {
      end = UINT64_MAX;
    }
    return value >= it->Base && value < end ? &(*it) : nullptr;
  };

  if (const ChildModuleEntry *module = findInSnapshot(address)) {
    return module;
  }

  RefreshChildModules(ctx);
  return findInSnapshot(address);
}

const ChildModuleEntry *FindChildModuleNoRefresh(const ServerContext &ctx,
                                                 UINT64 address) noexcept {
  if (address == 0 || ctx.ChildModules.empty()) {
    return nullptr;
  }

  auto it = std::upper_bound(
      ctx.ChildModules.begin(), ctx.ChildModules.end(), address,
      [](UINT64 addressValue, const ChildModuleEntry &module) {
        return addressValue < module.Base;
      });
  if (it == ctx.ChildModules.begin()) {
    return nullptr;
  }
  --it;
  UINT64 end = it->Base + it->Size;
  if (end <= it->Base) {
    end = UINT64_MAX;
  }
  return address >= it->Base && address < end ? &(*it) : nullptr;
}

bool InitializeSymbols(ServerContext &ctx) noexcept {
  if (ctx.SymbolsInitialized) {
    return true;
  }

  DWORD options = SymGetOptions();
  options |=
      SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_UNDNAME;
  options &= ~SYMOPT_LOAD_ANYTHING;
  SymSetOptions(options);

  const wchar_t *symbolSearchPath =
      ctx.SymbolSearchPath.empty() ? nullptr : ctx.SymbolSearchPath.c_str();
  if (!SymInitializeW(GetCurrentProcess(), symbolSearchPath, FALSE)) {
    return false;
  }
  ctx.SymbolsInitialized = true;
  return true;
}

bool SymbolBaseAttempted(const ServerContext &ctx, UINT64 base) noexcept {
  return ctx.SymbolAttemptedBases.find(base) != ctx.SymbolAttemptedBases.end();
}

void EnsureChildSymbols(ServerContext &ctx) {
  if (!ctx.ResolveSymbols || !InitializeSymbols(ctx)) {
    return;
  }

  if (ctx.ChildModules.empty() ||
      GetTickCount() - ctx.LastModuleSnapshotTick > 1000) {
    RefreshChildModules(ctx);
  }
  if (ctx.LastSymbolSweepModuleTick == ctx.LastModuleSnapshotTick) {
    return;
  }

  for (const auto &module : ctx.ChildModules) {
    if (module.Base == 0 || module.Path[0] == L'\0' ||
        SymbolBaseAttempted(ctx, module.Base)) {
      continue;
    }

    ctx.SymbolAttemptedBases.insert(module.Base);
    DWORD imageSize =
        module.Size > 0xFFFFFFFFull ? 0 : static_cast<DWORD>(module.Size);
    (void)SymLoadModuleExW(GetCurrentProcess(), nullptr, module.Path, nullptr,
                           module.Base, imageSize, nullptr, 0);
  }
  ctx.LastSymbolSweepModuleTick = ctx.LastModuleSnapshotTick;
}

void FormatChildAddress(ServerContext &ctx, UINT64 address, char *out,
                        std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  if (address == 0) {
    (void)StringCchCopyA(out, outChars, "0x0");
    return;
  }

  if (ctx.ChildModules.empty() ||
      GetTickCount() - ctx.LastModuleSnapshotTick > 1000) {
    RefreshChildModules(ctx);
  }

  if (const ChildModuleEntry *module = FindChildModuleNoRefresh(ctx, address)) {
    (void)StringCchPrintfA(
        out, outChars, "%s+0x%llX", module->Name,
        static_cast<unsigned long long>(address - module->Base));
    return;
  }

  RefreshChildModules(ctx);
  if (const ChildModuleEntry *module = FindChildModuleNoRefresh(ctx, address)) {
    (void)StringCchPrintfA(
        out, outChars, "%s+0x%llX", module->Name,
        static_cast<unsigned long long>(address - module->Base));
    return;
  }

  (void)StringCchPrintfA(out, outChars, "0x%llX",
                         static_cast<unsigned long long>(address));
}

void FormatChildSymbolAddress(ServerContext &ctx, UINT64 address, char *out,
                              std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  if (address == 0) {
    (void)StringCchCopyA(out, outChars, "0x0");
    return;
  }

  EnsureChildSymbols(ctx);
  if (ctx.SymbolsInitialized) {
    constexpr DWORD kMaxSymbolName = 1024;
    alignas(
        SYMBOL_INFO) char symbolBuffer[sizeof(SYMBOL_INFO) + kMaxSymbolName]{};
    auto *symbol = reinterpret_cast<SYMBOL_INFO *>(symbolBuffer);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = kMaxSymbolName;

    DWORD64 displacement = 0;
    if (SymFromAddr(GetCurrentProcess(), address, &displacement, symbol)) {
      const ChildModuleEntry *module = FindChildModule(ctx, address);
      const char *moduleName = module != nullptr && module->Name[0] != '\0'
                                   ? module->Name
                                   : "module";
      char displaySymbol[1024]{};
      CopyDisplaySymbolName(symbol->Name, displaySymbol,
                            RTL_NUMBER_OF(displaySymbol));
      const char *symbolText =
          displaySymbol[0] != '\0' ? displaySymbol : symbol->Name;
      if (displacement != 0) {
        (void)StringCchPrintfA(out, outChars, "%s!%s+0x%llX", moduleName,
                               symbolText,
                               static_cast<unsigned long long>(displacement));
      } else {
        (void)StringCchPrintfA(out, outChars, "%s!%s", moduleName, symbolText);
      }
      return;
    }
  }

  FormatChildAddress(ctx, address, out, outChars);
}

void CleanupSymbols(ServerContext &ctx) noexcept {
  if (ctx.SymbolsInitialized) {
    SymCleanup(GetCurrentProcess());
    ctx.SymbolsInitialized = false;
  }
  ctx.SymbolAttemptedBases.clear();
  ctx.LastSymbolSweepModuleTick = 0;
}
bool NtStatusSucceeded(UINT32 status) noexcept {
  return static_cast<LONG>(status) >= 0;
}

bool ApiIs(const IXIPC_HOOK_EVENT &eventRecord, const char *name) noexcept {
  return eventRecord.ApiName[0] != '\0' &&
         _stricmp(eventRecord.ApiName, name) == 0;
}

bool SmartAreaEnabled(const ServerContext &ctx, UINT32 flag) noexcept {
  return (ctx.SmartAreas & flag) != 0;
}

UINT64 StackHash(const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  UINT64 hash = 1469598103934665603ull;
  hash ^= eventRecord.Caller;
  hash *= 1099511628211ull;
  UINT32 count = eventRecord.StackCount < IXIPC_MAX_HOOK_STACK_FRAMES
                     ? eventRecord.StackCount
                     : IXIPC_MAX_HOOK_STACK_FRAMES;
  for (UINT32 i = 0; i < count; ++i) {
    hash ^= eventRecord.Stack[i];
    hash *= 1099511628211ull;
  }
  return hash;
}

UINT64 PageCount(UINT64 size) noexcept {
  return size == 0 ? 0 : ((size + 0xFFFu) >> 12);
}

UINT64 PageBase(UINT64 address) noexcept { return address & ~0xFFFull; }

UINT64 RangeEnd(UINT64 base, UINT64 size) noexcept {
  UINT64 end = base + (size != 0 ? size : 1);
  return end <= base ? UINT64_MAX : end;
}

} // namespace blind::injector
