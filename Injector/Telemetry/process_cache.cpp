#include "Telemetry/process_cache.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_symbols.h"

namespace blind::injector {
void CloseCachedProcessHandles(ServerContext &ctx) noexcept {
  for (auto &entry : ctx.ProcessHandleCache) {
    if (entry.Handle != nullptr && entry.Handle != ctx.ChildProcessHandle) {
      CloseHandle(entry.Handle);
    }
    entry.Handle = nullptr;
  }
  ctx.ProcessHandleCache.clear();
}

void RemoveCachedProcessHandle(ServerContext &ctx, DWORD pid) noexcept {
  DWORD normalized = NormalizeTargetPid(ctx, pid);
  for (auto it = ctx.ProcessHandleCache.begin();
       it != ctx.ProcessHandleCache.end(); ++it) {
    if (it->ProcessId != normalized) {
      continue;
    }
    if (it->Handle != nullptr && it->Handle != ctx.ChildProcessHandle) {
      CloseHandle(it->Handle);
    }
    ctx.ProcessHandleCache.erase(it);
    return;
  }
}

HANDLE CachedProcessHandle(ServerContext &ctx, DWORD pid) noexcept {
  DWORD normalized = NormalizeTargetPid(ctx, pid);
  if (normalized == 0 || normalized == ctx.ChildProcessId) {
    return ctx.ChildProcessHandle;
  }

  DWORD now = GetTickCount();
  for (auto &entry : ctx.ProcessHandleCache) {
    if (entry.ProcessId == normalized) {
      entry.LastUseTick = now;
      return entry.Handle;
    }
  }

  HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, normalized);
  if (process == nullptr) {
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, normalized);
  }
  if (process == nullptr) {
    return nullptr;
  }

  ProcessHandleEntry entry{};
  entry.ProcessId = normalized;
  entry.Handle = process;
  entry.LastUseTick = now;
  try {
    if (ctx.ProcessHandleCache.size() < kMaxCachedProcessHandles) {
      ctx.ProcessHandleCache.push_back(entry);
    } else {
      auto victim = std::min_element(
          ctx.ProcessHandleCache.begin(), ctx.ProcessHandleCache.end(),
          [](const ProcessHandleEntry &left, const ProcessHandleEntry &right) {
            return left.LastUseTick < right.LastUseTick;
          });
      if (victim != ctx.ProcessHandleCache.end()) {
        if (victim->Handle != nullptr &&
            victim->Handle != ctx.ChildProcessHandle) {
          CloseHandle(victim->Handle);
        }
        *victim = entry;
      }
    }
  } catch (...) {
    CloseHandle(process);
    return nullptr;
  }
  return process;
}

HANDLE OpenSmartProcessHandle(ServerContext &ctx, DWORD pid,
                              bool &mustClose) noexcept {
  mustClose = false;
  return CachedProcessHandle(ctx, pid);
}

bool TryGetCachedVadInfo(ServerContext &ctx, DWORD targetPid, UINT64 address,
                         SmartVadInfo &out) noexcept {
  DWORD normalized = NormalizeTargetPid(ctx, targetPid);
  if (normalized == 0 || address == 0) {
    return false;
  }

  DWORD now = GetTickCount();
  auto it = ctx.VadCache.upper_bound(AddressRangeKey{normalized, address});
  if (it == ctx.VadCache.begin()) {
    return false;
  }
  --it;
  VadCacheEntry &entry = it->second;
  if (entry.TargetPid == normalized && address >= entry.Base &&
      address < entry.End) {
    entry.LastUseTick = now;
    out = entry.Vad;
    return true;
  }
  return false;
}

void CacheVadInfo(ServerContext &ctx, DWORD targetPid,
                  const SmartVadInfo &vad) noexcept {
  DWORD normalized = NormalizeTargetPid(ctx, targetPid);
  if (normalized == 0 || !vad.Valid || vad.RegionSize == 0) {
    return;
  }

  VadCacheEntry entry{};
  entry.TargetPid = normalized;
  entry.Base = vad.BaseAddress;
  entry.End = RangeEnd(vad.BaseAddress, vad.RegionSize);
  entry.LastUseTick = GetTickCount();
  entry.Vad = vad;

  try {
    ctx.VadCache[AddressRangeKey{entry.TargetPid, entry.Base}] = entry;
    if (ctx.VadCache.size() <= kMaxCachedVadEntries) {
      return;
    }

    auto victim = std::min_element(ctx.VadCache.begin(), ctx.VadCache.end(),
                                   [](const auto &left, const auto &right) {
                                     return left.second.LastUseTick <
                                            right.second.LastUseTick;
                                   });
    if (victim != ctx.VadCache.end()) {
      ctx.VadCache.erase(victim);
    }
  } catch (...) {
  }
}

void InvalidateVadCache(ServerContext &ctx, DWORD targetPid, UINT64 base,
                        UINT64 size) noexcept {
  DWORD normalized = NormalizeTargetPid(ctx, targetPid);
  if (normalized == 0) {
    return;
  }

  UINT64 end = RangeEnd(base, size);
  for (auto it = ctx.VadCache.lower_bound(AddressRangeKey{normalized, 0});
       it != ctx.VadCache.end();) {
    const VadCacheEntry &entry = it->second;
    if (entry.TargetPid != normalized) {
      break;
    }
    if (entry.Base < end && entry.End > base) {
      it = ctx.VadCache.erase(it);
      continue;
    }
    ++it;
  }
}

bool QueryVadInfo(ServerContext &ctx, DWORD targetPid, UINT64 address,
                  SmartVadInfo &out) noexcept {
  out = SmartVadInfo{};
  if (address == 0) {
    return false;
  }
  DWORD normalizedPid = NormalizeTargetPid(ctx, targetPid);
  if (TryGetCachedVadInfo(ctx, normalizedPid, address, out)) {
    return true;
  }

  bool mustClose = false;
  HANDLE process = OpenSmartProcessHandle(ctx, normalizedPid, mustClose);
  if (process == nullptr) {
    return false;
  }

  MEMORY_BASIC_INFORMATION mbi{};
  SIZE_T result = VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address),
                                 &mbi, sizeof(mbi));
  if (mustClose) {
    CloseHandle(process);
  }
  if (result == 0) {
    RemoveCachedProcessHandle(ctx, normalizedPid);
    return false;
  }

  out.Valid = true;
  out.BaseAddress = reinterpret_cast<UINT64>(mbi.BaseAddress);
  out.AllocationBase = reinterpret_cast<UINT64>(mbi.AllocationBase);
  out.RegionSize = static_cast<UINT64>(mbi.RegionSize);
  out.Protect = mbi.Protect;
  out.AllocationProtect = mbi.AllocationProtect;
  out.State = mbi.State;
  out.Type = mbi.Type;
  CacheVadInfo(ctx, normalizedPid, out);
  return true;
}

template <std::size_t Count>
bool ModuleNameIn(const char *moduleName,
                  const char *const (&names)[Count]) noexcept {
  if (moduleName == nullptr || moduleName[0] == '\0') {
    return false;
  }

  for (const char *name : names) {
    if (_stricmp(moduleName, name) == 0) {
      return true;
    }
  }
  return false;
}

const char *FrameRoleForModuleName(const char *moduleName) noexcept {
  if (moduleName == nullptr || moduleName[0] == '\0') {
    return "[unknown]";
  }

  if (_stricmp(moduleName, "BLIND.dll") == 0) {
    return "[internal]";
  }

  static const char *const systemModules[] = {
      "ntdll.dll",
      "kernel32.dll",
      "kernelbase.dll",
      "advapi32.dll",
      "sechost.dll",
      "rpcrt4.dll",
      "ole32.dll",
      "combase.dll",
      "user32.dll",
      "gdi32.dll",
      "gdi32full.dll",
      "win32u.dll",
      "shell32.dll",
      "shlwapi.dll",
      "crypt32.dll",
      "bcrypt.dll",
      "bcryptprimitives.dll",
      "ncrypt.dll",
      "secur32.dll",
      "sspicli.dll",
      "ws2_32.dll",
      "mswsock.dll",
      "dnsapi.dll",
      "iphlpapi.dll",
      "winhttp.dll",
      "wininet.dll",
      "rasapi32.dll",
      "rasman.dll",
      "psapi.dll",
      "version.dll",
      "ucrtbase.dll",
      "vcruntime140.dll",
      "vcruntime140_1.dll",
      "msvcp140.dll",
      "msvcp_win.dll",
      "windows.storage.dll",
      "kernel.appcore.dll",
      "imm32.dll",
      "cfgmgr32.dll",
      "devobj.dll",
      "wintrust.dll",
      "profapi.dll",
      "powrprof.dll",
      "umpdc.dll",
  };
  if (ModuleNameIn(moduleName, systemModules)) {
    return "[system]";
  }

  static const char *const runtimeModules[] = {
      "clr.dll",
      "clrjit.dll",
      "mscoree.dll",
      "mscoreei.dll",
      "mscorlib.ni.dll",
      "system.ni.dll",
      "system.core.ni.dll",
      "diasymreader.dll",
      "sos.dll",
      "sos_amd64.dll",
  };
  if (ModuleNameIn(moduleName, runtimeModules)) {
    return "[runtime]";
  }

  std::size_t length = std::strlen(moduleName);
  if (length > 4 && _stricmp(moduleName + length - 4, ".exe") == 0) {
    return "[app]";
  }

  return "[module]";
}

const char *FrameRoleForVad(const SmartVadInfo &vad) noexcept {
  if (!vad.Valid) {
    return "[unmapped]";
  }

  switch (vad.Type) {
  case MEM_IMAGE:
    return "[image]";
  case MEM_MAPPED:
    return "[mapped]";
  case MEM_PRIVATE:
    return "[private]";
  default:
    return "[memory]";
  }
}

const char *FrameRoleForChildAddress(ServerContext &ctx, UINT64 address) {
  const ChildModuleEntry *module = FindChildModule(ctx, address);
  if (module != nullptr) {
    return FrameRoleForModuleName(module->Name);
  }

  SmartVadInfo vad{};
  if (QueryVadInfo(ctx, ctx.ChildProcessId, address, vad)) {
    return FrameRoleForVad(vad);
  }
  return "[unmapped]";
}

} // namespace blind::injector
