#include "Telemetry/event_formatting.h"
#include "Telemetry/process_symbols.h"

namespace blind::injector {
void FormatBytes(UINT64 bytes, char *out, std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  if (bytes >= 1024ull * 1024ull * 1024ull) {
    (void)StringCchPrintfA(out, outChars, "%.2fGB",
                           static_cast<double>(bytes) /
                               (1024.0 * 1024.0 * 1024.0));
  } else if (bytes >= 1024ull * 1024ull) {
    (void)StringCchPrintfA(out, outChars, "%.2fMB",
                           static_cast<double>(bytes) / (1024.0 * 1024.0));
  } else if (bytes >= 1024ull) {
    (void)StringCchPrintfA(out, outChars, "%.2fKB",
                           static_cast<double>(bytes) / 1024.0);
  } else {
    (void)StringCchPrintfA(out, outChars, "%lluB",
                           static_cast<unsigned long long>(bytes));
  }
}

bool IsWriteExecuteProtect(UINT32 protect) noexcept {
  UINT32 base = protect & 0xFFu;
  return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool IsExecutableProtect(UINT32 protect) noexcept {
  UINT32 base = protect & 0xFFu;
  return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
         base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

void FormatProtect(UINT32 protect, char *out, std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }

  UINT32 base = protect & 0xFFu;
  const char *name = "UNKNOWN";
  switch (base) {
  case PAGE_NOACCESS:
    name = "NOACCESS";
    break;
  case PAGE_READONLY:
    name = "R";
    break;
  case PAGE_READWRITE:
    name = "RW";
    break;
  case PAGE_WRITECOPY:
    name = "WC";
    break;
  case PAGE_EXECUTE:
    name = "X";
    break;
  case PAGE_EXECUTE_READ:
    name = "RX";
    break;
  case PAGE_EXECUTE_READWRITE:
    name = "RWX";
    break;
  case PAGE_EXECUTE_WRITECOPY:
    name = "XWC";
    break;
  default:
    break;
  }

  (void)StringCchCopyA(out, outChars, name);
  if ((protect & PAGE_GUARD) != 0) {
    (void)StringCchCatA(out, outChars, "|GUARD");
  }
  if ((protect & PAGE_NOCACHE) != 0) {
    (void)StringCchCatA(out, outChars, "|NOCACHE");
  }
  if ((protect & PAGE_WRITECOMBINE) != 0) {
    (void)StringCchCatA(out, outChars, "|WRITECOMBINE");
  }
}

const char *MemoryStateName(UINT32 state) noexcept {
  switch (state) {
  case MEM_COMMIT:
    return "MEM_COMMIT";
  case MEM_RESERVE:
    return "MEM_RESERVE";
  case MEM_FREE:
    return "MEM_FREE";
  default:
    return "MEM_UNKNOWN";
  }
}

const char *MemoryTypeName(UINT32 type) noexcept {
  switch (type) {
  case MEM_IMAGE:
    return "MEM_IMAGE";
  case MEM_MAPPED:
    return "MEM_MAPPED";
  case MEM_PRIVATE:
    return "MEM_PRIVATE";
  default:
    return "MEM_UNKNOWN";
  }
}

void FormatAllocationType(UINT32 allocationType, char *out,
                          std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  if ((allocationType & MEM_COMMIT) != 0) {
    (void)StringCchCatA(out, outChars, "COMMIT");
  }
  if ((allocationType & MEM_RESERVE) != 0) {
    (void)StringCchCatA(out, outChars, out[0] ? "|RESERVE" : "RESERVE");
  }
  if ((allocationType & MEM_RESET) != 0) {
    (void)StringCchCatA(out, outChars, out[0] ? "|RESET" : "RESET");
  }
  if ((allocationType & MEM_TOP_DOWN) != 0) {
    (void)StringCchCatA(out, outChars, out[0] ? "|TOP_DOWN" : "TOP_DOWN");
  }
  if (out[0] == '\0') {
    (void)StringCchPrintfA(out, outChars, "0x%lX",
                           static_cast<unsigned long>(allocationType));
  }
}

const char *MemoryInformationClassName(UINT64 informationClass) noexcept {
  switch (informationClass) {
  case 0:
    return "MemoryBasicInformation";
  case 1:
    return "MemoryWorkingSetInformation";
  case 2:
    return "MemoryMappedFilenameInformation";
  case 3:
    return "MemoryRegionInformation";
  case 4:
    return "MemoryWorkingSetExInformation";
  case 5:
    return "MemorySharedCommitInformation";
  case 6:
    return "MemoryImageInformation";
  case 7:
    return "MemoryRegionInformationEx";
  case 8:
    return "MemoryPrivilegedBasicInformation";
  case 9:
    return "MemoryEnclaveImageInformation";
  case 10:
    return "MemoryBasicInformationCapped";
  case 11:
    return "MemoryPhysicalContiguityInformation";
  case 12:
    return "MemoryBadInformation";
  case 13:
    return "MemoryBadInformationAllProcesses";
  default:
    return "MemoryInformationClass";
  }
}
struct AccessMaskName {
  UINT32 Mask;
  const char *Name;
};

template <std::size_t Count>
void FormatAccessMask(UINT32 mask, const AccessMaskName (&names)[Count],
                      char *out, std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }

  (void)StringCchPrintfA(out, outChars, "0x%lX",
                         static_cast<unsigned long>(mask));
  char suffix[256]{};
  UINT32 shown = 0;
  UINT32 omitted = 0;
  constexpr UINT32 kInlineAccessNameLimit = 5;
  for (const auto &name : names) {
    if ((mask & name.Mask) == 0) {
      continue;
    }
    if (shown >= kInlineAccessNameLimit) {
      ++omitted;
      continue;
    }
    if (suffix[0] != '\0') {
      (void)StringCchCatA(suffix, RTL_NUMBER_OF(suffix), "|");
    }
    (void)StringCchCatA(suffix, RTL_NUMBER_OF(suffix), name.Name);
    ++shown;
  }
  if (omitted != 0) {
    char extra[32]{};
    (void)StringCchPrintfA(extra, RTL_NUMBER_OF(extra), "|+%lu",
                           static_cast<unsigned long>(omitted));
    (void)StringCchCatA(suffix, RTL_NUMBER_OF(suffix), extra);
  }
  if (suffix[0] != '\0') {
    (void)StringCchCatA(out, outChars, "(");
    (void)StringCchCatA(out, outChars, suffix);
    (void)StringCchCatA(out, outChars, ")");
  }
}

void FormatProcessAccess(UINT32 mask, char *out,
                         std::size_t outChars) noexcept {
  static constexpr AccessMaskName names[] = {
      {PROCESS_TERMINATE, "TERMINATE"},
      {PROCESS_CREATE_THREAD, "CREATE_THREAD"},
      {PROCESS_VM_OPERATION, "VM_OPERATION"},
      {PROCESS_VM_READ, "VM_READ"},
      {PROCESS_VM_WRITE, "VM_WRITE"},
      {PROCESS_DUP_HANDLE, "DUP_HANDLE"},
      {PROCESS_CREATE_PROCESS, "CREATE_PROCESS"},
      {PROCESS_SET_QUOTA, "SET_QUOTA"},
      {PROCESS_SET_INFORMATION, "SET_INFORMATION"},
      {PROCESS_QUERY_INFORMATION, "QUERY_INFORMATION"},
      {PROCESS_SUSPEND_RESUME, "SUSPEND_RESUME"},
      {PROCESS_QUERY_LIMITED_INFORMATION, "QUERY_LIMITED_INFORMATION"},
      {SYNCHRONIZE, "SYNCHRONIZE"},
  };
  FormatAccessMask(mask, names, out, outChars);
}

void FormatThreadAccess(UINT32 mask, char *out, std::size_t outChars) noexcept {
  static constexpr AccessMaskName names[] = {
      {THREAD_TERMINATE, "TERMINATE"},
      {THREAD_SUSPEND_RESUME, "SUSPEND_RESUME"},
      {THREAD_GET_CONTEXT, "GET_CONTEXT"},
      {THREAD_SET_CONTEXT, "SET_CONTEXT"},
      {THREAD_SET_INFORMATION, "SET_INFORMATION"},
      {THREAD_QUERY_INFORMATION, "QUERY_INFORMATION"},
      {THREAD_SET_THREAD_TOKEN, "SET_THREAD_TOKEN"},
      {THREAD_IMPERSONATE, "IMPERSONATE"},
      {THREAD_DIRECT_IMPERSONATION, "DIRECT_IMPERSONATION"},
      {THREAD_SET_LIMITED_INFORMATION, "SET_LIMITED_INFORMATION"},
      {THREAD_QUERY_LIMITED_INFORMATION, "QUERY_LIMITED_INFORMATION"},
      {SYNCHRONIZE, "SYNCHRONIZE"},
  };
  FormatAccessMask(mask, names, out, outChars);
}
void CopyBaseNameA(const wchar_t *path, char *out,
                   std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  if (path == nullptr || path[0] == L'\0') {
    return;
  }
  const wchar_t *base = path;
  for (const wchar_t *p = path; *p != L'\0'; ++p) {
    if (*p == L'\\' || *p == L'/') {
      base = p + 1;
    }
  }
  (void)WideCharToMultiByte(CP_UTF8, 0, base, -1, out,
                            static_cast<int>(outChars), nullptr, nullptr);
  out[outChars - 1] = '\0';
}

bool QueryProcessImageName(DWORD pid, char *out,
                           std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return false;
  }
  out[0] = '\0';
  if (pid == 0) {
    return false;
  }

  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) {
    return false;
  }

  wchar_t path[MAX_PATH]{};
  DWORD chars = RTL_NUMBER_OF(path);
  bool ok = QueryFullProcessImageNameW(process, 0, path, &chars) != FALSE;
  CloseHandle(process);
  if (!ok) {
    return false;
  }

  CopyBaseNameA(path, out, outChars);
  return out[0] != '\0';
}

const ProcessInfoEntry &ResolveProcessInfo(ServerContext &ctx, DWORD pid) {
  auto found = ctx.ProcessInfoByPid.find(pid);
  if (found != ctx.ProcessInfoByPid.end() &&
      found->second < ctx.ProcessInfoCache.size()) {
    return ctx.ProcessInfoCache[found->second];
  }

  ProcessInfoEntry entry{};
  entry.ProcessId = pid;
  entry.Queried = true;
  (void)QueryProcessImageName(pid, entry.ImageName,
                              RTL_NUMBER_OF(entry.ImageName));
  ctx.ProcessInfoCache.push_back(entry);
  ctx.ProcessInfoByPid[pid] = ctx.ProcessInfoCache.size() - 1;
  return ctx.ProcessInfoCache.back();
}

void FormatTargetProcess(ServerContext &ctx, DWORD sourcePid, DWORD targetPid,
                         char *out, std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  if (targetPid == 0) {
    (void)StringCchCopyA(out, outChars, "unknown");
    return;
  }

  const ProcessInfoEntry &info = ResolveProcessInfo(ctx, targetPid);
  const bool self = targetPid == sourcePid || targetPid == ctx.ChildProcessId;
  if (info.ImageName[0] != '\0') {
    (void)StringCchPrintfA(
        out, outChars, "%s(pid=%lu name=%s)", self ? "self" : "remote",
        static_cast<unsigned long>(targetPid), info.ImageName);
  } else {
    (void)StringCchPrintfA(out, outChars, "%s(pid=%lu)",
                           self ? "self" : "remote",
                           static_cast<unsigned long>(targetPid));
  }
}

DWORD QueryThreadOwnerProcessId(DWORD threadId) noexcept {
  if (threadId == 0) {
    return 0;
  }

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return 0;
  }

  THREADENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  DWORD ownerPid = 0;
  if (Thread32First(snapshot, &entry)) {
    do {
      if (entry.th32ThreadID == threadId) {
        ownerPid = entry.th32OwnerProcessID;
        break;
      }
      entry.dwSize = sizeof(entry);
    } while (Thread32Next(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return ownerPid;
}

bool QueryThreadWin32StartAddress(DWORD threadId,
                                  UINT64 &startAddress) noexcept {
  startAddress = 0;
  if (threadId == 0) {
    return false;
  }

  HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
  if (thread == nullptr) {
    thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
  }
  if (thread == nullptr) {
    return false;
  }

  using NtQueryInformationThreadFn =
      LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto query = ntdll != nullptr
                   ? reinterpret_cast<NtQueryInformationThreadFn>(
                         GetProcAddress(ntdll, "NtQueryInformationThread"))
                   : nullptr;
  if (query == nullptr) {
    CloseHandle(thread);
    return false;
  }

  ULONG_PTR start = 0;
  LONG status =
      query(thread, 9, &start, static_cast<ULONG>(sizeof(start)), nullptr);
  CloseHandle(thread);
  if (status < 0 || start == 0) {
    return false;
  }

  startAddress = static_cast<UINT64>(start);
  return true;
}

const ThreadInfoEntry &ResolveThreadInfo(ServerContext &ctx, DWORD threadId) {
  auto found = ctx.ThreadInfoByTid.find(threadId);
  if (found != ctx.ThreadInfoByTid.end() &&
      found->second < ctx.ThreadInfoCache.size()) {
    return ctx.ThreadInfoCache[found->second];
  }

  ThreadInfoEntry entry{};
  entry.ThreadId = threadId;
  entry.Queried = true;
  entry.OwnerProcessId = QueryThreadOwnerProcessId(threadId);
  entry.HasOwnerProcess = entry.OwnerProcessId != 0;
  entry.HasWin32StartAddress =
      QueryThreadWin32StartAddress(threadId, entry.Win32StartAddress);
  ctx.ThreadInfoCache.push_back(entry);
  ctx.ThreadInfoByTid[threadId] = ctx.ThreadInfoCache.size() - 1;
  return ctx.ThreadInfoCache.back();
}

std::string TargetLabel(ServerContext &ctx, DWORD sourcePid, DWORD targetPid) {
  DWORD normalized = NormalizeTargetPid(ctx, targetPid);
  if (normalized == 0 || normalized == sourcePid ||
      normalized == ctx.ChildProcessId) {
    return "self";
  }

  const ProcessInfoEntry &info = ResolveProcessInfo(ctx, normalized);
  if (info.ImageName[0] != '\0') {
    return std::string("remote(") + info.ImageName + ")";
  }

  char fallback[64]{};
  (void)StringCchPrintfA(fallback, RTL_NUMBER_OF(fallback), "remote(pid=%lu)",
                         static_cast<unsigned long>(normalized));
  return fallback;
}

bool IsRemoteTarget(const ServerContext &ctx, DWORD targetPid) noexcept {
  DWORD normalized = NormalizeTargetPid(ctx, targetPid);
  return normalized != 0 && normalized != ctx.ChildProcessId;
}

LogColor RemoteAwareColor(const ServerContext &ctx, DWORD targetPid,
                          LogColor color) noexcept {
  if (!IsRemoteTarget(ctx, targetPid)) {
    return color;
  }
  return color == LogColor::Warning || color == LogColor::Error ||
                 color == LogColor::Suspicious
             ? LogColor::RemoteRisk
             : LogColor::Remote;
}
} // namespace blind::injector
