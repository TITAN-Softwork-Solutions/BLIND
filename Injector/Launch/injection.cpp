#include "Launch/injection.h"
#include "Diagnostics/diagnostics.h"

#include <limits>

namespace blind::injector {
std::wstring WideBaseName(const std::wstring &path) {
  std::size_t pos = path.find_last_of(L"\\/");
  return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

bool GetRemoteModuleBase(DWORD pid, const std::wstring &baseName,
                         UINT64 &base) {
  base = 0;
  HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool found = false;
  if (Module32FirstW(snapshot, &entry)) {
    do {
      if (_wcsicmp(entry.szModule, baseName.c_str()) == 0) {
        base = reinterpret_cast<UINT64>(entry.modBaseAddr);
        found = true;
        break;
      }
      entry.dwSize = sizeof(entry);
    } while (Module32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return found;
}

bool InjectDllIntoChild(ServerContext &ctx, HANDLE process,
                        const std::wstring &dllPath) {
  if (dllPath.size() >=
      (std::numeric_limits<SIZE_T>::max() / sizeof(wchar_t)) - 1u) {
    std::printf("[blind] DLL path is too long to inject safely\n");
    return false;
  }

  SIZE_T bytes = (dllPath.size() + 1u) * sizeof(wchar_t);
  void *remotePath = VirtualAllocEx(process, nullptr, bytes,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (remotePath == nullptr) {
    std::printf("[blind] VirtualAllocEx failed gle=%lu\n", GetLastError());
    return false;
  }

  bool ok = false;
  SIZE_T written = 0;
  if (WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes,
                         &written) &&
      written == bytes) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto loadLibraryW = kernel32 != nullptr
                            ? reinterpret_cast<LPTHREAD_START_ROUTINE>(
                                  GetProcAddress(kernel32, "LoadLibraryW"))
                            : nullptr;
    if (loadLibraryW == nullptr) {
      std::printf("[blind] LoadLibraryW resolution failed gle=%lu\n",
                  GetLastError());
    }
    HANDLE thread = loadLibraryW != nullptr
                        ? CreateRemoteThread(process, nullptr, 0, loadLibraryW,
                                             remotePath, 0, nullptr)
                        : nullptr;
    if (thread != nullptr) {
      DWORD wait = WaitForSingleObject(thread, kInjectTimeoutMs);
      DWORD exitCode = 0;
      if (wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &exitCode) &&
          exitCode != 0) {
        ok = true;
      } else {
        std::printf("[blind] LoadLibrary remote thread failed wait=%lu "
                    "exit=0x%08lX gle=%lu\n",
                    wait, exitCode, GetLastError());
      }
      CloseHandle(thread);
    } else {
      std::printf("[blind] CreateRemoteThread failed gle=%lu\n",
                  GetLastError());
    }
  } else {
    std::printf("[blind] WriteProcessMemory failed gle=%lu\n", GetLastError());
  }

  VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
  HostDebugLog(ctx, "loadlibrary injection complete ok=%u", ok ? 1u : 0u);
  return ok;
}
} // namespace blind::injector
