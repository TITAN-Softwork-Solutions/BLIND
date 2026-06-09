#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalLoadLibraryA == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = CallOriginalTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalLoadLibraryA), g_OriginalLoadLibraryA, lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryA,
                           "LoadLibraryA",
                           "KERNELBASE",
                           moduleHandle,
                           lpLibFileName,
                           CopyAnsiLength(lpLibFileName),
                           0,
                           0,
                           0,
                           0,
                           caller);
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalLoadLibraryW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = CallOriginalTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalLoadLibraryW), g_OriginalLoadLibraryW, lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryW,
                           "LoadLibraryW",
                           "KERNELBASE",
                           moduleHandle,
                           lpLibFileName,
                           CopyWideLength(lpLibFileName),
                           0,
                           0,
                           0,
                           0,
                           caller);
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalLoadLibraryExA == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalLoadLibraryExA),
                                                               g_OriginalLoadLibraryExA,
                                                               lpLibFileName,
                                                               hFile,
                                                               dwFlags);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryExA,
                           "LoadLibraryExA",
                           "KERNELBASE",
                           moduleHandle,
                           lpLibFileName,
                           CopyAnsiLength(lpLibFileName),
                           static_cast<std::uint64_t>(dwFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(hFile)),
                           0,
                           0,
                           caller);
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalLoadLibraryExW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalLoadLibraryExW),
                                                               g_OriginalLoadLibraryExW,
                                                               lpLibFileName,
                                                               hFile,
                                                               dwFlags);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryExW,
                           "LoadLibraryExW",
                           "KERNELBASE",
                           moduleHandle,
                           lpLibFileName,
                           CopyWideLength(lpLibFileName),
                           static_cast<std::uint64_t>(dwFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(hFile)),
                           0,
                           0,
                           caller);
        return moduleHandle;
    }

    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath,
                                  PULONG loadFlags,
                                  PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalLdrLoadDll == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalLdrLoadDll),
                                                          g_OriginalLdrLoadDll,
                                                          searchPath,
                                                          loadFlags,
                                                          moduleFileName,
                                                          moduleHandle);
        HMODULE resolved = nullptr;
        if (NT_SUCCESS(status) && moduleHandle != nullptr)
        {
            resolved = reinterpret_cast<HMODULE>(*moduleHandle);
        }

        PublishModuleEvent(ModuleHookOperation::LdrLoadDll,
                           "LdrLoadDll",
                           "ntdll",
                           resolved,
                           (moduleFileName != nullptr) ? moduleFileName->Buffer : nullptr,
                           (moduleFileName != nullptr && moduleFileName->Length > 0) ? moduleFileName->Length : 0,
                           static_cast<std::uint64_t>((loadFlags != nullptr) ? *loadFlags : 0),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(searchPath)),
                           static_cast<std::uint64_t>((moduleFileName != nullptr) ? moduleFileName->Length : 0),
                           caller);
        return status;
    }
} // namespace IX_MODULE_INTERNAL
