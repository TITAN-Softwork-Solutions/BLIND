#include "internal.h"

namespace blind::mapper
{
    bool ResolveRemoteRtlAddFunctionTable(ServerContext &ctx, HANDLE process, UINT64 &remoteAddress)
    {
        remoteAddress = 0;
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC localProc = kernel32 != nullptr ? GetProcAddress(kernel32, "RtlAddFunctionTable") : nullptr;
        if (localProc == nullptr)
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            localProc = ntdll != nullptr ? GetProcAddress(ntdll, "RtlAddFunctionTable") : nullptr;
        }
        if (localProc == nullptr)
        {
            return Fail(ctx, "host cannot resolve RtlAddFunctionTable");
        }

        if (!ResolveRemoteAddressForLocalProc(process, localProc, remoteAddress, nullptr) || remoteAddress == 0)
        {
            return Fail(ctx, "child cannot resolve RtlAddFunctionTable");
        }
        return true;
    }

    bool RunBootstrap(ServerContext &ctx, HANDLE process, UINT64 remoteBase, MappedImage &mapped)
    {
        auto *nt = ImageNtHeaders64(mapped.Image);
        if (nt == nullptr)
        {
            return Fail(ctx, "cannot bootstrap invalid image");
        }

        UINT64 remoteRtlAddFunctionTable = 0;
        if (!ResolveRemoteRtlAddFunctionTable(ctx, process, remoteRtlAddFunctionTable))
        {
            return false;
        }

        const IMAGE_DATA_DIRECTORY &exceptionDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        BootstrapData data{};
        data.ImageBase = remoteBase;
        data.EntryPoint = mapped.EntryPointRva != 0 ? remoteBase + mapped.EntryPointRva : 0;
        data.TlsCallbacks = GetTlsCallbacks(mapped);
        data.RtlAddFunctionTable = remoteRtlAddFunctionTable;
        if (exceptionDir.VirtualAddress != 0 && exceptionDir.Size >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
        {
            data.ExceptionTable = remoteBase + exceptionDir.VirtualAddress;
            data.ExceptionCount = exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        }

        static const BYTE kBootstrapCode[] = {
            0x53, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xD9, 0xC7, 0x43, 0x2C, 0x01, 0x00, 0x00, 0x00, 0x48,
            0x8B, 0x43, 0x18, 0x48, 0x85, 0xC0, 0x74, 0x1F, 0x8B, 0x53, 0x28, 0x85, 0xD2, 0x74, 0x18, 0x48, 0x8B,
            0x4B, 0x20, 0x4C, 0x8B, 0x03, 0xFF, 0xD0, 0x85, 0xC0, 0x75, 0x0B, 0xC7, 0x43, 0x2C, 0x01, 0x00, 0x00,
            0x80, 0x33, 0xC0, 0xEB, 0x59, 0x48, 0x8B, 0x73, 0x10, 0x48, 0x85, 0xF6, 0x74, 0x1B, 0x48, 0x8B, 0x06,
            0x48, 0x85, 0xC0, 0x74, 0x13, 0x48, 0x8B, 0x0B, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xFF,
            0xD0, 0x48, 0x83, 0xC6, 0x08, 0xEB, 0xE5, 0x48, 0x8B, 0x43, 0x08, 0x48, 0x85, 0xC0, 0x74, 0x20, 0x48,
            0x8B, 0x0B, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xFF, 0xD0, 0x48, 0x89, 0x43, 0x30, 0x85,
            0xC0, 0x75, 0x0B, 0xC7, 0x43, 0x2C, 0x02, 0x00, 0x00, 0x80, 0x33, 0xC0, 0xEB, 0x0C, 0xC7, 0x43, 0x2C,
            0x02, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0x5E, 0x5B, 0xC3};

        SYSTEM_INFO systemInfo{};
        GetNativeSystemInfo(&systemInfo);
        const SIZE_T pageSize = systemInfo.dwPageSize != 0 ? systemInfo.dwPageSize : 0x1000u;
        const SIZE_T bootstrapCodeBytes = ((sizeof(kBootstrapCode) + pageSize - 1u) / pageSize) * pageSize;
        const SIZE_T allocationSize = bootstrapCodeBytes + sizeof(data);
        BYTE *remoteBootstrap = reinterpret_cast<BYTE *>(
            VirtualAllocEx(process, nullptr, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (remoteBootstrap == nullptr)
        {
            return FailLastError(ctx, "VirtualAllocEx(bootstrap)");
        }

        BYTE *remoteData = remoteBootstrap + bootstrapCodeBytes;
        SIZE_T written = 0;
        bool ok = WriteProcessMemory(process, remoteBootstrap, kBootstrapCode, sizeof(kBootstrapCode), &written) &&
                  written == sizeof(kBootstrapCode) &&
                  WriteProcessMemory(process, remoteData, &data, sizeof(data), &written) && written == sizeof(data);
        if (!ok)
        {
            VirtualFreeEx(process, remoteBootstrap, 0, MEM_RELEASE);
            return FailLastError(ctx, "WriteProcessMemory(bootstrap)");
        }

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(process, remoteBootstrap, bootstrapCodeBytes, PAGE_EXECUTE_READ, &oldProtect))
        {
            VirtualFreeEx(process, remoteBootstrap, 0, MEM_RELEASE);
            return FailLastError(ctx, "VirtualProtectEx(bootstrap RX)");
        }

        (void)FlushInstructionCache(process, remoteBootstrap, sizeof(kBootstrapCode));
        HANDLE thread = CreateRemoteThread(
            process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteBootstrap), remoteData, 0, nullptr);
        if (thread == nullptr)
        {
            VirtualFreeEx(process, remoteBootstrap, 0, MEM_RELEASE);
            return FailLastError(ctx, "CreateRemoteThread(bootstrap)");
        }

        DWORD wait = WaitForSingleObject(thread, kInjectTimeoutMs);
        DWORD exitCode = 0;
        bool threadOk = wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &exitCode);
        CloseHandle(thread);

        BootstrapData result{};
        SIZE_T read = 0;
        bool readResult =
            ReadProcessMemory(process, remoteData, &result, sizeof(result), &read) && read == sizeof(result);
        VirtualFreeEx(process, remoteBootstrap, 0, MEM_RELEASE);

        if (!threadOk || !readResult)
        {
            HostDebugLog(ctx,
                         "manual-map: bootstrap wait=%lu exit=0x%08lX read=%u gle=%lu",
                         wait,
                         exitCode,
                         readResult ? 1u : 0u,
                         GetLastError());
            return Fail(ctx, "bootstrap thread failed");
        }
        if (exitCode == 0 || result.Status != kBootstrapSucceeded)
        {
            HostDebugLog(ctx,
                         "manual-map: bootstrap status=0x%08lX exit=0x%08lX entry=0x%llX",
                         result.Status,
                         exitCode,
                         static_cast<unsigned long long>(result.EntryResult));
            if (result.Status == kBootstrapRtlAddFunctionTableFailed)
            {
                return Fail(ctx, "bootstrap failed to register x64 unwind metadata");
            }
            if (result.Status == kBootstrapEntryPointFailed)
            {
                return Fail(ctx, "DLL entrypoint returned FALSE");
            }
            return Fail(ctx, "bootstrap did not complete successfully");
        }

        HostDebugLog(ctx,
                     "manual-map: bootstrap complete image=0x%llX entry=0x%llX tls=0x%llX pdata=0x%llX count=%lu",
                     static_cast<unsigned long long>(data.ImageBase),
                     static_cast<unsigned long long>(data.EntryPoint),
                     static_cast<unsigned long long>(data.TlsCallbacks),
                     static_cast<unsigned long long>(data.ExceptionTable),
                     data.ExceptionCount);
        return true;
    }
} // namespace blind::mapper
