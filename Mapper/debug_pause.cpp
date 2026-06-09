#include "internal.h"

namespace blind::mapper
{
    void CloseDebugEventFileHandle(DEBUG_EVENT &event) noexcept
    {
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && event.u.CreateProcessInfo.hFile != nullptr)
        {
            CloseHandle(event.u.CreateProcessInfo.hFile);
            event.u.CreateProcessInfo.hFile = nullptr;
        }
        else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile != nullptr)
        {
            CloseHandle(event.u.LoadDll.hFile);
            event.u.LoadDll.hFile = nullptr;
        }
    }

    bool QueryRemoteImageEntryPoint(HANDLE process, void *imageBase, UINT64 &entryPoint)
    {
        entryPoint = 0;
        if (imageBase == nullptr)
        {
            return false;
        }

        IMAGE_DOS_HEADER dos{};
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, imageBase, &dos, sizeof(dos), &read) || read != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
        {
            return false;
        }

        IMAGE_NT_HEADERS64 nt{};
        BYTE *ntAddress = reinterpret_cast<BYTE *>(imageBase) + dos.e_lfanew;
        if (!ReadProcessMemory(process, ntAddress, &nt, sizeof(nt), &read) || read != sizeof(nt) ||
            nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt.OptionalHeader.AddressOfEntryPoint == 0)
        {
            return false;
        }

        entryPoint = reinterpret_cast<UINT64>(imageBase) + nt.OptionalHeader.AddressOfEntryPoint;
        return true;
    }

    bool WriteRemoteByteWithProtect(HANDLE process, UINT64 address, BYTE value, BYTE *previousValue)
    {
        SIZE_T transferred = 0;
        if (previousValue != nullptr)
        {
            if (!ReadProcessMemory(
                    process, reinterpret_cast<const void *>(address), previousValue, sizeof(BYTE), &transferred) ||
                transferred != sizeof(BYTE))
            {
                return false;
            }
        }

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(
                process, reinterpret_cast<void *>(address), sizeof(BYTE), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }

        transferred = 0;
        bool ok = WriteProcessMemory(process, reinterpret_cast<void *>(address), &value, sizeof(BYTE), &transferred) &&
                  transferred == sizeof(BYTE);
        DWORD ignoredProtect = 0;
        (void)VirtualProtectEx(process, reinterpret_cast<void *>(address), sizeof(BYTE), oldProtect, &ignoredProtect);
        (void)FlushInstructionCache(process, reinterpret_cast<void *>(address), sizeof(BYTE));
        return ok;
    }

    bool PauseDebuggedChildAtEntrypoint(ServerContext &ctx, PROCESS_INFORMATION &pi)
    {
        const DWORD deadline = GetTickCount() + kReadyTimeoutMs;
        UINT64 entryPoint = 0;
        BYTE originalEntryByte = 0;
        bool entryBreakpointArmed = false;

        for (;;)
        {
            DWORD now = GetTickCount();
            DWORD waitMs = now < deadline ? (deadline - now) : 0;
            if (waitMs == 0)
            {
                HostDebugLog(ctx, "manual-map: debug pre-entry wait timed out");
                return false;
            }

            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, waitMs))
            {
                HostDebugLog(ctx, "manual-map: WaitForDebugEvent failed gle=%lu", GetLastError());
                return false;
            }

            DWORD continueStatus = DBG_CONTINUE;
            bool detachAtPreEntry = false;

            switch (event.dwDebugEventCode)
            {
            case CREATE_PROCESS_DEBUG_EVENT:
                HostDebugLog(ctx, "manual-map: debug create-process event pid=%lu", event.dwProcessId);
                if (!QueryRemoteImageEntryPoint(pi.hProcess, event.u.CreateProcessInfo.lpBaseOfImage, entryPoint) ||
                    !WriteRemoteByteWithProtect(pi.hProcess, entryPoint, 0xCC, &originalEntryByte))
                {
                    CloseDebugEventFileHandle(event);
                    (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                    HostDebugLog(ctx, "manual-map: failed to arm entrypoint breakpoint gle=%lu", GetLastError());
                    return false;
                }
                entryBreakpointArmed = true;
                HostDebugLog(ctx,
                             "manual-map: armed entrypoint breakpoint image=0x%llX entry=0x%llX original=0x%02X",
                             reinterpret_cast<unsigned long long>(event.u.CreateProcessInfo.lpBaseOfImage),
                             static_cast<unsigned long long>(entryPoint),
                             originalEntryByte);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                CloseDebugEventFileHandle(event);
                (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                HostDebugLog(ctx,
                             "manual-map: child exited during debug pre-entry status=0x%08lX",
                             event.u.ExitProcess.dwExitCode);
                return false;
            case EXCEPTION_DEBUG_EVENT:
                if (entryBreakpointArmed && event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT &&
                    reinterpret_cast<UINT64>(event.u.Exception.ExceptionRecord.ExceptionAddress) == entryPoint)
                {
                    if (!WriteRemoteByteWithProtect(pi.hProcess, entryPoint, originalEntryByte, nullptr))
                    {
                        CloseDebugEventFileHandle(event);
                        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                        HostDebugLog(ctx, "manual-map: failed to restore entrypoint byte gle=%lu", GetLastError());
                        return false;
                    }

                    CONTEXT threadContext{};
                    threadContext.ContextFlags = CONTEXT_CONTROL;
                    if (!GetThreadContext(pi.hThread, &threadContext))
                    {
                        CloseDebugEventFileHandle(event);
                        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                        HostDebugLog(ctx, "manual-map: GetThreadContext at entrypoint failed gle=%lu", GetLastError());
                        return false;
                    }
#if defined(_M_X64)
                    threadContext.Rip = entryPoint;
#else
                    threadContext.Eip = static_cast<DWORD>(entryPoint);
#endif
                    if (!SetThreadContext(pi.hThread, &threadContext))
                    {
                        CloseDebugEventFileHandle(event);
                        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                        HostDebugLog(ctx, "manual-map: SetThreadContext at entrypoint failed gle=%lu", GetLastError());
                        return false;
                    }

                    DWORD previousSuspend = SuspendThread(pi.hThread);
                    if (previousSuspend == static_cast<DWORD>(-1))
                    {
                        CloseDebugEventFileHandle(event);
                        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                        HostDebugLog(
                            ctx, "manual-map: failed to suspend primary thread at pre-entry gle=%lu", GetLastError());
                        return false;
                    }
                    HostDebugLog(ctx,
                                 "manual-map: debug entrypoint breakpoint tid=%lu previous_suspend=%lu",
                                 event.dwThreadId,
                                 previousSuspend);
                    detachAtPreEntry = true;
                }
                else
                {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
            default:
                break;
            }

            CloseDebugEventFileHandle(event);
            if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus))
            {
                HostDebugLog(ctx, "manual-map: ContinueDebugEvent failed gle=%lu", GetLastError());
                return false;
            }

            if (detachAtPreEntry)
            {
                if (!DebugActiveProcessStop(pi.dwProcessId))
                {
                    HostDebugLog(ctx, "manual-map: DebugActiveProcessStop failed gle=%lu", GetLastError());
                    return false;
                }
                HostDebugLog(ctx, "manual-map: child detached at pre-entry with primary thread suspended");
                return true;
            }
        }
    }
} // namespace blind::mapper
