#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <strsafe.h>

#include <blind/blind_ipc.h>

#include <atomic>
#include <cstdio>
#include <string>

namespace
{
    constexpr DWORD kPipeBufferBytes = 64 * 1024;
    constexpr DWORD kReadyTimeoutMs = 15000;
    constexpr DWORD kChildTimeoutMs = 30000;
    constexpr DWORD kInjectTimeoutMs = 10000;

    struct HostState
    {
        HANDLE ReadyEvent = nullptr;
        std::atomic<bool> Stop{false};
        std::atomic<DWORD> ReadyMask{0};
        std::atomic<DWORD> EventCount{0};
        bool Verbose = false;
        std::wstring PipeName;
    };

    bool FileExists(const std::wstring &path) noexcept
    {
        const DWORD attrs = GetFileAttributesW(path.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    std::wstring DirectoryOf(const wchar_t *path)
    {
        wchar_t buffer[MAX_PATH]{};
        (void)StringCchCopyW(buffer, RTL_NUMBER_OF(buffer), path);
        wchar_t *slash = wcsrchr(buffer, L'\\');
        if (slash != nullptr)
        {
            *slash = L'\0';
        }
        return buffer;
    }

    std::wstring ModuleDirectory()
    {
        wchar_t path[MAX_PATH]{};
        const DWORD chars = GetModuleFileNameW(nullptr, path, RTL_NUMBER_OF(path));
        if (chars == 0 || chars >= RTL_NUMBER_OF(path))
        {
            return L".";
        }
        return DirectoryOf(path);
    }

    std::wstring JoinPath(const std::wstring &left, const wchar_t *right)
    {
        std::wstring joined = left;
        if (!joined.empty() && joined.back() != L'\\')
        {
            joined += L'\\';
        }
        joined += right;
        return joined;
    }

    std::wstring QuotePath(const std::wstring &path)
    {
        std::wstring quoted = L"\"";
        quoted += path;
        quoted += L"\"";
        return quoted;
    }

    std::wstring EffectivePipeName()
    {
        wchar_t pipeName[IXIPC_MAX_PIPE_NAME_CHARS]{};
        DWORD chars = GetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, pipeName, RTL_NUMBER_OF(pipeName));
        if (chars > 0 && chars < RTL_NUMBER_OF(pipeName))
        {
            return pipeName;
        }
        return IXIPC_HOOK_PIPE_NAME;
    }

    const char *KindName(UINT32 kind) noexcept
    {
        switch (kind)
        {
        case IxIpcHookEventNt:
            return "nt";
        case IxIpcHookEventWinsock:
            return "winsock";
        case IxIpcHookEventKi:
            return "ki";
        case IxIpcHookEventExceptionLowNoise:
        case IxIpcHookEventExceptionHighPriv:
            return "exception";
        case IxIpcHookEventIntegrity:
            return "integrity";
        case IxIpcHookEventModule:
            return "module";
        default:
            return "unknown";
        }
    }

    bool WritePacket(HANDLE pipe, const IXIPC_PACKET &packet) noexcept
    {
        DWORD written = 0;
        return WriteFile(pipe, &packet, sizeof(packet), &written, nullptr) && written == sizeof(packet);
    }

    void PrintHookEvent(const IXIPC_HOOK_EVENT &eventRecord)
    {
        std::printf("[sdk-host] event pid=%lu tid=%lu kind=%s op=%lu api=%s module=%s caller=0x%llX\n",
                    static_cast<unsigned long>(eventRecord.ProcessId),
                    static_cast<unsigned long>(eventRecord.ThreadId), KindName(eventRecord.Kind),
                    static_cast<unsigned long>(eventRecord.Operation),
                    eventRecord.ApiName[0] != '\0' ? eventRecord.ApiName : "<none>",
                    eventRecord.ModuleName[0] != '\0' ? eventRecord.ModuleName : "<none>",
                    static_cast<unsigned long long>(eventRecord.Caller));
    }

    void HandleHookEvent(HostState &state, const IXIPC_HOOK_EVENT &eventRecord)
    {
        const DWORD current = state.EventCount.fetch_add(1, std::memory_order_relaxed) + 1;
        if (state.Verbose || current <= 16)
        {
            PrintHookEvent(eventRecord);
        }
        else if (current == 17)
        {
            std::printf("[sdk-host] suppressing additional event details; rerun with --verbose for full output\n");
        }
    }

    bool HandlePacket(HostState &state, HANDLE pipe, const IXIPC_PACKET &request)
    {
        IXIPC_PACKET response{};
        response.Magic = IXIPC_MAGIC;
        response.Version = IXIPC_VERSION;
        response.PacketType = IxIpcPacketResponse;
        response.Command = request.Command;
        response.Sequence = request.Sequence;
        response.Status = ERROR_SUCCESS;

        if (request.Magic != IXIPC_MAGIC || request.Version != IXIPC_VERSION ||
            request.PacketType != IxIpcPacketRequest)
        {
            response.Status = ERROR_INVALID_DATA;
            return WritePacket(pipe, response);
        }

        switch (request.Command)
        {
        case IxIpcCommandHandshake:
            response.Payload.HandshakeResponse.NegotiatedVersion = IXIPC_VERSION;
            response.Payload.HandshakeResponse.Capabilities = 1;
            break;
        case IxIpcCommandNotifyHookReady:
        {
            const DWORD localMask = request.Payload.NotifyHookReadyRequest.ReadyMask;
            const DWORD observed = state.ReadyMask.fetch_or(localMask, std::memory_order_acq_rel) | localMask;
            response.Payload.NotifyHookReadyResponse.ProcessId = request.Payload.NotifyHookReadyRequest.ProcessId;
            response.Payload.NotifyHookReadyResponse.ObservedMask = observed;
            response.Payload.NotifyHookReadyResponse.RequiredMask = BLIND_SDK_READY_CORE_MASK;
            response.Payload.NotifyHookReadyResponse.PendingCommand = 0;
            std::printf("[sdk-host] ready pid=%lu mask=0x%08lX observed=0x%08lX\n",
                        static_cast<unsigned long>(request.Payload.NotifyHookReadyRequest.ProcessId),
                        static_cast<unsigned long>(localMask), static_cast<unsigned long>(observed));
            if ((observed & BLIND_SDK_READY_CORE_MASK) == BLIND_SDK_READY_CORE_MASK)
            {
                SetEvent(state.ReadyEvent);
            }
            break;
        }
        case IxIpcCommandPublishHookEvent:
            HandleHookEvent(state, request.Payload.HookEvent);
            break;
        case IxIpcCommandPublishHookEventBatch:
        {
            const UINT32 count = request.Payload.HookEventBatch.Count;
            if (count > IXIPC_MAX_HOOK_EVENT_BATCH)
            {
                response.Status = ERROR_INVALID_DATA;
                break;
            }
            for (UINT32 i = 0; i < count; ++i)
            {
                HandleHookEvent(state, request.Payload.HookEventBatch.Events[i]);
            }
            break;
        }
        case IxIpcCommandRegisterInstrumentationRange:
        case IxIpcCommandRegisterHookPatch:
        case IxIpcCommandRegisterProcessInstrumentationCallback:
            break;
        default:
            response.Status = ERROR_INVALID_FUNCTION;
            break;
        }

        return WritePacket(pipe, response);
    }

    DWORD WINAPI PipeServerThread(LPVOID parameter)
    {
        auto *state = static_cast<HostState *>(parameter);
        HANDLE pipe = CreateNamedPipeW(state->PipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, kPipeBufferBytes,
                                       kPipeBufferBytes, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            std::printf("[sdk-host] CreateNamedPipe failed gle=%lu\n", GetLastError());
            SetEvent(state->ReadyEvent);
            return 1;
        }

        std::printf("[sdk-host] listening on %ls\n", state->PipeName.c_str());
        const BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            std::printf("[sdk-host] ConnectNamedPipe failed gle=%lu\n", GetLastError());
            CloseHandle(pipe);
            SetEvent(state->ReadyEvent);
            return 1;
        }

        std::printf("[sdk-host] BLIND client connected\n");
        while (!state->Stop.load(std::memory_order_acquire))
        {
            IXIPC_PACKET request{};
            DWORD read = 0;
            if (!ReadFile(pipe, &request, sizeof(request), &read, nullptr))
            {
                const DWORD gle = GetLastError();
                if (gle != ERROR_BROKEN_PIPE && gle != ERROR_PIPE_NOT_CONNECTED)
                {
                    std::printf("[sdk-host] ReadFile failed gle=%lu\n", gle);
                }
                break;
            }
            if (read != sizeof(request))
            {
                std::printf("[sdk-host] short packet read bytes=%lu expected=%zu\n", read, sizeof(request));
                break;
            }
            if (!HandlePacket(*state, pipe, request))
            {
                std::printf("[sdk-host] response write failed gle=%lu\n", GetLastError());
                break;
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 0;
    }

    bool InjectDllIntoChild(HANDLE process, const std::wstring &dllPath)
    {
        const SIZE_T bytes = (dllPath.size() + 1u) * sizeof(wchar_t);
        void *remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remotePath == nullptr)
        {
            std::printf("[sdk-host] VirtualAllocEx failed gle=%lu\n", GetLastError());
            return false;
        }

        bool ok = false;
        SIZE_T written = 0;
        if (WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes, &written) && written == bytes)
        {
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            auto loadLibraryW = kernel32 != nullptr
                                    ? reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"))
                                    : nullptr;
            if (loadLibraryW != nullptr)
            {
                HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibraryW, remotePath, 0, nullptr);
                if (thread != nullptr)
                {
                    DWORD exitCode = 0;
                    const DWORD wait = WaitForSingleObject(thread, kInjectTimeoutMs);
                    if (wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &exitCode) && exitCode != 0)
                    {
                        ok = true;
                    }
                    else
                    {
                        std::printf("[sdk-host] LoadLibrary wait=%lu exit=0x%08lX gle=%lu\n", wait, exitCode,
                                    GetLastError());
                    }
                    CloseHandle(thread);
                }
            }
        }
        else
        {
            std::printf("[sdk-host] WriteProcessMemory failed gle=%lu\n", GetLastError());
        }

        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        return ok;
    }
} // namespace

int wmain(int argc, wchar_t **argv)
{
    std::wstring baseDir = ModuleDirectory();
    std::wstring dllPath = JoinPath(baseDir, L"BLIND.dll");
    std::wstring targetPath = JoinPath(baseDir, L"BlindTestTarget.exe");

    HostState state{};
    bool targetSet = false;
    for (int argIndex = 1; argIndex < argc; ++argIndex)
    {
        if (wcscmp(argv[argIndex], L"--help") == 0)
        {
            std::wprintf(L"Usage: BlindSdkHost.exe [--verbose] [--pipe \\\\.\\pipe\\Name] [owned-test-exe]\n");
            std::wprintf(L"Hosts the BLIND IPC pipe and loads BLIND.dll into a child process it creates.\n");
            return 0;
        }
        if (wcscmp(argv[argIndex], L"--verbose") == 0)
        {
            state.Verbose = true;
            continue;
        }
        if (wcscmp(argv[argIndex], L"--pipe") == 0)
        {
            if (argIndex + 1 >= argc)
            {
                std::wprintf(L"[sdk-host] --pipe requires a named-pipe path\n");
                return 2;
            }
            (void)SetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, argv[++argIndex]);
            continue;
        }
        if (!targetSet)
        {
            targetPath = argv[argIndex];
            targetSet = true;
            continue;
        }

        std::wprintf(L"[sdk-host] unexpected argument: %ls\n", argv[argIndex]);
        return 2;
    }

    if (!FileExists(dllPath))
    {
        std::wprintf(L"[sdk-host] missing DLL: %ls\n", dllPath.c_str());
        return 2;
    }
    if (!FileExists(targetPath))
    {
        std::wprintf(L"[sdk-host] missing target: %ls\n", targetPath.c_str());
        return 2;
    }

    (void)SetEnvironmentVariableW(L"BLIND_LOG_DIR", baseDir.c_str());
    (void)SetEnvironmentVariableW(L"BLIND_RUNNER_OWNS_PIPE", L"1");
    state.PipeName = EffectivePipeName();

    state.ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (state.ReadyEvent == nullptr)
    {
        std::printf("[sdk-host] CreateEvent failed gle=%lu\n", GetLastError());
        return 2;
    }

    HANDLE serverThread = CreateThread(nullptr, 0, PipeServerThread, &state, 0, nullptr);
    if (serverThread == nullptr)
    {
        std::printf("[sdk-host] server thread failed gle=%lu\n", GetLastError());
        CloseHandle(state.ReadyEvent);
        return 2;
    }

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring commandLine = QuotePath(targetPath);
    const BOOL created = CreateProcessW(targetPath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, 0, nullptr,
                                        baseDir.c_str(), &si, &pi);
    if (!created)
    {
        std::printf("[sdk-host] CreateProcess failed gle=%lu\n", GetLastError());
        state.Stop.store(true, std::memory_order_release);
        WaitForSingleObject(serverThread, 1000);
        CloseHandle(serverThread);
        CloseHandle(state.ReadyEvent);
        return 3;
    }

    std::wprintf(L"[sdk-host] child pid=%lu target=%ls\n", pi.dwProcessId, targetPath.c_str());
    Sleep(500);
    if (!InjectDllIntoChild(pi.hProcess, dllPath))
    {
        TerminateProcess(pi.hProcess, ERROR_DLL_INIT_FAILED);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        state.Stop.store(true, std::memory_order_release);
        WaitForSingleObject(serverThread, 1000);
        CloseHandle(serverThread);
        CloseHandle(state.ReadyEvent);
        return 4;
    }

    const DWORD readyWait = WaitForSingleObject(state.ReadyEvent, kReadyTimeoutMs);
    std::printf("[sdk-host] ready wait=%lu mask=0x%08lX core=0x%08lX\n", readyWait,
                static_cast<unsigned long>(state.ReadyMask.load(std::memory_order_acquire)),
                static_cast<unsigned long>(BLIND_SDK_READY_CORE_MASK));

    DWORD childWait = WaitForSingleObject(pi.hProcess, kChildTimeoutMs);
    if (childWait == WAIT_TIMEOUT)
    {
        std::printf("[sdk-host] child timed out; terminating pid=%lu\n", pi.dwProcessId);
        TerminateProcess(pi.hProcess, WAIT_TIMEOUT);
        childWait = WaitForSingleObject(pi.hProcess, 5000);
    }

    DWORD exitCode = 0;
    (void)GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    Sleep(250);
    state.Stop.store(true, std::memory_order_release);
    WaitForSingleObject(serverThread, 1000);
    CloseHandle(serverThread);
    CloseHandle(state.ReadyEvent);

    const DWORD readyMask = state.ReadyMask.load(std::memory_order_acquire);
    const DWORD events = state.EventCount.load(std::memory_order_acquire);
    std::printf("[sdk-host] child_wait=0x%08lX child_exit=0x%08lX events=%lu ready_mask=0x%08lX\n", childWait,
                exitCode, static_cast<unsigned long>(events), static_cast<unsigned long>(readyMask));

    return exitCode == 0 && events != 0 && (readyMask & BLIND_SDK_READY_CORE_MASK) == BLIND_SDK_READY_CORE_MASK
               ? 0
               : 5;
}
