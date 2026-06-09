#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <TlHelp32.h>
#include <evntprov.h>
#include <strsafe.h>

#include "../ABI/blind_ipc.h"
#include "../DLL/support/win32_util.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    constexpr DWORD kPipeBufferBytes = 64 * 1024;
    constexpr LONG kCliProbeStatusAccessDenied = static_cast<LONG>(0xC0000022u);

    struct CliProbeProcessBasicInformation
    {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    };

    using NtQueryInformationProcessProbeFn = LONG(NTAPI *)(HANDLE ProcessHandle,
                                                           ULONG ProcessInformationClass,
                                                           PVOID ProcessInformation,
                                                           ULONG ProcessInformationLength,
                                                           PULONG ReturnLength);
    using WSAStartupProbeFn = int(WSAAPI *)(WORD, LPWSADATA);
    using WSACleanupProbeFn = int(WSAAPI *)();
    using SocketProbeFn = SOCKET(WSAAPI *)(int, int, int);
    using IoctlSocketProbeFn = int(WSAAPI *)(SOCKET, long, u_long *);
    using ConnectProbeFn = int(WSAAPI *)(SOCKET, const sockaddr *, int);
    using CloseSocketProbeFn = int(WSAAPI *)(SOCKET);
    using AmsiInitializeProbeFn = HRESULT(WINAPI *)(LPCWSTR, PVOID *);
    using AmsiOpenSessionProbeFn = HRESULT(WINAPI *)(PVOID, PVOID *);
    using AmsiScanBufferProbeFn = HRESULT(WINAPI *)(PVOID, PVOID, ULONG, LPCWSTR, PVOID, PVOID);
    using AmsiScanStringProbeFn = HRESULT(WINAPI *)(PVOID, LPCWSTR, LPCWSTR, PVOID, PVOID);
    using AmsiNotifyOperationProbeFn = HRESULT(WINAPI *)(PVOID, PVOID, ULONG, LPCWSTR, PVOID);
    using AmsiCloseSessionProbeFn = void(WINAPI *)(PVOID, PVOID);
    using AmsiUninitializeProbeFn = void(WINAPI *)(PVOID);
    using EventRegisterProbeFn = ULONG(WINAPI *)(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE);
    using EventUnregisterProbeFn = ULONG(WINAPI *)(REGHANDLE);
    using EtwEventWriteProbeFn = ULONG(NTAPI *)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);

    struct SelfHostContext
    {
        HANDLE ReadyEvent = nullptr;
        HANDLE ServerThread = nullptr;
        HMODULE Blind = nullptr;
        CRITICAL_SECTION DiagnosticsLock{};
        bool DiagnosticsLockInitialized = false;
        std::atomic<bool> Stop{false};
        std::atomic<DWORD> ReadyMask{0};
        std::atomic<DWORD> HookEvents{0};
        std::atomic<DWORD> SelfMapEvents{0};
        std::wstring RunDir;
        std::wstring LogDir;
        std::wstring RuntimeLogPath;
        std::wstring EventsPath;
        std::wstring SelfMapPath;
        std::wstring SummaryPath;
        std::wstring PipeName;
        FILE *EventsFile = nullptr;
        FILE *SelfMapFile = nullptr;
        DWORD EventKindCounts[8]{};
        DWORD SelfMapKindCounts[9]{};
    };

    struct SelfMapEntry
    {
        UINT32 Index = 0;
        UINT32 Total = 0;
        UINT32 Truncated = 0;
        UINT32 Kind = 0;
        UINT32 Flags = 0;
        UINT32 Protect = 0;
        UINT32 State = 0;
        UINT32 Type = 0;
        UINT64 Address = 0;
        UINT64 Size = 0;
        UINT64 Reference0 = 0;
        UINT64 Reference1 = 0;
        UINT64 AllocationBase = 0;
        UINT64 RegionSize = 0;
        char Owner[IXIPC_MAX_HOOK_MODULE_NAME]{};
        char Name[IXIPC_MAX_HOOK_API_NAME]{};
    };

    using BLIND_SUPPORT::EffectivePipeName;
    using BLIND_SUPPORT::EnsureDirectory;
    using BLIND_SUPPORT::JoinPath;
    using BLIND_SUPPORT::KindName;
    using BLIND_SUPPORT::ModuleDirectory;
    using BLIND_SUPPORT::WritePacket;

    std::wstring BuildDirectRunDirectory(const std::wstring &baseDir)
    {
        SYSTEMTIME now{};
        GetLocalTime(&now);
        wchar_t leaf[96]{};
        swprintf_s(leaf,
                   L"direct-%04u%02u%02u-%02u%02u%02u-%lu",
                   now.wYear,
                   now.wMonth,
                   now.wDay,
                   now.wHour,
                   now.wMinute,
                   now.wSecond,
                   GetCurrentProcessId());
        std::wstring root = JoinPath(baseDir, L"BlindDiagnostics");
        (void)EnsureDirectory(root);
        std::wstring runDir = JoinPath(root, leaf);
        (void)EnsureDirectory(runDir);
        return runDir;
    }

    const char *SelfMapKindName(UINT32 kind) noexcept
    {
        switch (kind)
        {
        case IX_SELF_MAP_KIND_RUNTIME_STATE:
            return "runtime";
        case IX_SELF_MAP_KIND_INDIRECT_HANDLE:
            return "indirect_handle";
        case IX_SELF_MAP_KIND_HOOK_PATCH:
            return "hook_patch";
        case IX_SELF_MAP_KIND_SYSCALL_STUB:
            return "syscall_stub";
        case IX_SELF_MAP_KIND_LAUNCH_GATE_PAGE:
            return "launch_gate_page";
        case IX_SELF_MAP_KIND_LAUNCH_GATE_CONTEXT:
            return "launch_gate_context";
        case IX_SELF_MAP_KIND_CALLBACK:
            return "callback";
        case IX_SELF_MAP_KIND_SNAPSHOT_SUMMARY:
            return "summary";
        default:
            return "unknown";
        }
    }

    void CopyEventSampleString(const IXIPC_HOOK_EVENT &eventRecord, char *out, std::size_t outChars) noexcept
    {
        if (out == nullptr || outChars == 0)
        {
            return;
        }
        out[0] = '\0';

        UINT32 safe =
            eventRecord.DataSize < IXIPC_MAX_HOOK_DATA_SAMPLE ? eventRecord.DataSize : IXIPC_MAX_HOOK_DATA_SAMPLE;
        safe = safe < outChars - 1 ? safe : static_cast<UINT32>(outChars - 1);
        for (UINT32 i = 0; i < safe; ++i)
        {
            unsigned char ch = eventRecord.DataSample[i];
            out[i] = (ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '.';
        }
        out[safe] = '\0';
    }

    void WriteJsonEscaped(FILE *file, const char *value) noexcept
    {
        if (file == nullptr || value == nullptr)
        {
            return;
        }

        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); *p != 0; ++p)
        {
            switch (*p)
            {
            case '\\':
                std::fputs("\\\\", file);
                break;
            case '"':
                std::fputs("\\\"", file);
                break;
            case '\n':
                std::fputs("\\n", file);
                break;
            case '\r':
                std::fputs("\\r", file);
                break;
            case '\t':
                std::fputs("\\t", file);
                break;
            default:
                if (*p < 0x20)
                {
                    std::fprintf(file, "\\u%04x", static_cast<unsigned int>(*p));
                }
                else
                {
                    std::fputc(*p, file);
                }
                break;
            }
        }
    }

    bool OpenDirectDiagnostics(SelfHostContext &ctx, const std::wstring &baseDir)
    {
        InitializeCriticalSection(&ctx.DiagnosticsLock);
        ctx.DiagnosticsLockInitialized = true;
        ctx.RunDir = BuildDirectRunDirectory(baseDir);
        ctx.LogDir = JoinPath(ctx.RunDir, L"logs");
        (void)EnsureDirectory(ctx.LogDir);
        ctx.EventsPath = JoinPath(ctx.RunDir, L"events.jsonl");
        ctx.SelfMapPath = JoinPath(ctx.RunDir, L"selfmap.tsv");
        ctx.SummaryPath = JoinPath(ctx.RunDir, L"summary.txt");

        if (_wfopen_s(&ctx.EventsFile, ctx.EventsPath.c_str(), L"wb") != 0 || ctx.EventsFile == nullptr)
        {
            return false;
        }
        if (_wfopen_s(&ctx.SelfMapFile, ctx.SelfMapPath.c_str(), L"wb") != 0 || ctx.SelfMapFile == nullptr)
        {
            if (ctx.EventsFile != nullptr)
            {
                std::fclose(ctx.EventsFile);
                ctx.EventsFile = nullptr;
            }
            return false;
        }

        std::fputs("index\ttotal\ttruncated\tkind\towner\tname\taddress\tsize\tflags\tref0\tref1\tallocation_"
                   "base\tregion_size\tprotect\tstate\ttype\n",
                   ctx.SelfMapFile);
        return true;
    }

    void CloseDirectDiagnostics(SelfHostContext &ctx) noexcept
    {
        if (ctx.EventsFile != nullptr)
        {
            std::fflush(ctx.EventsFile);
            std::fclose(ctx.EventsFile);
            ctx.EventsFile = nullptr;
        }
        if (ctx.SelfMapFile != nullptr)
        {
            std::fflush(ctx.SelfMapFile);
            std::fclose(ctx.SelfMapFile);
            ctx.SelfMapFile = nullptr;
        }
        if (ctx.DiagnosticsLockInitialized)
        {
            DeleteCriticalSection(&ctx.DiagnosticsLock);
            ctx.DiagnosticsLockInitialized = false;
        }
    }

    void WriteRawEventUnlocked(SelfHostContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) noexcept
    {
        if (ctx.EventsFile == nullptr)
        {
            return;
        }

        char sample[IXIPC_MAX_HOOK_DATA_SAMPLE + 1]{};
        CopyEventSampleString(eventRecord, sample, RTL_NUMBER_OF(sample));

        std::fprintf(ctx.EventsFile,
                     "{\"pid\":%lu,\"tid\":%lu,\"kind\":\"%s\",\"kind_id\":%lu,\"op\":%lu,"
                     "\"api\":\"",
                     static_cast<unsigned long>(eventRecord.ProcessId),
                     static_cast<unsigned long>(eventRecord.ThreadId),
                     KindName(eventRecord.Kind),
                     static_cast<unsigned long>(eventRecord.Kind),
                     static_cast<unsigned long>(eventRecord.Operation));
        WriteJsonEscaped(ctx.EventsFile, eventRecord.ApiName);
        std::fputs("\",\"module\":\"", ctx.EventsFile);
        WriteJsonEscaped(ctx.EventsFile, eventRecord.ModuleName);
        std::fprintf(ctx.EventsFile,
                     "\",\"caller\":\"0x%llX\",\"c0\":\"0x%llX\",\"c1\":\"0x%llX\",\"c2\":\"0x%llX\","
                     "\"c3\":\"0x%llX\",\"args\":[",
                     static_cast<unsigned long long>(eventRecord.Caller),
                     static_cast<unsigned long long>(eventRecord.Context0),
                     static_cast<unsigned long long>(eventRecord.Context1),
                     static_cast<unsigned long long>(eventRecord.Context2),
                     static_cast<unsigned long long>(eventRecord.Context3));
        for (UINT32 i = 0; i < eventRecord.ArgCount && i < IXIPC_MAX_HOOK_ARGS; ++i)
        {
            std::fprintf(ctx.EventsFile,
                         "%s\"0x%llX\"",
                         i == 0 ? "" : ",",
                         static_cast<unsigned long long>(eventRecord.Args[i]));
        }
        std::fputs("],\"sample\":\"", ctx.EventsFile);
        WriteJsonEscaped(ctx.EventsFile, sample);
        std::fputs("\"}\n", ctx.EventsFile);
    }

    void CaptureSelfMapEventUnlocked(SelfHostContext &ctx, const IXIPC_HOOK_EVENT &eventRecord)
    {
        if (eventRecord.Kind != IxIpcHookEventIntegrity || eventRecord.Operation != IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY)
        {
            return;
        }

        SelfMapEntry entry{};
        entry.Kind = eventRecord.Context0 & 0xFFFFFFFFu;
        entry.Address = eventRecord.Context1;
        entry.Size = eventRecord.Context2;
        entry.Flags = eventRecord.Context3 & 0xFFFFFFFFu;
        entry.Reference0 = eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0;
        entry.Reference1 = eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0;
        entry.AllocationBase = eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0;
        entry.RegionSize = eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0;
        if (eventRecord.ArgCount > 4)
        {
            entry.Protect = static_cast<UINT32>(eventRecord.Args[4] >> 32);
            entry.State = static_cast<UINT32>(eventRecord.Args[4] & 0xFFFFFFFFu);
        }
        entry.Type = eventRecord.ArgCount > 5 ? static_cast<UINT32>(eventRecord.Args[5] & 0xFFFFFFFFu) : 0;
        entry.Index = eventRecord.ArgCount > 6 ? static_cast<UINT32>(eventRecord.Args[6] & 0xFFFFFFFFu) : 0;
        if (eventRecord.ArgCount > 7)
        {
            entry.Total = static_cast<UINT32>(eventRecord.Args[7] >> 32);
            entry.Truncated = static_cast<UINT32>(eventRecord.Args[7] & 0xFFFFFFFFu);
        }

        (void)StringCchCopyA(entry.Owner, RTL_NUMBER_OF(entry.Owner), eventRecord.ModuleName);
        CopyEventSampleString(eventRecord, entry.Name, RTL_NUMBER_OF(entry.Name));
        if (entry.Kind < RTL_NUMBER_OF(ctx.SelfMapKindCounts))
        {
            ctx.SelfMapKindCounts[entry.Kind] += 1;
        }

        if (ctx.SelfMapFile != nullptr)
        {
            std::fprintf(ctx.SelfMapFile,
                         "%lu\t%lu\t%lu\t%s\t%s\t%s\t0x%llX\t0x%llX\t0x%08lX\t0x%llX\t0x%llX\t"
                         "0x%llX\t0x%llX\t0x%08lX\t0x%08lX\t0x%08lX\n",
                         static_cast<unsigned long>(entry.Index),
                         static_cast<unsigned long>(entry.Total),
                         static_cast<unsigned long>(entry.Truncated),
                         SelfMapKindName(entry.Kind),
                         entry.Owner,
                         entry.Name,
                         static_cast<unsigned long long>(entry.Address),
                         static_cast<unsigned long long>(entry.Size),
                         static_cast<unsigned long>(entry.Flags),
                         static_cast<unsigned long long>(entry.Reference0),
                         static_cast<unsigned long long>(entry.Reference1),
                         static_cast<unsigned long long>(entry.AllocationBase),
                         static_cast<unsigned long long>(entry.RegionSize),
                         static_cast<unsigned long>(entry.Protect),
                         static_cast<unsigned long>(entry.State),
                         static_cast<unsigned long>(entry.Type));
        }
    }

    void HandleSelfHostHookEvent(SelfHostContext &ctx, const IXIPC_HOOK_EVENT &eventRecord)
    {
        ctx.HookEvents.fetch_add(1, std::memory_order_relaxed);

        if (ctx.DiagnosticsLockInitialized)
        {
            EnterCriticalSection(&ctx.DiagnosticsLock);
        }
        if (eventRecord.Kind < RTL_NUMBER_OF(ctx.EventKindCounts))
        {
            ctx.EventKindCounts[eventRecord.Kind] += 1;
        }
        WriteRawEventUnlocked(ctx, eventRecord);
        CaptureSelfMapEventUnlocked(ctx, eventRecord);
        if (ctx.DiagnosticsLockInitialized)
        {
            LeaveCriticalSection(&ctx.DiagnosticsLock);
        }

        if (eventRecord.Kind == IxIpcHookEventIntegrity && eventRecord.Operation == IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY)
        {
            ctx.SelfMapEvents.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void FlushDirectDiagnostics(SelfHostContext &ctx) noexcept
    {
        if (ctx.DiagnosticsLockInitialized)
        {
            EnterCriticalSection(&ctx.DiagnosticsLock);
        }
        if (ctx.EventsFile != nullptr)
        {
            std::fflush(ctx.EventsFile);
        }
        if (ctx.SelfMapFile != nullptr)
        {
            std::fflush(ctx.SelfMapFile);
        }
        if (ctx.DiagnosticsLockInitialized)
        {
            LeaveCriticalSection(&ctx.DiagnosticsLock);
        }
    }

    void WriteDirectSummary(SelfHostContext &ctx)
    {
        FILE *summary = nullptr;
        if (_wfopen_s(&summary, ctx.SummaryPath.c_str(), L"wb") != 0 || summary == nullptr)
        {
            return;
        }

        if (ctx.DiagnosticsLockInitialized)
        {
            EnterCriticalSection(&ctx.DiagnosticsLock);
        }
        std::fprintf(summary, "BLIND direct self-host diagnostic summary\n");
        std::fprintf(summary, "pid=%lu\n", static_cast<unsigned long>(GetCurrentProcessId()));
        std::fprintf(
            summary, "ready_mask=0x%08lX\n", static_cast<unsigned long>(ctx.ReadyMask.load(std::memory_order_acquire)));
        std::fprintf(
            summary, "events=%lu\n", static_cast<unsigned long>(ctx.HookEvents.load(std::memory_order_acquire)));
        std::fprintf(summary,
                     "self_map_entries=%lu\n",
                     static_cast<unsigned long>(ctx.SelfMapEvents.load(std::memory_order_acquire)));
        std::fprintf(summary, "runtime_log=%S\n", ctx.RuntimeLogPath.c_str());
        std::fprintf(summary, "events_file=%S\n", ctx.EventsPath.c_str());
        std::fprintf(summary, "selfmap_file=%S\n", ctx.SelfMapPath.c_str());
        std::fprintf(summary, "run_dir=%S\n\n", ctx.RunDir.c_str());

        std::fprintf(summary, "event_counts:\n");
        for (UINT32 kind = 0; kind < RTL_NUMBER_OF(ctx.EventKindCounts); ++kind)
        {
            if (ctx.EventKindCounts[kind] != 0)
            {
                std::fprintf(
                    summary, "  %s=%lu\n", KindName(kind), static_cast<unsigned long>(ctx.EventKindCounts[kind]));
            }
        }

        std::fprintf(summary, "\nself_map_by_kind:\n");
        for (UINT32 kind = 0; kind < RTL_NUMBER_OF(ctx.SelfMapKindCounts); ++kind)
        {
            if (ctx.SelfMapKindCounts[kind] != 0)
            {
                std::fprintf(summary,
                             "  %s=%lu\n",
                             SelfMapKindName(kind),
                             static_cast<unsigned long>(ctx.SelfMapKindCounts[kind]));
            }
        }
        if (ctx.DiagnosticsLockInitialized)
        {
            LeaveCriticalSection(&ctx.DiagnosticsLock);
        }

        std::fclose(summary);
    }

    bool HandleSelfHostPacket(SelfHostContext &ctx, HANDLE pipe, const IXIPC_PACKET &request)
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
            DWORD localMask = request.Payload.NotifyHookReadyRequest.ReadyMask;
            DWORD observed = ctx.ReadyMask.fetch_or(localMask, std::memory_order_acq_rel) | localMask;
            response.Payload.NotifyHookReadyResponse.ProcessId = request.Payload.NotifyHookReadyRequest.ProcessId;
            response.Payload.NotifyHookReadyResponse.ObservedMask = observed;
            response.Payload.NotifyHookReadyResponse.RequiredMask = IXIPC_HOOK_READY_REQUIRED_MASK;
            response.Payload.NotifyHookReadyResponse.PendingCommand = 0;
            std::printf("[target] blind ready mask=0x%08lX observed=0x%08lX\n", localMask, observed);
            if ((observed & (IXIPC_HOOK_READY_FLAG_IPC_CONNECTED | IXIPC_HOOK_READY_FLAG_NT)) ==
                (IXIPC_HOOK_READY_FLAG_IPC_CONNECTED | IXIPC_HOOK_READY_FLAG_NT))
            {
                SetEvent(ctx.ReadyEvent);
            }
            break;
        }
        case IxIpcCommandQueryHookPolicy:
            response.Payload.QueryHookPolicyResponse.PolicyVersion = IXIPC_HOOK_POLICY_VERSION;
            break;
        case IxIpcCommandPublishHookEvent:
            HandleSelfHostHookEvent(ctx, request.Payload.HookEvent);
            break;
        case IxIpcCommandPublishHookEventBatch:
        {
            UINT32 count = request.Payload.HookEventBatch.Count;
            if (count > IXIPC_MAX_HOOK_EVENT_BATCH)
            {
                response.Status = ERROR_INVALID_DATA;
                break;
            }
            for (UINT32 i = 0; i < count; ++i)
            {
                HandleSelfHostHookEvent(ctx, request.Payload.HookEventBatch.Events[i]);
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

    DWORD WINAPI SelfHostPipeThread(LPVOID parameter)
    {
        auto *ctx = static_cast<SelfHostContext *>(parameter);
        HANDLE pipe = CreateNamedPipeW(ctx->PipeName.c_str(),
                                       PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                       1,
                                       kPipeBufferBytes,
                                       kPipeBufferBytes,
                                       0,
                                       nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            std::printf("[target] blind self-host pipe failed gle=%lu\n", GetLastError());
            SetEvent(ctx->ReadyEvent);
            return 1;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            CloseHandle(pipe);
            SetEvent(ctx->ReadyEvent);
            return 1;
        }

        while (!ctx->Stop.load(std::memory_order_acquire))
        {
            IXIPC_PACKET request{};
            DWORD read = 0;
            if (!ReadFile(pipe, &request, sizeof(request), &read, nullptr) || read != sizeof(request))
            {
                break;
            }
            if (!HandleSelfHostPacket(*ctx, pipe, request))
            {
                break;
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 0;
    }

    bool ShouldSelfHostBlind()
    {
        wchar_t value[8]{};
        DWORD chars = GetEnvironmentVariableW(L"BLIND_RUNNER_OWNS_PIPE", value, RTL_NUMBER_OF(value));
        return chars == 0;
    }

    bool StartBlindSelfHost(SelfHostContext &ctx)
    {
        if (!ShouldSelfHostBlind())
        {
            return false;
        }

        std::wstring baseDir = ModuleDirectory();
        std::wstring dllPath = JoinPath(baseDir, L"BLIND.dll");
        if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            std::printf("[target] BLIND.dll not found next to target; run BlindRunner.exe for instrumentation\n");
            return false;
        }

        if (!OpenDirectDiagnostics(ctx, baseDir))
        {
            std::printf("[target] blind self-host diagnostics failed\n");
            CloseDirectDiagnostics(ctx);
            return false;
        }
        wchar_t logName[64]{};
        swprintf_s(logName, L"blind-runtime-%lu.log", GetCurrentProcessId());
        ctx.RuntimeLogPath = JoinPath(ctx.LogDir, logName);
        ctx.PipeName = EffectivePipeName();
        (void)SetEnvironmentVariableW(L"BLIND_LOG_DIR", ctx.LogDir.c_str());

        ctx.ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (ctx.ReadyEvent == nullptr)
        {
            CloseDirectDiagnostics(ctx);
            return false;
        }

        ctx.ServerThread = CreateThread(nullptr, 0, SelfHostPipeThread, &ctx, 0, nullptr);
        if (ctx.ServerThread == nullptr)
        {
            CloseHandle(ctx.ReadyEvent);
            ctx.ReadyEvent = nullptr;
            CloseDirectDiagnostics(ctx);
            return false;
        }

        std::wprintf(L"[target] blind self-host diagnostics=%ls\n", ctx.RunDir.c_str());
        ctx.Blind = LoadLibraryW(dllPath.c_str());
        if (ctx.Blind == nullptr)
        {
            std::printf("[target] LoadLibrary(BLIND.dll) failed gle=%lu\n", GetLastError());
            ctx.Stop.store(true, std::memory_order_release);
            WaitForSingleObject(ctx.ServerThread, 1000);
            CloseHandle(ctx.ServerThread);
            CloseHandle(ctx.ReadyEvent);
            ctx.ServerThread = nullptr;
            ctx.ReadyEvent = nullptr;
            CloseDirectDiagnostics(ctx);
            return false;
        }

        (void)WaitForSingleObject(ctx.ReadyEvent, 15000);
        return true;
    }

    void StopBlindSelfHost(SelfHostContext &ctx)
    {
        if (ctx.ServerThread == nullptr)
        {
            return;
        }

        Sleep(500);
        ctx.Stop.store(true, std::memory_order_release);
        FlushDirectDiagnostics(ctx);
        WriteDirectSummary(ctx);
        DWORD serverWait = WaitForSingleObject(ctx.ServerThread, 1000);
        std::printf("[target] blind events=%lu self_map=%lu ready=0x%08lX\n",
                    static_cast<unsigned long>(ctx.HookEvents.load(std::memory_order_acquire)),
                    static_cast<unsigned long>(ctx.SelfMapEvents.load(std::memory_order_acquire)),
                    static_cast<unsigned long>(ctx.ReadyMask.load(std::memory_order_acquire)));
        std::wprintf(L"[target] blind events file=%ls\n", ctx.EventsPath.c_str());
        std::wprintf(L"[target] blind selfmap file=%ls\n", ctx.SelfMapPath.c_str());
        std::wprintf(L"[target] blind summary=%ls\n", ctx.SummaryPath.c_str());
        std::wprintf(L"[target] blind runtime log=%ls\n", ctx.RuntimeLogPath.c_str());
        if (serverWait == WAIT_OBJECT_0)
        {
            CloseDirectDiagnostics(ctx);
        }
        CloseHandle(ctx.ServerThread);
        CloseHandle(ctx.ReadyEvent);
        ctx.ServerThread = nullptr;
        ctx.ReadyEvent = nullptr;
    }

    void ExerciseLoader()
    {
        HMODULE version = LoadLibraryW(L"version.dll");
        if (version != nullptr)
        {
            FARPROC proc = GetProcAddress(version, "GetFileVersionInfoSizeW");
            std::printf("[target] version.dll proc=%p\n", proc);
            FreeLibrary(version);
        }
    }

    void ExerciseMemory()
    {
        void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (region == nullptr)
        {
            return;
        }

        auto *bytes = static_cast<unsigned char *>(region);
        for (DWORD i = 0; i < 32; ++i)
        {
            bytes[i] = static_cast<unsigned char>(i);
        }

        DWORD oldProtect = 0;
        (void)VirtualProtect(region, 4096, PAGE_READONLY, &oldProtect);
        (void)VirtualProtect(region, 4096, oldProtect, &oldProtect);
        VirtualFree(region, 0, MEM_RELEASE);
    }

    void ExerciseWinsock()
    {
        HMODULE winsock = LoadLibraryW(L"ws2_32.dll");
        if (winsock == nullptr)
        {
            return;
        }

        auto wsaStartupFn = reinterpret_cast<WSAStartupProbeFn>(GetProcAddress(winsock, "WSAStartup"));
        auto wsaCleanupFn = reinterpret_cast<WSACleanupProbeFn>(GetProcAddress(winsock, "WSACleanup"));
        auto socketFn = reinterpret_cast<SocketProbeFn>(GetProcAddress(winsock, "socket"));
        auto ioctlSocketFn = reinterpret_cast<IoctlSocketProbeFn>(GetProcAddress(winsock, "ioctlsocket"));
        auto connectFn = reinterpret_cast<ConnectProbeFn>(GetProcAddress(winsock, "connect"));
        auto closeSocketFn = reinterpret_cast<CloseSocketProbeFn>(GetProcAddress(winsock, "closesocket"));
        if (wsaStartupFn == nullptr || wsaCleanupFn == nullptr || socketFn == nullptr || ioctlSocketFn == nullptr ||
            connectFn == nullptr || closeSocketFn == nullptr)
        {
            return;
        }

        WSADATA wsa{};
        if (wsaStartupFn(MAKEWORD(2, 2), &wsa) != 0)
        {
            return;
        }

        SOCKET sock = socketFn(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET)
        {
            u_long nonblocking = 1;
            (void)ioctlSocketFn(sock, FIONBIO, &nonblocking);

            sockaddr_in loopback{};
            loopback.sin_family = AF_INET;
            loopback.sin_port = static_cast<u_short>(9u << 8);
            loopback.sin_addr.S_un.S_addr = 0x0100007Fu;
            (void)connectFn(sock, reinterpret_cast<const sockaddr *>(&loopback), sizeof(loopback));
            closeSocketFn(sock);
        }

        wsaCleanupFn();
    }

    NtQueryInformationProcessProbeFn ResolveNtQueryInformationProcessProbe()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            ntdll = LoadLibraryW(L"ntdll.dll");
        }
        if (ntdll == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<NtQueryInformationProcessProbeFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    }

    LONG RunNtQueryInformationProcessProbeOnce(NtQueryInformationProcessProbeFn fn,
                                               CliProbeProcessBasicInformation &info,
                                               ULONG &returnLength)
    {
        return fn(GetCurrentProcess(), 0, &info, sizeof(info), &returnLength);
    }

    int ValidateCliProbeStatus(const char *name,
                               LONG status,
                               const CliProbeProcessBasicInformation &info,
                               ULONG returnLength,
                               bool expectDeny,
                               bool expectSilent)
    {
        std::printf("[target] %s status=0x%08lX pid_field=0x%llX return_len=0x%08lX\n",
                    name,
                    static_cast<unsigned long>(status),
                    static_cast<unsigned long long>(info.UniqueProcessId),
                    static_cast<unsigned long>(returnLength));

        if (expectDeny)
        {
            return status == kCliProbeStatusAccessDenied ? 0 : 41;
        }
        if (expectSilent)
        {
            return status == 0 && info.UniqueProcessId == 0xCCCCCCCCCCCCCCCCull && returnLength == 0xCCCCCCCCu ? 0 : 42;
        }
        return status == 0 ? 0 : 43;
    }

    int RunCliProbeDirect(bool expectDeny, bool expectSilent)
    {
        NtQueryInformationProcessProbeFn fn = ResolveNtQueryInformationProcessProbe();
        if (fn == nullptr)
        {
            std::printf("[target] NtQueryInformationProcess missing\n");
            return 40;
        }

        CliProbeProcessBasicInformation info{};
        std::memset(&info, 0xCC, sizeof(info));
        ULONG returnLength = 0xCCCCCCCCu;
        LONG status = RunNtQueryInformationProcessProbeOnce(fn, info, returnLength);
        return ValidateCliProbeStatus("cli_probe_direct", status, info, returnLength, expectDeny, expectSilent);
    }

    int RunCliProbeDuplicates()
    {
        NtQueryInformationProcessProbeFn fn = ResolveNtQueryInformationProcessProbe();
        if (fn == nullptr)
        {
            std::printf("[target] NtQueryInformationProcess missing\n");
            return 40;
        }

        CliProbeProcessBasicInformation info{};
        ULONG returnLength = 0;
        LONG status = 0;
        for (DWORD i = 0; i < 8; ++i)
        {
            std::memset(&info, 0, sizeof(info));
            returnLength = 0;
            status = RunNtQueryInformationProcessProbeOnce(fn, info, returnLength);
            std::printf("[target] cli_probe_duplicate[%lu] status=0x%08lX\n",
                        static_cast<unsigned long>(i),
                        static_cast<unsigned long>(status));
        }
        return status == 0 ? 0 : 44;
    }

    void WriteU32(std::vector<unsigned char> &code, std::uint32_t value)
    {
        for (DWORD i = 0; i < 4; ++i)
        {
            code.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xFFu));
        }
    }

    void WriteU64(std::vector<unsigned char> &code, std::uint64_t value)
    {
        for (DWORD i = 0; i < 8; ++i)
        {
            code.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xFFu));
        }
    }

    int RunCliProbePrivateCaller()
    {
#if defined(_M_X64)
        NtQueryInformationProcessProbeFn fn = ResolveNtQueryInformationProcessProbe();
        if (fn == nullptr)
        {
            std::printf("[target] NtQueryInformationProcess missing\n");
            return 40;
        }

        CliProbeProcessBasicInformation info{};
        ULONG returnLength = 0;
        std::vector<unsigned char> code;
        code.reserve(96);

        code.push_back(0x48);
        code.push_back(0x83);
        code.push_back(0xEC);
        code.push_back(0x38); // sub rsp,38h
        code.push_back(0x48);
        code.push_back(0xC7);
        code.push_back(0xC1);
        WriteU32(code, 0xFFFFFFFFu); // mov rcx,-1
        code.push_back(0x33);
        code.push_back(0xD2); // xor edx,edx
        code.push_back(0x49);
        code.push_back(0xB8);
        WriteU64(code, reinterpret_cast<std::uint64_t>(&info)); // mov r8,info
        code.push_back(0x41);
        code.push_back(0xB9);
        WriteU32(code, static_cast<std::uint32_t>(sizeof(info))); // mov r9d,sizeof
        code.push_back(0x48);
        code.push_back(0xB8);
        WriteU64(code, reinterpret_cast<std::uint64_t>(&returnLength));
        code.push_back(0x48);
        code.push_back(0x89);
        code.push_back(0x44);
        code.push_back(0x24);
        code.push_back(0x20);
        code.push_back(0x48);
        code.push_back(0xB8);
        WriteU64(code, reinterpret_cast<std::uint64_t>(fn)); // mov rax,fn
        code.push_back(0xFF);
        code.push_back(0xD0); // call rax
        code.push_back(0x48);
        code.push_back(0x83);
        code.push_back(0xC4);
        code.push_back(0x38); // add rsp,38h
        code.push_back(0xC3); // ret

        void *thunk = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (thunk == nullptr)
        {
            return 45;
        }
        std::memcpy(thunk, code.data(), code.size());
        FlushInstructionCache(GetCurrentProcess(), thunk, code.size());

        using ProbeThunk = LONG(NTAPI *)();
        LONG status = reinterpret_cast<ProbeThunk>(thunk)();
        VirtualFree(thunk, 0, MEM_RELEASE);
        return ValidateCliProbeStatus("cli_probe_private", status, info, returnLength, false, false);
#else
        return 46;
#endif
    }

    int RunCliProbeProtectChurn()
    {
        constexpr SIZE_T kPageSize = 0x1000;
        constexpr SIZE_T kPageCount = 32;
        unsigned char *region = static_cast<unsigned char *>(
            VirtualAlloc(nullptr, kPageSize * kPageCount, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (region == nullptr)
        {
            return 47;
        }

        for (SIZE_T i = 0; i < kPageCount; ++i)
        {
            region[i * kPageSize] = static_cast<unsigned char>(i);
        }

        for (SIZE_T i = 0; i < kPageCount; ++i)
        {
            DWORD oldProtect = 0;
            void *page = region + (i * kPageSize);
            if (!VirtualProtect(page, kPageSize, PAGE_EXECUTE_READ, &oldProtect))
            {
                VirtualFree(region, 0, MEM_RELEASE);
                return 48;
            }
            if (!VirtualProtect(page, kPageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                VirtualFree(region, 0, MEM_RELEASE);
                return 49;
            }
            if (!VirtualProtect(page, kPageSize, PAGE_NOACCESS, &oldProtect))
            {
                VirtualFree(region, 0, MEM_RELEASE);
                return 50;
            }
            if (!VirtualProtect(page, kPageSize, PAGE_READWRITE, &oldProtect))
            {
                VirtualFree(region, 0, MEM_RELEASE);
                return 51;
            }
        }

        VirtualFree(region, 0, MEM_RELEASE);
        return 0;
    }

    int RunCliProbeLazyAmsi()
    {
        HMODULE amsi = LoadLibraryW(L"amsi.dll");
        if (amsi == nullptr)
        {
            std::printf("[target] lazy_amsi load failed gle=%lu\n", GetLastError());
            return 61;
        }

        auto amsiInitialize = reinterpret_cast<AmsiInitializeProbeFn>(GetProcAddress(amsi, "AmsiInitialize"));
        auto amsiOpenSession = reinterpret_cast<AmsiOpenSessionProbeFn>(GetProcAddress(amsi, "AmsiOpenSession"));
        auto amsiScanBuffer = reinterpret_cast<AmsiScanBufferProbeFn>(GetProcAddress(amsi, "AmsiScanBuffer"));
        auto amsiScanString = reinterpret_cast<AmsiScanStringProbeFn>(GetProcAddress(amsi, "AmsiScanString"));
        auto amsiNotifyOperation =
            reinterpret_cast<AmsiNotifyOperationProbeFn>(GetProcAddress(amsi, "AmsiNotifyOperation"));
        auto amsiCloseSession = reinterpret_cast<AmsiCloseSessionProbeFn>(GetProcAddress(amsi, "AmsiCloseSession"));
        auto amsiUninitialize = reinterpret_cast<AmsiUninitializeProbeFn>(GetProcAddress(amsi, "AmsiUninitialize"));
        if (amsiInitialize == nullptr || amsiScanBuffer == nullptr || amsiUninitialize == nullptr)
        {
            return 62;
        }

        PVOID context = nullptr;
        HRESULT hr = amsiInitialize(L"BLINDProbe", &context);
        if (FAILED(hr) || context == nullptr)
        {
            std::printf("[target] lazy_amsi init hr=0x%08lX\n", static_cast<unsigned long>(hr));
            return 63;
        }

        PVOID session = nullptr;
        if (amsiOpenSession != nullptr)
        {
            (void)amsiOpenSession(context, &session);
        }

        const char sample[] = "Write-Host blind lazy amsi probe";
        ULONG result = 0;
        hr = amsiScanBuffer(context,
                            const_cast<char *>(sample),
                            static_cast<ULONG>(sizeof(sample) - 1),
                            L"blind-lazy-amsi.ps1",
                            session,
                            &result);
        if (amsiScanString != nullptr)
        {
            ULONG stringResult = 0;
            (void)amsiScanString(
                context, L"Write-Host blind lazy amsi string", L"blind-lazy-amsi-string.ps1", session, &stringResult);
        }
        if (amsiNotifyOperation != nullptr)
        {
            ULONG notifyResult = 0;
            const char notifySample[] = "blind lazy amsi notify";
            (void)amsiNotifyOperation(context,
                                      const_cast<char *>(notifySample),
                                      static_cast<ULONG>(sizeof(notifySample) - 1),
                                      L"blind-lazy-amsi-notify",
                                      &notifyResult);
        }

        if (session != nullptr && amsiCloseSession != nullptr)
        {
            amsiCloseSession(context, session);
        }
        amsiUninitialize(context);
        std::printf("[target] lazy_amsi scan hr=0x%08lX result=0x%08lX\n",
                    static_cast<unsigned long>(hr),
                    static_cast<unsigned long>(result));
        return 0;
    }

    int RunCliProbeLazyEtw()
    {
        HMODULE advapi = LoadLibraryW(L"advapi32.dll");
        if (advapi == nullptr)
        {
            std::printf("[target] lazy_etw advapi load failed gle=%lu\n", GetLastError());
            return 65;
        }

        auto eventRegister = reinterpret_cast<EventRegisterProbeFn>(GetProcAddress(advapi, "EventRegister"));
        auto eventUnregister = reinterpret_cast<EventUnregisterProbeFn>(GetProcAddress(advapi, "EventUnregister"));
        if (eventRegister == nullptr || eventUnregister == nullptr)
        {
            return 66;
        }

        static const GUID kProvider = {
            0x5f0b2a11u, 0xb33du, 0x4d93u, {0x91u, 0x31u, 0x11u, 0x71u, 0x4bu, 0x7du, 0x44u, 0x21u}};
        REGHANDLE regHandle = 0;
        ULONG status = eventRegister(&kProvider, nullptr, nullptr, &regHandle);

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto etwEventWrite =
            ntdll != nullptr ? reinterpret_cast<EtwEventWriteProbeFn>(GetProcAddress(ntdll, "EtwEventWrite")) : nullptr;
        if (etwEventWrite != nullptr)
        {
            EVENT_DESCRIPTOR descriptor{};
            descriptor.Id = 1;
            descriptor.Version = 1;
            descriptor.Level = 4;
            descriptor.Keyword = 0x10ull;
            (void)etwEventWrite(regHandle, &descriptor, 0, nullptr);
        }

        if (regHandle != 0)
        {
            (void)eventUnregister(regHandle);
        }
        std::printf("[target] lazy_etw register status=0x%08lX handle=0x%llX\n",
                    static_cast<unsigned long>(status),
                    static_cast<unsigned long long>(regHandle));
        return 0;
    }

    int RunCliProbeLazyWinsock()
    {
        ExerciseWinsock();
        return 0;
    }

    DWORD QueryParentProcessId()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto query =
            ntdll != nullptr
                ? reinterpret_cast<NtQueryInformationProcessProbeFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"))
                : nullptr;
        if (query == nullptr)
        {
            return 0;
        }

        CliProbeProcessBasicInformation info{};
        ULONG returned = 0;
        if (query(GetCurrentProcess(), 0, &info, static_cast<ULONG>(sizeof(info)), &returned) < 0)
        {
            return 0;
        }

        return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.Reserved3));
    }

    DWORD FindThreadForProcess(DWORD processId)
    {
        if (processId == 0)
        {
            return 0;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        DWORD threadId = 0;
        if (Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID == processId)
                {
                    threadId = entry.th32ThreadID;
                    break;
                }
                entry.dwSize = sizeof(entry);
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return threadId;
    }

    int RunCliProbeRemoteHandles()
    {
        DWORD parentPid = QueryParentProcessId();
        if (parentPid == 0)
        {
            return 77;
        }

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
        if (process == nullptr)
        {
            std::printf("[target] remote_handles OpenProcess(%lu) failed gle=%lu\n",
                        static_cast<unsigned long>(parentPid),
                        GetLastError());
            return 78;
        }

        DWORD threadId = FindThreadForProcess(parentPid);
        HANDLE thread = nullptr;
        if (threadId != 0)
        {
            thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto query =
            ntdll != nullptr
                ? reinterpret_cast<NtQueryInformationProcessProbeFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"))
                : nullptr;
        CliProbeProcessBasicInformation info{};
        ULONG returned = 0;
        if (query == nullptr || query(process, 0, &info, static_cast<ULONG>(sizeof(info)), &returned) < 0 ||
            info.PebBaseAddress == nullptr)
        {
            if (thread != nullptr)
            {
                CloseHandle(thread);
            }
            CloseHandle(process);
            return 79;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T queried = VirtualQueryEx(process, info.PebBaseAddress, &mbi, sizeof(mbi));
        unsigned char sample[32]{};
        SIZE_T bytesRead = 0;
        BOOL readOk = ReadProcessMemory(process, info.PebBaseAddress, sample, sizeof(sample), &bytesRead);

        std::printf("[target] remote_handles parent_pid=%lu process=%p thread_id=%lu thread=%p peb=%p "
                    "query=%llu read=%llu read_ok=%lu\n",
                    static_cast<unsigned long>(parentPid),
                    process,
                    static_cast<unsigned long>(threadId),
                    thread,
                    info.PebBaseAddress,
                    static_cast<unsigned long long>(queried),
                    static_cast<unsigned long long>(bytesRead),
                    static_cast<unsigned long>(readOk != FALSE));

        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
        CloseHandle(process);
        return queried != 0 && readOk ? 0 : 80;
    }

    int RunCliProbeNtdllEatRead()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            return 70;
        }

        auto *base = reinterpret_cast<const unsigned char *>(ntdll);
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        {
            return 71;
        }

        auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return 72;
        }

        const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        {
            return 73;
        }

        auto *exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + dir.VirtualAddress);
        auto *functions = reinterpret_cast<const DWORD *>(base + exports->AddressOfFunctions);
        auto *names = reinterpret_cast<const DWORD *>(base + exports->AddressOfNames);
        auto *ordinals = reinterpret_cast<const WORD *>(base + exports->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exports->NumberOfNames; ++i)
        {
            const char *name = reinterpret_cast<const char *>(base + names[i]);
            if (std::strcmp(name, "NtClose") != 0)
            {
                continue;
            }

            WORD ordinal = ordinals[i];
            if (ordinal >= exports->NumberOfFunctions)
            {
                return 74;
            }

            volatile const DWORD *eatSlot = &functions[ordinal];
            DWORD rva = *eatSlot;
            const void *proc = base + rva;
            std::printf("[target] ntdll_eat_read NtClose slot=%p rva=0x%08lX proc=%p\n",
                        eatSlot,
                        static_cast<unsigned long>(rva),
                        proc);
            return rva != 0 ? 0 : 75;
        }

        return 76;
    }

    int RunCliProbeDirectSyscallPage()
    {
#if defined(_M_X64)
        unsigned char *page =
            static_cast<unsigned char *>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (page == nullptr)
        {
            return 72;
        }

        const unsigned char stub[] = {
            0x4C,
            0x8B,
            0xD1, // mov r10, rcx
            0xB8,
            0x34,
            0x12,
            0x00,
            0x00, // mov eax,1234h
            0x0F,
            0x05, // syscall
            0xC3  // ret
        };
        std::memcpy(page, stub, sizeof(stub));
        FlushInstructionCache(GetCurrentProcess(), page, sizeof(stub));

        DWORD oldProtect = 0;
        if (!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
        {
            VirtualFree(page, 0, MEM_RELEASE);
            return 73;
        }

        volatile unsigned char *guarded = reinterpret_cast<volatile unsigned char *>(page);
        volatile unsigned char firstByte = guarded[0];
        std::printf("[target] direct_syscall_page page=%p first=0x%02X\n", page, static_cast<unsigned int>(firstByte));
        VirtualFree(page, 0, MEM_RELEASE);
        return 0;
#else
        return 74;
#endif
    }
} // namespace

int wmain(int argc, wchar_t **argv)
{
    SelfHostContext blind{};
    bool selfHosted = StartBlindSelfHost(blind);

    bool cliProbeDirect = false;
    bool cliProbeDuplicates = false;
    bool cliProbePrivate = false;
    bool cliProbeProtectChurn = false;
    bool cliProbeLazyAmsi = false;
    bool cliProbeLazyEtw = false;
    bool cliProbeLazyWinsock = false;
    bool cliProbeRemoteHandles = false;
    bool cliProbeNtdllEatRead = false;
    bool cliProbeDirectSyscallPage = false;
    bool expectDeny = false;
    bool expectSilent = false;
    for (int i = 1; i < argc; ++i)
    {
        if (wcscmp(argv[i], L"--cli-probe-direct") == 0)
            cliProbeDirect = true;
        else if (wcscmp(argv[i], L"--cli-probe-duplicates") == 0)
            cliProbeDuplicates = true;
        else if (wcscmp(argv[i], L"--cli-probe-private") == 0)
            cliProbePrivate = true;
        else if (wcscmp(argv[i], L"--cli-probe-protect-churn") == 0)
            cliProbeProtectChurn = true;
        else if (wcscmp(argv[i], L"--cli-probe-lazy-amsi") == 0)
            cliProbeLazyAmsi = true;
        else if (wcscmp(argv[i], L"--cli-probe-lazy-etw") == 0)
            cliProbeLazyEtw = true;
        else if (wcscmp(argv[i], L"--cli-probe-lazy-winsock") == 0)
            cliProbeLazyWinsock = true;
        else if (wcscmp(argv[i], L"--cli-probe-remote-handles") == 0)
            cliProbeRemoteHandles = true;
        else if (wcscmp(argv[i], L"--cli-probe-ntdll-eat-read") == 0)
            cliProbeNtdllEatRead = true;
        else if (wcscmp(argv[i], L"--cli-probe-direct-syscall") == 0)
            cliProbeDirectSyscallPage = true;
        else if (wcscmp(argv[i], L"--expect-deny") == 0)
            expectDeny = true;
        else if (wcscmp(argv[i], L"--expect-silent") == 0)
            expectSilent = true;
    }

    std::printf("[target] BLIND owned test target start pid=%lu\n", GetCurrentProcessId());
    Sleep(1000);
    if (cliProbeDirect || cliProbeDuplicates || cliProbePrivate || cliProbeProtectChurn || cliProbeLazyAmsi ||
        cliProbeLazyEtw || cliProbeLazyWinsock || cliProbeRemoteHandles || cliProbeNtdllEatRead ||
        cliProbeDirectSyscallPage)
    {
        int probeExit = 0;
        if (cliProbeDirect)
            probeExit = RunCliProbeDirect(expectDeny, expectSilent);
        else if (cliProbeDuplicates)
            probeExit = RunCliProbeDuplicates();
        else if (cliProbePrivate)
            probeExit = RunCliProbePrivateCaller();
        else if (cliProbeProtectChurn)
            probeExit = RunCliProbeProtectChurn();
        else if (cliProbeLazyAmsi)
            probeExit = RunCliProbeLazyAmsi();
        else if (cliProbeLazyEtw)
            probeExit = RunCliProbeLazyEtw();
        else if (cliProbeLazyWinsock)
            probeExit = RunCliProbeLazyWinsock();
        else if (cliProbeRemoteHandles)
            probeExit = RunCliProbeRemoteHandles();
        else if (cliProbeNtdllEatRead)
            probeExit = RunCliProbeNtdllEatRead();
        else
            probeExit = RunCliProbeDirectSyscallPage();

        Sleep(250);
        if (selfHosted)
        {
            StopBlindSelfHost(blind);
        }
        ExitProcess(static_cast<UINT>(probeExit));
    }

    ExerciseLoader();
    ExerciseMemory();
    ExerciseWinsock();
    Sleep(1000);
    std::printf("[target] done\n");
    if (selfHosted)
    {
        StopBlindSelfHost(blind);
    }
    ExitProcess(0);
}
