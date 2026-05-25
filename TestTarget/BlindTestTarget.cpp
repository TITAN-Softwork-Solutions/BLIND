#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <strsafe.h>

#include "../ABI/blind_ipc.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace
{
    constexpr DWORD kPipeBufferBytes = 64 * 1024;

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

    std::wstring DirectoryOf(const wchar_t *path)
    {
        wchar_t buffer[MAX_PATH]{};
        lstrcpynW(buffer, path, RTL_NUMBER_OF(buffer));
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
        DWORD chars = GetModuleFileNameW(nullptr, path, RTL_NUMBER_OF(path));
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

    bool EnsureDirectory(const std::wstring &path) noexcept
    {
        if (CreateDirectoryW(path.c_str(), nullptr))
        {
            return true;
        }
        return GetLastError() == ERROR_ALREADY_EXISTS;
    }

    std::wstring BuildDirectRunDirectory(const std::wstring &baseDir)
    {
        SYSTEMTIME now{};
        GetLocalTime(&now);
        wchar_t leaf[96]{};
        swprintf_s(leaf, L"direct-%04u%02u%02u-%02u%02u%02u-%lu", now.wYear, now.wMonth, now.wDay, now.wHour,
                   now.wMinute, now.wSecond, GetCurrentProcessId());
        std::wstring root = JoinPath(baseDir, L"BlindDiagnostics");
        (void)EnsureDirectory(root);
        std::wstring runDir = JoinPath(root, leaf);
        (void)EnsureDirectory(runDir);
        return runDir;
    }

    bool WritePacket(HANDLE pipe, const IXIPC_PACKET &packet) noexcept
    {
        DWORD written = 0;
        return WriteFile(pipe, &packet, sizeof(packet), &written, nullptr) && written == sizeof(packet);
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

        UINT32 safe = eventRecord.DataSize < IXIPC_MAX_HOOK_DATA_SAMPLE ? eventRecord.DataSize
                                                                        : IXIPC_MAX_HOOK_DATA_SAMPLE;
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

        std::fputs(
            "index\ttotal\ttruncated\tkind\towner\tname\taddress\tsize\tflags\tref0\tref1\tallocation_base\tregion_size\tprotect\tstate\ttype\n",
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
                     static_cast<unsigned long>(eventRecord.ThreadId), KindName(eventRecord.Kind),
                     static_cast<unsigned long>(eventRecord.Kind), static_cast<unsigned long>(eventRecord.Operation));
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
            std::fprintf(ctx.EventsFile, "%s\"0x%llX\"", i == 0 ? "" : ",",
                         static_cast<unsigned long long>(eventRecord.Args[i]));
        }
        std::fputs("],\"sample\":\"", ctx.EventsFile);
        WriteJsonEscaped(ctx.EventsFile, sample);
        std::fputs("\"}\n", ctx.EventsFile);
    }

    void CaptureSelfMapEventUnlocked(SelfHostContext &ctx, const IXIPC_HOOK_EVENT &eventRecord)
    {
        if (eventRecord.Kind != IxIpcHookEventIntegrity ||
            eventRecord.Operation != IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY)
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
                         static_cast<unsigned long>(entry.Index), static_cast<unsigned long>(entry.Total),
                         static_cast<unsigned long>(entry.Truncated), SelfMapKindName(entry.Kind), entry.Owner,
                         entry.Name, static_cast<unsigned long long>(entry.Address),
                         static_cast<unsigned long long>(entry.Size), static_cast<unsigned long>(entry.Flags),
                         static_cast<unsigned long long>(entry.Reference0),
                         static_cast<unsigned long long>(entry.Reference1),
                         static_cast<unsigned long long>(entry.AllocationBase),
                         static_cast<unsigned long long>(entry.RegionSize), static_cast<unsigned long>(entry.Protect),
                         static_cast<unsigned long>(entry.State), static_cast<unsigned long>(entry.Type));
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

        if (eventRecord.Kind == IxIpcHookEventIntegrity &&
            eventRecord.Operation == IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY)
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
        std::fprintf(summary, "ready_mask=0x%08lX\n",
                     static_cast<unsigned long>(ctx.ReadyMask.load(std::memory_order_acquire)));
        std::fprintf(summary, "events=%lu\n",
                     static_cast<unsigned long>(ctx.HookEvents.load(std::memory_order_acquire)));
        std::fprintf(summary, "self_map_entries=%lu\n",
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
                std::fprintf(summary, "  %s=%lu\n", KindName(kind),
                             static_cast<unsigned long>(ctx.EventKindCounts[kind]));
            }
        }

        std::fprintf(summary, "\nself_map_by_kind:\n");
        for (UINT32 kind = 0; kind < RTL_NUMBER_OF(ctx.SelfMapKindCounts); ++kind)
        {
            if (ctx.SelfMapKindCounts[kind] != 0)
            {
                std::fprintf(summary, "  %s=%lu\n", SelfMapKindName(kind),
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
        HANDLE pipe = CreateNamedPipeW(ctx->PipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, kPipeBufferBytes,
                                       kPipeBufferBytes, 0, nullptr);
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
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            return;
        }

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET)
        {
            u_long nonblocking = 1;
            (void)ioctlsocket(sock, FIONBIO, &nonblocking);

            sockaddr_in loopback{};
            loopback.sin_family = AF_INET;
            loopback.sin_port = static_cast<u_short>(9u << 8);
            loopback.sin_addr.S_un.S_addr = 0x0100007Fu;
            (void)connect(sock, reinterpret_cast<const sockaddr *>(&loopback), sizeof(loopback));
            closesocket(sock);
        }

        WSACleanup();
    }
}

int wmain()
{
    SelfHostContext blind{};
    bool selfHosted = StartBlindSelfHost(blind);

    std::printf("[target] BLIND owned test target start pid=%lu\n", GetCurrentProcessId());
    Sleep(1000);
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
    return 0;
}
