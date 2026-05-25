#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <strsafe.h>

#include "../ABI/blind_ipc.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace
{
    constexpr DWORD kPipeBufferBytes = 64 * 1024;
    constexpr DWORD kReadyTimeoutMs = 15000;
    constexpr DWORD kInjectTimeoutMs = 10000;

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

    struct ServerContext
    {
        HANDLE ReadyEvent = nullptr;
        std::atomic<bool> Stop{false};
        bool Verbose = false;
        bool LaunchGateMode = false;
        std::wstring RunDir;
        std::wstring LogDir;
        std::wstring RuntimeLogPath;
        FILE *EventsFile = nullptr;
        FILE *SelfMapFile = nullptr;
        DWORD ChildProcessId = 0;
        std::atomic<DWORD> ReadyMask{0};
        std::atomic<DWORD> HookEventCount{0};
        std::atomic<DWORD> LaunchGateTrapCount{0};
        std::atomic<DWORD> PrintedEventCount{0};
        std::atomic<DWORD> SuppressedEventCount{0};
        DWORD EventKindCounts[8]{};
        std::wstring PipeName;
        std::vector<SelfMapEntry> SelfMapEntries;
    };

    bool FileExists(const std::wstring &path) noexcept
    {
        DWORD attrs = GetFileAttributesW(path.c_str());
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

    bool EnsureDirectory(const std::wstring &path) noexcept
    {
        if (path.empty())
        {
            return false;
        }

        if (CreateDirectoryW(path.c_str(), nullptr))
        {
            return true;
        }

        return GetLastError() == ERROR_ALREADY_EXISTS;
    }

    std::wstring BuildRunDirectory(const std::wstring &baseDir)
    {
        SYSTEMTIME now{};
        GetLocalTime(&now);

        wchar_t leaf[96]{};
        (void)StringCchPrintfW(leaf, RTL_NUMBER_OF(leaf), L"run-%04u%02u%02u-%02u%02u%02u-%lu",
                               now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
                               GetCurrentProcessId());

        std::wstring root = JoinPath(baseDir, L"BlindDiagnostics");
        (void)EnsureDirectory(root);
        std::wstring runDir = JoinPath(root, leaf);
        (void)EnsureDirectory(runDir);
        return runDir;
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

    bool WritePacket(HANDLE pipe, const IXIPC_PACKET &packet) noexcept
    {
        DWORD written = 0;
        return WriteFile(pipe, &packet, sizeof(packet), &written, nullptr) && written == sizeof(packet);
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

    bool OpenDiagnostics(ServerContext &ctx, const std::wstring &baseDir)
    {
        ctx.RunDir = BuildRunDirectory(baseDir);
        ctx.LogDir = JoinPath(ctx.RunDir, L"logs");
        if (!EnsureDirectory(ctx.LogDir))
        {
            std::wprintf(L"[blind] failed to create diagnostics log dir: %ls\n", ctx.LogDir.c_str());
            return false;
        }

        std::wstring eventsPath = JoinPath(ctx.RunDir, L"events.jsonl");
        std::wstring selfMapPath = JoinPath(ctx.RunDir, L"selfmap.tsv");
        if (_wfopen_s(&ctx.EventsFile, eventsPath.c_str(), L"wb") != 0 || ctx.EventsFile == nullptr)
        {
            std::wprintf(L"[blind] failed to open diagnostics events file: %ls\n", eventsPath.c_str());
            return false;
        }
        if (_wfopen_s(&ctx.SelfMapFile, selfMapPath.c_str(), L"wb") != 0 || ctx.SelfMapFile == nullptr)
        {
            std::wprintf(L"[blind] failed to open diagnostics self-map file: %ls\n", selfMapPath.c_str());
            return false;
        }

        std::fputs(
            "index\ttotal\ttruncated\tkind\towner\tname\taddress\tsize\tflags\tref0\tref1\tallocation_base\tregion_size\tprotect\tstate\ttype\n",
            ctx.SelfMapFile);
        std::wprintf(L"[blind] diagnostics dir=%ls\n", ctx.RunDir.c_str());
        return true;
    }

    void CloseDiagnostics(ServerContext &ctx) noexcept
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
    }

    void WriteSummary(ServerContext &ctx, DWORD exitCode, DWORD childWait)
    {
        std::wstring summaryPath = JoinPath(ctx.RunDir, L"summary.txt");
        FILE *summary = nullptr;
        if (_wfopen_s(&summary, summaryPath.c_str(), L"wb") != 0 || summary == nullptr)
        {
            return;
        }

        std::fprintf(summary, "BLIND standalone diagnostic summary\n");
        std::fprintf(summary, "child_pid=%lu\n", static_cast<unsigned long>(ctx.ChildProcessId));
        std::fprintf(summary, "child_wait=0x%08lX\n", static_cast<unsigned long>(childWait));
        std::fprintf(summary, "child_exit=0x%08lX\n", static_cast<unsigned long>(exitCode));
        std::fprintf(summary, "ready_mask=0x%08lX\n",
                     static_cast<unsigned long>(ctx.ReadyMask.load(std::memory_order_acquire)));
        std::fprintf(summary, "events=%lu\n",
                     static_cast<unsigned long>(ctx.HookEventCount.load(std::memory_order_acquire)));
        std::fprintf(summary, "launch_gate_mode=%u\n", ctx.LaunchGateMode ? 1u : 0u);
        std::fprintf(summary, "launch_gate_traps=%lu\n",
                     static_cast<unsigned long>(ctx.LaunchGateTrapCount.load(std::memory_order_acquire)));
        std::fprintf(summary, "self_map_entries=%zu\n", ctx.SelfMapEntries.size());
        std::fprintf(summary, "runtime_log=%S\n", ctx.RuntimeLogPath.c_str());
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
        DWORD selfMapKindCounts[9]{};
        for (const auto &entry : ctx.SelfMapEntries)
        {
            if (entry.Kind < RTL_NUMBER_OF(selfMapKindCounts))
            {
                selfMapKindCounts[entry.Kind] += 1;
            }
        }
        for (UINT32 kind = 0; kind < RTL_NUMBER_OF(selfMapKindCounts); ++kind)
        {
            if (selfMapKindCounts[kind] != 0)
            {
                std::fprintf(summary, "  %s=%lu\n", SelfMapKindName(kind),
                             static_cast<unsigned long>(selfMapKindCounts[kind]));
            }
        }

        std::fprintf(summary, "\nnotable_self_map_entries:\n");
        for (const auto &entry : ctx.SelfMapEntries)
        {
            if (entry.Kind == IX_SELF_MAP_KIND_RUNTIME_STATE ||
                entry.Kind == IX_SELF_MAP_KIND_SNAPSHOT_SUMMARY ||
                entry.Kind == IX_SELF_MAP_KIND_SYSCALL_STUB)
            {
                std::fprintf(summary, "  [%s] %s/%s addr=0x%llX size=0x%llX flags=0x%08lX\n",
                             SelfMapKindName(entry.Kind), entry.Owner, entry.Name,
                             static_cast<unsigned long long>(entry.Address),
                             static_cast<unsigned long long>(entry.Size), static_cast<unsigned long>(entry.Flags));
            }
        }

        std::fclose(summary);
    }

    void WriteRawEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) noexcept
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

    void CaptureSelfMapEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord)
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
        ctx.SelfMapEntries.push_back(entry);

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

    void PrintHookEvent(const IXIPC_HOOK_EVENT &eventRecord)
    {
        char sample[IXIPC_MAX_HOOK_DATA_SAMPLE + 1]{};
        if (eventRecord.DataSize != 0)
        {
            UINT32 safe = eventRecord.DataSize < IXIPC_MAX_HOOK_DATA_SAMPLE ? eventRecord.DataSize
                                                                            : IXIPC_MAX_HOOK_DATA_SAMPLE;
            for (UINT32 i = 0; i < safe; ++i)
            {
                unsigned char ch = eventRecord.DataSample[i];
                sample[i] = (ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '.';
            }
            sample[safe] = '\0';
        }

        std::printf("[blind] event pid=%lu tid=%lu kind=%s op=%lu api=%s module=%s caller=0x%llX "
                    "c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX%s%s\n",
                    static_cast<unsigned long>(eventRecord.ProcessId),
                    static_cast<unsigned long>(eventRecord.ThreadId), KindName(eventRecord.Kind),
                    static_cast<unsigned long>(eventRecord.Operation),
                    eventRecord.ApiName[0] != '\0' ? eventRecord.ApiName : "<none>",
                    eventRecord.ModuleName[0] != '\0' ? eventRecord.ModuleName : "<none>",
                    static_cast<unsigned long long>(eventRecord.Caller),
                    static_cast<unsigned long long>(eventRecord.Context0),
                    static_cast<unsigned long long>(eventRecord.Context1),
                    static_cast<unsigned long long>(eventRecord.Context2),
                    static_cast<unsigned long long>(eventRecord.Context3), sample[0] != '\0' ? " sample=" : "",
                    sample[0] != '\0' ? sample : "");
    }

    void HandleHookEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord)
    {
        ctx.HookEventCount.fetch_add(1, std::memory_order_relaxed);
        if (eventRecord.Kind == IxIpcHookEventIntegrity &&
            (eventRecord.Operation == IX_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY ||
             eventRecord.Operation == IX_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK))
        {
            ctx.LaunchGateTrapCount.fetch_add(1, std::memory_order_relaxed);
            std::printf("[blind] launch-gate trap op=%lu tid=%lu caller=0x%llX page=0x%llX\n",
                        static_cast<unsigned long>(eventRecord.Operation),
                        static_cast<unsigned long>(eventRecord.ThreadId),
                        static_cast<unsigned long long>(eventRecord.Context0),
                        static_cast<unsigned long long>(eventRecord.Context1));
        }
        if (eventRecord.Kind < RTL_NUMBER_OF(ctx.EventKindCounts))
        {
            ctx.EventKindCounts[eventRecord.Kind] += 1;
        }
        WriteRawEvent(ctx, eventRecord);
        CaptureSelfMapEvent(ctx, eventRecord);

        DWORD printed = ctx.PrintedEventCount.load(std::memory_order_relaxed);
        bool shouldPrint = ctx.Verbose || printed < 24 ||
                           (eventRecord.Kind == IxIpcHookEventWinsock && printed < 64);
        if (shouldPrint)
        {
            ctx.PrintedEventCount.fetch_add(1, std::memory_order_relaxed);
            PrintHookEvent(eventRecord);
            return;
        }

        DWORD suppressed = ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
        if (suppressed == 0)
        {
            std::printf("[blind] suppressing additional event details; rerun with --verbose for full dump\n");
        }
    }

    bool HandlePacket(ServerContext &ctx, HANDLE pipe, const IXIPC_PACKET &request)
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
            std::printf("[blind] ready pid=%lu mask=0x%08lX observed=0x%08lX\n",
                        static_cast<unsigned long>(request.Payload.NotifyHookReadyRequest.ProcessId),
                        static_cast<unsigned long>(localMask), static_cast<unsigned long>(observed));
            if ((observed & (IXIPC_HOOK_READY_FLAG_IPC_CONNECTED | IXIPC_HOOK_READY_FLAG_NT)) ==
                (IXIPC_HOOK_READY_FLAG_IPC_CONNECTED | IXIPC_HOOK_READY_FLAG_NT))
            {
                SetEvent(ctx.ReadyEvent);
            }
            break;
        }
        case IxIpcCommandPublishHookEvent:
            HandleHookEvent(ctx, request.Payload.HookEvent);
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
                HandleHookEvent(ctx, request.Payload.HookEventBatch.Events[i]);
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
        auto *ctx = static_cast<ServerContext *>(parameter);
        HANDLE pipe = CreateNamedPipeW(ctx->PipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, kPipeBufferBytes,
                                       kPipeBufferBytes, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            std::printf("[blind] CreateNamedPipe failed gle=%lu\n", GetLastError());
            SetEvent(ctx->ReadyEvent);
            return 1;
        }

        std::printf("[blind] listening on %ls\n", ctx->PipeName.c_str());
        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            std::printf("[blind] ConnectNamedPipe failed gle=%lu\n", GetLastError());
            CloseHandle(pipe);
            SetEvent(ctx->ReadyEvent);
            return 1;
        }

        std::printf("[blind] hook client connected\n");
        while (!ctx->Stop.load(std::memory_order_acquire))
        {
            IXIPC_PACKET request{};
            DWORD read = 0;
            if (!ReadFile(pipe, &request, sizeof(request), &read, nullptr))
            {
                DWORD err = GetLastError();
                if (err != ERROR_BROKEN_PIPE && err != ERROR_PIPE_NOT_CONNECTED)
                {
                    std::printf("[blind] pipe read failed gle=%lu\n", err);
                }
                break;
            }
            if (read != sizeof(request))
            {
                std::printf("[blind] short packet read bytes=%lu expected=%zu\n", read, sizeof(request));
                break;
            }
            if (!HandlePacket(*ctx, pipe, request))
            {
                std::printf("[blind] response write failed gle=%lu\n", GetLastError());
                break;
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 0;
    }

    bool InjectDllIntoChild(HANDLE process, const std::wstring &dllPath)
    {
        SIZE_T bytes = (dllPath.size() + 1u) * sizeof(wchar_t);
        void *remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remotePath == nullptr)
        {
            std::printf("[blind] VirtualAllocEx failed gle=%lu\n", GetLastError());
            return false;
        }

        bool ok = false;
        SIZE_T written = 0;
        if (WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes, &written) && written == bytes)
        {
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            auto loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
            HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibraryW, remotePath, 0, nullptr);
            if (thread != nullptr)
            {
                DWORD wait = WaitForSingleObject(thread, kInjectTimeoutMs);
                DWORD exitCode = 0;
                if (wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &exitCode) && exitCode != 0)
                {
                    ok = true;
                }
                else
                {
                    std::printf("[blind] LoadLibrary remote thread failed wait=%lu exit=0x%08lX gle=%lu\n", wait,
                                exitCode, GetLastError());
                }
                CloseHandle(thread);
            }
            else
            {
                std::printf("[blind] CreateRemoteThread failed gle=%lu\n", GetLastError());
            }
        }
        else
        {
            std::printf("[blind] WriteProcessMemory failed gle=%lu\n", GetLastError());
        }

        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        return ok;
    }
}

int wmain(int argc, wchar_t **argv)
{
    std::wstring baseDir = ModuleDirectory();
    std::wstring dllPath = baseDir + L"\\BLIND.dll";
    std::wstring targetPath = baseDir + L"\\BlindTestTarget.exe";

    bool verbose = false;
    bool launchGateMode = false;
    bool targetSet = false;
    for (int argIndex = 1; argIndex < argc; ++argIndex)
    {
        if (wcscmp(argv[argIndex], L"--help") == 0)
        {
            std::wprintf(
                L"Usage: BlindRunner.exe [--verbose] [--launch-gate] [--pipe \\\\.\\pipe\\Name] [owned-test-exe]\n");
            std::wprintf(L"Only processes spawned by this runner are supported.\n");
            return 0;
        }
        if (wcscmp(argv[argIndex], L"--verbose") == 0)
        {
            verbose = true;
            continue;
        }
        if (wcscmp(argv[argIndex], L"--launch-gate") == 0)
        {
            launchGateMode = true;
            continue;
        }
        if (wcscmp(argv[argIndex], L"--pipe") == 0)
        {
            if (argIndex + 1 >= argc)
            {
                std::wprintf(L"[blind] --pipe requires a named-pipe path\n");
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

        std::wprintf(L"[blind] unexpected argument: %ls\n", argv[argIndex]);
        return 2;
    }
    if (launchGateMode && !targetSet)
    {
        targetPath = baseDir + L"\\BlindLaunchGateTarget.exe";
    }

    if (!FileExists(dllPath))
    {
        std::wprintf(L"[blind] missing DLL: %ls\n", dllPath.c_str());
        return 2;
    }
    if (!FileExists(targetPath))
    {
        std::wprintf(L"[blind] missing target: %ls\n", targetPath.c_str());
        return 2;
    }

    ServerContext ctx{};
    ctx.Verbose = verbose;
    ctx.LaunchGateMode = launchGateMode;
    ctx.PipeName = EffectivePipeName();
    if (!OpenDiagnostics(ctx, baseDir))
    {
        CloseDiagnostics(ctx);
        return 2;
    }
    (void)SetEnvironmentVariableW(L"BLIND_LOG_DIR", ctx.LogDir.c_str());
    (void)SetEnvironmentVariableW(L"BLIND_RUNNER_OWNS_PIPE", L"1");
    if (launchGateMode)
    {
        (void)SetEnvironmentVariableW(L"IX_HOOK_LAUNCH_GATE", L"1");
    }
    else
    {
        (void)SetEnvironmentVariableW(L"IX_HOOK_LAUNCH_GATE", nullptr);
    }

    ctx.ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ctx.ReadyEvent == nullptr)
    {
        std::printf("[blind] CreateEvent failed gle=%lu\n", GetLastError());
        CloseDiagnostics(ctx);
        return 2;
    }

    HANDLE serverThread = CreateThread(nullptr, 0, PipeServerThread, &ctx, 0, nullptr);
    if (serverThread == nullptr)
    {
        std::printf("[blind] server thread failed gle=%lu\n", GetLastError());
        CloseHandle(ctx.ReadyEvent);
        CloseDiagnostics(ctx);
        return 2;
    }

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring commandLine = QuotePath(targetPath);
    DWORD creationFlags = launchGateMode ? CREATE_SUSPENDED : 0;
    BOOL created = CreateProcessW(targetPath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, creationFlags, nullptr,
                                  baseDir.c_str(), &si, &pi);
    if (!created)
    {
        std::printf("[blind] CreateProcess failed gle=%lu\n", GetLastError());
        ctx.Stop.store(true, std::memory_order_release);
        WaitForSingleObject(serverThread, 1000);
        CloseHandle(serverThread);
        CloseHandle(ctx.ReadyEvent);
        CloseDiagnostics(ctx);
        return 3;
    }

    std::wprintf(L"[blind] child pid=%lu target=%ls launch_gate=%u\n", pi.dwProcessId, targetPath.c_str(),
                 launchGateMode ? 1u : 0u);
    ctx.ChildProcessId = pi.dwProcessId;
    {
        wchar_t logName[64]{};
        (void)StringCchPrintfW(logName, RTL_NUMBER_OF(logName), L"blind-runtime-%lu.log", pi.dwProcessId);
        ctx.RuntimeLogPath = JoinPath(ctx.LogDir, logName);
        std::wprintf(L"[blind] runtime log=%ls\n", ctx.RuntimeLogPath.c_str());
    }
    if (!launchGateMode)
    {
        Sleep(500);
    }
    if (!InjectDllIntoChild(pi.hProcess, dllPath))
    {
        TerminateProcess(pi.hProcess, ERROR_DLL_INIT_FAILED);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ctx.Stop.store(true, std::memory_order_release);
        WaitForSingleObject(serverThread, 1000);
        CloseHandle(serverThread);
        CloseHandle(ctx.ReadyEvent);
        CloseDiagnostics(ctx);
        return 4;
    }

    if (launchGateMode)
    {
        DWORD previousSuspendCount = ResumeThread(pi.hThread);
        if (previousSuspendCount == static_cast<DWORD>(-1))
        {
            std::printf("[blind] ResumeThread failed gle=%lu\n", GetLastError());
            TerminateProcess(pi.hProcess, ERROR_INVALID_STATE);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            ctx.Stop.store(true, std::memory_order_release);
            WaitForSingleObject(serverThread, 1000);
            CloseHandle(serverThread);
            CloseHandle(ctx.ReadyEvent);
            CloseDiagnostics(ctx);
            return 4;
        }
        std::printf("[blind] launch-gate child resumed previous_suspend_count=%lu\n",
                    static_cast<unsigned long>(previousSuspendCount));
    }

    DWORD readyWait = WaitForSingleObject(ctx.ReadyEvent, kReadyTimeoutMs);
    std::printf("[blind] ready wait=%lu mask=0x%08lX\n", readyWait,
                static_cast<unsigned long>(ctx.ReadyMask.load(std::memory_order_acquire)));

    DWORD childWait = WaitForSingleObject(pi.hProcess, 30000);
    if (childWait == WAIT_TIMEOUT)
    {
        std::printf("[blind] child wait timed out; terminating pid=%lu\n", pi.dwProcessId);
        TerminateProcess(pi.hProcess, WAIT_TIMEOUT);
        WaitForSingleObject(pi.hProcess, 5000);
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    std::printf("[blind] child exit=0x%08lX events=%lu suppressed=%lu\n", exitCode,
                static_cast<unsigned long>(ctx.HookEventCount.load(std::memory_order_acquire)),
                static_cast<unsigned long>(ctx.SuppressedEventCount.load(std::memory_order_acquire)));
    std::printf("[blind] launch-gate traps=%lu\n",
                static_cast<unsigned long>(ctx.LaunchGateTrapCount.load(std::memory_order_acquire)));
    std::printf("[blind] self-map entries=%zu\n", ctx.SelfMapEntries.size());
    std::wprintf(L"[blind] diagnostics summary=%ls\n", JoinPath(ctx.RunDir, L"summary.txt").c_str());

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    Sleep(500);
    ctx.Stop.store(true, std::memory_order_release);
    WaitForSingleObject(serverThread, 1000);
    CloseHandle(serverThread);
    CloseHandle(ctx.ReadyEvent);
    if (ctx.EventsFile != nullptr)
    {
        std::fflush(ctx.EventsFile);
    }
    if (ctx.SelfMapFile != nullptr)
    {
        std::fflush(ctx.SelfMapFile);
    }
    WriteSummary(ctx, exitCode, childWait);
    CloseDiagnostics(ctx);

    DWORD finalReadyMask = ctx.ReadyMask.load(std::memory_order_acquire);
    bool ok = exitCode == 0 && ctx.HookEventCount.load(std::memory_order_acquire) != 0 &&
              ((finalReadyMask & BLIND_SDK_READY_CORE_MASK) == BLIND_SDK_READY_CORE_MASK);
    if (launchGateMode)
    {
        ok = ok && ctx.LaunchGateTrapCount.load(std::memory_order_acquire) != 0;
    }
    return ok ? 0 : 5;
}
