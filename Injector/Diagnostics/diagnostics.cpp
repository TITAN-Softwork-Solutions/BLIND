#include "Diagnostics/diagnostics.h"
#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"

namespace blind::injector {
void WriteJsonEscaped(FILE *file, const char *value) noexcept {
  if (file == nullptr || value == nullptr) {
    return;
  }

  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value);
       *p != 0; ++p) {
    switch (*p) {
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
      if (*p < 0x20) {
        std::fprintf(file, "\\u%04x", static_cast<unsigned int>(*p));
      } else {
        std::fputc(*p, file);
      }
      break;
    }
  }
}

const char *SelfMapKindName(UINT32 kind) noexcept {
  switch (kind) {
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

bool OpenDiagnostics(ServerContext &ctx, const std::wstring &baseDir) {
  const std::wstring diagnosticsRoot = JoinPath(baseDir, L"BlindDiagnostics");
  if (!EnsureDirectory(diagnosticsRoot)) {
    std::wprintf(L"[blind] failed to create diagnostics dir: %ls\n",
                 diagnosticsRoot.c_str());
    return false;
  }

  ctx.RunDir = BuildRunDirectory(baseDir);
  if (!EnsureDirectory(ctx.RunDir)) {
    std::wprintf(L"[blind] failed to create diagnostics run dir: %ls\n",
                 ctx.RunDir.c_str());
    return false;
  }

  ctx.LogDir = JoinPath(ctx.RunDir, L"logs");
  if (!EnsureDirectory(ctx.LogDir)) {
    std::wprintf(L"[blind] failed to create diagnostics log dir: %ls\n",
                 ctx.LogDir.c_str());
    return false;
  }

  std::wstring eventsPath = JoinPath(ctx.RunDir, L"events.jsonl");
  std::wstring selfMapPath = JoinPath(ctx.RunDir, L"selfmap.tsv");
  ctx.HostLogPath = JoinPath(ctx.LogDir, L"blind-host.log");
  if (_wfopen_s(&ctx.EventsFile, eventsPath.c_str(), L"wb") != 0 ||
      ctx.EventsFile == nullptr) {
    std::wprintf(L"[blind] failed to open diagnostics events file: %ls\n",
                 eventsPath.c_str());
    return false;
  }
  if (_wfopen_s(&ctx.SelfMapFile, selfMapPath.c_str(), L"wb") != 0 ||
      ctx.SelfMapFile == nullptr) {
    std::wprintf(L"[blind] failed to open diagnostics self-map file: %ls\n",
                 selfMapPath.c_str());
    return false;
  }
  if (_wfopen_s(&ctx.HostLogFile, ctx.HostLogPath.c_str(), L"ab") != 0) {
    ctx.HostLogFile = nullptr;
  }

  std::fputs("index\ttotal\ttruncated\tkind\towner\tname\taddress\tsize\tflags"
             "\tref0\tref1\tallocation_base\tregion_"
             "size\tprotect\tstate\ttype\n",
             ctx.SelfMapFile);
  std::wprintf(L"[blind] diagnostics dir=%ls\n", ctx.RunDir.c_str());
  HostDebugLog(ctx, "diagnostics opened");
  return true;
}

void CloseDiagnostics(ServerContext &ctx) noexcept {
  if (ctx.EventsFile != nullptr) {
    std::fflush(ctx.EventsFile);
    std::fclose(ctx.EventsFile);
    ctx.EventsFile = nullptr;
  }
  if (ctx.SelfMapFile != nullptr) {
    std::fflush(ctx.SelfMapFile);
    std::fclose(ctx.SelfMapFile);
    ctx.SelfMapFile = nullptr;
  }
  if (ctx.HostLogFile != nullptr) {
    std::fflush(ctx.HostLogFile);
    std::fclose(ctx.HostLogFile);
    ctx.HostLogFile = nullptr;
  }
}

void WriteSummary(ServerContext &ctx, DWORD exitCode, DWORD childWait) {
  std::wstring summaryPath = JoinPath(ctx.RunDir, L"summary.txt");
  FILE *summary = nullptr;
  if (_wfopen_s(&summary, summaryPath.c_str(), L"wb") != 0 ||
      summary == nullptr) {
    return;
  }

  std::fprintf(summary, "BLIND standalone diagnostic summary\n");
  std::fprintf(summary, "child_pid=%lu\n",
               static_cast<unsigned long>(ctx.ChildProcessId));
  std::fprintf(summary, "child_wait=0x%08lX\n",
               static_cast<unsigned long>(childWait));
  std::fprintf(summary, "child_exit=0x%08lX\n",
               static_cast<unsigned long>(exitCode));
  std::fprintf(summary, "ready_mask=0x%08lX\n",
               static_cast<unsigned long>(
                   ctx.ReadyMask.load(std::memory_order_acquire)));
  std::fprintf(summary, "events=%lu\n",
               static_cast<unsigned long>(
                   ctx.HookEventCount.load(std::memory_order_acquire)));
  std::fprintf(summary, "launch_gate_mode=%u\n", ctx.LaunchGateMode ? 1u : 0u);
  std::fprintf(summary, "launch_gate_traps=%lu\n",
               static_cast<unsigned long>(
                   ctx.LaunchGateTrapCount.load(std::memory_order_acquire)));
  std::fprintf(summary, "self_map_entries=%zu\n", ctx.SelfMapEntries.size());
  std::fprintf(summary, "runtime_log=%S\n", ctx.RuntimeLogPath.c_str());
  std::fprintf(summary, "host_log=%S\n", ctx.HostLogPath.c_str());
  std::fprintf(summary, "run_dir=%S\n\n", ctx.RunDir.c_str());

  std::fprintf(summary, "event_counts:\n");
  for (UINT32 kind = 0; kind < RTL_NUMBER_OF(ctx.EventKindCounts); ++kind) {
    if (ctx.EventKindCounts[kind] != 0) {
      std::fprintf(summary, "  %s=%lu\n", KindName(kind),
                   static_cast<unsigned long>(ctx.EventKindCounts[kind]));
    }
  }

  std::fprintf(summary, "\nself_map_by_kind:\n");
  DWORD selfMapKindCounts[9]{};
  for (const auto &entry : ctx.SelfMapEntries) {
    if (entry.Kind < RTL_NUMBER_OF(selfMapKindCounts)) {
      selfMapKindCounts[entry.Kind] += 1;
    }
  }
  for (UINT32 kind = 0; kind < RTL_NUMBER_OF(selfMapKindCounts); ++kind) {
    if (selfMapKindCounts[kind] != 0) {
      std::fprintf(summary, "  %s=%lu\n", SelfMapKindName(kind),
                   static_cast<unsigned long>(selfMapKindCounts[kind]));
    }
  }

  std::fprintf(summary, "\nnotable_self_map_entries:\n");
  for (const auto &entry : ctx.SelfMapEntries) {
    if (entry.Kind == IX_SELF_MAP_KIND_RUNTIME_STATE ||
        entry.Kind == IX_SELF_MAP_KIND_SNAPSHOT_SUMMARY ||
        entry.Kind == IX_SELF_MAP_KIND_SYSCALL_STUB) {
      std::fprintf(summary,
                   "  [%s] %s/%s addr=0x%llX size=0x%llX flags=0x%08lX\n",
                   SelfMapKindName(entry.Kind), entry.Owner, entry.Name,
                   static_cast<unsigned long long>(entry.Address),
                   static_cast<unsigned long long>(entry.Size),
                   static_cast<unsigned long>(entry.Flags));
    }
  }

  std::fclose(summary);
}

void WriteRawEvent(ServerContext &ctx,
                   const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  if (ctx.EventsFile == nullptr) {
    return;
  }

  char sample[IXIPC_MAX_HOOK_DATA_SAMPLE + 1]{};
  CopyEventSampleString(eventRecord, sample, RTL_NUMBER_OF(sample));

  std::fprintf(
      ctx.EventsFile,
      "{\"pid\":%lu,\"tid\":%lu,\"kind\":\"%s\",\"kind_id\":%lu,\"op\":%lu,"
      "\"status\":\"0x%08lX\",\"action\":%lu,\"api\":\"",
      static_cast<unsigned long>(eventRecord.ProcessId),
      static_cast<unsigned long>(eventRecord.ThreadId),
      KindName(eventRecord.Kind), static_cast<unsigned long>(eventRecord.Kind),
      static_cast<unsigned long>(eventRecord.Operation),
      static_cast<unsigned long>(eventRecord.Status),
      static_cast<unsigned long>(eventRecord.Action));
  WriteJsonEscaped(ctx.EventsFile, eventRecord.ApiName);
  std::fputs("\",\"module\":\"", ctx.EventsFile);
  WriteJsonEscaped(ctx.EventsFile, eventRecord.ModuleName);
  std::fprintf(ctx.EventsFile,
               "\",\"caller\":\"0x%llX\",\"c0\":\"0x%llX\",\"c1\":\"0x%llX\","
               "\"c2\":\"0x%llX\","
               "\"c3\":\"0x%llX\",\"args\":[",
               static_cast<unsigned long long>(eventRecord.Caller),
               static_cast<unsigned long long>(eventRecord.Context0),
               static_cast<unsigned long long>(eventRecord.Context1),
               static_cast<unsigned long long>(eventRecord.Context2),
               static_cast<unsigned long long>(eventRecord.Context3));
  for (UINT32 i = 0; i < eventRecord.ArgCount && i < IXIPC_MAX_HOOK_ARGS; ++i) {
    std::fprintf(ctx.EventsFile, "%s\"0x%llX\"", i == 0 ? "" : ",",
                 static_cast<unsigned long long>(eventRecord.Args[i]));
  }
  std::fputs("],\"sample\":\"", ctx.EventsFile);
  WriteJsonEscaped(ctx.EventsFile, sample);
  std::fputs("\"}\n", ctx.EventsFile);
}
void CaptureSelfMapEvent(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord) {
  if (eventRecord.Kind != IxIpcHookEventIntegrity ||
      eventRecord.Operation != IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY) {
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
  if (eventRecord.ArgCount > 4) {
    entry.Protect = static_cast<UINT32>(eventRecord.Args[4] >> 32);
    entry.State = static_cast<UINT32>(eventRecord.Args[4] & 0xFFFFFFFFu);
  }
  entry.Type = eventRecord.ArgCount > 5
                   ? static_cast<UINT32>(eventRecord.Args[5] & 0xFFFFFFFFu)
                   : 0;
  entry.Index = eventRecord.ArgCount > 6
                    ? static_cast<UINT32>(eventRecord.Args[6] & 0xFFFFFFFFu)
                    : 0;
  if (eventRecord.ArgCount > 7) {
    entry.Total = static_cast<UINT32>(eventRecord.Args[7] >> 32);
    entry.Truncated = static_cast<UINT32>(eventRecord.Args[7] & 0xFFFFFFFFu);
  }

  (void)StringCchCopyA(entry.Owner, RTL_NUMBER_OF(entry.Owner),
                       eventRecord.ModuleName);
  CopyEventSampleString(eventRecord, entry.Name, RTL_NUMBER_OF(entry.Name));
  ctx.SelfMapEntries.push_back(entry);

  if (ctx.SelfMapFile != nullptr) {
    std::fprintf(
        ctx.SelfMapFile,
        "%lu\t%lu\t%lu\t%s\t%s\t%s\t0x%llX\t0x%llX\t0x%08lX\t0x%llX\t0x%llX\t"
        "0x%llX\t0x%llX\t0x%08lX\t0x%08lX\t0x%08lX\n",
        static_cast<unsigned long>(entry.Index),
        static_cast<unsigned long>(entry.Total),
        static_cast<unsigned long>(entry.Truncated),
        SelfMapKindName(entry.Kind), entry.Owner, entry.Name,
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

} // namespace blind::injector
