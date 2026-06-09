#include "Core/runner_console.h"
#include "Telemetry/cli_events.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/smart_capture.h"
#include "Telemetry/stack_address.h"

namespace blind::injector {
const char *HookActionName(UINT32 action) noexcept {
  switch (action) {
  case IXIPC_HOOK_ACTION_DENY:
    return "denied";
  case IXIPC_HOOK_ACTION_SILENT_DENY:
    return "silent-denied";
  default:
    return "hit";
  }
}

bool CliEventsEquivalentForRepeat(const IXIPC_HOOK_EVENT &left,
                                  const IXIPC_HOOK_EVENT &right) noexcept {
  if (left.Kind != right.Kind || left.ProcessId != right.ProcessId ||
      left.ThreadId != right.ThreadId || left.Operation != right.Operation ||
      left.Caller != right.Caller || left.Context0 != right.Context0 ||
      left.Context1 != right.Context1 || left.Context2 != right.Context2 ||
      left.Context3 != right.Context3 || left.ArgCount != right.ArgCount ||
      left.DataSize != right.DataSize || left.Status != right.Status ||
      left.Action != right.Action) {
    return false;
  }

  if (std::strncmp(left.ApiName, right.ApiName, IXIPC_MAX_HOOK_API_NAME) != 0 ||
      std::strncmp(left.ModuleName, right.ModuleName,
                   IXIPC_MAX_HOOK_MODULE_NAME) != 0) {
    return false;
  }

  const UINT32 argCount =
      left.ArgCount < IXIPC_MAX_HOOK_ARGS ? left.ArgCount : IXIPC_MAX_HOOK_ARGS;
  for (UINT32 i = 0; i < argCount; ++i) {
    if (left.Args[i] != right.Args[i]) {
      return false;
    }
  }

  const UINT32 dataSize = left.DataSize < IXIPC_MAX_HOOK_DATA_SAMPLE
                              ? left.DataSize
                              : IXIPC_MAX_HOOK_DATA_SAMPLE;
  return dataSize == 0 ||
         std::memcmp(left.DataSample, right.DataSample, dataSize) == 0;
}

bool ShouldPrintRepeatMilestone(UINT32 repeat) noexcept {
  return repeat <= 4 || repeat == 8 || repeat == 16 || repeat == 32 ||
         repeat == 64 || repeat == 128 || repeat == 256 || repeat == 512 ||
         repeat == 1024 || repeat == 2048 || repeat == 4095;
}

bool ApplyCliRepeatAnnotation(ServerContext &ctx,
                              IXIPC_HOOK_EVENT &eventRecord) noexcept {
  UINT32 runtimeRepeat = DecodeRepeatCount(eventRecord.CallerFlags);
  if (!ctx.HasLastPrintedCliEvent ||
      !CliEventsEquivalentForRepeat(ctx.LastPrintedCliEvent, eventRecord)) {
    ctx.LastPrintedCliEvent = eventRecord;
    ctx.LastPrintedCliRepeat = runtimeRepeat;
    ctx.LastPrintedCliRepeatMilestone = runtimeRepeat;
    ctx.HasLastPrintedCliEvent = true;
    eventRecord.CallerFlags =
        EncodeRepeatCount(eventRecord.CallerFlags, runtimeRepeat);
    return true;
  }

  UINT32 repeat = ctx.LastPrintedCliRepeat;
  if (runtimeRepeat > repeat) {
    repeat = runtimeRepeat;
  } else if (repeat < 0xFFFu) {
    ++repeat;
  }

  ctx.LastPrintedCliRepeat = repeat;
  ctx.LastPrintedCliEvent = eventRecord;
  eventRecord.CallerFlags = EncodeRepeatCount(eventRecord.CallerFlags, repeat);
  if (!ShouldPrintRepeatMilestone(repeat) ||
      repeat == ctx.LastPrintedCliRepeatMilestone) {
    return false;
  }
  ctx.LastPrintedCliRepeatMilestone = repeat;
  return true;
}

bool SameDirectSyscallFold(const CliDetectionFoldState &fold,
                           const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  if (fold.Operation != eventRecord.Operation ||
      fold.Caller != eventRecord.Caller ||
      fold.SyscallNumber !=
          (eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0) ||
      fold.StubOffset != (eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0) ||
      std::strncmp(fold.ModuleName, eventRecord.ModuleName,
                   IXIPC_MAX_HOOK_MODULE_NAME) != 0) {
    return false;
  }

  UINT32 sampleSize = eventRecord.DataSize < sizeof(fold.Sample)
                          ? eventRecord.DataSize
                          : static_cast<UINT32>(sizeof(fold.Sample));
  if (fold.SampleSize != sampleSize) {
    return false;
  }

  return sampleSize == 0 ||
         std::memcmp(fold.Sample, eventRecord.DataSample, sampleSize) == 0;
}

bool ShouldPrintFoldedDirectSyscallDetection(
    ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) {
  if (eventRecord.Operation != IX_HOOK_EVENT_OP_DIRECT_SYSCALL_PAGE) {
    return true;
  }

  for (auto &fold : ctx.CliDetectionFolds) {
    if (!SameDirectSyscallFold(fold, eventRecord)) {
      continue;
    }

    fold.Count += 1;
    fold.LastPage = eventRecord.Context0;
    ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  CliDetectionFoldState fold{};
  fold.Operation = eventRecord.Operation;
  fold.Caller = eventRecord.Caller;
  fold.SyscallNumber = eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0;
  fold.StubOffset = eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0;
  fold.FirstPage = eventRecord.Context0;
  fold.LastPage = eventRecord.Context0;
  fold.Count = 1;
  fold.SampleSize = eventRecord.DataSize < sizeof(fold.Sample)
                        ? eventRecord.DataSize
                        : static_cast<UINT32>(sizeof(fold.Sample));
  if (fold.SampleSize != 0) {
    std::memcpy(fold.Sample, eventRecord.DataSample, fold.SampleSize);
  }
  (void)StringCchCopyA(
      fold.ModuleName, RTL_NUMBER_OF(fold.ModuleName),
      eventRecord.ModuleName[0] != '\0' ? eventRecord.ModuleName : "memory");
  ctx.CliDetectionFolds.push_back(fold);
  return true;
}

bool ShouldPrintCliEvent(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord) {
  if (!ctx.CliMode) {
    return false;
  }

  if (eventRecord.Kind == IxIpcHookEventIntegrity) {
    switch (eventRecord.Operation) {
    case IX_HOOK_EVENT_OP_HOOK_INTEGRITY:
      return eventRecord.Context0 != 0;
    case IX_HOOK_EVENT_OP_AMSI_PATCH:
    case IX_HOOK_EVENT_OP_ETW_PATCH:
      return eventRecord.Context0 != 0;
    case IX_HOOK_EVENT_OP_PIC_DIRECT_SYSCALL:
    case IX_HOOK_EVENT_OP_NTDLL_DOUBLE_LOAD:
    case IX_HOOK_EVENT_OP_DIRECT_SYSCALL_PAGE:
      return ShouldPrintFoldedDirectSyscallDetection(ctx, eventRecord);
    case IX_HOOK_EVENT_OP_DIRECT_SYSCALL_ACCESS:
      return true;
    case IX_HOOK_EVENT_OP_NTDLL_EAT_ACCESS:
      return ImmediateFrameHasDetectionOrigin(ctx, eventRecord);
    default:
      break;
    }
  }

  const IXIPC_HOOK_POLICY_RULE *rule = FindCliRule(ctx, eventRecord);
  return ctx.Verbose ||
         (rule != nullptr && (rule->Flags & IXIPC_HOOK_RULE_FLAG_LOG) != 0);
}

bool IsCliDetectionEvent(const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  if (eventRecord.Kind != IxIpcHookEventIntegrity) {
    return false;
  }

  switch (eventRecord.Operation) {
  case IX_HOOK_EVENT_OP_HOOK_INTEGRITY:
  case IX_HOOK_EVENT_OP_AMSI_PATCH:
  case IX_HOOK_EVENT_OP_ETW_PATCH:
  case IX_HOOK_EVENT_OP_PIC_DIRECT_SYSCALL:
  case IX_HOOK_EVENT_OP_NTDLL_DOUBLE_LOAD:
  case IX_HOOK_EVENT_OP_NTDLL_EAT_ACCESS:
  case IX_HOOK_EVENT_OP_DIRECT_SYSCALL_PAGE:
  case IX_HOOK_EVENT_OP_DIRECT_SYSCALL_ACCESS:
    return true;
  default:
    return false;
  }
}

bool IsSmartManagedEvent(const ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  if (!ctx.SmartMode || eventRecord.Kind != IxIpcHookEventNt) {
    return false;
  }

  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  const bool remoteTarget = IsRemoteTarget(ctx, targetPid);

  return ((SmartAreaEnabled(ctx, kSmartAreaMemory) &&
           (ApiIs(eventRecord, "NtAllocateVirtualMemory") ||
            ApiIs(eventRecord, "NtAllocateVirtualMemoryEx"))) ||
          (SmartAreaEnabled(ctx, kSmartAreaProtect) &&
           ApiIs(eventRecord, "NtProtectVirtualMemory")) ||
          ((SmartAreaEnabled(ctx, kSmartAreaQueries) || remoteTarget) &&
           ApiIs(eventRecord, "NtQueryVirtualMemory")) ||
          ((SmartAreaEnabled(ctx, kSmartAreaReads) || remoteTarget) &&
           ApiIs(eventRecord, "NtReadVirtualMemory")) ||
          ((SmartAreaEnabled(ctx, kSmartAreaWrites) || remoteTarget) &&
           ApiIs(eventRecord, "NtWriteVirtualMemory")) ||
          ((SmartAreaEnabled(ctx, kSmartAreaHandles) || remoteTarget) &&
           (ApiIs(eventRecord, "NtOpenProcess") ||
            ApiIs(eventRecord, "NtOpenThread"))) ||
          (SmartAreaEnabled(ctx, kSmartAreaThreads) &&
           (ApiIs(eventRecord, "NtCreateThread") ||
            ApiIs(eventRecord, "NtCreateThreadEx"))) ||
          (SmartAreaEnabled(ctx, kSmartAreaApc) &&
           (ApiIs(eventRecord, "NtQueueApcThread") ||
            ApiIs(eventRecord, "NtQueueApcThreadEx") ||
            ApiIs(eventRecord, "NtQueueApcThreadEx2"))) ||
          (SmartAreaEnabled(ctx, kSmartAreaMaps) &&
           (ApiIs(eventRecord, "NtMapViewOfSection") ||
            ApiIs(eventRecord, "NtMapViewOfSectionEx"))));
}

bool ShouldSuppressRawForSmart(const ServerContext &ctx,
                               const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  return ctx.SmartMode && !ctx.SmartRawEvents &&
         IsSmartManagedEvent(ctx, eventRecord);
}
} // namespace blind::injector
