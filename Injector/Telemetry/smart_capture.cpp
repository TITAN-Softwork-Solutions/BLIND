#include "Telemetry/smart_capture.h"
#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_cache.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/smart_state.h"
#include "Telemetry/stack_address.h"

namespace blind::injector {
void InvalidateVadCacheForEvent(ServerContext &ctx,
                                const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  if (eventRecord.Kind != IxIpcHookEventNt ||
      !NtStatusSucceeded(eventRecord.Status)) {
    return;
  }

  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  if (ApiIs(eventRecord, "NtAllocateVirtualMemory") ||
      ApiIs(eventRecord, "NtAllocateVirtualMemoryEx") ||
      ApiIs(eventRecord, "NtProtectVirtualMemory")) {
    InvalidateVadCache(ctx, targetPid, eventRecord.Context0,
                       eventRecord.Context1);
    return;
  }

  if (ApiIs(eventRecord, "NtMapViewOfSection") ||
      ApiIs(eventRecord, "NtMapViewOfSectionEx")) {
    InvalidateVadCache(ctx, targetPid, eventRecord.Context2,
                       eventRecord.Context3);
    return;
  }

  if (ApiIs(eventRecord, "NtUnmapViewOfSection") ||
      ApiIs(eventRecord, "NtUnmapViewOfSectionEx")) {
    InvalidateVadCache(ctx, targetPid, eventRecord.Context1, 0);
  }
}

void CaptureSmartAllocation(ServerContext &ctx,
                            const IXIPC_HOOK_EVENT &eventRecord, bool mapped) {
  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  UINT64 base = mapped ? eventRecord.Context2 : eventRecord.Context0;
  UINT64 size = mapped ? eventRecord.Context3 : eventRecord.Context1;
  UINT32 allocationType = mapped ? static_cast<UINT32>(eventRecord.ArgCount > 5
                                                           ? eventRecord.Args[5]
                                                           : 0)
                                 : static_cast<UINT32>(eventRecord.Context2);
  UINT32 protect = mapped
                       ? static_cast<UINT32>(
                             eventRecord.ArgCount > 6 ? eventRecord.Args[6] : 0)
                       : static_cast<UINT32>(eventRecord.Context3);

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  if (mapped) {
    target.MapCount += 1;
    target.MapBytes += size;
  } else {
    target.AllocCount += 1;
    target.AllocBytes += size;
  }
  if (IsWriteExecuteProtect(protect)) {
    target.RwxBytes += size;
  }

  SmartMemoryRegion &region = SmartRegionFor(ctx, targetPid, base, size);
  region.Caller = eventRecord.Caller;
  region.StackHash = StackHash(eventRecord);
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, region.CallerVad,
                               region.PrivateFrame, region.PrivateFrameVad,
                               region.RwxFrame, region.RwxFrameVad,
                               region.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, region.Stack);
  region.Protect = protect;
  region.AllocationType = allocationType;
  if ((allocationType & MEM_COMMIT) != 0) {
    region.State = MEM_COMMIT;
  }
  region.RwxSeen = region.RwxSeen || IsWriteExecuteProtect(protect);
  if (mapped) {
    region.MapCount += 1;
  } else {
    region.AllocCount += 1;
  }
  FormatProtect(protect, region.LastProtect, RTL_NUMBER_OF(region.LastProtect));
  UpdateRegionVad(ctx, region);

  MaybePrintRwxAlert(ctx, region);
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartProtect(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord) {
  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  UINT64 base = eventRecord.Context0;
  UINT64 size = eventRecord.Context1;
  UINT32 newProtect = static_cast<UINT32>(eventRecord.Context2);
  UINT32 oldProtect = static_cast<UINT32>(eventRecord.Context3);
  UINT64 stackHash = StackHash(eventRecord);

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  target.ProtectCount += 1;
  if (IsWriteExecuteProtect(newProtect)) {
    target.RwxBytes += size;
  }

  SmartMemoryRegion &region = SmartRegionFor(ctx, targetPid, base, size);
  region.Caller = eventRecord.Caller;
  region.StackHash = stackHash;
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, region.CallerVad,
                               region.PrivateFrame, region.PrivateFrameVad,
                               region.RwxFrame, region.RwxFrameVad,
                               region.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, region.Stack);
  region.ProtectCount += 1;
  if (region.State == 0) {
    region.State = MEM_COMMIT;
  }
  region.RwxSeen = region.RwxSeen || IsWriteExecuteProtect(newProtect);
  if ((region.Protect != 0 && region.Protect != newProtect) ||
      (oldProtect != 0 && oldProtect != newProtect)) {
    region.FlipCount += 1;
  }
  AppendProtectTransition(region, oldProtect != 0 ? oldProtect : region.Protect,
                          newProtect);
  region.Protect = newProtect;
  UpdateRegionVad(ctx, region);

  SmartProtectGroup &group =
      SmartProtectGroupFor(ctx, targetPid, eventRecord.Caller, stackHash, base,
                           size, oldProtect, newProtect);
  group.Count += 1;
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, group.CallerVad,
                               group.PrivateFrame, group.PrivateFrameVad,
                               group.RwxFrame, group.RwxFrameVad,
                               group.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, group.Stack);
  group.Pages += PageCount(size);
  group.LastBase = base;
  group.MinBase = group.MinBase == 0 ? base : std::min(group.MinBase, base);
  group.MaxBase = std::max(group.MaxBase, base);
  if (IsWriteExecuteProtect(newProtect)) {
    group.RwxCount += 1;
  }
  CopyVadFromRegion(region, group.Vad);

  MaybePrintRwxAlert(ctx, region);
  MaybePrintProtectFlipAlert(ctx, region);
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartWrite(ServerContext &ctx,
                       const IXIPC_HOOK_EVENT &eventRecord) {
  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  UINT64 base = eventRecord.Context0;
  UINT64 size = eventRecord.Context1;
  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  target.WriteCount += 1;
  target.WriteBytes += size;

  SmartMemoryRegion &region =
      SmartRegionFor(ctx, targetPid, PageBase(base), size);
  region.Caller = eventRecord.Caller;
  region.StackHash = StackHash(eventRecord);
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, region.CallerVad,
                               region.PrivateFrame, region.PrivateFrameVad,
                               region.RwxFrame, region.RwxFrameVad,
                               region.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, region.Stack);
  region.WriteCount += 1;
  region.TotalWritten += size;
  UpdateRegionVad(ctx, region);
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartRead(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) {
  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  UINT64 base = eventRecord.Context0;
  UINT64 size = eventRecord.Context1;
  UINT64 bytesRead = eventRecord.Context3 != 0 ? eventRecord.Context3 : size;

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  target.ReadCount += 1;
  target.ReadBytes += bytesRead;

  SmartVadInfo vad{};
  UINT64 regionBase = PageBase(base);
  UINT64 regionSize = size != 0 ? size : 0x1000;
  if (QueryVadInfo(ctx, targetPid, base, vad) && vad.Valid) {
    regionBase = vad.BaseAddress;
    regionSize = vad.RegionSize != 0 ? vad.RegionSize : regionSize;
  }

  SmartMemoryRegion &region =
      SmartRegionFor(ctx, targetPid, regionBase, regionSize);
  region.Caller = eventRecord.Caller;
  region.StackHash = StackHash(eventRecord);
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, region.CallerVad,
                               region.PrivateFrame, region.PrivateFrameVad,
                               region.RwxFrame, region.RwxFrameVad,
                               region.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, region.Stack);
  region.ReadCount += 1;
  region.TotalRead += bytesRead;
  if (vad.Valid) {
    region.State = vad.State;
    region.Type = vad.Type;
    region.Protect = vad.Protect;
    region.AllocationProtect = vad.AllocationProtect;
  } else {
    UpdateRegionVad(ctx, region);
  }
  MaybePrintTargetAlerts(ctx, target);
}
void CaptureSmartQuery(ServerContext &ctx,
                       const IXIPC_HOOK_EVENT &eventRecord) {
  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  UINT64 base = eventRecord.Context0;
  UINT64 informationClass = eventRecord.Context1;
  UINT64 infoLength = eventRecord.Context3;

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  target.QueryCount += 1;
  target.QueryInfoBytes += infoLength;

  SmartVadInfo vad{};
  UINT64 regionBase = PageBase(base);
  UINT64 regionSize = 0x1000;
  if (QueryVadInfo(ctx, targetPid, base, vad) && vad.Valid) {
    regionBase = vad.BaseAddress;
    regionSize = vad.RegionSize != 0 ? vad.RegionSize : regionSize;
  }

  SmartMemoryRegion &region =
      SmartRegionFor(ctx, targetPid, regionBase, regionSize);
  region.Caller = eventRecord.Caller;
  region.StackHash = StackHash(eventRecord);
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, region.CallerVad,
                               region.PrivateFrame, region.PrivateFrameVad,
                               region.RwxFrame, region.RwxFrameVad,
                               region.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, region.Stack);
  region.QueryCount += 1;
  region.LastQueryClass = static_cast<UINT32>(informationClass);
  if (vad.Valid) {
    region.State = vad.State;
    region.Type = vad.Type;
    region.Protect = vad.Protect;
    region.AllocationProtect = vad.AllocationProtect;
  }
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartOpenProcess(ServerContext &ctx,
                             const IXIPC_HOOK_EVENT &eventRecord) {
  DWORD targetPid =
      static_cast<DWORD>(eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0);
  DWORD targetTid =
      static_cast<DWORD>(eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0);
  UINT32 desiredAccess =
      static_cast<UINT32>(eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0);

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  target.OpenProcessCount += 1;

  SmartHandleGroup &group = SmartHandleGroupFor(
      ctx, SmartHandleKind::Process, targetPid, targetTid, desiredAccess,
      eventRecord.Caller, StackHash(eventRecord));
  group.Count += 1;
  group.LastStatus = eventRecord.Status;
  if (!NtStatusSucceeded(eventRecord.Status)) {
    group.FailedCount += 1;
  }
  group.LastHandle = eventRecord.ArgCount > 5 ? eventRecord.Args[5] : 0;
  group.LastObject = eventRecord.ArgCount > 4 ? eventRecord.Args[4] : 0;
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, group.CallerVad,
                               group.PrivateFrame, group.PrivateFrameVad,
                               group.RwxFrame, group.RwxFrameVad,
                               group.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, group.Stack);
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartOpenThread(ServerContext &ctx,
                            const IXIPC_HOOK_EVENT &eventRecord) {
  DWORD targetPid =
      static_cast<DWORD>(eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0);
  DWORD targetTid =
      static_cast<DWORD>(eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0);
  UINT32 desiredAccess =
      static_cast<UINT32>(eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0);
  const ThreadInfoEntry &thread = ResolveThreadInfo(ctx, targetTid);
  if (targetPid == 0 && thread.HasOwnerProcess) {
    targetPid = thread.OwnerProcessId;
  }

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  target.OpenThreadCount += 1;

  SmartHandleGroup &group = SmartHandleGroupFor(
      ctx, SmartHandleKind::Thread, targetPid, targetTid, desiredAccess,
      eventRecord.Caller, StackHash(eventRecord));
  group.Count += 1;
  group.LastStatus = eventRecord.Status;
  if (!NtStatusSucceeded(eventRecord.Status)) {
    group.FailedCount += 1;
  }
  group.LastHandle = eventRecord.ArgCount > 5 ? eventRecord.Args[5] : 0;
  group.LastObject = eventRecord.ArgCount > 4 ? eventRecord.Args[4] : 0;
  if (thread.HasWin32StartAddress) {
    group.ThreadStart = thread.Win32StartAddress;
    (void)QueryVadInfo(ctx, targetPid, group.ThreadStart, group.ThreadVad);
  }
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, group.CallerVad,
                               group.PrivateFrame, group.PrivateFrameVad,
                               group.RwxFrame, group.RwxFrameVad,
                               group.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, group.Stack);
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartThread(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord,
                        bool apc) {
  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  UINT64 start = 0;
  UINT32 flags = 0;
  if (apc) {
    if (ApiIs(eventRecord, "NtQueueApcThread")) {
      start = eventRecord.Context1;
    } else if (ApiIs(eventRecord, "NtQueueApcThreadEx")) {
      start =
          eventRecord.ArgCount > 2 ? eventRecord.Args[2] : eventRecord.Context1;
    } else {
      start =
          eventRecord.ArgCount > 3 ? eventRecord.Args[3] : eventRecord.Context1;
    }
  } else {
    start = eventRecord.Context1;
    flags = static_cast<UINT32>(eventRecord.Context2);
  }

  SmartTargetSummary &target = SmartTargetFor(ctx, targetPid);
  if (apc) {
    target.ApcCount += 1;
  } else {
    target.ThreadCount += 1;
  }

  SmartThreadGroup &group =
      SmartThreadGroupFor(ctx, targetPid, start, StackHash(eventRecord));
  group.Caller = eventRecord.Caller;
  CaptureSmartCallsiteEvidence(ctx, targetPid, eventRecord, group.CallerVad,
                               group.PrivateFrame, group.PrivateFrameVad,
                               group.RwxFrame, group.RwxFrameVad,
                               group.EvidenceCaptured);
  CaptureSmartStackSample(eventRecord, group.Stack);
  group.Count += 1;
  if (!apc && (flags & 0x1u) != 0) {
    group.SuspendedCount += 1;
  }
  if (QueryVadInfo(ctx, targetPid, start, group.Vad)) {
    group.PrivateStart = group.Vad.Type == MEM_PRIVATE;
  } else if (targetPid == ctx.ChildProcessId && start != 0) {
    group.PrivateStart = !AddressInChildModule(ctx, start);
  }

  MaybePrintThreadAlerts(ctx, group);
  MaybePrintTargetAlerts(ctx, target);
}

void CaptureSmartEvent(ServerContext &ctx,
                       const IXIPC_HOOK_EVENT &eventRecord) {
  if (!ctx.SmartMode || eventRecord.Kind != IxIpcHookEventNt) {
    return;
  }

  const bool handleAttempt =
      ApiIs(eventRecord, "NtOpenProcess") || ApiIs(eventRecord, "NtOpenThread");
  if (!NtStatusSucceeded(eventRecord.Status) && !handleAttempt) {
    return;
  }

  DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
  const bool remoteTarget = IsRemoteTarget(ctx, targetPid);

  if ((SmartAreaEnabled(ctx, kSmartAreaMemory) &&
       ApiIs(eventRecord, "NtAllocateVirtualMemory")) ||
      (SmartAreaEnabled(ctx, kSmartAreaMemory) &&
       ApiIs(eventRecord, "NtAllocateVirtualMemoryEx"))) {
    CaptureSmartAllocation(ctx, eventRecord, false);
  } else if (SmartAreaEnabled(ctx, kSmartAreaMaps) &&
             (ApiIs(eventRecord, "NtMapViewOfSection") ||
              ApiIs(eventRecord, "NtMapViewOfSectionEx"))) {
    CaptureSmartAllocation(ctx, eventRecord, true);
  } else if (SmartAreaEnabled(ctx, kSmartAreaProtect) &&
             ApiIs(eventRecord, "NtProtectVirtualMemory")) {
    CaptureSmartProtect(ctx, eventRecord);
  } else if ((SmartAreaEnabled(ctx, kSmartAreaQueries) || remoteTarget) &&
             ApiIs(eventRecord, "NtQueryVirtualMemory")) {
    CaptureSmartQuery(ctx, eventRecord);
  } else if ((SmartAreaEnabled(ctx, kSmartAreaReads) || remoteTarget) &&
             ApiIs(eventRecord, "NtReadVirtualMemory")) {
    CaptureSmartRead(ctx, eventRecord);
  } else if ((SmartAreaEnabled(ctx, kSmartAreaWrites) || remoteTarget) &&
             ApiIs(eventRecord, "NtWriteVirtualMemory")) {
    CaptureSmartWrite(ctx, eventRecord);
  } else if ((SmartAreaEnabled(ctx, kSmartAreaHandles) || remoteTarget) &&
             ApiIs(eventRecord, "NtOpenProcess")) {
    CaptureSmartOpenProcess(ctx, eventRecord);
  } else if ((SmartAreaEnabled(ctx, kSmartAreaHandles) || remoteTarget) &&
             ApiIs(eventRecord, "NtOpenThread")) {
    CaptureSmartOpenThread(ctx, eventRecord);
  } else if (SmartAreaEnabled(ctx, kSmartAreaThreads) &&
             (ApiIs(eventRecord, "NtCreateThread") ||
              ApiIs(eventRecord, "NtCreateThreadEx"))) {
    CaptureSmartThread(ctx, eventRecord, false);
  } else if (SmartAreaEnabled(ctx, kSmartAreaApc) &&
             (ApiIs(eventRecord, "NtQueueApcThread") ||
              ApiIs(eventRecord, "NtQueueApcThreadEx") ||
              ApiIs(eventRecord, "NtQueueApcThreadEx2"))) {
    CaptureSmartThread(ctx, eventRecord, true);
  }
}
} // namespace blind::injector
