#include "Telemetry/smart_state.h"
#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_cache.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/stack_address.h"

namespace blind::injector {
bool SmartRegionOverlaps(const SmartMemoryRegion &region, DWORD targetPid,
                         UINT64 base, UINT64 end) noexcept {
  if (region.TargetPid != targetPid) {
    return false;
  }
  UINT64 regionEnd = RangeEnd(region.Base, region.Size);
  return base == region.Base || (base >= region.Base && base < regionEnd) ||
         (region.Base >= base && region.Base < end);
}

void UpdateSmartRegionRange(ServerContext &ctx, std::size_t index, UINT64 base,
                            UINT64 size) {
  if (index >= ctx.SmartRegions.size() || size == 0) {
    return;
  }

  SmartMemoryRegion &region = ctx.SmartRegions[index];
  UINT64 oldBase = region.Base;
  UINT64 regionEnd = RangeEnd(region.Base, region.Size);
  UINT64 queryEnd = RangeEnd(base, size);
  UINT64 low = std::min(region.Base, base);
  UINT64 high = std::max(regionEnd, queryEnd);
  region.Base = low;
  region.Size = high > low ? high - low : size;
  if (oldBase != region.Base) {
    ctx.SmartRegionByBase.erase(AddressRangeKey{region.TargetPid, oldBase});
    ctx.SmartRegionByBase[AddressRangeKey{region.TargetPid, region.Base}] =
        index;
  }
}

SmartMemoryRegion &SmartRegionFor(ServerContext &ctx, DWORD targetPid,
                                  UINT64 base, UINT64 size) {
  DWORD normalized = targetPid == 0 ? ctx.ChildProcessId : targetPid;
  UINT64 queryEnd = RangeEnd(base, size);
  AddressRangeKey seek{normalized, base};

  auto exact = ctx.SmartRegionByBase.find(seek);
  if (exact != ctx.SmartRegionByBase.end() &&
      exact->second < ctx.SmartRegions.size()) {
    UpdateSmartRegionRange(ctx, exact->second, base, size);
    return ctx.SmartRegions[exact->second];
  }

  auto lower = ctx.SmartRegionByBase.lower_bound(seek);
  if (lower != ctx.SmartRegionByBase.end() &&
      lower->first.TargetPid == normalized &&
      lower->second < ctx.SmartRegions.size() &&
      SmartRegionOverlaps(ctx.SmartRegions[lower->second], normalized, base,
                          queryEnd)) {
    std::size_t index = lower->second;
    UpdateSmartRegionRange(ctx, index, base, size);
    return ctx.SmartRegions[index];
  }

  if (lower != ctx.SmartRegionByBase.begin()) {
    auto previous = lower;
    --previous;
    if (previous->first.TargetPid == normalized &&
        previous->second < ctx.SmartRegions.size() &&
        SmartRegionOverlaps(ctx.SmartRegions[previous->second], normalized,
                            base, queryEnd)) {
      std::size_t index = previous->second;
      UpdateSmartRegionRange(ctx, index, base, size);
      return ctx.SmartRegions[index];
    }
  }

  SmartMemoryRegion region{};
  region.TargetPid = normalized;
  region.Base = base;
  region.Size = size;
  ctx.SmartRegions.push_back(region);
  ctx.SmartRegionByBase[AddressRangeKey{normalized, region.Base}] =
      ctx.SmartRegions.size() - 1;
  return ctx.SmartRegions.back();
}

void CopyVadFromRegion(const SmartMemoryRegion &region,
                       SmartVadInfo &vad) noexcept {
  vad.Valid = region.State != 0 || region.Type != 0 || region.Protect != 0 ||
              region.AllocationProtect != 0;
  vad.BaseAddress = region.Base;
  vad.AllocationBase = 0;
  vad.RegionSize = region.Size;
  vad.Protect = region.Protect;
  vad.AllocationProtect = region.AllocationProtect;
  vad.State = region.State;
  vad.Type = region.Type;
}

SmartProtectGroup &SmartProtectGroupFor(ServerContext &ctx, DWORD targetPid,
                                        UINT64 caller, UINT64 stackHash,
                                        UINT64 base, UINT64 size,
                                        UINT32 oldProtect, UINT32 newProtect) {
  DWORD normalized = targetPid == 0 ? ctx.ChildProcessId : targetPid;
  SmartProtectKey key{normalized, caller,     stackHash,
                      size,       oldProtect, newProtect};
  auto found = ctx.SmartProtectGroupByKey.find(key);
  if (found != ctx.SmartProtectGroupByKey.end() &&
      found->second < ctx.SmartProtectGroups.size()) {
    return ctx.SmartProtectGroups[found->second];
  }

  SmartProtectGroup group{};
  group.TargetPid = normalized;
  group.Caller = caller;
  group.StackHash = stackHash;
  group.FirstBase = base;
  group.LastBase = base;
  group.MinBase = base;
  group.MaxBase = base;
  group.Size = size;
  group.OldProtect = oldProtect;
  group.NewProtect = newProtect;
  ctx.SmartProtectGroups.push_back(group);
  ctx.SmartProtectGroupByKey[key] = ctx.SmartProtectGroups.size() - 1;
  return ctx.SmartProtectGroups.back();
}

SmartThreadGroup &SmartThreadGroupFor(ServerContext &ctx, DWORD targetPid,
                                      UINT64 start, UINT64 stackHash) {
  DWORD normalized = targetPid == 0 ? ctx.ChildProcessId : targetPid;
  SmartThreadKey key{normalized, start, stackHash};
  auto found = ctx.SmartThreadGroupByKey.find(key);
  if (found != ctx.SmartThreadGroupByKey.end() &&
      found->second < ctx.SmartThreadGroups.size()) {
    return ctx.SmartThreadGroups[found->second];
  }

  SmartThreadGroup group{};
  group.TargetPid = normalized;
  group.Start = start;
  group.StackHash = stackHash;
  ctx.SmartThreadGroups.push_back(group);
  ctx.SmartThreadGroupByKey[key] = ctx.SmartThreadGroups.size() - 1;
  return ctx.SmartThreadGroups.back();
}

SmartHandleGroup &SmartHandleGroupFor(ServerContext &ctx, SmartHandleKind kind,
                                      DWORD targetPid, DWORD targetTid,
                                      UINT32 desiredAccess, UINT64 caller,
                                      UINT64 stackHash) {
  DWORD normalized = targetPid == 0 ? ctx.ChildProcessId : targetPid;
  SmartHandleKey key{normalized,    targetTid, kind,
                     desiredAccess, caller,    stackHash};
  auto found = ctx.SmartHandleGroupByKey.find(key);
  if (found != ctx.SmartHandleGroupByKey.end() &&
      found->second < ctx.SmartHandleGroups.size()) {
    return ctx.SmartHandleGroups[found->second];
  }

  SmartHandleGroup group{};
  group.Kind = kind;
  group.TargetPid = normalized;
  group.TargetTid = targetTid;
  group.DesiredAccess = desiredAccess;
  group.Caller = caller;
  group.StackHash = stackHash;
  ctx.SmartHandleGroups.push_back(group);
  ctx.SmartHandleGroupByKey[key] = ctx.SmartHandleGroups.size() - 1;
  return ctx.SmartHandleGroups.back();
}

void AppendProtectTransition(SmartMemoryRegion &region, UINT32 oldProtect,
                             UINT32 newProtect) noexcept {
  char oldText[32]{};
  char newText[32]{};
  FormatProtect(oldProtect, oldText, RTL_NUMBER_OF(oldText));
  FormatProtect(newProtect, newText, RTL_NUMBER_OF(newText));
  (void)StringCchCopyA(region.LastProtect, RTL_NUMBER_OF(region.LastProtect),
                       newText);

  if (region.ProtectSequence[0] == '\0') {
    (void)StringCchPrintfA(region.ProtectSequence,
                           RTL_NUMBER_OF(region.ProtectSequence), "%s->%s",
                           oldText, newText);
    return;
  }

  if (strlen(region.ProtectSequence) + strlen(newText) + 3 <
      RTL_NUMBER_OF(region.ProtectSequence)) {
    (void)StringCchCatA(region.ProtectSequence,
                        RTL_NUMBER_OF(region.ProtectSequence), "->");
    (void)StringCchCatA(region.ProtectSequence,
                        RTL_NUMBER_OF(region.ProtectSequence), newText);
  }
}

void UpdateRegionVad(ServerContext &ctx, SmartMemoryRegion &region) {
  SmartVadInfo vad{};
  if (QueryVadInfo(ctx, region.TargetPid, region.Base, vad)) {
    if (vad.State == MEM_FREE) {
      return;
    }
    region.State = vad.State;
    region.Type = vad.Type;
    region.AllocationProtect = vad.AllocationProtect;
    if (vad.Protect != 0) {
      region.Protect = vad.Protect;
      char protectText[32]{};
      FormatProtect(vad.Protect, protectText, RTL_NUMBER_OF(protectText));
      (void)StringCchCopyA(region.LastProtect,
                           RTL_NUMBER_OF(region.LastProtect), protectText);
    }
    if (vad.RegionSize != 0 &&
        (region.Size == 0 || vad.RegionSize > region.Size)) {
      region.Size = vad.RegionSize;
    }
  }
}

void PrintSmartConditionAlert(ServerContext &ctx, const char *kind,
                              DWORD targetPid, UINT64 address,
                              const char *detail) {
  char addressText[256]{};
  FormatSmartAddress(ctx, targetPid, address, addressText,
                     RTL_NUMBER_OF(addressText));
  std::string label = TargetLabel(ctx, ctx.ChildProcessId, targetPid);
  ColorPrintf(LogColor::Alert,
              "[blind:behavior] alert %s target=%s address=%s %s\n", kind,
              label.c_str(), addressText, detail != nullptr ? detail : "");
}

void MaybePrintRwxAlert(ServerContext &ctx, SmartMemoryRegion &region) {
  if (!ctx.Conditions.Rwx || region.AlertedRwx || !region.RwxSeen) {
    return;
  }
  char detail[128]{};
  char sizeText[32]{};
  char protectText[32]{};
  FormatBytes(region.Size, sizeText, RTL_NUMBER_OF(sizeText));
  FormatProtect(region.Protect, protectText, RTL_NUMBER_OF(protectText));
  (void)StringCchPrintfA(
      detail, RTL_NUMBER_OF(detail), "size=%s pages=%llu protect=%s", sizeText,
      static_cast<unsigned long long>(PageCount(region.Size)), protectText);
  PrintSmartConditionAlert(ctx, "rwx", region.TargetPid, region.Base, detail);
  region.AlertedRwx = true;
}

void MaybePrintProtectFlipAlert(ServerContext &ctx, SmartMemoryRegion &region) {
  if (ctx.Conditions.ProtectFlipsAtLeast == 0 || region.AlertedFlips ||
      region.FlipCount < ctx.Conditions.ProtectFlipsAtLeast) {
    return;
  }
  char detail[224]{};
  (void)StringCchPrintfA(detail, RTL_NUMBER_OF(detail), "flips=%lu sequence=%s",
                         static_cast<unsigned long>(region.FlipCount),
                         region.ProtectSequence);
  PrintSmartConditionAlert(ctx, "protect.flip", region.TargetPid, region.Base,
                           detail);
  region.AlertedFlips = true;
}
void MaybePrintTargetAlerts(ServerContext &ctx, SmartTargetSummary &target) {
  if (ctx.Conditions.Remote && target.TargetPid != ctx.ChildProcessId &&
      !target.AlertedRemote) {
    std::string label = TargetLabel(ctx, ctx.ChildProcessId, target.TargetPid);
    ColorPrintf(LogColor::Alert,
                "[blind:behavior] alert remote target=%s pid=%lu opens=%lu/%lu "
                "queries=%lu reads=%lu "
                "writes=%lu threads=%lu\n",
                label.c_str(), static_cast<unsigned long>(target.TargetPid),
                static_cast<unsigned long>(target.OpenProcessCount),
                static_cast<unsigned long>(target.OpenThreadCount),
                static_cast<unsigned long>(target.QueryCount),
                static_cast<unsigned long>(target.ReadCount),
                static_cast<unsigned long>(target.WriteCount),
                static_cast<unsigned long>(target.ThreadCount));
    target.AlertedRemote = true;
  }

  if (ctx.Conditions.AllocTotalGreater != 0 && !target.AlertedAllocTotal &&
      target.AllocBytes > ctx.Conditions.AllocTotalGreater) {
    char totalText[32]{};
    FormatBytes(target.AllocBytes, totalText, RTL_NUMBER_OF(totalText));
    std::string label = TargetLabel(ctx, ctx.ChildProcessId, target.TargetPid);
    ColorPrintf(
        LogColor::Alert,
        "[blind:behavior] alert alloc.total target=%s total=%s allocs=%lu\n",
        label.c_str(), totalText,
        static_cast<unsigned long>(target.AllocCount));
    target.AlertedAllocTotal = true;
  }
}

void MaybePrintThreadAlerts(ServerContext &ctx, SmartThreadGroup &group) {
  if (ctx.Conditions.ThreadCountAtLeast != 0 && !group.AlertedCount &&
      group.Count >= ctx.Conditions.ThreadCountAtLeast) {
    char startText[256]{};
    FormatSmartAddress(ctx, group.TargetPid, group.Start, startText,
                       RTL_NUMBER_OF(startText));
    std::string label = TargetLabel(ctx, ctx.ChildProcessId, group.TargetPid);
    ColorPrintf(LogColor::Alert,
                "[blind:behavior] alert thread.count target=%s count=%lu "
                "start=%s stack=0x%llX\n",
                label.c_str(), static_cast<unsigned long>(group.Count),
                startText, static_cast<unsigned long long>(group.StackHash));
    group.AlertedCount = true;
  }
  if (ctx.Conditions.StartPrivate && !group.AlertedPrivate &&
      group.PrivateStart) {
    char startText[256]{};
    FormatSmartAddress(ctx, group.TargetPid, group.Start, startText,
                       RTL_NUMBER_OF(startText));
    std::string label = TargetLabel(ctx, ctx.ChildProcessId, group.TargetPid);
    ColorPrintf(LogColor::Alert,
                "[blind:behavior] alert start.private target=%s start=%s "
                "stack=0x%llX\n",
                label.c_str(), startText,
                static_cast<unsigned long long>(group.StackHash));
    group.AlertedPrivate = true;
  }
}
DWORD TargetPidForEvent(const IXIPC_HOOK_EVENT &eventRecord,
                        DWORD childPid) noexcept {
  if (ApiIs(eventRecord, "NtAllocateVirtualMemory")) {
    return eventRecord.ArgCount > 6 ? static_cast<DWORD>(eventRecord.Args[6])
                                    : childPid;
  }
  if (ApiIs(eventRecord, "NtAllocateVirtualMemoryEx") ||
      ApiIs(eventRecord, "NtProtectVirtualMemory") ||
      ApiIs(eventRecord, "NtMapViewOfSection") ||
      ApiIs(eventRecord, "NtMapViewOfSectionEx")) {
    return eventRecord.ArgCount > 7 ? static_cast<DWORD>(eventRecord.Args[7])
                                    : childPid;
  }
  if (ApiIs(eventRecord, "NtWriteVirtualMemory")) {
    return eventRecord.Context2 != 0
               ? static_cast<DWORD>(eventRecord.Context2)
               : (eventRecord.ArgCount > 5
                      ? static_cast<DWORD>(eventRecord.Args[5])
                      : childPid);
  }
  if (ApiIs(eventRecord, "NtReadVirtualMemory")) {
    return eventRecord.Context2 != 0
               ? static_cast<DWORD>(eventRecord.Context2)
               : (eventRecord.ArgCount > 7
                      ? static_cast<DWORD>(eventRecord.Args[7])
                      : childPid);
  }
  if (ApiIs(eventRecord, "NtQueryVirtualMemory")) {
    return eventRecord.Context2 != 0
               ? static_cast<DWORD>(eventRecord.Context2)
               : (eventRecord.ArgCount > 7
                      ? static_cast<DWORD>(eventRecord.Args[7])
                      : childPid);
  }
  if (ApiIs(eventRecord, "NtOpenProcess")) {
    return eventRecord.ArgCount > 2 && eventRecord.Args[2] != 0
               ? static_cast<DWORD>(eventRecord.Args[2])
               : childPid;
  }
  if (ApiIs(eventRecord, "NtOpenThread")) {
    return eventRecord.ArgCount > 2 && eventRecord.Args[2] != 0
               ? static_cast<DWORD>(eventRecord.Args[2])
               : childPid;
  }
  if (ApiIs(eventRecord, "NtCreateThread") ||
      ApiIs(eventRecord, "NtCreateThreadEx")) {
    return eventRecord.ArgCount > 6 ? static_cast<DWORD>(eventRecord.Args[6])
                                    : childPid;
  }
  if (ApiIs(eventRecord, "NtQueueApcThread")) {
    return eventRecord.ArgCount > 6 ? static_cast<DWORD>(eventRecord.Args[6])
                                    : childPid;
  }
  if (ApiIs(eventRecord, "NtQueueApcThreadEx") ||
      ApiIs(eventRecord, "NtQueueApcThreadEx2")) {
    return eventRecord.ArgCount > 7 ? static_cast<DWORD>(eventRecord.Args[7])
                                    : childPid;
  }
  if (ApiIs(eventRecord, "NtUnmapViewOfSection") ||
      ApiIs(eventRecord, "NtUnmapViewOfSectionEx")) {
    return eventRecord.ArgCount > 2 ? static_cast<DWORD>(eventRecord.Args[2])
                                    : childPid;
  }
  return childPid;
}

} // namespace blind::injector
