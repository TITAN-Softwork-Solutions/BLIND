#include "Telemetry/smart_summary.h"
#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/stack_address.h"

namespace blind::injector {
void PrintSmartSummary(ServerContext &ctx, bool finalSummary) {
  if (!ctx.SmartMode) {
    return;
  }

  ColorPrintf(LogColor::Smart,
              "[blind:behavior] %s targets=%zu regions=%zu protect_groups=%zu "
              "thread_starts=%zu handles=%zu\n",
              finalSummary ? "final" : "update", ctx.SmartTargets.size(),
              ctx.SmartRegions.size(), ctx.SmartProtectGroups.size(),
              ctx.SmartThreadGroups.size(), ctx.SmartHandleGroups.size());

  for (const auto &target : ctx.SmartTargets) {
    std::string label = TargetLabel(ctx, ctx.ChildProcessId, target.TargetPid);
    UINT32 regionCount = 0;
    for (const auto &region : ctx.SmartRegions) {
      if (region.TargetPid == target.TargetPid) {
        regionCount += 1;
      }
    }

    char allocText[32]{};
    char mapText[32]{};
    char queryText[32]{};
    char readText[32]{};
    char writeText[32]{};
    char rwxText[32]{};
    FormatBytes(target.AllocBytes, allocText, RTL_NUMBER_OF(allocText));
    FormatBytes(target.MapBytes, mapText, RTL_NUMBER_OF(mapText));
    FormatBytes(target.QueryInfoBytes, queryText, RTL_NUMBER_OF(queryText));
    FormatBytes(target.ReadBytes, readText, RTL_NUMBER_OF(readText));
    FormatBytes(target.WriteBytes, writeText, RTL_NUMBER_OF(writeText));
    FormatBytes(target.RwxBytes, rwxText, RTL_NUMBER_OF(rwxText));
    ColorPrintf(SmartTargetColor(ctx, target),
                "[blind:behavior] memory target=%s allocs=%lu total=%s "
                "pages=%llu maps=%lu mapped=%s "
                "regions=%lu protects=%lu queries=%lu query_info=%s reads=%lu "
                "read=%s writes=%lu "
                "written=%s opens=%lu/%lu rwx=%s threads=%lu apc=%lu risk=%s\n",
                label.c_str(), static_cast<unsigned long>(target.AllocCount),
                allocText,
                static_cast<unsigned long long>(PageCount(target.AllocBytes)),
                static_cast<unsigned long>(target.MapCount), mapText,
                static_cast<unsigned long>(regionCount),
                static_cast<unsigned long>(target.ProtectCount),
                static_cast<unsigned long>(target.QueryCount), queryText,
                static_cast<unsigned long>(target.ReadCount), readText,
                static_cast<unsigned long>(target.WriteCount), writeText,
                static_cast<unsigned long>(target.OpenProcessCount),
                static_cast<unsigned long>(target.OpenThreadCount), rwxText,
                static_cast<unsigned long>(target.ThreadCount),
                static_cast<unsigned long>(target.ApcCount),
                SmartTargetRisk(ctx, target));

    std::vector<const SmartHandleGroup *> handleGroups;
    for (const auto &group : ctx.SmartHandleGroups) {
      if (group.TargetPid == target.TargetPid) {
        handleGroups.push_back(&group);
      }
    }
    std::sort(handleGroups.begin(), handleGroups.end(),
              [](const SmartHandleGroup *left, const SmartHandleGroup *right) {
                if (left->Count != right->Count) {
                  return left->Count > right->Count;
                }
                return left->DesiredAccess > right->DesiredAccess;
              });

    UINT32 printedHandles = 0;
    for (const auto *group : handleGroups) {
      if (printedHandles >= 8) {
        break;
      }

      char accessText[320]{};
      char callerText[256]{};
      char startText[256]{};
      char startRegionText[64]{};
      char evidenceText[640]{};
      if (group->Kind == SmartHandleKind::Process) {
        FormatProcessAccess(group->DesiredAccess, accessText,
                            RTL_NUMBER_OF(accessText));
        (void)StringCchCopyA(startText, RTL_NUMBER_OF(startText), "-");
        (void)StringCchCopyA(startRegionText, RTL_NUMBER_OF(startRegionText),
                             "-");
      } else {
        FormatThreadAccess(group->DesiredAccess, accessText,
                           RTL_NUMBER_OF(accessText));
        if (group->ThreadStart != 0) {
          FormatSmartAddress(ctx, group->TargetPid, group->ThreadStart,
                             startText, RTL_NUMBER_OF(startText));
          FormatVadRegion(group->ThreadVad, startRegionText,
                          RTL_NUMBER_OF(startRegionText));
        } else {
          (void)StringCchCopyA(startText, RTL_NUMBER_OF(startText), "unknown");
          (void)StringCchCopyA(startRegionText, RTL_NUMBER_OF(startRegionText),
                               "unknown");
        }
      }
      if (ctx.ResolveSymbols) {
        FormatChildSymbolAddress(ctx, group->Caller, callerText,
                                 RTL_NUMBER_OF(callerText));
      } else {
        FormatChildAddress(ctx, group->Caller, callerText,
                           RTL_NUMBER_OF(callerText));
      }
      FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, group->CallerVad,
                                group->PrivateFrame, group->PrivateFrameVad,
                                group->RwxFrame, group->RwxFrameVad,
                                evidenceText, RTL_NUMBER_OF(evidenceText));
      ColorPrintf(SmartHandleColor(ctx, *group),
                  "[blind:behavior] handle kind=%s target=%s count=%lu "
                  "failed=%lu status=0x%08lX tid=%lu "
                  "access=%s handle=0x%llX object=0x%llX start=%s "
                  "start_region=%s caller=%s "
                  "stack=0x%llX risk=%s%s\n",
                  group->Kind == SmartHandleKind::Process ? "process"
                                                          : "thread",
                  label.c_str(), static_cast<unsigned long>(group->Count),
                  static_cast<unsigned long>(group->FailedCount),
                  static_cast<unsigned long>(group->LastStatus),
                  static_cast<unsigned long>(group->TargetTid), accessText,
                  static_cast<unsigned long long>(group->LastHandle),
                  static_cast<unsigned long long>(group->LastObject), startText,
                  startRegionText, callerText,
                  static_cast<unsigned long long>(group->StackHash),
                  SmartHandleRisk(*group), evidenceText);
      PrintSmartStackSample(
          ctx, "handle",
          group->Kind == SmartHandleKind::Process ? "pid" : "tid",
          group->Kind == SmartHandleKind::Process ? group->TargetPid
                                                  : group->TargetTid,
          group->TargetPid, group->StackHash, group->Stack);
      printedHandles += 1;
    }

    std::vector<const SmartProtectGroup *> protectGroups;
    for (const auto &group : ctx.SmartProtectGroups) {
      if (group.TargetPid == target.TargetPid) {
        protectGroups.push_back(&group);
      }
    }
    std::sort(
        protectGroups.begin(), protectGroups.end(),
        [](const SmartProtectGroup *left, const SmartProtectGroup *right) {
          if (left->Count != right->Count) {
            return left->Count > right->Count;
          }
          return left->FirstBase < right->FirstBase;
        });

    UINT32 printedProtectGroups = 0;
    for (const auto *group : protectGroups) {
      if (printedProtectGroups >= 12) {
        break;
      }

      char oldText[32]{};
      char newText[32]{};
      char sizeText[32]{};
      char firstText[256]{};
      char lastText[256]{};
      char callerText[256]{};
      char evidenceText[640]{};
      FormatProtect(group->OldProtect, oldText, RTL_NUMBER_OF(oldText));
      FormatProtect(group->NewProtect, newText, RTL_NUMBER_OF(newText));
      FormatBytes(group->Size, sizeText, RTL_NUMBER_OF(sizeText));
      FormatSmartAddress(ctx, group->TargetPid, group->FirstBase, firstText,
                         RTL_NUMBER_OF(firstText));
      FormatSmartAddress(ctx, group->TargetPid, group->LastBase, lastText,
                         RTL_NUMBER_OF(lastText));
      if (ctx.ResolveSymbols) {
        FormatChildSymbolAddress(ctx, group->Caller, callerText,
                                 RTL_NUMBER_OF(callerText));
      } else {
        FormatChildAddress(ctx, group->Caller, callerText,
                           RTL_NUMBER_OF(callerText));
      }
      FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, group->CallerVad,
                                group->PrivateFrame, group->PrivateFrameVad,
                                group->RwxFrame, group->RwxFrameVad,
                                evidenceText, RTL_NUMBER_OF(evidenceText));
      ColorPrintf(
          SmartProtectColor(*group),
          "[blind:behavior] protect target=%s count=%lu pages=%llu size=%s "
          "%s->%s "
          "first=%s last=%s span=0x%llX-0x%llX vad=%s/%s caller=%s "
          "stack=0x%llX rwx=%lu risk=%s%s\n",
          label.c_str(), static_cast<unsigned long>(group->Count),
          static_cast<unsigned long long>(group->Pages), sizeText, oldText,
          newText, firstText, lastText,
          static_cast<unsigned long long>(group->MinBase),
          static_cast<unsigned long long>(group->MaxBase),
          group->Vad.Valid ? MemoryStateName(group->Vad.State) : "unknown",
          group->Vad.Valid ? MemoryTypeName(group->Vad.Type) : "unknown",
          callerText, static_cast<unsigned long long>(group->StackHash),
          static_cast<unsigned long>(group->RwxCount), SmartProtectRisk(*group),
          evidenceText);
      PrintSmartStackSample(ctx, "protect", "first", group->FirstBase,
                            group->TargetPid, group->StackHash, group->Stack);
      printedProtectGroups += 1;
    }

    std::vector<const SmartMemoryRegion *> regions;
    for (const auto &region : ctx.SmartRegions) {
      if (region.TargetPid == target.TargetPid) {
        regions.push_back(&region);
      }
    }
    std::sort(
        regions.begin(), regions.end(),
        [](const SmartMemoryRegion *left, const SmartMemoryRegion *right) {
          UINT64 leftActivity = static_cast<UINT64>(left->AllocCount) +
                                left->MapCount + left->ProtectCount +
                                left->QueryCount + left->ReadCount +
                                left->WriteCount;
          UINT64 rightActivity = static_cast<UINT64>(right->AllocCount) +
                                 right->MapCount + right->ProtectCount +
                                 right->QueryCount + right->ReadCount +
                                 right->WriteCount;
          if (leftActivity != rightActivity) {
            return leftActivity > rightActivity;
          }
          if (left->Size != right->Size) {
            return left->Size > right->Size;
          }
          return left->Base < right->Base;
        });

    UINT32 printedRegions = 0;
    for (const auto *region : regions) {
      if (printedRegions >= 12) {
        break;
      }

      char sizeText[32]{};
      char protectText[32]{};
      char allocProtectText[32]{};
      char allocTypeText[64]{};
      char callerText[256]{};
      char regionReadText[32]{};
      char writtenText[32]{};
      char evidenceText[640]{};
      FormatBytes(region->Size, sizeText, RTL_NUMBER_OF(sizeText));
      FormatProtect(region->Protect, protectText, RTL_NUMBER_OF(protectText));
      FormatProtect(region->AllocationProtect, allocProtectText,
                    RTL_NUMBER_OF(allocProtectText));
      FormatAllocationType(region->AllocationType, allocTypeText,
                           RTL_NUMBER_OF(allocTypeText));
      if (ctx.ResolveSymbols) {
        FormatChildSymbolAddress(ctx, region->Caller, callerText,
                                 RTL_NUMBER_OF(callerText));
      } else {
        FormatChildAddress(ctx, region->Caller, callerText,
                           RTL_NUMBER_OF(callerText));
      }
      FormatBytes(region->TotalRead, regionReadText,
                  RTL_NUMBER_OF(regionReadText));
      FormatBytes(region->TotalWritten, writtenText,
                  RTL_NUMBER_OF(writtenText));
      FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, region->CallerVad,
                                region->PrivateFrame, region->PrivateFrameVad,
                                region->RwxFrame, region->RwxFrameVad,
                                evidenceText, RTL_NUMBER_OF(evidenceText));
      ColorPrintf(
          SmartRegionColor(ctx, *region),
          "[blind:behavior] region target=%s base=0x%llX size=%s pages=%llu "
          "protect=%s "
          "vad=%s/%s alloc_protect=%s alloc_type=%s allocs=%lu maps=%lu "
          "protects=%lu flips=%lu "
          "queries=%lu last_query=%s(%lu) reads=%lu read=%s writes=%lu "
          "written=%s "
          "caller=%s stack=0x%llX risk=%s seq=%s%s\n",
          label.c_str(), static_cast<unsigned long long>(region->Base),
          sizeText, static_cast<unsigned long long>(PageCount(region->Size)),
          protectText, MemoryStateName(region->State),
          MemoryTypeName(region->Type), allocProtectText, allocTypeText,
          static_cast<unsigned long>(region->AllocCount),
          static_cast<unsigned long>(region->MapCount),
          static_cast<unsigned long>(region->ProtectCount),
          static_cast<unsigned long>(region->FlipCount),
          static_cast<unsigned long>(region->QueryCount),
          MemoryInformationClassName(region->LastQueryClass),
          static_cast<unsigned long>(region->LastQueryClass),
          static_cast<unsigned long>(region->ReadCount), regionReadText,
          static_cast<unsigned long>(region->WriteCount), writtenText,
          callerText, static_cast<unsigned long long>(region->StackHash),
          SmartRegionRisk(*region),
          region->ProtectSequence[0] != '\0' ? region->ProtectSequence : "-",
          evidenceText);
      PrintSmartStackSample(ctx, "region", "base", region->Base,
                            region->TargetPid, region->StackHash,
                            region->Stack);
      printedRegions += 1;
    }
  }

  UINT32 printedThreads = 0;
  for (const auto &group : ctx.SmartThreadGroups) {
    if (printedThreads >= 12) {
      break;
    }
    std::string label = TargetLabel(ctx, ctx.ChildProcessId, group.TargetPid);
    char startText[256]{};
    char callerText[256]{};
    char protectText[32]{};
    char startRegionText[64]{};
    char evidenceText[640]{};
    FormatSmartAddress(ctx, group.TargetPid, group.Start, startText,
                       RTL_NUMBER_OF(startText));
    if (ctx.ResolveSymbols) {
      FormatChildSymbolAddress(ctx, group.Caller, callerText,
                               RTL_NUMBER_OF(callerText));
    } else {
      FormatChildAddress(ctx, group.Caller, callerText,
                         RTL_NUMBER_OF(callerText));
    }
    FormatProtect(group.Vad.Protect, protectText, RTL_NUMBER_OF(protectText));
    FormatVadRegion(group.Vad, startRegionText, RTL_NUMBER_OF(startRegionText));
    FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, group.CallerVad,
                              group.PrivateFrame, group.PrivateFrameVad,
                              group.RwxFrame, group.RwxFrameVad, evidenceText,
                              RTL_NUMBER_OF(evidenceText));
    ColorPrintf(
        SmartThreadColor(group),
        "[blind:behavior] thread target=%s count=%lu suspended=%lu start=%s "
        "private=%u "
        "vad=%s/%s/%s start_region=%s caller=%s stack=0x%llX risk=%s%s\n",
        label.c_str(), static_cast<unsigned long>(group.Count),
        static_cast<unsigned long>(group.SuspendedCount), startText,
        group.PrivateStart ? 1u : 0u,
        group.Vad.Valid ? MemoryStateName(group.Vad.State) : "unknown",
        group.Vad.Valid ? MemoryTypeName(group.Vad.Type) : "unknown",
        protectText, startRegionText, callerText,
        static_cast<unsigned long long>(group.StackHash),
        SmartThreadRisk(group), evidenceText);
    PrintSmartStackSample(ctx, "thread", "start", group.Start, group.TargetPid,
                          group.StackHash, group.Stack);
    printedThreads += 1;
  }
}
void MaybePrintSmartSummary(ServerContext &ctx) {
  if (!ctx.SmartMode || ctx.SmartSummaryIntervalMs == 0) {
    return;
  }
  DWORD now = GetTickCount();
  if (ctx.LastSmartSummaryTick == 0 ||
      now - ctx.LastSmartSummaryTick >= ctx.SmartSummaryIntervalMs) {
    PrintSmartSummary(ctx, false);
    ctx.LastSmartSummaryTick = now;
  }
}
} // namespace blind::injector
