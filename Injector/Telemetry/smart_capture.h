#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void PrintSmartConditionAlert(ServerContext &ctx, LogColor color,
                              const char *category, const char *message,
                              DWORD targetPid, UINT64 address,
                              const SmartVadInfo *vad);
void MaybePrintRwxAlert(ServerContext &ctx, SmartMemoryRegion &region);
void MaybePrintProtectFlipAlert(ServerContext &ctx, SmartMemoryRegion &region);
void MaybePrintTargetAlerts(ServerContext &ctx, SmartTargetSummary &target);
void MaybePrintThreadAlerts(ServerContext &ctx, SmartThreadGroup &group);
DWORD TargetPidForEvent(const IXIPC_HOOK_EVENT &eventRecord,
                        DWORD childPid) noexcept;
void InvalidateVadCacheForEvent(ServerContext &ctx,
                                const IXIPC_HOOK_EVENT &eventRecord) noexcept;
void CaptureSmartAllocation(ServerContext &ctx,
                            const IXIPC_HOOK_EVENT &eventRecord, bool mapped);
void CaptureSmartProtect(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord);
void CaptureSmartWrite(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
void CaptureSmartRead(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
void CaptureSmartQuery(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
void CaptureSmartOpenProcess(ServerContext &ctx,
                             const IXIPC_HOOK_EVENT &eventRecord);
void CaptureSmartOpenThread(ServerContext &ctx,
                            const IXIPC_HOOK_EVENT &eventRecord);
void CaptureSmartThread(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord,
                        bool apc);
void CaptureSmartEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
} // namespace blind::injector
