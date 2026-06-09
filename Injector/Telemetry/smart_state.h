#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
bool SmartRegionOverlaps(const SmartMemoryRegion &region, DWORD targetPid,
                         UINT64 base, UINT64 end) noexcept;
void UpdateSmartRegionRange(ServerContext &ctx, std::size_t index, UINT64 base,
                            UINT64 size);
SmartMemoryRegion &SmartRegionFor(ServerContext &ctx, DWORD targetPid,
                                  UINT64 base, UINT64 size);
void CopyVadFromRegion(const SmartMemoryRegion &region,
                       SmartVadInfo &vad) noexcept;
SmartTargetSummary &SmartTargetFor(ServerContext &ctx, DWORD targetPid);
SmartProtectGroup &SmartProtectGroupFor(ServerContext &ctx, DWORD targetPid,
                                        UINT64 caller, UINT64 stackHash,
                                        UINT64 base, UINT64 size,
                                        UINT32 oldProtect, UINT32 newProtect);
SmartThreadGroup &SmartThreadGroupFor(ServerContext &ctx, DWORD targetPid,
                                      UINT64 start, UINT64 stackHash);
SmartHandleGroup &SmartHandleGroupFor(ServerContext &ctx, SmartHandleKind kind,
                                      DWORD targetPid, DWORD targetTid,
                                      UINT32 desiredAccess, UINT64 caller,
                                      UINT64 stackHash);
void AppendProtectTransition(SmartMemoryRegion &region, UINT32 oldProtect,
                             UINT32 newProtect) noexcept;
void UpdateRegionVad(ServerContext &ctx, SmartMemoryRegion &region);
} // namespace blind::injector
