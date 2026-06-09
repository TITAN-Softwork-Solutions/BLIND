#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
LogColor SmartTargetColor(const ServerContext &ctx,
                          const SmartTargetSummary &target) noexcept;
LogColor SmartProtectColor(const SmartProtectGroup &group) noexcept;
LogColor SmartRegionColor(const ServerContext &ctx,
                          const SmartMemoryRegion &region) noexcept;
LogColor SmartThreadColor(const SmartThreadGroup &group) noexcept;
LogColor SmartHandleColor(const ServerContext &ctx,
                          const SmartHandleGroup &group) noexcept;
const char *SmartTargetRisk(const ServerContext &ctx,
                            const SmartTargetSummary &target) noexcept;
const char *SmartRegionRisk(const SmartMemoryRegion &region) noexcept;
const char *SmartProtectRisk(const SmartProtectGroup &group) noexcept;
const char *SmartHandleRisk(const SmartHandleGroup &group) noexcept;
const char *SmartThreadRisk(const SmartThreadGroup &group) noexcept;
void PrintSmartStackSample(ServerContext &ctx, const char *kind,
                           const char *label, UINT64 address, DWORD targetPid,
                           UINT64 stackHash, const SmartStackSample &sample);
void PrintSmartSummary(ServerContext &ctx, bool finalSummary);
void MaybePrintSmartSummary(ServerContext &ctx);
} // namespace blind::injector
