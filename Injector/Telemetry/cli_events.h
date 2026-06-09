#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
const IXIPC_HOOK_POLICY_RULE *
FindCliRule(const ServerContext &ctx,
            const IXIPC_HOOK_EVENT &eventRecord) noexcept;
DWORD CliReadyMaskForPolicy(const ServerContext &ctx) noexcept;
bool RuleApiIs(const IXIPC_HOOK_POLICY_RULE &rule,
               const char *apiName) noexcept;
const char *HookActionName(UINT32 action) noexcept;
bool CliEventsEquivalentForRepeat(const IXIPC_HOOK_EVENT &left,
                                  const IXIPC_HOOK_EVENT &right) noexcept;
bool ShouldPrintRepeatMilestone(UINT32 repeat) noexcept;
bool ApplyCliRepeatAnnotation(ServerContext &ctx,
                              IXIPC_HOOK_EVENT &eventRecord) noexcept;
bool SameDirectSyscallFold(const CliDetectionFoldState &fold,
                           const IXIPC_HOOK_EVENT &eventRecord) noexcept;
bool ShouldPrintFoldedDirectSyscallDetection(
    ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
bool ShouldPrintCliEvent(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord);
bool IsCliDetectionEvent(const IXIPC_HOOK_EVENT &eventRecord) noexcept;
bool IsSmartManagedEvent(const ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord) noexcept;
bool ShouldSuppressRawForSmart(const ServerContext &ctx,
                               const IXIPC_HOOK_EVENT &eventRecord) noexcept;
void PrintCliStack(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
void PrintCliStackAlways(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord, UINT32 limit);
void FormatHexSample(const IXIPC_HOOK_EVENT &eventRecord, char *out,
                     std::size_t outChars, UINT32 maxBytes) noexcept;
void PrintCliDetectionEvent(ServerContext &ctx,
                            const IXIPC_HOOK_EVENT &eventRecord);
void PrintCliDetectionFoldSummary(ServerContext &ctx);
void PrintCliRegisters(const ServerContext &ctx,
                       const IXIPC_HOOK_EVENT &eventRecord);
void PrintCliNtEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
void PrintCliGenericEvent(ServerContext &ctx,
                          const IXIPC_HOOK_EVENT &eventRecord);
} // namespace blind::injector
