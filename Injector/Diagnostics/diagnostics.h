#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void HostDebugLog(ServerContext &ctx, const char *format, ...);
std::wstring BuildRunDirectory(const std::wstring &baseDir);
void WriteJsonEscaped(FILE *file, const char *value) noexcept;
const char *SelfMapKindName(UINT32 kind) noexcept;
bool OpenDiagnostics(ServerContext &ctx, const std::wstring &baseDir);
void CloseDiagnostics(ServerContext &ctx) noexcept;
void WriteSummary(ServerContext &ctx, DWORD exitCode, DWORD childWait);
void WriteRawEvent(ServerContext &ctx,
                   const IXIPC_HOOK_EVENT &eventRecord) noexcept;
void CaptureSelfMapEvent(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord);
} // namespace blind::injector
