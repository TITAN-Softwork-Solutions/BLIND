#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
bool FrameRoleIsDetectionOrigin(const char *role) noexcept;
bool StackHasDetectionOrigin(ServerContext &ctx,
                             const IXIPC_HOOK_EVENT &eventRecord);
bool ImmediateFrameHasDetectionOrigin(ServerContext &ctx,
                                      const IXIPC_HOOK_EVENT &eventRecord);
void FormatChildFrameAddress(ServerContext &ctx, UINT64 address, char *out,
                             std::size_t outChars);
void FormatSmartFrameAddress(ServerContext &ctx, DWORD targetPid,
                             UINT64 address, char *out, std::size_t outChars);
bool AddressInChildModule(ServerContext &ctx, UINT64 address);
const char *FrameRoleForVad(const SmartVadInfo &vad) noexcept;
const char *FrameRoleForChildAddress(ServerContext &ctx, UINT64 address);
bool IsPrivateVad(const SmartVadInfo &vad) noexcept;
bool IsRwxVad(const SmartVadInfo &vad) noexcept;
bool IsExecutablePrivateVad(const SmartVadInfo &vad) noexcept;
void FormatVadRegion(const SmartVadInfo &vad, char *out,
                     std::size_t outChars) noexcept;
void FormatVadSuffix(ServerContext &ctx, DWORD targetPid, UINT64 address,
                     char *out, std::size_t outChars) noexcept;
void CaptureSmartCallsiteEvidence(ServerContext &ctx, DWORD targetPid,
                                  const IXIPC_HOOK_EVENT &eventRecord,
                                  SmartVadInfo &callerVad, UINT64 &privateFrame,
                                  SmartVadInfo &privateFrameVad,
                                  UINT64 &rwxFrame, SmartVadInfo &rwxFrameVad,
                                  bool &captured);
void CaptureSmartStackSample(const IXIPC_HOOK_EVENT &eventRecord,
                             SmartStackSample &sample) noexcept;
void FormatSmartEvidenceSuffix(ServerContext &ctx, DWORD targetPid,
                               const SmartVadInfo &callerVad,
                               UINT64 privateFrame,
                               const SmartVadInfo &privateFrameVad,
                               UINT64 rwxFrame, const SmartVadInfo &rwxFrameVad,
                               char *out, std::size_t outChars);
bool HasSuspiciousCallsite(const SmartVadInfo &callerVad, UINT64 privateFrame,
                           const SmartVadInfo &privateFrameVad, UINT64 rwxFrame,
                           const SmartVadInfo &rwxFrameVad) noexcept;
void FormatSmartAddress(ServerContext &ctx, DWORD targetPid, UINT64 address,
                        char *out, std::size_t outChars);
} // namespace blind::injector
