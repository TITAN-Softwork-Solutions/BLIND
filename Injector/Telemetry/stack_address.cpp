#include "Telemetry/stack_address.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_cache.h"
#include "Telemetry/process_symbols.h"

namespace blind::injector {
bool FrameRoleIsDetectionOrigin(const char *role) noexcept {
  return role != nullptr &&
         (_stricmp(role, "[app]") == 0 || _stricmp(role, "[module]") == 0 ||
          _stricmp(role, "[private]") == 0 || _stricmp(role, "[image]") == 0);
}

bool StackHasDetectionOrigin(ServerContext &ctx,
                             const IXIPC_HOOK_EVENT &eventRecord) {
  UINT32 count = eventRecord.StackCount < IXIPC_MAX_HOOK_STACK_FRAMES
                     ? eventRecord.StackCount
                     : IXIPC_MAX_HOOK_STACK_FRAMES;
  for (UINT32 i = 0; i < count; ++i) {
    if (FrameRoleIsDetectionOrigin(
            FrameRoleForChildAddress(ctx, eventRecord.Stack[i]))) {
      return true;
    }
  }
  return FrameRoleIsDetectionOrigin(
             FrameRoleForChildAddress(ctx, eventRecord.Caller)) ||
         FrameRoleIsDetectionOrigin(
             FrameRoleForChildAddress(ctx, eventRecord.Context3));
}

bool ImmediateFrameHasDetectionOrigin(ServerContext &ctx,
                                      const IXIPC_HOOK_EVENT &eventRecord) {
  return FrameRoleIsDetectionOrigin(
             FrameRoleForChildAddress(ctx, eventRecord.Caller)) ||
         FrameRoleIsDetectionOrigin(
             FrameRoleForChildAddress(ctx, eventRecord.Context3));
}

void FormatChildFrameAddress(ServerContext &ctx, UINT64 address, char *out,
                             std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  char addressText[320]{};
  if (ctx.ResolveSymbols) {
    FormatChildSymbolAddress(ctx, address, addressText,
                             RTL_NUMBER_OF(addressText));
  } else {
    FormatChildAddress(ctx, address, addressText, RTL_NUMBER_OF(addressText));
  }

  (void)StringCchPrintfA(out, outChars, "%-10s %s",
                         FrameRoleForChildAddress(ctx, address), addressText);
}

void FormatSmartFrameAddress(ServerContext &ctx, DWORD targetPid,
                             UINT64 address, char *out, std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  DWORD normalizedPid = targetPid == 0 ? ctx.ChildProcessId : targetPid;
  if (normalizedPid == ctx.ChildProcessId) {
    FormatChildFrameAddress(ctx, address, out, outChars);
    return;
  }

  SmartVadInfo vad{};
  const char *role = QueryVadInfo(ctx, normalizedPid, address, vad)
                         ? FrameRoleForVad(vad)
                         : "[remote]";
  (void)StringCchPrintfA(out, outChars, "%-10s 0x%llX", role,
                         static_cast<unsigned long long>(address));
}

bool AddressInChildModule(ServerContext &ctx, UINT64 address) {
  return FindChildModule(ctx, address) != nullptr;
}

void FormatSmartAddress(ServerContext &ctx, DWORD targetPid, UINT64 address,
                        char *out, std::size_t outChars);

bool IsPrivateVad(const SmartVadInfo &vad) noexcept {
  return vad.Valid && vad.Type == MEM_PRIVATE;
}

bool IsRwxVad(const SmartVadInfo &vad) noexcept {
  return vad.Valid && IsWriteExecuteProtect(vad.Protect);
}

bool IsExecutablePrivateVad(const SmartVadInfo &vad) noexcept {
  return IsPrivateVad(vad) && IsExecutableProtect(vad.Protect);
}

void FormatVadRegion(const SmartVadInfo &vad, char *out,
                     std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  if (!vad.Valid) {
    (void)StringCchCopyA(out, outChars, "unknown");
    return;
  }

  char protectText[32]{};
  FormatProtect(vad.Protect, protectText, RTL_NUMBER_OF(protectText));
  (void)StringCchPrintfA(out, outChars, "%s/%s", MemoryTypeName(vad.Type),
                         protectText);
}

void FormatVadSuffix(ServerContext &ctx, DWORD targetPid, UINT64 address,
                     char *out, std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  if (address == 0) {
    return;
  }

  SmartVadInfo vad{};
  if (!QueryVadInfo(ctx, targetPid, address, vad)) {
    (void)StringCchCopyA(out, outChars, " vad=unknown");
    return;
  }

  char regionText[64]{};
  char sizeText[32]{};
  FormatVadRegion(vad, regionText, RTL_NUMBER_OF(regionText));
  FormatBytes(vad.RegionSize, sizeText, RTL_NUMBER_OF(sizeText));
  (void)StringCchPrintfA(
      out, outChars, " vad=%s region=0x%llX-0x%llX region_size=%s", regionText,
      static_cast<unsigned long long>(vad.BaseAddress),
      static_cast<unsigned long long>(vad.BaseAddress + vad.RegionSize),
      sizeText);
}
void CaptureSmartCallsiteEvidence(ServerContext &ctx, DWORD targetPid,
                                  const IXIPC_HOOK_EVENT &eventRecord,
                                  SmartVadInfo &callerVad, UINT64 &privateFrame,
                                  SmartVadInfo &privateFrameVad,
                                  UINT64 &rwxFrame, SmartVadInfo &rwxFrameVad,
                                  bool &captured) {
  if (captured) {
    return;
  }
  captured = true;

  (void)targetPid;
  DWORD sourcePid =
      eventRecord.ProcessId != 0 ? eventRecord.ProcessId : ctx.ChildProcessId;
  SmartVadInfo localCallerVad{};
  if (QueryVadInfo(ctx, sourcePid, eventRecord.Caller, localCallerVad)) {
    callerVad = localCallerVad;
  }

  UINT32 count = eventRecord.StackCount < IXIPC_MAX_HOOK_STACK_FRAMES
                     ? eventRecord.StackCount
                     : IXIPC_MAX_HOOK_STACK_FRAMES;
  for (UINT32 i = 0; i < count; ++i) {
    UINT64 frame = eventRecord.Stack[i];
    if (frame == 0) {
      continue;
    }

    SmartVadInfo vad{};
    bool hasVad = QueryVadInfo(ctx, sourcePid, frame, vad);
    if (hasVad && IsRwxVad(vad) &&
        (rwxFrame == 0 || (!IsPrivateVad(rwxFrameVad) && IsPrivateVad(vad)))) {
      rwxFrame = frame;
      rwxFrameVad = vad;
    }
    if (hasVad && privateFrame == 0 && IsPrivateVad(vad)) {
      privateFrame = frame;
      privateFrameVad = vad;
    } else if (!hasVad && privateFrame == 0 &&
               sourcePid == ctx.ChildProcessId &&
               !AddressInChildModule(ctx, frame)) {
      privateFrame = frame;
      privateFrameVad = SmartVadInfo{};
    }

    if (rwxFrame != 0 && privateFrame != 0) {
      break;
    }
  }
}

void CaptureSmartStackSample(const IXIPC_HOOK_EVENT &eventRecord,
                             SmartStackSample &sample) noexcept {
  if (sample.Count != 0 || eventRecord.StackCount == 0) {
    return;
  }

  UINT32 count = eventRecord.StackCount < IXIPC_MAX_HOOK_STACK_FRAMES
                     ? eventRecord.StackCount
                     : IXIPC_MAX_HOOK_STACK_FRAMES;
  sample.ProcessId = eventRecord.ProcessId;
  sample.Count = count;
  for (UINT32 i = 0; i < count; ++i) {
    sample.Frames[i] = eventRecord.Stack[i];
  }
}

void FormatSmartEvidenceSuffix(ServerContext &ctx, DWORD targetPid,
                               const SmartVadInfo &callerVad,
                               UINT64 privateFrame,
                               const SmartVadInfo &privateFrameVad,
                               UINT64 rwxFrame, const SmartVadInfo &rwxFrameVad,
                               char *out, std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  char callerRegion[64]{};
  FormatVadRegion(callerVad, callerRegion, RTL_NUMBER_OF(callerRegion));
  (void)StringCchPrintfA(out, outChars, " caller_region=%s", callerRegion);

  bool preferPrivate =
      privateFrame != 0 && IsExecutablePrivateVad(privateFrameVad);
  UINT64 frame =
      preferPrivate ? privateFrame : (rwxFrame != 0 ? rwxFrame : privateFrame);
  const SmartVadInfo &frameVad =
      preferPrivate ? privateFrameVad
                    : (rwxFrame != 0 ? rwxFrameVad : privateFrameVad);
  if (frame == 0) {
    return;
  }

  char frameText[256]{};
  char frameRegion[64]{};
  FormatSmartAddress(ctx, targetPid, frame, frameText,
                     RTL_NUMBER_OF(frameText));
  FormatVadRegion(frameVad, frameRegion, RTL_NUMBER_OF(frameRegion));
  const char *kind = preferPrivate
                         ? " stack_private="
                         : (rwxFrame != 0 ? " stack_rwx=" : " stack_private=");
  (void)StringCchCatA(out, outChars, kind);
  (void)StringCchCatA(out, outChars, frameText);
  (void)StringCchCatA(out, outChars, " stack_region=");
  (void)StringCchCatA(out, outChars, frameRegion);

  if (privateFrame != 0 && privateFrame != frame) {
    char privateText[256]{};
    char privateRegion[64]{};
    FormatSmartAddress(ctx, targetPid, privateFrame, privateText,
                       RTL_NUMBER_OF(privateText));
    FormatVadRegion(privateFrameVad, privateRegion,
                    RTL_NUMBER_OF(privateRegion));
    (void)StringCchCatA(out, outChars, " stack_private=");
    (void)StringCchCatA(out, outChars, privateText);
    (void)StringCchCatA(out, outChars, " private_region=");
    (void)StringCchCatA(out, outChars, privateRegion);
  }
}

bool HasSuspiciousCallsite(const SmartVadInfo &callerVad, UINT64 privateFrame,
                           const SmartVadInfo &privateFrameVad, UINT64 rwxFrame,
                           const SmartVadInfo &rwxFrameVad) noexcept {
  return IsExecutablePrivateVad(callerVad) || IsRwxVad(callerVad) ||
         (privateFrame != 0 && (IsExecutablePrivateVad(privateFrameVad) ||
                                !privateFrameVad.Valid)) ||
         (rwxFrame != 0 && IsRwxVad(rwxFrameVad));
}

void FormatSmartAddress(ServerContext &ctx, DWORD targetPid, UINT64 address,
                        char *out, std::size_t outChars) {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  if (targetPid == 0 || targetPid == ctx.ChildProcessId) {
    if (ctx.ResolveSymbols) {
      FormatChildSymbolAddress(ctx, address, out, outChars);
    } else {
      FormatChildAddress(ctx, address, out, outChars);
    }
    return;
  }
  (void)StringCchPrintfA(out, outChars, "0x%llX",
                         static_cast<unsigned long long>(address));
}

SmartTargetSummary &SmartTargetFor(ServerContext &ctx, DWORD targetPid) {
  DWORD normalized = targetPid == 0 ? ctx.ChildProcessId : targetPid;
  auto found = ctx.SmartTargetByPid.find(normalized);
  if (found != ctx.SmartTargetByPid.end() &&
      found->second < ctx.SmartTargets.size()) {
    return ctx.SmartTargets[found->second];
  }

  SmartTargetSummary target{};
  target.TargetPid = normalized;
  ctx.SmartTargets.push_back(target);
  ctx.SmartTargetByPid[normalized] = ctx.SmartTargets.size() - 1;
  return ctx.SmartTargets.back();
}

} // namespace blind::injector
