#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/smart_summary.h"
#include "Telemetry/stack_address.h"

namespace blind::injector {
LogColor SmartTargetColor(const ServerContext &ctx,
                          const SmartTargetSummary &target) noexcept {
  bool remoteActivity =
      IsRemoteTarget(ctx, target.TargetPid) &&
      (target.OpenProcessCount != 0 || target.OpenThreadCount != 0 ||
       target.QueryCount != 0 || target.ReadCount != 0 ||
       target.WriteCount != 0 || target.ThreadCount != 0 ||
       target.ApcCount != 0);
  if (remoteActivity) {
    return target.RwxBytes != 0 || target.ReadCount != 0 ||
                   target.WriteCount != 0 || target.ThreadCount != 0 ||
                   target.ApcCount != 0 || target.OpenProcessCount != 0 ||
                   target.OpenThreadCount != 0
               ? LogColor::RemoteRisk
               : LogColor::Remote;
  }
  return target.RwxBytes != 0 ? LogColor::Suspicious : LogColor::Smart;
}

const char *SmartTargetRisk(const ServerContext &ctx,
                            const SmartTargetSummary &target) noexcept {
  if (target.RwxBytes != 0) {
    return "rwx";
  }
  if (IsRemoteTarget(ctx, target.TargetPid)) {
    if (target.ReadCount != 0 || target.WriteCount != 0 ||
        target.OpenProcessCount != 0 || target.OpenThreadCount != 0) {
      return "remote_io";
    }
    if (target.QueryCount != 0) {
      return "remote_query";
    }
  }
  return "-";
}

LogColor SmartProtectColor(const SmartProtectGroup &group) noexcept {
  if (IsWriteExecuteProtect(group.OldProtect) ||
      IsWriteExecuteProtect(group.NewProtect) ||
      HasSuspiciousCallsite(group.CallerVad, group.PrivateFrame,
                            group.PrivateFrameVad, group.RwxFrame,
                            group.RwxFrameVad)) {
    return LogColor::Suspicious;
  }
  return LogColor::Smart;
}

LogColor SmartRegionColor(const ServerContext &ctx,
                          const SmartMemoryRegion &region) noexcept {
  bool risky =
      region.RwxSeen || IsWriteExecuteProtect(region.Protect) ||
      (region.Type == MEM_PRIVATE && IsExecutableProtect(region.Protect)) ||
      HasSuspiciousCallsite(region.CallerVad, region.PrivateFrame,
                            region.PrivateFrameVad, region.RwxFrame,
                            region.RwxFrameVad);
  if (IsRemoteTarget(ctx, region.TargetPid)) {
    return risky || region.ReadCount != 0 || region.WriteCount != 0
               ? LogColor::RemoteRisk
               : LogColor::Remote;
  }
  if (risky) {
    return LogColor::Suspicious;
  }
  return LogColor::Smart;
}

LogColor SmartThreadColor(const SmartThreadGroup &group) noexcept {
  if (group.PrivateStart || IsExecutablePrivateVad(group.Vad) ||
      HasSuspiciousCallsite(group.CallerVad, group.PrivateFrame,
                            group.PrivateFrameVad, group.RwxFrame,
                            group.RwxFrameVad)) {
    return LogColor::Suspicious;
  }
  return LogColor::Smart;
}

LogColor SmartHandleColor(const ServerContext &ctx,
                          const SmartHandleGroup &group) noexcept {
  bool risky = false;
  if (group.Kind == SmartHandleKind::Process &&
      (group.DesiredAccess &
       (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_TERMINATE)) != 0) {
    risky = true;
  }
  if (group.Kind == SmartHandleKind::Thread &&
      (group.DesiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                              THREAD_TERMINATE | THREAD_GET_CONTEXT)) != 0) {
    risky = true;
  }
  if (HasSuspiciousCallsite(group.CallerVad, group.PrivateFrame,
                            group.PrivateFrameVad, group.RwxFrame,
                            group.RwxFrameVad)) {
    risky = true;
  }
  if (IsRemoteTarget(ctx, group.TargetPid)) {
    return risky || group.FailedCount != 0 ? LogColor::RemoteRisk
                                           : LogColor::Remote;
  }
  if (risky) {
    return LogColor::Suspicious;
  }
  if (group.FailedCount != 0) {
    return LogColor::Warning;
  }
  return LogColor::Smart;
}

const char *SmartRegionRisk(const SmartMemoryRegion &region) noexcept {
  if (region.Type == MEM_PRIVATE &&
      (IsWriteExecuteProtect(region.Protect) || region.RwxSeen)) {
    return "private_rwx";
  }
  if (region.Type == MEM_PRIVATE && IsExecutableProtect(region.Protect)) {
    return "private_exec";
  }
  if (HasSuspiciousCallsite(region.CallerVad, region.PrivateFrame,
                            region.PrivateFrameVad, region.RwxFrame,
                            region.RwxFrameVad)) {
    return IsRwxVad(region.CallerVad) || IsRwxVad(region.RwxFrameVad)
               ? "rwx_stack"
               : "private_stack";
  }
  if (region.FlipCount != 0) {
    return "protect_flips";
  }
  return "-";
}

const char *SmartProtectRisk(const SmartProtectGroup &group) noexcept {
  if (IsWriteExecuteProtect(group.OldProtect) ||
      IsWriteExecuteProtect(group.NewProtect)) {
    return "rwx_transition";
  }
  if (HasSuspiciousCallsite(group.CallerVad, group.PrivateFrame,
                            group.PrivateFrameVad, group.RwxFrame,
                            group.RwxFrameVad)) {
    return "private_stack";
  }
  return "-";
}

const char *SmartHandleRisk(const SmartHandleGroup &group) noexcept {
  if (group.Kind == SmartHandleKind::Process &&
      (group.DesiredAccess & (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                              PROCESS_VM_WRITE)) != 0) {
    return "remote_process_control";
  }
  if (group.Kind == SmartHandleKind::Process &&
      (group.DesiredAccess & PROCESS_VM_READ) != 0) {
    return "remote_process_read";
  }
  if (group.Kind == SmartHandleKind::Thread &&
      (group.DesiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                              THREAD_GET_CONTEXT)) != 0) {
    return "remote_thread_control";
  }
  if (HasSuspiciousCallsite(group.CallerVad, group.PrivateFrame,
                            group.PrivateFrameVad, group.RwxFrame,
                            group.RwxFrameVad)) {
    return "private_stack";
  }
  if (group.FailedCount != 0) {
    return "access_denied";
  }
  return "-";
}

const char *SmartThreadRisk(const SmartThreadGroup &group) noexcept {
  if (group.PrivateStart && IsExecutableProtect(group.Vad.Protect)) {
    return "private_start";
  }
  if (HasSuspiciousCallsite(group.CallerVad, group.PrivateFrame,
                            group.PrivateFrameVad, group.RwxFrame,
                            group.RwxFrameVad)) {
    return "private_stack";
  }
  return "-";
}
void PrintSmartStackSample(ServerContext &ctx, const char *subject,
                           const char *keyName, UINT64 keyValue,
                           DWORD targetPid, UINT64 stackHash,
                           const SmartStackSample &sample) {
  if (!ctx.SmartStacks || sample.Count == 0) {
    return;
  }

  UINT32 limit = ctx.SmartStackFrameLimit;
  if (limit == 0 || limit > IXIPC_MAX_HOOK_STACK_FRAMES) {
    limit = IXIPC_MAX_HOOK_STACK_FRAMES;
  }
  DWORD stackPid =
      sample.ProcessId != 0 ? sample.ProcessId : ctx.ChildProcessId;
  UINT32 firstNonBlind = 0;
  if (stackPid == ctx.ChildProcessId) {
    while (firstNonBlind < sample.Count) {
      const ChildModuleEntry *module =
          FindChildModule(ctx, sample.Frames[firstNonBlind]);
      if (module == nullptr || _stricmp(module->Name, "BLIND.dll") != 0) {
        break;
      }
      ++firstNonBlind;
    }
  }

  UINT32 available = sample.Count;
  UINT32 count = available < limit ? available : limit;
  ColorPrintf(LogColor::Muted,
              "[blind:behavior:stack] %s %s=0x%llX target=%s stack=0x%llX "
              "frames=%lu/%lu first_non_blind=%lu\n",
              subject, keyName, static_cast<unsigned long long>(keyValue),
              TargetLabel(ctx, ctx.ChildProcessId, targetPid).c_str(),
              static_cast<unsigned long long>(stackHash),
              static_cast<unsigned long>(count),
              static_cast<unsigned long>(sample.Count),
              static_cast<unsigned long>(firstNonBlind));

  for (UINT32 i = 0; i < count; ++i) {
    char frame[384]{};
    FormatSmartFrameAddress(ctx, stackPid, sample.Frames[i], frame,
                            RTL_NUMBER_OF(frame));
    ColorPrintf(LogColor::Stack, "    #%02lu %s\n",
                static_cast<unsigned long>(i), frame);
  }
  if (available > count) {
    ColorPrintf(LogColor::Muted, "    ... %lu frame(s) truncated\n",
                static_cast<unsigned long>(available - count));
  }
}
} // namespace blind::injector
