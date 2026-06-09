#include "Telemetry/cli_events.h"
#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_cache.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/smart_capture.h"
#include "Telemetry/stack_address.h"

namespace blind::injector {
void PrintCliStack(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) {
  const IXIPC_HOOK_POLICY_RULE *rule = FindCliRule(ctx, eventRecord);
  if (rule == nullptr ||
      (rule->Flags & IXIPC_HOOK_RULE_FLAG_STACK_TRACE) == 0) {
    return;
  }

  UINT32 count = eventRecord.StackCount < IXIPC_MAX_HOOK_STACK_FRAMES
                     ? eventRecord.StackCount
                     : IXIPC_MAX_HOOK_STACK_FRAMES;
  for (UINT32 i = 0; i < count; ++i) {
    char frame[384]{};
    FormatChildFrameAddress(ctx, eventRecord.Stack[i], frame,
                            RTL_NUMBER_OF(frame));
    ColorPrintf(LogColor::Stack, "    #%02lu %s\n",
                static_cast<unsigned long>(i), frame);
  }
}

void PrintCliStackAlways(ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord, UINT32 limit) {
  UINT32 count = eventRecord.StackCount < IXIPC_MAX_HOOK_STACK_FRAMES
                     ? eventRecord.StackCount
                     : IXIPC_MAX_HOOK_STACK_FRAMES;
  if (limit != 0 && count > limit) {
    count = limit;
  }
  for (UINT32 i = 0; i < count; ++i) {
    char frame[384]{};
    FormatChildFrameAddress(ctx, eventRecord.Stack[i], frame,
                            RTL_NUMBER_OF(frame));
    ColorPrintf(LogColor::Stack, "    #%02lu %s\n",
                static_cast<unsigned long>(i), frame);
  }
}

void PrintWrappedWords(LogColor color, const char *firstPrefix,
                       const char *continuationPrefix, const char *text,
                       std::size_t maxColumns = 160) noexcept {
  if (text == nullptr || text[0] == '\0') {
    return;
  }

  const char *prefix = firstPrefix != nullptr ? firstPrefix : "";
  const char *continuation =
      continuationPrefix != nullptr ? continuationPrefix : prefix;
  std::size_t column = std::strlen(prefix);
  ColorPrintf(color, "%s", prefix);

  const char *cursor = text;
  bool wroteWord = false;
  while (*cursor != '\0') {
    while (*cursor == ' ' || *cursor == '\t') {
      ++cursor;
    }
    if (*cursor == '\0') {
      break;
    }

    const char *word = cursor;
    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') {
      ++cursor;
    }
    const std::size_t wordLength = static_cast<std::size_t>(cursor - word);
    const std::size_t separator = wroteWord ? 1u : 0u;
    if (wroteWord && column + separator + wordLength > maxColumns) {
      ColorPrintf(color, "\n%s", continuation);
      column = std::strlen(continuation);
      wroteWord = false;
    } else if (wroteWord) {
      ColorPrintf(color, " ");
      ++column;
    }

    ColorPrintf(color, "%.*s", static_cast<int>(wordLength), word);
    column += wordLength;
    wroteWord = true;
  }

  ColorPrintf(color, "\n");
}

bool CliContextRequested(const ServerContext &ctx,
                         const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  const IXIPC_HOOK_POLICY_RULE *rule = FindCliRule(ctx, eventRecord);
  if (rule == nullptr) {
    return false;
  }
  return (rule->Flags & (IXIPC_HOOK_RULE_FLAG_REGISTERS |
                         IXIPC_HOOK_RULE_FLAG_STACK_TRACE)) != 0;
}

const char *AccessKindName(UINT64 accessKind) noexcept {
  switch (accessKind) {
  case 0:
    return "read";
  case 1:
    return "write";
  case 8:
    return "execute";
  default:
    return "access";
  }
}

void FormatHexSample(const IXIPC_HOOK_EVENT &eventRecord, char *out,
                     std::size_t outChars, UINT32 maxBytes = 48) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  UINT32 count = eventRecord.DataSize < IXIPC_MAX_HOOK_DATA_SAMPLE
                     ? eventRecord.DataSize
                     : IXIPC_MAX_HOOK_DATA_SAMPLE;
  if (count > maxBytes) {
    count = maxBytes;
  }

  char *cursor = out;
  std::size_t remaining = outChars;
  for (UINT32 i = 0; i < count && remaining > 3; ++i) {
    HRESULT hr = StringCchPrintfExA(
        cursor, remaining, &cursor, &remaining, 0, "%02X",
        static_cast<unsigned int>(eventRecord.DataSample[i]));
    if (FAILED(hr)) {
      break;
    }
  }
  if (eventRecord.DataSize > count && remaining > 4) {
    (void)StringCchCatA(out, outChars, "...");
  }
}

void PrintCliDetectionEvent(ServerContext &ctx,
                            const IXIPC_HOOK_EVENT &eventRecord) {
  char caller[256]{};
  FormatChildAddress(ctx, eventRecord.Caller, caller, RTL_NUMBER_OF(caller));

  if (eventRecord.Operation == IX_HOOK_EVENT_OP_HOOK_INTEGRITY) {
    ColorPrintf(LogColor::Suspicious,
                "[blind:detection] own-hook-patched mask=0x%llX winsock=%llu "
                "nt=%llu ki=%llu module=%llu "
                "check=%llu\n",
                static_cast<unsigned long long>(eventRecord.Context0),
                static_cast<unsigned long long>(eventRecord.Context1),
                static_cast<unsigned long long>(eventRecord.Context2),
                static_cast<unsigned long long>(eventRecord.Context3),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0));
    return;
  }

  if (eventRecord.Operation == IX_HOOK_EVENT_OP_AMSI_PATCH ||
      eventRecord.Operation == IX_HOOK_EVENT_OP_ETW_PATCH) {
    char sample[128]{};
    FormatHexSample(eventRecord, sample, RTL_NUMBER_OF(sample), 16);
    ColorPrintf(LogColor::Suspicious,
                "[blind:detection] patched-security-export api=%s module=%s "
                "tampered=%llu suspicious=%llu "
                "expected_mismatch=%llu sample=%s\n",
                eventRecord.ApiName[0] ? eventRecord.ApiName : "export",
                eventRecord.ModuleName[0] ? eventRecord.ModuleName : "unknown",
                static_cast<unsigned long long>(eventRecord.Context0),
                static_cast<unsigned long long>(eventRecord.Context1),
                static_cast<unsigned long long>(eventRecord.Context2),
                sample[0] ? sample : "-");
    return;
  }

  if (eventRecord.Operation == IX_HOOK_EVENT_OP_NTDLL_DOUBLE_LOAD) {
    char path[IXIPC_MAX_HOOK_DATA_SAMPLE + 1]{};
    CopyEventSampleString(eventRecord, path, RTL_NUMBER_OF(path));
    ColorPrintf(LogColor::Suspicious,
                "[blind:detection] ntdll-double-load module=0x%llX eat=0x%llX "
                "guard=0x%llX size=0x%llX "
                "caller=%s path=%s\n",
                static_cast<unsigned long long>(eventRecord.Context0),
                static_cast<unsigned long long>(eventRecord.Context1),
                static_cast<unsigned long long>(eventRecord.Context2),
                static_cast<unsigned long long>(eventRecord.Context3), caller,
                path[0] ? path : "-");
    PrintCliStackAlways(ctx, eventRecord, ctx.SmartStackFrameLimit);
    return;
  }

  if (eventRecord.Operation == IX_HOOK_EVENT_OP_NTDLL_EAT_ACCESS) {
    char rip[256]{};
    FormatChildAddress(ctx, eventRecord.Context3, rip, RTL_NUMBER_OF(rip));
    const char *which = (eventRecord.ArgCount > 0 && eventRecord.Args[0] == 2)
                            ? "double-loaded"
                            : "original";
    UINT64 access = eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0;
    ColorPrintf(LogColor::Suspicious,
                "[blind:detection] resolving-system-service-call-numbers "
                "ntdll=%s access=%s fault=0x%llX "
                "eat=0x%llX guard=0x%llX size=0x%llX rip=%s hits=%llu\n",
                which, AccessKindName(access),
                static_cast<unsigned long long>(eventRecord.Context2),
                static_cast<unsigned long long>(eventRecord.Context1),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0),
                rip,
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 4 ? eventRecord.Args[4] : 0));
    PrintCliStackAlways(ctx, eventRecord, ctx.SmartStackFrameLimit);
    return;
  }

  if (eventRecord.Operation == IX_HOOK_EVENT_OP_DIRECT_SYSCALL_PAGE ||
      eventRecord.Operation == IX_HOOK_EVENT_OP_DIRECT_SYSCALL_ACCESS ||
      eventRecord.Operation == IX_HOOK_EVENT_OP_PIC_DIRECT_SYSCALL) {
    char stub[256]{};
    char rip[256]{};
    char sample[160]{};
    FormatChildAddress(ctx, eventRecord.Context2, stub, RTL_NUMBER_OF(stub));
    FormatChildAddress(ctx, eventRecord.Context3, rip, RTL_NUMBER_OF(rip));
    FormatHexSample(eventRecord, sample, RTL_NUMBER_OF(sample));
    bool accessEvent =
        eventRecord.Operation == IX_HOOK_EVENT_OP_DIRECT_SYSCALL_ACCESS;
    UINT64 access =
        accessEvent && eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0;
    ColorPrintf(LogColor::Suspicious,
                "[blind:detection] %s source=%s page=0x%llX size=0x%llX "
                "stub=%s ssn=0x%llX %s%s%s "
                "caller=%s sample=%s\n",
                accessEvent ? "direct-syscall-access" : "direct-syscall",
                eventRecord.ModuleName[0] ? eventRecord.ModuleName : "memory",
                static_cast<unsigned long long>(eventRecord.Context0),
                static_cast<unsigned long long>(eventRecord.Context1), stub,
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0),
                accessEvent ? "access=" : "",
                accessEvent ? AccessKindName(access) : "",
                accessEvent ? " " : "", caller, sample[0] ? sample : "-");
    PrintCliStackAlways(ctx, eventRecord, ctx.SmartStackFrameLimit);
    return;
  }

  ColorPrintf(LogColor::Suspicious,
              "[blind:detection] integrity op=%lu api=%s module=%s caller=%s "
              "c0=0x%llX c1=0x%llX\n",
              static_cast<unsigned long>(eventRecord.Operation),
              eventRecord.ApiName[0] ? eventRecord.ApiName : "-",
              eventRecord.ModuleName[0] ? eventRecord.ModuleName : "-", caller,
              static_cast<unsigned long long>(eventRecord.Context0),
              static_cast<unsigned long long>(eventRecord.Context1));
}

void PrintCliDetectionFoldSummary(ServerContext &ctx) {
  for (const auto &fold : ctx.CliDetectionFolds) {
    if (fold.Operation != IX_HOOK_EVENT_OP_DIRECT_SYSCALL_PAGE ||
        fold.Count <= 1) {
      continue;
    }

    char caller[256]{};
    FormatChildAddress(ctx, fold.Caller, caller, RTL_NUMBER_OF(caller));
    ColorPrintf(
        LogColor::Smart,
        "[blind:behavior] direct-syscall folded source=%s count=%lu ssn=0x%llX "
        "stub_offset=0x%llX first_page=0x%llX last_page=0x%llX caller=%s\n",
        fold.ModuleName[0] ? fold.ModuleName : "memory",
        static_cast<unsigned long>(fold.Count),
        static_cast<unsigned long long>(fold.SyscallNumber),
        static_cast<unsigned long long>(fold.StubOffset),
        static_cast<unsigned long long>(fold.FirstPage),
        static_cast<unsigned long long>(fold.LastPage), caller);
  }
}

void PrintCliRegisters(const ServerContext &ctx,
                       const IXIPC_HOOK_EVENT &eventRecord) {
  const IXIPC_HOOK_POLICY_RULE *rule = FindCliRule(ctx, eventRecord);
  if (rule == nullptr || (rule->Flags & IXIPC_HOOK_RULE_FLAG_REGISTERS) == 0 ||
      eventRecord.DataSize == 0) {
    return;
  }

  char registers[IXIPC_MAX_HOOK_DATA_SAMPLE + 1]{};
  CopyEventSampleString(eventRecord, registers, RTL_NUMBER_OF(registers));
  if (registers[0] != '\0') {
    PrintWrappedWords(LogColor::Muted, "    regs ", "         ", registers);
  }
}

void PrintCliContext(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) {
  const UINT32 repeat = DecodeRepeatCount(eventRecord.CallerFlags);
  if (repeat > 1) {
    if (CliContextRequested(ctx, eventRecord)) {
      ColorPrintf(LogColor::Muted,
                  "    repeat x%lu: same callsite folded; registers and stack "
                  "omitted\n",
                  static_cast<unsigned long>(repeat));
    }
    return;
  }

  PrintCliRegisters(ctx, eventRecord);
  PrintCliStack(ctx, eventRecord);
}

void PrintCliNtEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) {
  char caller[256]{};
  FormatChildAddress(ctx, eventRecord.Caller, caller, RTL_NUMBER_OF(caller));
  UINT32 repeat = DecodeRepeatCount(eventRecord.CallerFlags);
  char repeatText[32]{};
  if (repeat > 1) {
    (void)StringCchPrintfA(repeatText, RTL_NUMBER_OF(repeatText), " x%lu",
                           static_cast<unsigned long>(repeat));
  }

  const char *apiName =
      eventRecord.ApiName[0] != '\0' ? eventRecord.ApiName : "NtCall";
  const char *action = HookActionName(eventRecord.Action);
  LogColor lineColor = eventRecord.Action == IXIPC_HOOK_ACTION_NONE
                           ? LogColor::Info
                           : LogColor::Warning;
  if (_stricmp(apiName, "NtOpenProcess") == 0) {
    char target[256]{};
    char access[320]{};
    DWORD targetPid =
        static_cast<DWORD>(eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0);
    DWORD targetTid =
        static_cast<DWORD>(eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0);
    UINT32 desiredAccess =
        static_cast<UINT32>(eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0);
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatProcessAccess(desiredAccess, access, RTL_NUMBER_OF(access));
    if ((desiredAccess &
         (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
          PROCESS_DUP_HANDLE | PROCESS_TERMINATE)) != 0) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(lineColor,
                "[blind] %s%s %s status=0x%08lX target=%s access=%s "
                "handle=0x%llX caller=%s\n",
                apiName, repeatText, action,
                static_cast<unsigned long>(eventRecord.Status), target, access,
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 5 ? eventRecord.Args[5] : 0),
                caller);
    ColorPrintf(LogColor::Muted, "    client_tid=%lu object=0x%llX\n",
                static_cast<unsigned long>(targetTid),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 4 ? eventRecord.Args[4] : 0));
  } else if (_stricmp(apiName, "NtOpenThread") == 0) {
    char target[256]{};
    char owner[256]{};
    char access[320]{};
    char start[256]{};
    char vadSuffix[256]{};
    DWORD targetPid =
        static_cast<DWORD>(eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0);
    DWORD targetTid =
        static_cast<DWORD>(eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0);
    UINT32 desiredAccess =
        static_cast<UINT32>(eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0);
    const ThreadInfoEntry &thread = ResolveThreadInfo(ctx, targetTid);
    if (targetPid == 0 && thread.HasOwnerProcess) {
      targetPid = thread.OwnerProcessId;
    }
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatThreadAccess(desiredAccess, access, RTL_NUMBER_OF(access));
    if (thread.HasOwnerProcess) {
      FormatTargetProcess(ctx, ctx.ChildProcessId, thread.OwnerProcessId, owner,
                          RTL_NUMBER_OF(owner));
    } else {
      (void)StringCchCopyA(owner, RTL_NUMBER_OF(owner), "unknown");
    }
    if (thread.HasWin32StartAddress) {
      FormatSmartAddress(ctx, targetPid, thread.Win32StartAddress, start,
                         RTL_NUMBER_OF(start));
      FormatVadSuffix(ctx, targetPid, thread.Win32StartAddress, vadSuffix,
                      RTL_NUMBER_OF(vadSuffix));
    } else {
      (void)StringCchCopyA(start, RTL_NUMBER_OF(start), "unknown");
    }
    if ((desiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                          THREAD_TERMINATE | THREAD_GET_CONTEXT)) != 0) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(lineColor,
                "[blind] %s%s %s status=0x%08lX tid=%lu owner=%s access=%s "
                "handle=0x%llX caller=%s\n",
                apiName, repeatText, action,
                static_cast<unsigned long>(eventRecord.Status),
                static_cast<unsigned long>(targetTid), owner, access,
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 5 ? eventRecord.Args[5] : 0),
                caller);
    ColorPrintf(LogColor::Muted, "    target=%s win32_start=%s%s\n", target,
                start, vadSuffix);
  } else if (_stricmp(apiName, "NtAllocateVirtualMemory") == 0 ||
             _stricmp(apiName, "NtAllocateVirtualMemoryEx") == 0) {
    char protectText[32]{};
    char allocText[64]{};
    char target[256]{};
    char vadSuffix[256]{};
    DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
    UINT32 protect = static_cast<UINT32>(eventRecord.Context3);
    FormatProtect(protect, protectText, RTL_NUMBER_OF(protectText));
    FormatAllocationType(static_cast<UINT32>(eventRecord.Context2), allocText,
                         RTL_NUMBER_OF(allocText));
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatVadSuffix(ctx, targetPid, eventRecord.Context0, vadSuffix,
                    RTL_NUMBER_OF(vadSuffix));
    if (IsWriteExecuteProtect(protect)) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(
        lineColor,
        "[blind] %s%s %s status=0x%08lX target=%s addr=0x%llX size=0x%llX "
        "pages=%llu "
        "alloc=%s protect=%s%s caller=%s\n",
        apiName, repeatText, action,
        static_cast<unsigned long>(eventRecord.Status), target,
        static_cast<unsigned long long>(eventRecord.Context0),
        static_cast<unsigned long long>(eventRecord.Context1),
        static_cast<unsigned long long>(PageCount(eventRecord.Context1)),
        allocText, protectText, vadSuffix, caller);
  } else if (_stricmp(apiName, "NtProtectVirtualMemory") == 0) {
    char oldText[32]{};
    char newText[32]{};
    char target[256]{};
    char vadSuffix[256]{};
    DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
    UINT32 oldProtect = static_cast<UINT32>(eventRecord.Context3);
    UINT32 newProtect = static_cast<UINT32>(eventRecord.Context2);
    FormatProtect(oldProtect, oldText, RTL_NUMBER_OF(oldText));
    FormatProtect(newProtect, newText, RTL_NUMBER_OF(newText));
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatVadSuffix(ctx, targetPid, eventRecord.Context0, vadSuffix,
                    RTL_NUMBER_OF(vadSuffix));
    if (IsWriteExecuteProtect(oldProtect) ||
        IsWriteExecuteProtect(newProtect)) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(
        lineColor,
        "[blind] %s%s %s status=0x%08lX target=%s base=0x%llX size=0x%llX "
        "pages=%llu "
        "old=%s new=%s%s caller=%s\n",
        apiName, repeatText, action,
        static_cast<unsigned long>(eventRecord.Status), target,
        static_cast<unsigned long long>(eventRecord.Context0),
        static_cast<unsigned long long>(eventRecord.Context1),
        static_cast<unsigned long long>(PageCount(eventRecord.Context1)),
        oldText, newText, vadSuffix, caller);
  } else if (_stricmp(apiName, "NtReadVirtualMemory") == 0 ||
             _stricmp(apiName, "NtWriteVirtualMemory") == 0) {
    char target[256]{};
    char vadSuffix[256]{};
    char sizeText[32]{};
    char bytesText[32]{};
    DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatVadSuffix(ctx, targetPid, eventRecord.Context0, vadSuffix,
                    RTL_NUMBER_OF(vadSuffix));
    FormatBytes(eventRecord.Context1, sizeText, RTL_NUMBER_OF(sizeText));
    FormatBytes(eventRecord.Context3, bytesText, RTL_NUMBER_OF(bytesText));
    if (targetPid != 0 && targetPid != ctx.ChildProcessId) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(lineColor,
                "[blind] %s%s %s status=0x%08lX target=%s base=0x%llX size=%s "
                "local_buffer=0x%llX "
                "bytes=%s%s caller=%s\n",
                apiName, repeatText, action,
                static_cast<unsigned long>(eventRecord.Status), target,
                static_cast<unsigned long long>(eventRecord.Context0), sizeText,
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0),
                bytesText, vadSuffix, caller);
  } else if (_stricmp(apiName, "NtQueryVirtualMemory") == 0) {
    char target[256]{};
    char vadSuffix[256]{};
    char infoLenText[32]{};
    DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatVadSuffix(ctx, targetPid, eventRecord.Context0, vadSuffix,
                    RTL_NUMBER_OF(vadSuffix));
    FormatBytes(eventRecord.Context3, infoLenText, RTL_NUMBER_OF(infoLenText));
    if (targetPid != 0 && targetPid != ctx.ChildProcessId) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(
        lineColor,
        "[blind] %s%s %s status=0x%08lX target=%s base=0x%llX class=%s(%llu) "
        "info_buffer=0x%llX info_len=%s return_len=0x%llX%s caller=%s\n",
        apiName, repeatText, action,
        static_cast<unsigned long>(eventRecord.Status), target,
        static_cast<unsigned long long>(eventRecord.Context0),
        MemoryInformationClassName(eventRecord.Context1),
        static_cast<unsigned long long>(eventRecord.Context1),
        static_cast<unsigned long long>(
            eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0),
        infoLenText,
        static_cast<unsigned long long>(
            eventRecord.ArgCount > 5 ? eventRecord.Args[5] : 0),
        vadSuffix, caller);
  } else if (_stricmp(apiName, "NtCreateThreadEx") == 0) {
    char start[256]{};
    char target[256]{};
    char vadSuffix[256]{};
    DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    FormatSmartAddress(ctx, targetPid, eventRecord.Context1, start,
                       RTL_NUMBER_OF(start));
    FormatVadSuffix(ctx, targetPid, eventRecord.Context1, vadSuffix,
                    RTL_NUMBER_OF(vadSuffix));
    SmartVadInfo startVad{};
    if (QueryVadInfo(ctx, targetPid, eventRecord.Context1, startVad) &&
        IsExecutablePrivateVad(startVad)) {
      lineColor = LogColor::Suspicious;
    }
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(lineColor,
                "[blind] %s%s %s status=0x%08lX target=%s start=%s%s "
                "arg=0x%llX flags=0x%llX "
                "handle=0x%llX caller=%s\n",
                apiName, repeatText, action,
                static_cast<unsigned long>(eventRecord.Status), target, start,
                vadSuffix,
                static_cast<unsigned long long>(eventRecord.Context3),
                static_cast<unsigned long long>(eventRecord.Context2),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 7 ? eventRecord.Args[7] : 0),
                caller);
  } else if (_stricmp(apiName, "NtCreateThread") == 0) {
    char target[256]{};
    DWORD targetPid = TargetPidForEvent(eventRecord, ctx.ChildProcessId);
    FormatTargetProcess(ctx, ctx.ChildProcessId, targetPid, target,
                        RTL_NUMBER_OF(target));
    lineColor = RemoteAwareColor(ctx, targetPid, lineColor);
    ColorPrintf(lineColor,
                "[blind] %s%s %s status=0x%08lX target=%s suspended=%llu "
                "client_pid=%llu caller=%s\n",
                apiName, repeatText, action,
                static_cast<unsigned long>(eventRecord.Status), target,
                static_cast<unsigned long long>(eventRecord.Context2),
                static_cast<unsigned long long>(eventRecord.Context3), caller);
  } else {
    ColorPrintf(lineColor,
                "[blind] %s%s %s status=0x%08lX caller=%s "
                "args=[0x%llX,0x%llX,0x%llX,0x%llX]\n",
                apiName, repeatText, action,
                static_cast<unsigned long>(eventRecord.Status), caller,
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0),
                static_cast<unsigned long long>(
                    eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0));
  }

  PrintCliContext(ctx, eventRecord);
}
void PrintCliGenericEvent(ServerContext &ctx,
                          const IXIPC_HOOK_EVENT &eventRecord) {
  if (IsCliDetectionEvent(eventRecord)) {
    PrintCliDetectionEvent(ctx, eventRecord);
    return;
  }

  if (eventRecord.Kind == IxIpcHookEventNt) {
    PrintCliNtEvent(ctx, eventRecord);
    return;
  }

  char caller[256]{};
  if (ctx.ResolveSymbols) {
    FormatChildSymbolAddress(ctx, eventRecord.Caller, caller,
                             RTL_NUMBER_OF(caller));
  } else {
    FormatChildAddress(ctx, eventRecord.Caller, caller, RTL_NUMBER_OF(caller));
  }

  char sampleSuffix[224]{};
  FormatEventSampleSuffix(eventRecord, sampleSuffix,
                          RTL_NUMBER_OF(sampleSuffix));
  UINT32 repeat = DecodeRepeatCount(eventRecord.CallerFlags);
  char repeatText[32]{};
  if (repeat > 1) {
    (void)StringCchPrintfA(repeatText, RTL_NUMBER_OF(repeatText), " x%lu",
                           static_cast<unsigned long>(repeat));
  }

  const char *apiName =
      eventRecord.ApiName[0] != '\0' ? eventRecord.ApiName : "Hook";
  const char *moduleName =
      eventRecord.ModuleName[0] != '\0' ? eventRecord.ModuleName : "<unknown>";
  ColorPrintf(LogColor::Lifecycle,
              "[blind] %s%s hit kind=%s module=%s caller=%s "
              "args=[0x%llX,0x%llX,0x%llX,0x%llX]%s\n",
              apiName, repeatText, KindName(eventRecord.Kind), moduleName,
              caller,
              static_cast<unsigned long long>(
                  eventRecord.ArgCount > 0 ? eventRecord.Args[0] : 0),
              static_cast<unsigned long long>(
                  eventRecord.ArgCount > 1 ? eventRecord.Args[1] : 0),
              static_cast<unsigned long long>(
                  eventRecord.ArgCount > 2 ? eventRecord.Args[2] : 0),
              static_cast<unsigned long long>(
                  eventRecord.ArgCount > 3 ? eventRecord.Args[3] : 0),
              sampleSuffix);

  PrintCliContext(ctx, eventRecord);
}
} // namespace blind::injector
