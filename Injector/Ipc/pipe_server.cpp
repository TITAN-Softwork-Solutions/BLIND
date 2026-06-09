#include "Ipc/pipe_server.h"
#include "Core/runner_console.h"
#include "Diagnostics/diagnostics.h"
#include "Telemetry/cli_events.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/smart_capture.h"
#include "Telemetry/smart_summary.h"

namespace blind::injector {
void PrintHookEvent(const IXIPC_HOOK_EVENT &eventRecord) {
  char sampleSuffix[224]{};
  FormatEventSampleSuffix(eventRecord, sampleSuffix,
                          RTL_NUMBER_OF(sampleSuffix));

  ColorPrintf(
      LogColor::Info,
      "[blind] event pid=%lu tid=%lu kind=%s op=%lu api=%s module=%s "
      "caller=0x%llX "
      "c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX%s\n",
      static_cast<unsigned long>(eventRecord.ProcessId),
      static_cast<unsigned long>(eventRecord.ThreadId),
      KindName(eventRecord.Kind),
      static_cast<unsigned long>(eventRecord.Operation),
      eventRecord.ApiName[0] != '\0' ? eventRecord.ApiName : "<none>",
      eventRecord.ModuleName[0] != '\0' ? eventRecord.ModuleName : "<none>",
      static_cast<unsigned long long>(eventRecord.Caller),
      static_cast<unsigned long long>(eventRecord.Context0),
      static_cast<unsigned long long>(eventRecord.Context1),
      static_cast<unsigned long long>(eventRecord.Context2),
      static_cast<unsigned long long>(eventRecord.Context3), sampleSuffix);
}

void HandleHookEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord) {
  ctx.HookEventCount.fetch_add(1, std::memory_order_relaxed);
  if (eventRecord.Kind == IxIpcHookEventIntegrity &&
      (eventRecord.Operation == IX_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY ||
       eventRecord.Operation == IX_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK)) {
    ctx.LaunchGateTrapCount.fetch_add(1, std::memory_order_relaxed);
    ColorPrintf(
        LogColor::Lifecycle,
        "[blind] launch-gate trap op=%lu tid=%lu caller=0x%llX page=0x%llX\n",
        static_cast<unsigned long>(eventRecord.Operation),
        static_cast<unsigned long>(eventRecord.ThreadId),
        static_cast<unsigned long long>(eventRecord.Context0),
        static_cast<unsigned long long>(eventRecord.Context1));
  }
  if (eventRecord.Kind < RTL_NUMBER_OF(ctx.EventKindCounts)) {
    ctx.EventKindCounts[eventRecord.Kind] += 1;
  }
  WriteRawEvent(ctx, eventRecord);
  CaptureSelfMapEvent(ctx, eventRecord);
  InvalidateVadCacheForEvent(ctx, eventRecord);
  CaptureSmartEvent(ctx, eventRecord);
  MaybePrintSmartSummary(ctx);

  if (ctx.CliMode) {
    if (!ShouldSuppressRawForSmart(ctx, eventRecord) &&
        ShouldPrintCliEvent(ctx, eventRecord)) {
      IXIPC_HOOK_EVENT printableEvent = eventRecord;
      if (ApplyCliRepeatAnnotation(ctx, printableEvent)) {
        ctx.PrintedEventCount.fetch_add(1, std::memory_order_relaxed);
        PrintCliGenericEvent(ctx, printableEvent);
      } else {
        ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
      }
    }
    return;
  }

  DWORD printed = ctx.PrintedEventCount.load(std::memory_order_relaxed);
  bool shouldPrint =
      ctx.Verbose || printed < 24 ||
      (eventRecord.Kind == IxIpcHookEventWinsock && printed < 64);
  if (shouldPrint) {
    ctx.PrintedEventCount.fetch_add(1, std::memory_order_relaxed);
    PrintHookEvent(eventRecord);
    return;
  }

  DWORD suppressed =
      ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
  if (suppressed == 0) {
    std::printf("[blind] suppressing additional event details; rerun with "
                "--verbose for full dump\n");
  }
}

bool HandlePacket(ServerContext &ctx, HANDLE pipe,
                  const IXIPC_PACKET &request) {
  IXIPC_PACKET response{};
  response.Magic = IXIPC_MAGIC;
  response.Version = IXIPC_VERSION;
  response.PacketType = IxIpcPacketResponse;
  response.Command = request.Command;
  response.Sequence = request.Sequence;
  response.Status = ERROR_SUCCESS;

  if (request.Magic != IXIPC_MAGIC || request.Version != IXIPC_VERSION ||
      request.PacketType != IxIpcPacketRequest) {
    response.Status = ERROR_INVALID_DATA;
    return WritePacket(pipe, response);
  }

  switch (request.Command) {
  case IxIpcCommandHandshake:
    response.Payload.HandshakeResponse.NegotiatedVersion = IXIPC_VERSION;
    response.Payload.HandshakeResponse.Capabilities = 1;
    break;
  case IxIpcCommandNotifyHookReady: {
    DWORD localMask = request.Payload.NotifyHookReadyRequest.ReadyMask;
    DWORD observed =
        ctx.ReadyMask.fetch_or(localMask, std::memory_order_acq_rel) |
        localMask;
    const DWORD requiredMask = CliReadyMaskForPolicy(ctx);
    response.Payload.NotifyHookReadyResponse.ProcessId =
        request.Payload.NotifyHookReadyRequest.ProcessId;
    response.Payload.NotifyHookReadyResponse.ObservedMask = observed;
    response.Payload.NotifyHookReadyResponse.RequiredMask = requiredMask;
    response.Payload.NotifyHookReadyResponse.PendingCommand = 0;
    ColorPrintf(LogColor::Info,
                "[blind] ready pid=%lu mask=0x%08lX observed=0x%08lX\n",
                static_cast<unsigned long>(
                    request.Payload.NotifyHookReadyRequest.ProcessId),
                static_cast<unsigned long>(localMask),
                static_cast<unsigned long>(observed));
    if ((observed & requiredMask) == requiredMask) {
      SetEvent(ctx.ReadyEvent);
    }
    break;
  }
  case IxIpcCommandQueryHookPolicy:
    response.Payload.QueryHookPolicyResponse = ctx.CliPolicy;
    response.Payload.QueryHookPolicyResponse.PolicyVersion =
        IXIPC_HOOK_POLICY_VERSION;
    break;
  case IxIpcCommandPublishHookEvent:
    HandleHookEvent(ctx, request.Payload.HookEvent);
    break;
  case IxIpcCommandPublishHookEventBatch: {
    UINT32 count = request.Payload.HookEventBatch.Count;
    if (count > IXIPC_MAX_HOOK_EVENT_BATCH) {
      response.Status = ERROR_INVALID_DATA;
      break;
    }
    for (UINT32 i = 0; i < count; ++i) {
      HandleHookEvent(ctx, request.Payload.HookEventBatch.Events[i]);
    }
    break;
  }
  case IxIpcCommandRegisterInstrumentationRange:
  case IxIpcCommandRegisterHookPatch:
  case IxIpcCommandRegisterProcessInstrumentationCallback:
    break;
  default:
    response.Status = ERROR_INVALID_FUNCTION;
    break;
  }

  return WritePacket(pipe, response);
}

DWORD WINAPI PipeServerThread(LPVOID parameter) {
  auto *ctx = static_cast<ServerContext *>(parameter);
  HANDLE pipe =
      CreateNamedPipeW(ctx->PipeName.c_str(), PIPE_ACCESS_DUPLEX,
                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1,
                       kPipeBufferBytes, kPipeBufferBytes, 0, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    std::printf("[blind] CreateNamedPipe failed gle=%lu\n", GetLastError());
    SetEvent(ctx->ReadyEvent);
    return 1;
  }

  std::printf("[blind] listening on %ls\n", ctx->PipeName.c_str());
  BOOL connected = ConnectNamedPipe(pipe, nullptr)
                       ? TRUE
                       : (GetLastError() == ERROR_PIPE_CONNECTED);
  if (!connected) {
    std::printf("[blind] ConnectNamedPipe failed gle=%lu\n", GetLastError());
    CloseHandle(pipe);
    SetEvent(ctx->ReadyEvent);
    return 1;
  }

  std::printf("[blind] hook client connected\n");
  while (!ctx->Stop.load(std::memory_order_acquire)) {
    IXIPC_PACKET request{};
    DWORD read = 0;
    if (!ReadFile(pipe, &request, sizeof(request), &read, nullptr)) {
      DWORD err = GetLastError();
      if (err != ERROR_BROKEN_PIPE && err != ERROR_PIPE_NOT_CONNECTED) {
        std::printf("[blind] pipe read failed gle=%lu\n", err);
      }
      break;
    }
    if (read != sizeof(request)) {
      std::printf("[blind] short packet read bytes=%lu expected=%zu\n", read,
                  sizeof(request));
      break;
    }
    if (!HandlePacket(*ctx, pipe, request)) {
      DWORD err = GetLastError();
      if (err != ERROR_BROKEN_PIPE && err != ERROR_NO_DATA &&
          err != ERROR_PIPE_NOT_CONNECTED) {
        std::printf("[blind] response write failed gle=%lu\n", err);
      }
      break;
    }
  }

  DisconnectNamedPipe(pipe);
  CloseHandle(pipe);
  return 0;
}
} // namespace blind::injector
