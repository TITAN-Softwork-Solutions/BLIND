#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void PrintHookEvent(const IXIPC_HOOK_EVENT &eventRecord);
void HandleHookEvent(ServerContext &ctx, const IXIPC_HOOK_EVENT &eventRecord);
bool HandlePacket(ServerContext &ctx, HANDLE pipe, const IXIPC_PACKET &request);
DWORD WINAPI PipeServerThread(LPVOID parameter);
} // namespace blind::injector
