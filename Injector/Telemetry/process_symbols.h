#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void RefreshChildModules(ServerContext &ctx);
DWORD NormalizeTargetPid(const ServerContext &ctx, DWORD pid) noexcept;
const ChildModuleEntry *FindChildModule(ServerContext &ctx, UINT64 address);
const ChildModuleEntry *FindChildModuleNoRefresh(const ServerContext &ctx,
                                                 UINT64 address) noexcept;
bool InitializeSymbols(ServerContext &ctx) noexcept;
bool SymbolBaseAttempted(const ServerContext &ctx, UINT64 base) noexcept;
void EnsureChildSymbols(ServerContext &ctx);
void FormatChildAddress(ServerContext &ctx, UINT64 address, char *out,
                        std::size_t outChars);
void FormatChildSymbolAddress(ServerContext &ctx, UINT64 address, char *out,
                              std::size_t outChars);
void CleanupSymbols(ServerContext &ctx) noexcept;
void CopyBaseNameA(const wchar_t *path, char *out,
                   std::size_t outChars) noexcept;
bool QueryProcessImageName(DWORD pid, char *out, std::size_t outChars) noexcept;
void FormatTargetProcess(ServerContext &ctx, DWORD sourcePid, DWORD targetPid,
                         char *out, std::size_t outChars);
DWORD QueryThreadOwnerProcessId(DWORD threadId) noexcept;
bool QueryThreadWin32StartAddress(DWORD threadId,
                                  UINT64 &startAddress) noexcept;
const ThreadInfoEntry &ResolveThreadInfo(ServerContext &ctx, DWORD threadId);
std::string TargetLabel(ServerContext &ctx, DWORD sourcePid, DWORD targetPid);
bool IsRemoteTarget(const ServerContext &ctx, DWORD targetPid) noexcept;
LogColor RemoteAwareColor(const ServerContext &ctx, DWORD targetPid,
                          LogColor color) noexcept;
} // namespace blind::injector
