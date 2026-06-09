#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void CloseCachedProcessHandles(ServerContext &ctx) noexcept;
void RemoveCachedProcessHandle(ServerContext &ctx, DWORD pid) noexcept;
HANDLE CachedProcessHandle(ServerContext &ctx, DWORD pid) noexcept;
HANDLE OpenSmartProcessHandle(ServerContext &ctx, DWORD pid,
                              bool &mustClose) noexcept;
bool TryGetCachedVadInfo(ServerContext &ctx, DWORD targetPid, UINT64 address,
                         SmartVadInfo &out) noexcept;
void CacheVadInfo(ServerContext &ctx, DWORD targetPid,
                  const SmartVadInfo &vad) noexcept;
void InvalidateVadCache(ServerContext &ctx, DWORD targetPid, UINT64 base,
                        UINT64 size) noexcept;
bool QueryVadInfo(ServerContext &ctx, DWORD targetPid, UINT64 address,
                  SmartVadInfo &out) noexcept;
} // namespace blind::injector
