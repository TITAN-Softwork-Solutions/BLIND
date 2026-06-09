#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void CopyEventSampleString(const IXIPC_HOOK_EVENT &eventRecord, char *out,
                           std::size_t outChars) noexcept;
bool SampleLooksLikePath(const char *sample) noexcept;
void CopyConsoleSampleDisplay(const char *sample, char *out,
                              std::size_t outChars) noexcept;
void FormatEventSampleSuffix(const IXIPC_HOOK_EVENT &eventRecord, char *out,
                             std::size_t outChars) noexcept;
UINT32 DecodeRepeatCount(UINT32 callerFlags) noexcept;
UINT32 EncodeRepeatCount(UINT32 callerFlags, UINT32 repeat) noexcept;
bool NtStatusSucceeded(UINT32 status) noexcept;
bool ApiIs(const IXIPC_HOOK_EVENT &eventRecord, const char *name) noexcept;
bool SmartAreaEnabled(const ServerContext &ctx, UINT32 flag) noexcept;
UINT64 StackHash(const IXIPC_HOOK_EVENT &eventRecord) noexcept;
UINT64 PageCount(UINT64 size) noexcept;
UINT64 PageBase(UINT64 address) noexcept;
UINT64 RangeEnd(UINT64 base, UINT64 size) noexcept;
void FormatBytes(UINT64 bytes, char *out, std::size_t outChars) noexcept;
bool IsWriteExecuteProtect(UINT32 protect) noexcept;
bool IsExecutableProtect(UINT32 protect) noexcept;
void FormatProtect(UINT32 protect, char *out, std::size_t outChars) noexcept;
const char *MemoryInformationClassName(UINT64 informationClass) noexcept;
const char *MemoryStateName(UINT32 state) noexcept;
const char *MemoryTypeName(UINT32 type) noexcept;
void FormatAllocationType(UINT32 allocationType, char *out,
                          std::size_t outChars) noexcept;
void FormatProcessAccess(UINT32 mask, char *out, std::size_t outChars) noexcept;
void FormatThreadAccess(UINT32 mask, char *out, std::size_t outChars) noexcept;
} // namespace blind::injector
