#pragma once

#include <cstdint>
#include <cstddef>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

struct KiHookContext
{
    const char *StubName;
    void *Caller;
    void *StackPointer;
};

using KiHookCallback = void (*)(const KiHookContext &context) noexcept;

bool IxSetKiHook(KiHookCallback callback) noexcept;
bool IxIsKiHookSupported() noexcept;

void IxRemoveKiHook() noexcept;

bool IxCheckKiHookIntegrity(std::uint32_t *mismatchCount) noexcept;

struct KiHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
    std::uint32_t Flags;
};

std::size_t IxCollectKiHookPatchInfos(_Out_writes_(capacity) KiHookPatchInfo *out, _In_ std::size_t capacity) noexcept;
