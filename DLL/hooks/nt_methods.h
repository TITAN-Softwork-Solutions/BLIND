#pragma once

#include "../../ABI/blind_ipc.h"

#include <cstddef>
#include <cstdint>

namespace IX_NT_METHODS
{
    struct NtHookPatch
    {
        const char *Name;
        void *Target;
        void *HookEntry;
        std::uint8_t *OriginalBytes;
        std::uint32_t Method;
    };

    bool InstallNtHookPatch(NtHookPatch &patch) noexcept;
    void RemoveNtHookPatch(const NtHookPatch &patch) noexcept;
    bool CheckNtHookPatch(const NtHookPatch &patch) noexcept;
    std::size_t NtHookPatchSize(std::uint32_t method) noexcept;
    std::uint32_t NtHookPatchFlag(std::uint32_t method) noexcept;
} // namespace IX_NT_METHODS
