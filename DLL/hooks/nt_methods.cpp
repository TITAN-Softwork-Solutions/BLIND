#include "nt_methods.h"

namespace IX_NT_METHODS
{
    bool InstallNtInlineHook(NtHookPatch &patch) noexcept;
    void RemoveNtInlineHook(const NtHookPatch &patch) noexcept;
    bool CheckNtInlineHook(const NtHookPatch &patch) noexcept;

    bool InstallNtInt3Hook(NtHookPatch &patch) noexcept;
    void RemoveNtInt3Hook(const NtHookPatch &patch) noexcept;
    bool CheckNtInt3Hook(const NtHookPatch &patch) noexcept;

    bool InstallNtHookPatch(NtHookPatch &patch) noexcept
    {
        if (patch.Method == IXIPC_HOOK_METHOD_INT3)
        {
            return InstallNtInt3Hook(patch);
        }
        patch.Method = IXIPC_HOOK_METHOD_INLINE;
        return InstallNtInlineHook(patch);
    }

    void RemoveNtHookPatch(const NtHookPatch &patch) noexcept
    {
        if (patch.Method == IXIPC_HOOK_METHOD_INT3)
        {
            RemoveNtInt3Hook(patch);
            return;
        }
        RemoveNtInlineHook(patch);
    }

    bool CheckNtHookPatch(const NtHookPatch &patch) noexcept
    {
        if (patch.Method == IXIPC_HOOK_METHOD_INT3)
        {
            return CheckNtInt3Hook(patch);
        }
        return CheckNtInlineHook(patch);
    }

    std::size_t NtHookPatchSize(std::uint32_t method) noexcept
    {
        return method == IXIPC_HOOK_METHOD_INT3 ? 1u : 16u;
    }

    std::uint32_t NtHookPatchFlag(std::uint32_t method) noexcept
    {
        return method == IXIPC_HOOK_METHOD_INT3 ? IX_HOOK_PATCH_FLAG_NT_INT3 : IX_HOOK_PATCH_FLAG_NT_INLINE;
    }
} // namespace IX_NT_METHODS
