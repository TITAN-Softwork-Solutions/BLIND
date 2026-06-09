#include "module_internal.h"

using namespace IX_MODULE_INTERNAL;

bool IxSetModuleHook(ModuleHookCallback callback) noexcept
{
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveCallback = callback;
    ResetModuleHookInitFault();

    bool anyInstalled = false;
    for (std::size_t hookIndex = 0; hookIndex < g_HookCount; ++hookIndex)
    {
        auto &hook = g_Hooks[hookIndex];
        if (!IX_RUNTIME_INTERNAL::ShouldInstallModuleHookByPolicy(hook.SourceModule, hook.ExportName))
        {
            continue;
        }

        if (hook.Installed)
        {
            anyInstalled = true;
            continue;
        }

        HMODULE moduleHandle = GetModuleHandleW(hook.ModuleName);
        if (moduleHandle == nullptr)
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ModuleMissing, hook.ModuleName, hook.ExportName, nullptr);
            continue;
        }

        ModuleRange moduleRange{};
        if (!TryResolveModuleImageRange(moduleHandle, moduleRange))
        {
            SetModuleHookInitFault(
                ModuleHookInitFaultCode::ExportOutsideImage, hook.ModuleName, hook.ExportName, moduleHandle);
            continue;
        }

        FARPROC exportAddress = GetProcAddress(moduleHandle, hook.ExportName);
        if (exportAddress == nullptr)
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportMissing, hook.ModuleName, hook.ExportName, nullptr);
            continue;
        }

        hook.TargetAddress = reinterpret_cast<void *>(exportAddress);
        if (!AddressWithinRange(hook.TargetAddress, moduleRange))
        {
            SetModuleHookInitFault(
                ModuleHookInitFaultCode::ExportOutsideImage, hook.ModuleName, hook.ExportName, hook.TargetAddress);
            continue;
        }

        void *redirectTarget = nullptr;
        if (TryDecodeAbsoluteTarget(hook.TargetAddress, redirectTarget) && redirectTarget != nullptr &&
            !AddressWithinRange(redirectTarget, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportRedirectedOutsideImage,
                                   hook.ModuleName,
                                   hook.ExportName,
                                   hook.TargetAddress,
                                   redirectTarget);
            continue;
        }

        hook.HookMethod = IX_RUNTIME_INTERNAL::HookMethodForModuleHookByPolicy(hook.ExportName);
        bool installed = false;
        if (hook.HookMethod == IXIPC_HOOK_METHOD_IAT || hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT)
        {
            installed = InstallModuleIatHook(hook, hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT);
        }
        else
        {
            hook.HookMethod = IXIPC_HOOK_METHOD_INLINE;
            installed = InstallInlineHook(hook.TargetAddress, hook.HookEntry, hook.OriginalBytes, &hook.Trampoline);
            if (installed)
            {
                *hook.OriginalFunction = hook.Trampoline;
            }
        }

        if (!installed)
        {
            SetModuleHookInitFault(
                ModuleHookInitFaultCode::PatchInstallFailed, hook.ModuleName, hook.ExportName, hook.TargetAddress);
            continue;
        }

        hook.Installed = true;
        anyInstalled = true;
    }

    if (!anyInstalled)
    {
        g_ActiveCallback = nullptr;
    }

    return anyInstalled;
}

void IxRemoveModuleHook() noexcept
{
    for (std::size_t hookIndex = 0; hookIndex < g_HookCount; ++hookIndex)
    {
        auto &hook = g_Hooks[hookIndex];
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        if (hook.HookMethod == IXIPC_HOOK_METHOD_IAT || hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT)
        {
            RemoveModuleIatHook(hook);
        }
        else
        {
            RemoveInlineHook(hook.TargetAddress, hook.OriginalBytes, hook.Trampoline);
        }
        hook.TargetAddress = nullptr;
        hook.Trampoline = nullptr;
        hook.HookMethod = IXIPC_HOOK_METHOD_INLINE;
        *hook.OriginalFunction = nullptr;
        hook.Installed = false;
    }

    g_ActiveCallback = nullptr;
}

bool IxRefreshModuleHooks(HMODULE moduleHandle) noexcept
{
    if (moduleHandle == nullptr || g_ActiveCallback == nullptr)
    {
        return false;
    }

    bool anyInstalled = false;
    for (std::size_t hookIndex = 0; hookIndex < g_HookCount; ++hookIndex)
    {
        auto &hook = g_Hooks[hookIndex];
        if (!IX_RUNTIME_INTERNAL::ShouldInstallModuleHookByPolicy(hook.SourceModule, hook.ExportName))
        {
            continue;
        }

        if (hook.Installed)
        {
            if (hook.HookMethod == IXIPC_HOOK_METHOD_IAT || hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT)
            {
                anyInstalled = RefreshModuleIatHook(hook, moduleHandle) || anyInstalled;
            }
            continue;
        }

        HMODULE expectedModule = GetModuleHandleW(hook.ModuleName);
        if (expectedModule == nullptr)
        {
            continue;
        }

        ModuleRange moduleRange{};
        if (!TryResolveModuleImageRange(expectedModule, moduleRange))
        {
            continue;
        }

        FARPROC exportAddress = GetProcAddress(expectedModule, hook.ExportName);
        if (exportAddress == nullptr)
        {
            continue;
        }

        hook.TargetAddress = reinterpret_cast<void *>(exportAddress);
        if (!AddressWithinRange(hook.TargetAddress, moduleRange))
        {
            hook.TargetAddress = nullptr;
            continue;
        }

        void *redirectTarget = nullptr;
        if (TryDecodeAbsoluteTarget(hook.TargetAddress, redirectTarget) && redirectTarget != nullptr &&
            !AddressWithinRange(redirectTarget, moduleRange))
        {
            hook.TargetAddress = nullptr;
            continue;
        }

        hook.HookMethod = IX_RUNTIME_INTERNAL::HookMethodForModuleHookByPolicy(hook.ExportName);
        bool installed = false;
        if (hook.HookMethod == IXIPC_HOOK_METHOD_IAT || hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT)
        {
            installed = InstallModuleIatHook(hook, hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT);
        }
        else
        {
            hook.HookMethod = IXIPC_HOOK_METHOD_INLINE;
            installed = InstallInlineHook(hook.TargetAddress, hook.HookEntry, hook.OriginalBytes, &hook.Trampoline);
            if (installed)
            {
                *hook.OriginalFunction = hook.Trampoline;
            }
        }

        if (!installed)
        {
            hook.TargetAddress = nullptr;
            hook.Trampoline = nullptr;
            hook.HookMethod = IXIPC_HOOK_METHOD_INLINE;
            continue;
        }

        hook.Installed = true;
        anyInstalled = true;
    }

    return anyInstalled;
}

bool IxCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
    std::uint32_t mismatches = 0;

    for (std::size_t hookIndex = 0; hookIndex < g_HookCount; ++hookIndex)
    {
        const auto &hook = g_Hooks[hookIndex];
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        bool intact = false;
        if (hook.HookMethod == IXIPC_HOOK_METHOD_IAT || hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT)
        {
            intact = CheckModuleIatHookIntegrity(hook);
        }
        else
        {
            const auto *bytes = static_cast<const std::uint8_t *>(hook.TargetAddress);
            void *patchedTarget = nullptr;
            std::memcpy(&patchedTarget, &bytes[2], sizeof(patchedTarget));
            intact = bytes[0] == 0x48 && bytes[1] == 0xB8 && patchedTarget == hook.HookEntry && bytes[10] == 0xFF &&
                     bytes[11] == 0xE0;
        }
        if (!intact)
        {
            ++mismatches;
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

bool IxGetLastModuleHookInitFault(ModuleHookInitFault *faultOut) noexcept
{
    if (faultOut == nullptr)
    {
        return false;
    }

    *faultOut = g_LastModuleHookInitFault;
    return faultOut->Code != ModuleHookInitFaultCode::None;
}

std::size_t IxCollectModuleHookPatchInfos(ModuleHookPatchInfo *out, std::size_t capacity) noexcept
{
    if (out == nullptr || capacity == 0)
    {
        return 0;
    }

    std::size_t count = 0;
    for (std::size_t hookIndex = 0; hookIndex < g_HookCount; ++hookIndex)
    {
        const auto &hook = g_Hooks[hookIndex];
        if (count >= capacity)
        {
            break;
        }
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        if (hook.HookMethod == IXIPC_HOOK_METHOD_IAT || hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT)
        {
            const std::uint32_t flags = hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT
                                            ? IX_HOOK_PATCH_FLAG_MODULE_SHADOW_IAT
                                            : IX_HOOK_PATCH_FLAG_MODULE_IAT;
            for (std::size_t slotIndex = 0; slotIndex < hook.IatSlotCount && slotIndex < RTL_NUMBER_OF(hook.IatSlots);
                 ++slotIndex)
            {
                if (count >= capacity)
                {
                    break;
                }
                out[count].PatchAddress = hook.IatSlots[slotIndex];
                out[count].PatchSize = sizeof(void *);
                std::memset(out[count].OriginalBytes, 0, sizeof(out[count].OriginalBytes));
                std::memcpy(out[count].OriginalBytes, &hook.IatOriginals[slotIndex], sizeof(void *));
                out[count].HookName = hook.ExportName;
                out[count].Flags = flags;
                ++count;
            }
        }
        else
        {
            out[count].PatchAddress = hook.TargetAddress;
            out[count].PatchSize = sizeof(hook.OriginalBytes);
            std::memcpy(out[count].OriginalBytes, hook.OriginalBytes, sizeof(hook.OriginalBytes));
            out[count].HookName = hook.ExportName;
            out[count].Flags = IX_HOOK_PATCH_FLAG_MODULE_INLINE;
            ++count;
        }
    }

    return count;
}
