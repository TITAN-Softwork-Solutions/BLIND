#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    SRWLOCK g_ModuleOriginalCallLock = SRWLOCK_INIT;

    InlineHook *FindHookByOriginalFunction(void **originalFunction) noexcept
    {
        if (originalFunction == nullptr)
        {
            return nullptr;
        }

        for (std::size_t hookIndex = 0; hookIndex < g_HookCount; ++hookIndex)
        {
            auto &hook = g_Hooks[hookIndex];
            if (hook.OriginalFunction == originalFunction)
            {
                return &hook;
            }
        }
        return nullptr;
    }

    bool RestoreHookOriginalBytes(InlineHook &hook) noexcept
    {
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(hook.TargetAddress, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }

        std::memcpy(hook.TargetAddress, hook.OriginalBytes, 16);
        DWORD temp = 0;
        (void)VirtualProtect(hook.TargetAddress, 16, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), hook.TargetAddress, 16);
        return true;
    }

    bool ReinstallHookJump(InlineHook &hook) noexcept
    {
        if (!hook.Installed || hook.TargetAddress == nullptr || hook.HookEntry == nullptr)
        {
            return false;
        }

        auto *dst = static_cast<std::uint8_t *>(hook.TargetAddress);
        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }

        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook.HookEntry;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD temp = 0;
        (void)VirtualProtect(dst, 16, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, 16);
        return true;
    }

    bool InstallInlineHook(void *target, void *hook, std::uint8_t original[16], void **trampolineOut) noexcept
    {
        constexpr std::size_t kPatchSize = 16;
        constexpr std::size_t kTrampolineSize = 32;

        if (target == nullptr || hook == nullptr || original == nullptr || trampolineOut == nullptr)
        {
            return false;
        }

        void *trampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (trampoline == nullptr)
        {
            return false;
        }

        auto *dst = static_cast<std::uint8_t *>(target);
        auto *gate = static_cast<std::uint8_t *>(trampoline);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        auto restoreTargetProtection = [&]() noexcept
        {
            DWORD temp = 0;
            (void)VirtualProtect(dst, kPatchSize, oldProtect, &temp);
        };

        std::memcpy(original, dst, kPatchSize);
        std::memcpy(gate, dst, kPatchSize);
        gate[16] = 0x48;
        gate[17] = 0xB8;
        *reinterpret_cast<void **>(&gate[18]) = dst + kPatchSize;
        gate[26] = 0xFF;
        gate[27] = 0xE0;
        for (std::size_t i = 28; i < kTrampolineSize; ++i)
        {
            gate[i] = 0xCC;
        }

        DWORD trampolineProtect = 0;
        if (!VirtualProtect(trampoline, kTrampolineSize, PAGE_EXECUTE_READ, &trampolineProtect))
        {
            restoreTargetProtection();
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }
        FlushInstructionCache(GetCurrentProcess(), trampoline, kTrampolineSize);
        if (!IX_RUNTIME_INTERNAL::RegisterIxDynamicInstrumentationRange(
                trampoline, kTrampolineSize, IX_INSTRUMENTATION_FLAG_EXECUTABLE_HELPER, "rt.mod.trampoline"))
        {
            restoreTargetProtection();
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD temp = 0;
        (void)VirtualProtect(dst, kPatchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, kPatchSize);

        *trampolineOut = trampoline;
        return true;
    }

    void RemoveInlineHook(void *target, const std::uint8_t original[16], void *trampoline) noexcept
    {
        if (target == nullptr || original == nullptr)
        {
            return;
        }

        DWORD oldProtect = 0;
        if (VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            std::memcpy(target, original, 16);
            DWORD temp = 0;
            (void)VirtualProtect(target, 16, oldProtect, &temp);
            FlushInstructionCache(GetCurrentProcess(), target, 16);
        }

        if (trampoline != nullptr)
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
        }
    }
} // namespace IX_MODULE_INTERNAL
