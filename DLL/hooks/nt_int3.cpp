#include "nt_methods.h"

#include <Windows.h>
#include <cstring>

namespace IX_NT_METHODS
{
    namespace
    {
        constexpr std::size_t kMaxInt3Hooks = 64;

        struct Int3HookSlot
        {
            volatile LONG Active;
            void *Target;
            void *HookEntry;
        };

        Int3HookSlot g_Int3Hooks[kMaxInt3Hooks]{};
        PVOID g_Int3VehHandle = nullptr;
        volatile LONG g_Int3VehInitState = 0;

        LONG WINAPI NtInt3VectoredHandler(EXCEPTION_POINTERS *exceptionPointers) noexcept
        {
            if (exceptionPointers == nullptr || exceptionPointers->ExceptionRecord == nullptr ||
                exceptionPointers->ContextRecord == nullptr ||
                exceptionPointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            void *faultAddress = exceptionPointers->ExceptionRecord->ExceptionAddress;
            for (std::size_t i = 0; i < kMaxInt3Hooks; ++i)
            {
                if (g_Int3Hooks[i].Active == 0 || g_Int3Hooks[i].Target != faultAddress)
                {
                    continue;
                }

#if defined(_M_X64)
                exceptionPointers->ContextRecord->Rip = reinterpret_cast<DWORD64>(g_Int3Hooks[i].HookEntry);
#else
                exceptionPointers->ContextRecord->Eip = reinterpret_cast<DWORD>(g_Int3Hooks[i].HookEntry);
#endif
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        bool EnsureInt3VehInstalled() noexcept
        {
            if (g_Int3VehHandle != nullptr)
            {
                return true;
            }

            if (InterlockedCompareExchange(&g_Int3VehInitState, 1, 0) == 0)
            {
                g_Int3VehHandle = AddVectoredExceptionHandler(1, NtInt3VectoredHandler);
                InterlockedExchange(&g_Int3VehInitState, g_Int3VehHandle != nullptr ? 2 : 0);
                return g_Int3VehHandle != nullptr;
            }

            while (g_Int3VehInitState == 1)
            {
                Sleep(0);
            }
            return g_Int3VehHandle != nullptr;
        }

        bool AddInt3Slot(void *target, void *hook) noexcept
        {
            for (std::size_t i = 0; i < kMaxInt3Hooks; ++i)
            {
                if (g_Int3Hooks[i].Active != 0)
                {
                    continue;
                }

                if (InterlockedCompareExchange(&g_Int3Hooks[i].Active, -1, 0) != 0)
                {
                    continue;
                }

                g_Int3Hooks[i].Target = target;
                g_Int3Hooks[i].HookEntry = hook;
                MemoryBarrier();
                InterlockedExchange(&g_Int3Hooks[i].Active, 1);
                return true;
            }
            return false;
        }

        void RemoveInt3Slot(void *target) noexcept
        {
            for (std::size_t i = 0; i < kMaxInt3Hooks; ++i)
            {
                if (g_Int3Hooks[i].Active == 0 || g_Int3Hooks[i].Target != target)
                {
                    continue;
                }

                InterlockedExchange(&g_Int3Hooks[i].Active, 0);
                MemoryBarrier();
                g_Int3Hooks[i].Target = nullptr;
                g_Int3Hooks[i].HookEntry = nullptr;
                return;
            }
        }
    } // namespace

    bool InstallNtInt3Hook(NtHookPatch &patch) noexcept
    {
        if (patch.Target == nullptr || patch.HookEntry == nullptr || patch.OriginalBytes == nullptr ||
            !EnsureInt3VehInstalled())
        {
            return false;
        }

        auto *dst = static_cast<std::uint8_t *>(patch.Target);
        __try
        {
            std::memcpy(patch.OriginalBytes, dst, 16);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        if (!AddInt3Slot(patch.Target, patch.HookEntry))
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            RemoveInt3Slot(patch.Target);
            return false;
        }

        dst[0] = 0xCC;

        DWORD temp = 0;
        (void)VirtualProtect(dst, 1, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, 1);
        return true;
    }

    void RemoveNtInt3Hook(const NtHookPatch &patch) noexcept
    {
        if (patch.Target == nullptr || patch.OriginalBytes == nullptr)
        {
            return;
        }

        auto *dst = static_cast<std::uint8_t *>(patch.Target);
        DWORD oldProtect = 0;
        if (VirtualProtect(dst, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            dst[0] = patch.OriginalBytes[0];
            DWORD temp = 0;
            (void)VirtualProtect(dst, 1, oldProtect, &temp);
            FlushInstructionCache(GetCurrentProcess(), dst, 1);
        }

        RemoveInt3Slot(patch.Target);
    }

    bool CheckNtInt3Hook(const NtHookPatch &patch) noexcept
    {
        if (patch.Target == nullptr)
        {
            return false;
        }

        __try
        {
            return *static_cast<const std::uint8_t *>(patch.Target) == 0xCC;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
} // namespace IX_NT_METHODS
