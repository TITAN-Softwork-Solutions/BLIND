#include "module_internal.h"

#include <TlHelp32.h>

namespace IX_MODULE_INTERNAL
{
    namespace
    {
        constexpr std::size_t kIatThunkSize = 16;

        HMODULE OwnModuleBase() noexcept
        {
            static HMODULE s_ownModule = nullptr;
            if (s_ownModule != nullptr)
            {
                return s_ownModule;
            }

            HMODULE module = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCSTR>(&OwnModuleBase),
                                   &module))
            {
                s_ownModule = module;
            }
            return s_ownModule;
        }

        const char *WideBaseName(const wchar_t *name, char buffer[64]) noexcept
        {
            buffer[0] = '\0';
            if (name == nullptr)
            {
                return buffer;
            }

            const wchar_t *base = wcsrchr(name, L'\\');
            base = base != nullptr ? base + 1 : name;
            (void)WideCharToMultiByte(CP_ACP, 0, base, -1, buffer, 64, nullptr, nullptr);
            buffer[63] = '\0';
            return buffer;
        }

        bool ModuleNameMatches(const char *left, const char *right) noexcept
        {
            if (left == nullptr || right == nullptr || left[0] == '\0' || right[0] == '\0')
            {
                return false;
            }

            if (lstrcmpiA(left, right) == 0)
            {
                return true;
            }

            char leftNoExt[64]{};
            char rightNoExt[64]{};
            (void)strncpy_s(leftNoExt, left, _TRUNCATE);
            (void)strncpy_s(rightNoExt, right, _TRUNCATE);
            char *leftDot = strrchr(leftNoExt, '.');
            char *rightDot = strrchr(rightNoExt, '.');
            if (leftDot != nullptr && lstrcmpiA(leftDot, ".dll") == 0)
            {
                *leftDot = '\0';
            }
            if (rightDot != nullptr && lstrcmpiA(rightDot, ".dll") == 0)
            {
                *rightDot = '\0';
            }
            return lstrcmpiA(leftNoExt, rightNoExt) == 0;
        }

        bool SlotAlreadyTracked(const InlineHook &hook, void **slot) noexcept
        {
            for (std::size_t i = 0; i < hook.IatSlotCount && i < RTL_NUMBER_OF(hook.IatSlots); ++i)
            {
                if (hook.IatSlots[i] == slot)
                {
                    return true;
                }
            }
            return false;
        }

        bool PatchIatSlot(InlineHook &hook, void **slot, void *replacement) noexcept
        {
            if (slot == nullptr || replacement == nullptr || hook.IatSlotCount >= RTL_NUMBER_OF(hook.IatSlots) ||
                SlotAlreadyTracked(hook, slot))
            {
                return false;
            }

            void *original = nullptr;
            __try
            {
                original = *slot;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }

            if (original == replacement)
            {
                return false;
            }

            DWORD oldProtect = 0;
            if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldProtect))
            {
                return false;
            }

            *slot = replacement;

            DWORD temp = 0;
            (void)VirtualProtect(slot, sizeof(void *), oldProtect, &temp);
            FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void *));

            hook.IatSlots[hook.IatSlotCount] = slot;
            hook.IatOriginals[hook.IatSlotCount] = original;
            ++hook.IatSlotCount;
            return true;
        }

        bool ImportNameMatches(const std::uint8_t *moduleBase,
                               IMAGE_THUNK_DATA *nameThunk,
                               const char *exportName) noexcept
        {
            if (nameThunk == nullptr || IMAGE_SNAP_BY_ORDINAL(nameThunk->u1.Ordinal))
            {
                return false;
            }

            auto *byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(moduleBase + nameThunk->u1.AddressOfData);
            __try
            {
                return byName != nullptr && lstrcmpiA(reinterpret_cast<const char *>(byName->Name), exportName) == 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        std::size_t PatchModuleImports(InlineHook &hook, HMODULE importer, void *replacement) noexcept
        {
            if (importer == nullptr || importer == OwnModuleBase() || hook.TargetAddress == nullptr ||
                replacement == nullptr)
            {
                return 0;
            }

            auto *base = reinterpret_cast<std::uint8_t *>(importer);
            auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
            __try
            {
                if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                {
                    return 0;
                }
                auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE ||
                    nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
                {
                    return 0;
                }

                const auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
                {
                    return 0;
                }

                char hookModuleName[64]{};
                (void)WideBaseName(hook.ModuleName, hookModuleName);
                auto *desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + dir.VirtualAddress);
                std::size_t patched = 0;
                for (; desc->Name != 0; ++desc)
                {
                    const char *importModuleName = reinterpret_cast<const char *>(base + desc->Name);
                    const bool descriptorModuleMatches = ModuleNameMatches(importModuleName, hookModuleName);
                    auto *nameThunk = desc->OriginalFirstThunk != 0
                                          ? reinterpret_cast<IMAGE_THUNK_DATA *>(base + desc->OriginalFirstThunk)
                                          : nullptr;
                    auto *iatThunk = reinterpret_cast<IMAGE_THUNK_DATA *>(base + desc->FirstThunk);
                    if (iatThunk == nullptr)
                    {
                        continue;
                    }

                    for (std::size_t thunkIndex = 0; iatThunk[thunkIndex].u1.Function != 0; ++thunkIndex)
                    {
                        void **slot = reinterpret_cast<void **>(&iatThunk[thunkIndex].u1.Function);
                        void *current = reinterpret_cast<void *>(iatThunk[thunkIndex].u1.Function);
                        const bool namedMatch =
                            descriptorModuleMatches &&
                            ImportNameMatches(
                                base, nameThunk != nullptr ? &nameThunk[thunkIndex] : nullptr, hook.ExportName);
                        const bool addressMatch = current == hook.TargetAddress;
                        if ((namedMatch || addressMatch) && PatchIatSlot(hook, slot, replacement))
                        {
                            ++patched;
                        }
                    }
                }
                return patched;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
        }

        std::size_t PatchAllLoadedModuleImports(InlineHook &hook, void *replacement) noexcept
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                return 0;
            }

            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            std::size_t patched = 0;
            if (Module32FirstW(snapshot, &entry))
            {
                do
                {
                    patched += PatchModuleImports(hook, entry.hModule, replacement);
                    entry.dwSize = sizeof(entry);
                } while (Module32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
            return patched;
        }

        void *BuildShadowIatThunk(void *hookEntry) noexcept
        {
            if (hookEntry == nullptr)
            {
                return nullptr;
            }

            void *memory = VirtualAlloc(nullptr, kIatThunkSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (memory == nullptr)
            {
                return nullptr;
            }

            auto *code = static_cast<std::uint8_t *>(memory);
            code[0] = 0x48;
            code[1] = 0xB8;
            *reinterpret_cast<void **>(&code[2]) = hookEntry;
            code[10] = 0xFF;
            code[11] = 0xE0;
            for (std::size_t i = 12; i < kIatThunkSize; ++i)
            {
                code[i] = 0xCC;
            }

            DWORD oldProtect = 0;
            if (!VirtualProtect(memory, kIatThunkSize, PAGE_EXECUTE_READ, &oldProtect))
            {
                VirtualFree(memory, 0, MEM_RELEASE);
                return nullptr;
            }

            FlushInstructionCache(GetCurrentProcess(), memory, kIatThunkSize);
            if (!IX_RUNTIME_INTERNAL::RegisterIxDynamicInstrumentationRange(
                    memory, kIatThunkSize, IX_INSTRUMENTATION_FLAG_EXECUTABLE_HELPER, "rt.mod.shadow_iat"))
            {
                VirtualFree(memory, 0, MEM_RELEASE);
                return nullptr;
            }
            return memory;
        }

        void RestoreIatSlots(InlineHook &hook) noexcept
        {
            for (std::size_t i = 0; i < hook.IatSlotCount && i < RTL_NUMBER_OF(hook.IatSlots); ++i)
            {
                void **slot = hook.IatSlots[i];
                if (slot == nullptr)
                {
                    continue;
                }

                DWORD oldProtect = 0;
                if (VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldProtect))
                {
                    *slot = hook.IatOriginals[i];
                    DWORD temp = 0;
                    (void)VirtualProtect(slot, sizeof(void *), oldProtect, &temp);
                    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void *));
                }
                hook.IatSlots[i] = nullptr;
                hook.IatOriginals[i] = nullptr;
            }
            hook.IatSlotCount = 0;
        }
    } // namespace

    bool InstallModuleIatHook(InlineHook &hook, bool shadowCopy) noexcept
    {
        if (hook.TargetAddress == nullptr || hook.HookEntry == nullptr || hook.OriginalFunction == nullptr)
        {
            return false;
        }

        hook.IatThunk = shadowCopy ? BuildShadowIatThunk(hook.HookEntry) : nullptr;
        void *replacement = shadowCopy ? hook.IatThunk : hook.HookEntry;
        if (replacement == nullptr)
        {
            return false;
        }

        const std::size_t patched = PatchAllLoadedModuleImports(hook, replacement);
        if (patched == 0)
        {
            if (hook.IatThunk != nullptr)
            {
                VirtualFree(hook.IatThunk, 0, MEM_RELEASE);
                hook.IatThunk = nullptr;
            }
            return false;
        }

        *hook.OriginalFunction = hook.TargetAddress;
        return true;
    }

    bool RefreshModuleIatHook(InlineHook &hook, HMODULE moduleHandle) noexcept
    {
        if (!hook.Installed || moduleHandle == nullptr ||
            (hook.HookMethod != IXIPC_HOOK_METHOD_IAT && hook.HookMethod != IXIPC_HOOK_METHOD_SHADOW_IAT))
        {
            return false;
        }

        void *replacement = hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT ? hook.IatThunk : hook.HookEntry;
        const std::size_t before = hook.IatSlotCount;
        (void)PatchModuleImports(hook, moduleHandle, replacement);
        return hook.IatSlotCount != before;
    }

    void RemoveModuleIatHook(InlineHook &hook) noexcept
    {
        RestoreIatSlots(hook);
        if (hook.IatThunk != nullptr)
        {
            VirtualFree(hook.IatThunk, 0, MEM_RELEASE);
            hook.IatThunk = nullptr;
        }
    }

    bool CheckModuleIatHookIntegrity(const InlineHook &hook) noexcept
    {
        if (hook.IatSlotCount == 0)
        {
            return false;
        }

        void *replacement = hook.HookMethod == IXIPC_HOOK_METHOD_SHADOW_IAT ? hook.IatThunk : hook.HookEntry;
        for (std::size_t i = 0; i < hook.IatSlotCount && i < RTL_NUMBER_OF(hook.IatSlots); ++i)
        {
            void **slot = hook.IatSlots[i];
            if (slot == nullptr)
            {
                return false;
            }

            __try
            {
                if (*slot != replacement)
                {
                    return false;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }
        return true;
    }
} // namespace IX_MODULE_INTERNAL
