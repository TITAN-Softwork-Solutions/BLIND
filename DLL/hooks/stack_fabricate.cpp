#include "stack_fabricate.h"

#include <Windows.h>

namespace IX_STACK_FABRICATE
{
    struct OwnModuleRange
    {
        std::uintptr_t Base;
        std::uintptr_t End;
    };

    static OwnModuleRange OwnModule() noexcept
    {
        static OwnModuleRange s_ownModule{};
        if (s_ownModule.Base != 0 && s_ownModule.End != 0)
        {
            return s_ownModule;
        }

        HMODULE module = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(&OwnModule),
                               &module))
        {
            auto *base = reinterpret_cast<std::uint8_t *>(module);
            auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
            __try
            {
                if (dos->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.SizeOfImage != 0)
                    {
                        s_ownModule.Base = reinterpret_cast<std::uintptr_t>(base);
                        s_ownModule.End = s_ownModule.Base + nt->OptionalHeader.SizeOfImage;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                s_ownModule = {};
            }
        }
        return s_ownModule;
    }

    void SanitizeBlindFrames(IC_STACKTRACE::Trace &trace) noexcept
    {
        OwnModuleRange ownModule = OwnModule();
        if (ownModule.Base == 0 || ownModule.End == 0 || trace.Count == 0)
        {
            return;
        }

        std::uint16_t writeIndex = 0;
        for (std::uint16_t readIndex = 0; readIndex < trace.Count && readIndex < IC_STACKTRACE::kMaxFrames; ++readIndex)
        {
            const auto ip = reinterpret_cast<std::uintptr_t>(trace.Frames[readIndex].Ip);
            const auto moduleBase = reinterpret_cast<std::uintptr_t>(trace.Frames[readIndex].ModuleBase);
            if ((moduleBase >= ownModule.Base && moduleBase < ownModule.End) ||
                (ip >= ownModule.Base && ip < ownModule.End))
            {
                continue;
            }

            if (writeIndex != readIndex)
            {
                trace.Frames[writeIndex] = trace.Frames[readIndex];
            }
            ++writeIndex;
        }

        for (std::uint16_t i = writeIndex; i < trace.Count && i < IC_STACKTRACE::kMaxFrames; ++i)
        {
            trace.Frames[i] = {};
        }
        trace.Count = writeIndex;
    }
} // namespace IX_STACK_FABRICATE
