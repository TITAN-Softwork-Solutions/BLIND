#include "internal.h"

namespace blind::mapper
{
    bool MapDllIntoChild(ServerContext &ctx, HANDLE process, const std::wstring &dllPath)
    {
        MappedImage mapped;
        if (!PrepareMappedImage(ctx, dllPath, mapped))
        {
            return false;
        }

        void *remoteImage = VirtualAllocEx(process,
                                           reinterpret_cast<void *>(mapped.PreferredBase),
                                           mapped.SizeOfImage,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
        if (remoteImage == nullptr)
        {
            remoteImage =
                VirtualAllocEx(process, nullptr, mapped.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        if (remoteImage == nullptr)
        {
            return FailLastError(ctx, "VirtualAllocEx(remote image)");
        }

        const UINT64 remoteBase = reinterpret_cast<UINT64>(remoteImage);
        bool ok = ApplyRelocations(ctx, mapped, remoteBase) && ResolveImports(ctx, process, mapped);
        if (ok)
        {
            SIZE_T written = 0;
            ok = WriteProcessMemory(process, remoteImage, mapped.Image.data(), mapped.Image.size(), &written) &&
                 written == mapped.Image.size();
            if (!ok)
            {
                HostDebugLog(ctx,
                             "manual-map: WriteProcessMemory image failed written=%llu expected=%llu gle=%lu",
                             static_cast<unsigned long long>(written),
                             static_cast<unsigned long long>(mapped.Image.size()),
                             GetLastError());
                (void)Fail(ctx, "failed to write remote image");
            }
        }
        if (ok)
        {
            ok = ProtectMappedImage(ctx, process, remoteBase, mapped) && RunBootstrap(ctx, process, remoteBase, mapped);
        }

        if (!ok)
        {
            VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
            return false;
        }

        UINT64 visibleBase = 0;
        bool visible = GetRemoteModuleBase(GetProcessId(process), WideBaseName(dllPath), visibleBase);
        ColorPrintf(visible ? LogColor::Warning : LogColor::Success,
                    "[blind] manual-map visible=%u base=0x%llX mapped=0x%llX\n",
                    visible ? 1u : 0u,
                    static_cast<unsigned long long>(visibleBase),
                    static_cast<unsigned long long>(remoteBase));
        return !visible;
    }
} // namespace blind::mapper
