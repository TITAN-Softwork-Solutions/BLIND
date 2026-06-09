#include "internal.h"

namespace blind::mapper
{
    DWORD ProtectionFromSectionCharacteristics(DWORD characteristics) noexcept
    {
        const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (executable)
        {
            if (writable)
            {
                return readable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_WRITECOPY;
            }
            return readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        }
        if (writable)
        {
            return readable ? PAGE_READWRITE : PAGE_WRITECOPY;
        }
        if (readable)
        {
            return PAGE_READONLY;
        }
        return PAGE_NOACCESS;
    }

    bool ProtectMappedImage(ServerContext &ctx, HANDLE process, UINT64 remoteBase, MappedImage &mapped)
    {
        auto *nt = ImageNtHeaders64(mapped.Image);
        if (nt == nullptr)
        {
            return Fail(ctx, "cannot protect invalid image");
        }

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(
                process, reinterpret_cast<void *>(remoteBase), mapped.SizeOfHeaders, PAGE_READONLY, &oldProtect))
        {
            return FailLastError(ctx, "VirtualProtectEx(headers)");
        }

        IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            IMAGE_SECTION_HEADER &section = sections[i];
            const DWORD sectionSize = std::max<DWORD>(section.Misc.VirtualSize, section.SizeOfRawData);
            if (section.VirtualAddress == 0 || sectionSize == 0)
            {
                continue;
            }
            if (!ImageRangeValid(mapped.Image.size(), section.VirtualAddress, 1))
            {
                return Fail(ctx, "section protection target lies outside image");
            }

            SIZE_T protectSize =
                std::min<SIZE_T>(sectionSize, mapped.Image.size() - static_cast<std::size_t>(section.VirtualAddress));
            DWORD protect = ProtectionFromSectionCharacteristics(section.Characteristics);
            if (!VirtualProtectEx(process,
                                  reinterpret_cast<void *>(remoteBase + section.VirtualAddress),
                                  protectSize,
                                  protect,
                                  &oldProtect))
            {
                HostDebugLog(
                    ctx,
                    "manual-map: VirtualProtectEx failed section=%u rva=0x%08lX size=0x%IX protect=0x%08lX gle=%lu",
                    static_cast<unsigned>(i),
                    section.VirtualAddress,
                    protectSize,
                    protect,
                    GetLastError());
                return Fail(ctx, "failed to apply final section protections");
            }
        }

        (void)FlushInstructionCache(process, reinterpret_cast<void *>(remoteBase), mapped.SizeOfImage);
        return true;
    }

    UINT64 GetTlsCallbacks(MappedImage &mapped)
    {
        auto *nt = ImageNtHeaders64(mapped.Image);
        if (nt == nullptr)
        {
            return 0;
        }

        const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_TLS_DIRECTORY64))
        {
            return 0;
        }

        auto *tls = ImageRvaPtr<IMAGE_TLS_DIRECTORY64>(mapped.Image, dir.VirtualAddress);
        return tls != nullptr ? tls->AddressOfCallBacks : 0;
    }
} // namespace blind::mapper
