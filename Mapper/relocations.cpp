#include "internal.h"

namespace blind::mapper
{
    bool ApplyRelocations(ServerContext &ctx, MappedImage &mapped, UINT64 remoteBase)
    {
        auto *nt = ImageNtHeaders64(mapped.Image);
        if (nt == nullptr)
        {
            return Fail(ctx, "cannot relocate invalid image headers");
        }

        const INT64 delta = static_cast<INT64>(remoteBase - nt->OptionalHeader.ImageBase);
        if (delta == 0)
        {
            return true;
        }

        const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.VirtualAddress == 0 || dir.Size == 0)
        {
            return Fail(ctx, "image is not loaded at preferred base and has no relocations");
        }
        if (!ImageRangeValid(mapped.Image.size(), dir.VirtualAddress, dir.Size))
        {
            return Fail(ctx, "relocation directory lies outside image");
        }

        DWORD cursor = 0;
        while (cursor < dir.Size)
        {
            auto *block = ImageRvaPtr<IMAGE_BASE_RELOCATION>(mapped.Image, dir.VirtualAddress + cursor);
            if (block == nullptr || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
            {
                return Fail(ctx, "relocation block is truncated");
            }
            if (block->SizeOfBlock > dir.Size - cursor)
            {
                return Fail(ctx, "relocation block overruns directory");
            }

            const DWORD entryBytes = block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
            auto *entries = reinterpret_cast<WORD *>(reinterpret_cast<BYTE *>(block) + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < entryBytes / sizeof(WORD); ++i)
            {
                const WORD entry = entries[i];
                const WORD type = entry >> 12;
                const WORD offset = entry & 0x0FFFu;
                const DWORD patchRva = block->VirtualAddress + offset;

                if (type == IMAGE_REL_BASED_ABSOLUTE)
                {
                    continue;
                }
                if (type == IMAGE_REL_BASED_DIR64)
                {
                    auto *patch = ImageRvaPtr<UINT64>(mapped.Image, patchRva);
                    if (patch == nullptr)
                    {
                        return Fail(ctx, "DIR64 relocation target lies outside image");
                    }
                    *patch = static_cast<UINT64>(static_cast<INT64>(*patch) + delta);
                    continue;
                }
                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    auto *patch = ImageRvaPtr<UINT32>(mapped.Image, patchRva);
                    if (patch == nullptr)
                    {
                        return Fail(ctx, "HIGHLOW relocation target lies outside image");
                    }
                    *patch = static_cast<UINT32>(*patch + static_cast<INT32>(delta));
                    continue;
                }

                return Fail(ctx, "unsupported relocation type");
            }

            cursor += block->SizeOfBlock;
        }

        return true;
    }
} // namespace blind::mapper
