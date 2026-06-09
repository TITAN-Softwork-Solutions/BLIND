#include "internal.h"

namespace blind::mapper
{
    bool Fail(ServerContext &ctx, const char *message)
    {
        HostDebugLog(ctx, "manual-map: %s", message);
        ColorPrintf(LogColor::Error, "[blind] manual-map: %s\n", message);
        return false;
    }

    bool FailLastError(ServerContext &ctx, const char *operation, DWORD gle)
    {
        HostDebugLog(ctx, "manual-map: %s failed gle=%lu", operation, gle);
        ColorPrintf(LogColor::Error, "[blind] manual-map: %s failed gle=%lu\n", operation, gle);
        return false;
    }

    bool ReadFileBytes(const std::wstring &path, std::vector<BYTE> &out)
    {
        out.clear();
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        LARGE_INTEGER fileSize{};
        if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0 ||
            fileSize.QuadPart > static_cast<LONGLONG>(256 * 1024 * 1024))
        {
            CloseHandle(file);
            return false;
        }

        out.resize(static_cast<std::size_t>(fileSize.QuadPart));
        std::size_t offset = 0;
        while (offset < out.size())
        {
            DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(out.size() - offset, 1024 * 1024));
            DWORD read = 0;
            if (!ReadFile(file, out.data() + offset, chunk, &read, nullptr) || read == 0)
            {
                CloseHandle(file);
                out.clear();
                return false;
            }
            offset += read;
        }

        CloseHandle(file);
        return true;
    }

    bool ImageRangeValid(std::size_t imageSize, DWORD rva, std::size_t size) noexcept
    {
        return static_cast<std::size_t>(rva) <= imageSize && size <= imageSize - static_cast<std::size_t>(rva);
    }
    BYTE *ImageRvaBytes(std::vector<BYTE> &image, DWORD rva, std::size_t size)
    {
        if (!ImageRangeValid(image.size(), rva, size))
        {
            return nullptr;
        }
        return image.data() + rva;
    }

    const char *ImageRvaString(std::vector<BYTE> &image, DWORD rva)
    {
        if (!ImageRangeValid(image.size(), rva, 1))
        {
            return nullptr;
        }
        const char *value = reinterpret_cast<const char *>(image.data() + rva);
        std::size_t remaining = image.size() - static_cast<std::size_t>(rva);
        for (std::size_t i = 0; i < remaining; ++i)
        {
            if (value[i] == '\0')
            {
                return value;
            }
        }
        return nullptr;
    }

    IMAGE_NT_HEADERS64 *ImageNtHeaders64(std::vector<BYTE> &image)
    {
        if (image.size() < sizeof(IMAGE_DOS_HEADER))
        {
            return nullptr;
        }

        auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(image.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        {
            return nullptr;
        }

        if (static_cast<std::size_t>(dos->e_lfanew) > image.size() ||
            sizeof(IMAGE_NT_HEADERS64) > image.size() - static_cast<std::size_t>(dos->e_lfanew))
        {
            return nullptr;
        }

        auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(image.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            return nullptr;
        }
        return nt;
    }

    bool PrepareMappedImage(ServerContext &ctx, const std::wstring &dllPath, MappedImage &mapped)
    {
        std::vector<BYTE> raw;
        if (!ReadFileBytes(dllPath, raw))
        {
            return Fail(ctx, "failed to read DLL image");
        }

        if (raw.size() < sizeof(IMAGE_DOS_HEADER))
        {
            return Fail(ctx, "DLL image is too small");
        }

        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(raw.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            static_cast<std::size_t>(dos->e_lfanew) > raw.size() ||
            sizeof(IMAGE_NT_HEADERS64) > raw.size() - static_cast<std::size_t>(dos->e_lfanew))
        {
            return Fail(ctx, "DLL image has invalid DOS/NT headers");
        }

        auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(raw.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            return Fail(ctx, "manual mapper only supports x64 PE32+ DLLs");
        }
        if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
        {
            return Fail(ctx, "image is not a DLL");
        }
        if (nt->OptionalHeader.SizeOfImage == 0 || nt->OptionalHeader.SizeOfImage > 256 * 1024 * 1024 ||
            nt->OptionalHeader.SizeOfHeaders == 0)
        {
            return Fail(ctx, "DLL image has unsupported image size");
        }
        if (nt->OptionalHeader.SizeOfHeaders > nt->OptionalHeader.SizeOfImage ||
            nt->OptionalHeader.AddressOfEntryPoint >= nt->OptionalHeader.SizeOfImage)
        {
            return Fail(ctx, "DLL image headers or entrypoint lie outside SizeOfImage");
        }

        const std::size_t sectionTableOffset = static_cast<std::size_t>(dos->e_lfanew) +
                                               offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                               nt->FileHeader.SizeOfOptionalHeader;
        const std::size_t sectionTableBytes =
            static_cast<std::size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > raw.size() || sectionTableBytes > raw.size() - sectionTableOffset)
        {
            return Fail(ctx, "DLL section table is truncated");
        }

        mapped = {};
        mapped.Image.assign(nt->OptionalHeader.SizeOfImage, 0);
        mapped.PreferredBase = nt->OptionalHeader.ImageBase;
        mapped.SizeOfImage = nt->OptionalHeader.SizeOfImage;
        mapped.SizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
        mapped.EntryPointRva = nt->OptionalHeader.AddressOfEntryPoint;

        const std::size_t headerBytes = std::min<std::size_t>(mapped.SizeOfHeaders, raw.size());
        std::memcpy(mapped.Image.data(), raw.data(), headerBytes);

        auto *sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(raw.data() + sectionTableOffset);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            const IMAGE_SECTION_HEADER &section = sections[i];
            if (section.VirtualAddress >= mapped.SizeOfImage)
            {
                return Fail(ctx, "DLL section lies outside SizeOfImage");
            }
            if (section.PointerToRawData == 0 || section.SizeOfRawData == 0)
            {
                continue;
            }
            if (section.PointerToRawData >= raw.size())
            {
                return Fail(ctx, "DLL section raw pointer lies outside file");
            }

            const std::size_t rawRemaining = raw.size() - section.PointerToRawData;
            const std::size_t imageRemaining = mapped.Image.size() - section.VirtualAddress;
            const std::size_t copyBytes =
                std::min<std::size_t>(section.SizeOfRawData, std::min(rawRemaining, imageRemaining));
            if (copyBytes != 0)
            {
                std::memcpy(
                    mapped.Image.data() + section.VirtualAddress, raw.data() + section.PointerToRawData, copyBytes);
            }
        }

        if (ImageNtHeaders64(mapped.Image) == nullptr)
        {
            return Fail(ctx, "mapped image headers failed validation");
        }
        return true;
    }
} // namespace blind::mapper
