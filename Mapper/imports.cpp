#include "internal.h"

namespace blind::mapper
{
    HMODULE LoadLocalImportModule(const char *name)
    {
        if (name == nullptr || name[0] == '\0')
        {
            return nullptr;
        }

        const char *effectiveName = name;
        if (_strnicmp(name, "api-ms-win-crt-", 16) == 0 || _strnicmp(name, "ext-ms-win-crt-", 16) == 0)
        {
            effectiveName = "ucrtbase.dll";
        }

        HMODULE module = GetModuleHandleA(effectiveName);
        if (module != nullptr)
        {
            return module;
        }

        module = LoadLibraryExA(effectiveName, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module != nullptr)
        {
            return module;
        }
        return nullptr;
    }

    bool FindRemoteMappedImageBaseByName(HANDLE process, const std::wstring &baseName, UINT64 &base)
    {
        base = 0;
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        using K32GetMappedFileNameWFn = DWORD(WINAPI *)(HANDLE, LPVOID, LPWSTR, DWORD);
        auto getMappedFileName =
            kernel32 != nullptr
                ? reinterpret_cast<K32GetMappedFileNameWFn>(GetProcAddress(kernel32, "K32GetMappedFileNameW"))
                : nullptr;
        if (getMappedFileName == nullptr)
        {
            return false;
        }

        SYSTEM_INFO systemInfo{};
        GetNativeSystemInfo(&systemInfo);
        UINT64 current = reinterpret_cast<UINT64>(systemInfo.lpMinimumApplicationAddress);
        const UINT64 maximum = reinterpret_cast<UINT64>(systemInfo.lpMaximumApplicationAddress);
        std::unordered_set<UINT64> seenBases;
        seenBases.reserve(256);

        while (current < maximum)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(process, reinterpret_cast<const void *>(current), &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                current += 0x10000;
                continue;
            }

            const UINT64 next = reinterpret_cast<UINT64>(mbi.BaseAddress) + mbi.RegionSize;
            const UINT64 allocationBase = reinterpret_cast<UINT64>(mbi.AllocationBase);
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE && allocationBase != 0 &&
                seenBases.insert(allocationBase).second)
            {
                wchar_t mappedPath[1024]{};
                if (getMappedFileName(
                        process, reinterpret_cast<void *>(allocationBase), mappedPath, RTL_NUMBER_OF(mappedPath)) != 0)
                {
                    mappedPath[RTL_NUMBER_OF(mappedPath) - 1] = L'\0';
                    if (_wcsicmp(WideBaseName(mappedPath).c_str(), baseName.c_str()) == 0)
                    {
                        base = allocationBase;
                        return true;
                    }
                }
            }

            if (next <= current)
            {
                break;
            }
            current = next;
        }

        return false;
    }

    bool ResolveRemoteAddressForLocalProc(HANDLE process,
                                          FARPROC localProc,
                                          UINT64 &remoteAddress,
                                          std::wstring *moduleNameOut)
    {
        remoteAddress = 0;
        if (localProc == nullptr)
        {
            return false;
        }

        HMODULE localOwner = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(localProc),
                                &localOwner) ||
            localOwner == nullptr)
        {
            return false;
        }

        wchar_t ownerPath[MAX_PATH]{};
        if (GetModuleFileNameW(localOwner, ownerPath, RTL_NUMBER_OF(ownerPath)) == 0)
        {
            return false;
        }
        ownerPath[RTL_NUMBER_OF(ownerPath) - 1] = L'\0';

        std::wstring ownerBaseName = WideBaseName(ownerPath);
        UINT64 remoteModuleBase = 0;
        if (!GetRemoteModuleBase(GetProcessId(process), ownerBaseName, remoteModuleBase) || remoteModuleBase == 0)
        {
            MEMORY_BASIC_INFORMATION remoteMbi{};
            if (VirtualQueryEx(process, localOwner, &remoteMbi, sizeof(remoteMbi)) == sizeof(remoteMbi) &&
                remoteMbi.State == MEM_COMMIT && remoteMbi.Type == MEM_IMAGE && remoteMbi.AllocationBase == localOwner)
            {
                remoteAddress = reinterpret_cast<UINT64>(localProc);
                if (moduleNameOut != nullptr)
                {
                    *moduleNameOut = ownerBaseName;
                }
                return true;
            }
            if (FindRemoteMappedImageBaseByName(process, ownerBaseName, remoteModuleBase) && remoteModuleBase != 0)
            {
                remoteAddress =
                    remoteModuleBase + (reinterpret_cast<UINT64>(localProc) - reinterpret_cast<UINT64>(localOwner));
                if (moduleNameOut != nullptr)
                {
                    *moduleNameOut = ownerBaseName;
                }
                return true;
            }
            if (moduleNameOut != nullptr)
            {
                *moduleNameOut = ownerBaseName;
            }
            return false;
        }

        remoteAddress = remoteModuleBase + (reinterpret_cast<UINT64>(localProc) - reinterpret_cast<UINT64>(localOwner));
        if (moduleNameOut != nullptr)
        {
            *moduleNameOut = ownerBaseName;
        }
        return true;
    }

    bool ResolveImports(ServerContext &ctx, HANDLE process, MappedImage &mapped)
    {
        auto *nt = ImageNtHeaders64(mapped.Image);
        if (nt == nullptr)
        {
            return Fail(ctx, "cannot resolve imports for invalid image");
        }

        const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0)
        {
            return true;
        }
        if (!ImageRangeValid(mapped.Image.size(), dir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
        {
            return Fail(ctx, "import directory lies outside image");
        }

        const DWORD descriptorCount = dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (descriptorCount == 0)
        {
            return Fail(ctx, "import directory has no complete descriptors");
        }

        for (DWORD descriptorIndex = 0; descriptorIndex < descriptorCount; ++descriptorIndex)
        {
            auto *descriptor = ImageRvaPtr<IMAGE_IMPORT_DESCRIPTOR>(
                mapped.Image, dir.VirtualAddress + descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (descriptor == nullptr)
            {
                return Fail(ctx, "import descriptor is truncated");
            }
            if (descriptor->OriginalFirstThunk == 0 && descriptor->FirstThunk == 0 && descriptor->Name == 0)
            {
                break;
            }

            const char *dllName = ImageRvaString(mapped.Image, descriptor->Name);
            if (dllName == nullptr)
            {
                return Fail(ctx, "import DLL name is invalid");
            }

            HMODULE localImport = LoadLocalImportModule(dllName);
            if (localImport == nullptr)
            {
                HostDebugLog(
                    ctx, "manual-map: local import module load failed name=%s gle=%lu", dllName, GetLastError());
                return Fail(ctx, "failed to resolve an import module locally");
            }

            DWORD lookupRva =
                descriptor->OriginalFirstThunk != 0 ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
            DWORD iatRva = descriptor->FirstThunk;
            if (lookupRva == 0 || iatRva == 0)
            {
                return Fail(ctx, "import thunk table is invalid");
            }

            for (DWORD thunkIndex = 0; thunkIndex < 65536; ++thunkIndex)
            {
                const DWORD lookupOffset = thunkIndex * sizeof(IMAGE_THUNK_DATA64);
                if (lookupOffset > MAXDWORD - lookupRva || lookupOffset > MAXDWORD - iatRva)
                {
                    return Fail(ctx, "import thunk table offset overflowed");
                }

                auto *lookup = ImageRvaPtr<IMAGE_THUNK_DATA64>(mapped.Image, lookupRva + lookupOffset);
                auto *iat = ImageRvaPtr<IMAGE_THUNK_DATA64>(mapped.Image, iatRva + lookupOffset);
                if (lookup == nullptr || iat == nullptr)
                {
                    return Fail(ctx, "import thunk is truncated");
                }
                if (lookup->u1.AddressOfData == 0)
                {
                    break;
                }

                FARPROC localProc = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal))
                {
                    WORD ordinal = static_cast<WORD>(IMAGE_ORDINAL64(lookup->u1.Ordinal));
                    localProc = GetProcAddress(localImport, MAKEINTRESOURCEA(ordinal));
                }
                else
                {
                    auto *byName =
                        ImageRvaPtr<IMAGE_IMPORT_BY_NAME>(mapped.Image, static_cast<DWORD>(lookup->u1.AddressOfData));
                    if (byName == nullptr)
                    {
                        return Fail(ctx, "named import lies outside image");
                    }
                    const char *procName = ImageRvaString(
                        mapped.Image,
                        static_cast<DWORD>(lookup->u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name)));
                    if (procName == nullptr)
                    {
                        return Fail(ctx, "named import string is invalid");
                    }
                    localProc = GetProcAddress(localImport, procName);
                }

                if (localProc == nullptr)
                {
                    HostDebugLog(
                        ctx, "manual-map: local import proc resolve failed dll=%s gle=%lu", dllName, GetLastError());
                    return Fail(ctx, "failed to resolve an import procedure locally");
                }

                UINT64 remoteProc = 0;
                std::wstring ownerName;
                if (!ResolveRemoteAddressForLocalProc(process, localProc, remoteProc, &ownerName) || remoteProc == 0)
                {
                    char ownerText[MAX_PATH]{};
                    if (!ownerName.empty())
                    {
                        (void)WideCharToMultiByte(
                            CP_UTF8, 0, ownerName.c_str(), -1, ownerText, RTL_NUMBER_OF(ownerText), nullptr, nullptr);
                    }
                    HostDebugLog(ctx,
                                 "manual-map: import owner not loaded in child dll=%s owner=%s",
                                 dllName,
                                 ownerText[0] != '\0' ? ownerText : "<unknown>");
                    return Fail(ctx, "an import dependency is not loaded in the child process");
                }
                iat->u1.Function = remoteProc;
            }
        }

        return true;
    }
} // namespace blind::mapper
