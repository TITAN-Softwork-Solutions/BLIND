#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    void CopyLiteralWide(wchar_t buffer[32], const wchar_t *value) noexcept
    {
        if (buffer == nullptr)
        {
            return;
        }

        buffer[0] = L'\0';
        if (value == nullptr)
        {
            return;
        }

        (void)wcsncpy_s(buffer, 32, value, _TRUNCATE);
    }

    bool TryFormatGuid(const GUID *guid, wchar_t buffer[32]) noexcept
    {
        if (buffer == nullptr)
        {
            return false;
        }

        buffer[0] = L'\0';
        if (guid == nullptr)
        {
            return false;
        }

        __try
        {
            int chars = swprintf_s(buffer,
                                   32,
                                   L"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX",
                                   static_cast<unsigned long>(guid->Data1),
                                   guid->Data2,
                                   guid->Data3,
                                   guid->Data4[0],
                                   guid->Data4[1],
                                   guid->Data4[2],
                                   guid->Data4[3],
                                   guid->Data4[4],
                                   guid->Data4[5]);
            return chars > 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            buffer[0] = L'\0';
            return false;
        }
    }

    void FormatCoInitMode(DWORD coInit, wchar_t buffer[32]) noexcept
    {
        switch (coInit & 0x3u)
        {
        case COINIT_APARTMENTTHREADED:
            CopyLiteralWide(buffer, L"STA");
            break;
        case COINIT_MULTITHREADED:
            CopyLiteralWide(buffer, L"MTA");
            break;
        default:
            CopyLiteralWide(buffer, L"COINIT");
            break;
        }
    }

    void FormatJobInfoClass(JOBOBJECTINFOCLASS infoClass, wchar_t buffer[32]) noexcept
    {
        switch (infoClass)
        {
        case JobObjectBasicLimitInformation:
            CopyLiteralWide(buffer, L"BasicLimit");
            break;
        case JobObjectBasicUIRestrictions:
            CopyLiteralWide(buffer, L"UiRestrictions");
            break;
        case JobObjectAssociateCompletionPortInformation:
            CopyLiteralWide(buffer, L"CompletionPort");
            break;
        case JobObjectExtendedLimitInformation:
            CopyLiteralWide(buffer, L"ExtendedLimit");
            break;
        case JobObjectCpuRateControlInformation:
            CopyLiteralWide(buffer, L"CpuRate");
            break;
        case JobObjectNotificationLimitInformation:
            CopyLiteralWide(buffer, L"NotifyLimit");
            break;
        case JobObjectNotificationLimitInformation2:
            CopyLiteralWide(buffer, L"NotifyLimit2");
            break;
        case JobObjectSecurityLimitInformation:
            CopyLiteralWide(buffer, L"SecurityLimit");
            break;
        default:
            CopyLiteralWide(buffer, L"JobInfo");
            break;
        }
    }

    void PublishModuleEvent(ModuleHookOperation operation,
                            const char *functionName,
                            const char *sourceModule,
                            HMODULE moduleHandle,
                            const void *nameBuffer,
                            std::size_t nameLength,
                            std::uint64_t arg0,
                            std::uint64_t arg1,
                            std::uint64_t arg2,
                            std::uint64_t arg3,
                            void *caller) noexcept
    {
        if (IsModuleHookReentered() || IxIsInternalCall() || g_ActiveCallback == nullptr)
        {
            return;
        }

        ModuleHookReentryScope hookScope;
        if (!hookScope.Active)
        {
            return;
        }
        IxInternalScope internalScope;
        if (moduleHandle != nullptr)
        {
            IX_RUNTIME_INTERNAL::ObserveLoadedModuleForNtdllEatGuard(moduleHandle, nameBuffer, nameLength, caller);
            (void)IX_RUNTIME_INTERNAL::MaybeInitializeWinsockHookController();
            bool refreshedHooks = IxRefreshWinsockHooks(moduleHandle);
            refreshedHooks = IxRefreshModuleHooks(moduleHandle) || refreshedHooks;
            if (refreshedHooks)
            {
                IX_RUNTIME_INTERNAL::RegisterIxHookPatchOverlays();
            }
        }

        ModuleHookContext context{};
        context.Operation = operation;
        context.FunctionName = functionName;
        context.SourceModule = sourceModule;
        context.Caller = caller != nullptr ? caller : _ReturnAddress();
        context.ModuleHandle = moduleHandle;
        context.NameBuffer = nameBuffer;
        context.NameLength = nameLength;
        context.Args[0] = arg0;
        context.Args[1] = arg1;
        context.Args[2] = arg2;
        context.Args[3] = arg3;
        g_ActiveCallback(context);
    }

    std::size_t CopyAnsiLength(LPCSTR value) noexcept
    {
        return (value != nullptr) ? strnlen_s(value, 31) : 0;
    }

    std::size_t CopyWideLength(LPCWSTR value) noexcept
    {
        std::size_t chars = 0;
        if (value != nullptr)
        {
            while (value[chars] != L'\0' && chars < 31)
            {
                ++chars;
            }
        }
        return chars * sizeof(wchar_t);
    }

    bool WideContainsInsensitive(const wchar_t *value, const wchar_t *needle) noexcept
    {
        if (value == nullptr || needle == nullptr || *needle == L'\0')
        {
            return false;
        }

        std::size_t needleLen = wcslen(needle);
        for (std::size_t i = 0; value[i] != L'\0'; ++i)
        {
            if (_wcsnicmp(value + i, needle, needleLen) == 0)
            {
                return true;
            }
        }

        return false;
    }

    bool LooksSensitiveName(const wchar_t *value) noexcept
    {
        return WideContainsInsensitive(value, L"password") || WideContainsInsensitive(value, L"passwd") ||
               WideContainsInsensitive(value, L"secret") || WideContainsInsensitive(value, L"token") ||
               WideContainsInsensitive(value, L"cookie") || WideContainsInsensitive(value, L"privatekey");
    }

    void CopyRedactedWide(wchar_t buffer[32], LPCWSTR value) noexcept
    {
        buffer[0] = L'\0';
        if (value == nullptr)
        {
            return;
        }

        __try
        {
            std::size_t i = 0;
            for (; i < 31 && value[i] != L'\0'; ++i)
            {
                wchar_t ch = value[i];
                buffer[i] = (ch < 0x20 || ch == L'\x7F') ? L'?' : ch;
            }
            buffer[i] = L'\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            CopyLiteralWide(buffer, L"<invalid>");
        }

        if (LooksSensitiveName(buffer))
        {
            CopyLiteralWide(buffer, L"<redacted>");
        }
    }

    void CopyRedactedAnsiToWide(wchar_t buffer[32], LPCSTR value) noexcept
    {
        buffer[0] = L'\0';
        if (value == nullptr)
        {
            return;
        }

        __try
        {
            std::size_t i = 0;
            for (; i < 31 && value[i] != '\0'; ++i)
            {
                unsigned char ch = static_cast<unsigned char>(value[i]);
                buffer[i] = (ch < 0x20 || ch == 0x7F) ? L'?' : static_cast<wchar_t>(ch);
            }
            buffer[i] = L'\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            CopyLiteralWide(buffer, L"<invalid>");
        }

        if (LooksSensitiveName(buffer))
        {
            CopyLiteralWide(buffer, L"<redacted>");
        }
    }

    void CopyLsaStringToWide(wchar_t buffer[32], PLSA_STRING value) noexcept
    {
        buffer[0] = L'\0';
        if (value == nullptr)
        {
            return;
        }

        __try
        {
            if (value->Buffer == nullptr || value->Length == 0)
            {
                return;
            }

            std::size_t chars = value->Length;
            if (chars > 31)
            {
                chars = 31;
            }
            for (std::size_t i = 0; i < chars; ++i)
            {
                unsigned char ch = static_cast<unsigned char>(value->Buffer[i]);
                buffer[i] = (ch < 0x20 || ch == 0x7F) ? L'?' : static_cast<wchar_t>(ch);
            }
            buffer[chars] = L'\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            CopyLiteralWide(buffer, L"<invalid>");
        }
    }

    void CopyLsaUnicodeStringToWide(wchar_t buffer[32], PLSA_UNICODE_STRING value) noexcept
    {
        buffer[0] = L'\0';
        if (value == nullptr)
        {
            return;
        }

        __try
        {
            if (value->Buffer == nullptr || value->Length == 0)
            {
                return;
            }

            std::size_t chars = value->Length / sizeof(wchar_t);
            if (chars > 31)
            {
                chars = 31;
            }
            for (std::size_t i = 0; i < chars; ++i)
            {
                wchar_t ch = value->Buffer[i];
                buffer[i] = (ch < 0x20 || ch == L'\x7F') ? L'?' : ch;
            }
            buffer[chars] = L'\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            CopyLiteralWide(buffer, L"<invalid>");
        }

        if (LooksSensitiveName(buffer))
        {
            CopyLiteralWide(buffer, L"<redacted>");
        }
    }

    std::uint32_t SafeReadDword(const DWORD *value) noexcept
    {
        if (value == nullptr)
        {
            return 0;
        }

        __try
        {
            return *value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    std::uint32_t SafeReadUlong(const ULONG *value) noexcept
    {
        if (value == nullptr)
        {
            return 0;
        }

        __try
        {
            return *value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    NTSTATUS SafeReadNtStatus(const NTSTATUS *value) noexcept
    {
        if (value == nullptr)
        {
            return 0;
        }

        __try
        {
            return *value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    void *SafeReadPointer(void *const *value) noexcept
    {
        if (value == nullptr)
        {
            return nullptr;
        }

        __try
        {
            return *value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    std::uint32_t SafeReadFirstU32(const void *buffer, ULONG length) noexcept
    {
        if (buffer == nullptr || length < sizeof(std::uint32_t))
        {
            return 0;
        }

        __try
        {
            return *reinterpret_cast<const std::uint32_t *>(buffer);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    std::uint32_t SafeBlobSize(const DATA_BLOB *blob) noexcept
    {
        if (blob == nullptr)
        {
            return 0;
        }

        __try
        {
            return blob->cbData;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    struct LsaPackageCacheEntry
    {
        ULONG PackageId;
        wchar_t Name[32];
        bool Valid;
    };

    SRWLOCK g_LsaPackageCacheLock = SRWLOCK_INIT;
    LsaPackageCacheEntry g_LsaPackageCache[16]{};
    std::uint32_t g_LsaPackageCacheNext = 0;

    void StoreLsaPackageName(ULONG packageId, const wchar_t *name) noexcept
    {
        if (name == nullptr || name[0] == L'\0')
        {
            return;
        }

        AcquireSRWLockExclusive(&g_LsaPackageCacheLock);
        std::size_t slot = g_LsaPackageCacheNext % RTL_NUMBER_OF(g_LsaPackageCache);
        g_LsaPackageCacheNext += 1;
        g_LsaPackageCache[slot].PackageId = packageId;
        (void)wcsncpy_s(g_LsaPackageCache[slot].Name, name, _TRUNCATE);
        g_LsaPackageCache[slot].Valid = true;
        ReleaseSRWLockExclusive(&g_LsaPackageCacheLock);
    }

    void LookupLsaPackageName(ULONG packageId, wchar_t buffer[32]) noexcept
    {
        CopyLiteralWide(buffer, L"Package");
        AcquireSRWLockShared(&g_LsaPackageCacheLock);
        for (std::size_t i = 0; i < RTL_NUMBER_OF(g_LsaPackageCache); ++i)
        {
            if (g_LsaPackageCache[i].Valid && g_LsaPackageCache[i].PackageId == packageId)
            {
                (void)wcsncpy_s(buffer, 32, g_LsaPackageCache[i].Name, _TRUNCATE);
                break;
            }
        }
        ReleaseSRWLockShared(&g_LsaPackageCacheLock);
    }
} // namespace IX_MODULE_INTERNAL
