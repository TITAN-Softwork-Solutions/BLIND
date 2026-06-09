#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    ModuleHookInitFault g_LastModuleHookInitFault{};

    void ResetModuleHookInitFault() noexcept
    {
        std::memset(&g_LastModuleHookInitFault, 0, sizeof(g_LastModuleHookInitFault));
        g_LastModuleHookInitFault.Code = ModuleHookInitFaultCode::None;
    }

    void CaptureFaultSample(const void *address, std::uint8_t sample[16]) noexcept
    {
        std::memset(sample, 0, 16);
        if (address == nullptr)
        {
            return;
        }

        __try
        {
            std::memcpy(sample, address, 16);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(sample, 0, 16);
        }
    }

    void SetModuleHookInitFault(ModuleHookInitFaultCode code,
                                const wchar_t *moduleName,
                                const char *exportName,
                                void *address,
                                void *redirectTarget) noexcept
    {
        ResetModuleHookInitFault();
        g_LastModuleHookInitFault.Code = code;
        g_LastModuleHookInitFault.ModuleName = moduleName;
        g_LastModuleHookInitFault.ExportName = exportName;
        g_LastModuleHookInitFault.Address = address;
        g_LastModuleHookInitFault.RedirectTarget = redirectTarget;
        CaptureFaultSample(address, g_LastModuleHookInitFault.Sample);
    }

    bool TryResolveModuleImageRange(HMODULE module, ModuleRange &range) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
        {
            return false;
        }

        range.Base = reinterpret_cast<std::uintptr_t>(module);
        range.End = range.Base + nt->OptionalHeader.SizeOfImage;
        return true;
    }

    bool AddressWithinRange(void *address, const ModuleRange &range) noexcept
    {
        std::uintptr_t value = reinterpret_cast<std::uintptr_t>(address);
        return value >= range.Base && value < range.End;
    }

    bool TryDecodeAbsoluteTarget(void *entry, void *&target) noexcept
    {
        target = nullptr;
        if (entry == nullptr)
        {
            return false;
        }

        auto *bytes = static_cast<std::uint8_t *>(entry);
        __try
        {
            if (bytes[0] == 0xE9)
            {
                std::int32_t rel = *reinterpret_cast<std::int32_t *>(&bytes[1]);
                target = bytes + 5 + rel;
                return true;
            }

            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
                std::int32_t disp = *reinterpret_cast<std::int32_t *>(&bytes[2]);
                auto **slot = reinterpret_cast<void **>(bytes + 6 + disp);
                target = *slot;
                return true;
            }

            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
            {
                target = *reinterpret_cast<void **>(&bytes[2]);
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            target = nullptr;
            return false;
        }

        return false;
    }

    ModuleHookCallback g_ActiveCallback = nullptr;
    volatile LONG g_ModuleHookTls = static_cast<LONG>(TLS_OUT_OF_INDEXES);

    DWORD EnsureModuleHookTls() noexcept
    {
        LONG current = InterlockedCompareExchange(&g_ModuleHookTls, 0, 0);
        if (current != static_cast<LONG>(TLS_OUT_OF_INDEXES))
        {
            return static_cast<DWORD>(current);
        }

        DWORD created = TlsAlloc();
        if (created == TLS_OUT_OF_INDEXES)
        {
            return TLS_OUT_OF_INDEXES;
        }

        LONG previous = InterlockedCompareExchange(
            &g_ModuleHookTls, static_cast<LONG>(created), static_cast<LONG>(TLS_OUT_OF_INDEXES));
        if (previous != static_cast<LONG>(TLS_OUT_OF_INDEXES))
        {
            TlsFree(created);
            return static_cast<DWORD>(previous);
        }
        return created;
    }

    bool IsModuleHookReentered() noexcept
    {
        LONG current = InterlockedCompareExchange(&g_ModuleHookTls, 0, 0);
        if (current == static_cast<LONG>(TLS_OUT_OF_INDEXES))
        {
            return false;
        }
        return TlsGetValue(static_cast<DWORD>(current)) != nullptr;
    }

    ModuleHookReentryScope::ModuleHookReentryScope() noexcept
    {
        DWORD tls = EnsureModuleHookTls();
        if (tls == TLS_OUT_OF_INDEXES || TlsGetValue(tls) != nullptr)
        {
            return;
        }

        Active = TlsSetValue(tls, reinterpret_cast<void *>(1)) != FALSE;
    }

    ModuleHookReentryScope::~ModuleHookReentryScope() noexcept
    {
        if (!Active)
        {
            return;
        }

        LONG current = InterlockedCompareExchange(&g_ModuleHookTls, 0, 0);
        if (current != static_cast<LONG>(TLS_OUT_OF_INDEXES))
        {
            TlsSetValue(static_cast<DWORD>(current), nullptr);
        }
    }
    LoadLibraryAFn g_OriginalLoadLibraryA = nullptr;
    LoadLibraryWFn g_OriginalLoadLibraryW = nullptr;
    LoadLibraryExAFn g_OriginalLoadLibraryExA = nullptr;
    LoadLibraryExWFn g_OriginalLoadLibraryExW = nullptr;
    LdrLoadDllFn g_OriginalLdrLoadDll = nullptr;
    RtlAddFunctionTableFn g_OriginalRtlAddFunctionTable = nullptr;
    RtlInstallFunctionTableCallbackFn g_OriginalRtlInstallFunctionTableCallback = nullptr;
    RtlDeleteFunctionTableFn g_OriginalRtlDeleteFunctionTable = nullptr;
    RtlAddVectoredExceptionHandlerFn g_OriginalRtlAddVectoredExceptionHandler = nullptr;
    RtlRemoveVectoredExceptionHandlerFn g_OriginalRtlRemoveVectoredExceptionHandler = nullptr;
    SetUnhandledExceptionFilterFn g_OriginalSetUnhandledExceptionFilter = nullptr;
    CoInitializeExFn g_OriginalCoInitializeEx = nullptr;
    CoInitializeSecurityFn g_OriginalCoInitializeSecurity = nullptr;
    CoCreateInstanceFn g_OriginalCoCreateInstance = nullptr;
    EventRegisterFn g_OriginalEventRegister = nullptr;
    EventUnregisterFn g_OriginalEventUnregister = nullptr;
    StartTraceWFn g_OriginalStartTraceW = nullptr;
    EnableTraceEx2Fn g_OriginalEnableTraceEx2 = nullptr;
    EtwEventWriteFn g_OriginalEtwEventWrite = nullptr;
    EtwEventWriteExFn g_OriginalEtwEventWriteEx = nullptr;
    EtwEventWriteFullFn g_OriginalEtwEventWriteFull = nullptr;
    EtwEventWriteTransferFn g_OriginalEtwEventWriteTransfer = nullptr;
    CreateJobObjectWFn g_OriginalCreateJobObjectW = nullptr;
    OpenJobObjectWFn g_OriginalOpenJobObjectW = nullptr;
    AssignProcessToJobObjectFn g_OriginalAssignProcessToJobObject = nullptr;
    SetInformationJobObjectFn g_OriginalSetInformationJobObject = nullptr;
    LsaConnectUntrustedFn g_OriginalLsaConnectUntrusted = nullptr;
    LsaLookupAuthenticationPackageFn g_OriginalLsaLookupAuthenticationPackage = nullptr;
    LsaCallAuthenticationPackageFn g_OriginalLsaCallAuthenticationPackage = nullptr;
    AcquireCredentialsHandleAFn g_OriginalAcquireCredentialsHandleA = nullptr;
    AcquireCredentialsHandleWFn g_OriginalAcquireCredentialsHandleW = nullptr;
    InitializeSecurityContextAFn g_OriginalInitializeSecurityContextA = nullptr;
    InitializeSecurityContextWFn g_OriginalInitializeSecurityContextW = nullptr;
    AcceptSecurityContextFn g_OriginalAcceptSecurityContext = nullptr;
    CredReadAFn g_OriginalCredReadA = nullptr;
    CredReadWFn g_OriginalCredReadW = nullptr;
    CredEnumerateAFn g_OriginalCredEnumerateA = nullptr;
    CredEnumerateWFn g_OriginalCredEnumerateW = nullptr;
    CredReadDomainCredentialsAFn g_OriginalCredReadDomainCredentialsA = nullptr;
    CredReadDomainCredentialsWFn g_OriginalCredReadDomainCredentialsW = nullptr;
    LsaOpenPolicyFn g_OriginalLsaOpenPolicy = nullptr;
    LsaQueryInformationPolicyFn g_OriginalLsaQueryInformationPolicy = nullptr;
    VaultEnumerateVaultsFn g_OriginalVaultEnumerateVaults = nullptr;
    VaultOpenVaultFn g_OriginalVaultOpenVault = nullptr;
    VaultEnumerateItemsFn g_OriginalVaultEnumerateItems = nullptr;
    VaultGetItemFn g_OriginalVaultGetItem = nullptr;
    CryptUnprotectDataFn g_OriginalCryptUnprotectData = nullptr;
    NCryptUnprotectSecretFn g_OriginalNCryptUnprotectSecret = nullptr;
    NCryptOpenStorageProviderFn g_OriginalNCryptOpenStorageProvider = nullptr;
    NCryptOpenKeyFn g_OriginalNCryptOpenKey = nullptr;
    NCryptDecryptFn g_OriginalNCryptDecrypt = nullptr;
    CfAbortOperationFn g_OriginalCfAbortOperation = nullptr;
    CfRegisterSyncRootFn g_OriginalCfRegisterSyncRoot = nullptr;
    CfConnectSyncRootFn g_OriginalCfConnectSyncRoot = nullptr;
    CfCreatePlaceholdersFn g_OriginalCfCreatePlaceholders = nullptr;
    AmsiInitializeFn g_OriginalAmsiInitialize = nullptr;
    AmsiUninitializeFn g_OriginalAmsiUninitialize = nullptr;
    AmsiOpenSessionFn g_OriginalAmsiOpenSession = nullptr;
    AmsiCloseSessionFn g_OriginalAmsiCloseSession = nullptr;
    AmsiScanBufferFn g_OriginalAmsiScanBuffer = nullptr;
    AmsiScanStringFn g_OriginalAmsiScanString = nullptr;
    AmsiNotifyOperationFn g_OriginalAmsiNotifyOperation = nullptr;
    WinHttpConnectFn g_OriginalWinHttpConnect = nullptr;
    WinHttpOpenRequestFn g_OriginalWinHttpOpenRequest = nullptr;
    WinHttpSendRequestFn g_OriginalWinHttpSendRequest = nullptr;
    InternetConnectWFn g_OriginalInternetConnectW = nullptr;
    InternetConnectAFn g_OriginalInternetConnectA = nullptr;
    HttpOpenRequestWFn g_OriginalHttpOpenRequestW = nullptr;
    HttpOpenRequestAFn g_OriginalHttpOpenRequestA = nullptr;
    HttpSendRequestWFn g_OriginalHttpSendRequestW = nullptr;
    HttpSendRequestAFn g_OriginalHttpSendRequestA = nullptr;
    EncryptMessageFn g_OriginalEncryptMessage = nullptr;
    DecryptMessageFn g_OriginalDecryptMessage = nullptr;

    InlineHook g_Hooks[] = {
#define IX_MODULE_HOOK(module_name, export_name, source_name, hook_proc, original_slot)                                \
    {module_name,                                                                                                      \
     export_name,                                                                                                      \
     source_name,                                                                                                      \
     reinterpret_cast<void *>(&hook_proc),                                                                             \
     reinterpret_cast<void **>(&original_slot),                                                                        \
     nullptr,                                                                                                          \
     nullptr,                                                                                                          \
     {},                                                                                                               \
     false}
        // Hook manifest grouped by provider surface.
        // IX_MODULE_HOOK(module, export, source, hook, original)
        IX_MODULE_HOOK(L"KernelBase.dll", "LoadLibraryA", "KERNELBASE", LoadLibraryAHook, g_OriginalLoadLibraryA),
        IX_MODULE_HOOK(L"KernelBase.dll", "LoadLibraryW", "KERNELBASE", LoadLibraryWHook, g_OriginalLoadLibraryW),
        IX_MODULE_HOOK(L"KernelBase.dll", "LoadLibraryExA", "KERNELBASE", LoadLibraryExAHook, g_OriginalLoadLibraryExA),
        IX_MODULE_HOOK(L"KernelBase.dll", "LoadLibraryExW", "KERNELBASE", LoadLibraryExWHook, g_OriginalLoadLibraryExW),
        IX_MODULE_HOOK(L"ntdll.dll", "LdrLoadDll", "ntdll", LdrLoadDllHook, g_OriginalLdrLoadDll),
        IX_MODULE_HOOK(
            L"ntdll.dll", "RtlAddFunctionTable", "ntdll", RtlAddFunctionTableHook, g_OriginalRtlAddFunctionTable),
        IX_MODULE_HOOK(L"ntdll.dll",
                       "RtlInstallFunctionTableCallback",
                       "ntdll",
                       RtlInstallFunctionTableCallbackHook,
                       g_OriginalRtlInstallFunctionTableCallback),
        IX_MODULE_HOOK(L"ntdll.dll",
                       "RtlDeleteFunctionTable",
                       "ntdll",
                       RtlDeleteFunctionTableHook,
                       g_OriginalRtlDeleteFunctionTable),
        IX_MODULE_HOOK(L"ntdll.dll",
                       "RtlAddVectoredExceptionHandler",
                       "ntdll",
                       RtlAddVectoredExceptionHandlerHook,
                       g_OriginalRtlAddVectoredExceptionHandler),
        IX_MODULE_HOOK(L"ntdll.dll",
                       "RtlRemoveVectoredExceptionHandler",
                       "ntdll",
                       RtlRemoveVectoredExceptionHandlerHook,
                       g_OriginalRtlRemoveVectoredExceptionHandler),
        IX_MODULE_HOOK(L"KernelBase.dll",
                       "SetUnhandledExceptionFilter",
                       "KernelBase",
                       SetUnhandledExceptionFilterHook,
                       g_OriginalSetUnhandledExceptionFilter),
        IX_MODULE_HOOK(L"combase.dll", "CoInitializeEx", "combase", CoInitializeExHook, g_OriginalCoInitializeEx),
        IX_MODULE_HOOK(L"combase.dll",
                       "CoInitializeSecurity",
                       "combase",
                       CoInitializeSecurityHook,
                       g_OriginalCoInitializeSecurity),
        IX_MODULE_HOOK(L"combase.dll", "CoCreateInstance", "combase", CoCreateInstanceHook, g_OriginalCoCreateInstance),
        IX_MODULE_HOOK(L"advapi32.dll", "EventRegister", "advapi32", EventRegisterHook, g_OriginalEventRegister),
        IX_MODULE_HOOK(L"advapi32.dll", "EventUnregister", "advapi32", EventUnregisterHook, g_OriginalEventUnregister),
        IX_MODULE_HOOK(L"advapi32.dll", "StartTraceW", "advapi32", StartTraceWHook, g_OriginalStartTraceW),
        IX_MODULE_HOOK(L"advapi32.dll", "EnableTraceEx2", "advapi32", EnableTraceEx2Hook, g_OriginalEnableTraceEx2),
        IX_MODULE_HOOK(L"ntdll.dll", "EtwEventWrite", "ntdll", EtwEventWriteHook, g_OriginalEtwEventWrite),
        IX_MODULE_HOOK(L"ntdll.dll", "EtwEventWriteEx", "ntdll", EtwEventWriteExHook, g_OriginalEtwEventWriteEx),
        IX_MODULE_HOOK(L"ntdll.dll", "EtwEventWriteFull", "ntdll", EtwEventWriteFullHook, g_OriginalEtwEventWriteFull),
        IX_MODULE_HOOK(
            L"ntdll.dll", "EtwEventWriteTransfer", "ntdll", EtwEventWriteTransferHook, g_OriginalEtwEventWriteTransfer),
        IX_MODULE_HOOK(
            L"kernel32.dll", "CreateJobObjectW", "KERNEL32", CreateJobObjectWHook, g_OriginalCreateJobObjectW),
        IX_MODULE_HOOK(L"kernel32.dll", "OpenJobObjectW", "KERNEL32", OpenJobObjectWHook, g_OriginalOpenJobObjectW),
        IX_MODULE_HOOK(L"kernel32.dll",
                       "AssignProcessToJobObject",
                       "KERNEL32",
                       AssignProcessToJobObjectHook,
                       g_OriginalAssignProcessToJobObject),
        IX_MODULE_HOOK(L"kernel32.dll",
                       "SetInformationJobObject",
                       "KERNEL32",
                       SetInformationJobObjectHook,
                       g_OriginalSetInformationJobObject),
        IX_MODULE_HOOK(
            L"sspicli.dll", "LsaConnectUntrusted", "sspicli", LsaConnectUntrustedHook, g_OriginalLsaConnectUntrusted),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "LsaLookupAuthenticationPackage",
                       "sspicli",
                       LsaLookupAuthenticationPackageHook,
                       g_OriginalLsaLookupAuthenticationPackage),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "LsaCallAuthenticationPackage",
                       "sspicli",
                       LsaCallAuthenticationPackageHook,
                       g_OriginalLsaCallAuthenticationPackage),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "AcquireCredentialsHandleA",
                       "sspicli",
                       AcquireCredentialsHandleAHook,
                       g_OriginalAcquireCredentialsHandleA),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "AcquireCredentialsHandleW",
                       "sspicli",
                       AcquireCredentialsHandleWHook,
                       g_OriginalAcquireCredentialsHandleW),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "InitializeSecurityContextA",
                       "sspicli",
                       InitializeSecurityContextAHook,
                       g_OriginalInitializeSecurityContextA),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "InitializeSecurityContextW",
                       "sspicli",
                       InitializeSecurityContextWHook,
                       g_OriginalInitializeSecurityContextW),
        IX_MODULE_HOOK(L"sspicli.dll",
                       "AcceptSecurityContext",
                       "sspicli",
                       AcceptSecurityContextHook,
                       g_OriginalAcceptSecurityContext),
        IX_MODULE_HOOK(L"advapi32.dll", "CredReadA", "advapi32", CredReadAHook, g_OriginalCredReadA),
        IX_MODULE_HOOK(L"advapi32.dll", "CredReadW", "advapi32", CredReadWHook, g_OriginalCredReadW),
        IX_MODULE_HOOK(L"advapi32.dll", "CredEnumerateA", "advapi32", CredEnumerateAHook, g_OriginalCredEnumerateA),
        IX_MODULE_HOOK(L"advapi32.dll", "CredEnumerateW", "advapi32", CredEnumerateWHook, g_OriginalCredEnumerateW),
        IX_MODULE_HOOK(L"advapi32.dll",
                       "CredReadDomainCredentialsA",
                       "advapi32",
                       CredReadDomainCredentialsAHook,
                       g_OriginalCredReadDomainCredentialsA),
        IX_MODULE_HOOK(L"advapi32.dll",
                       "CredReadDomainCredentialsW",
                       "advapi32",
                       CredReadDomainCredentialsWHook,
                       g_OriginalCredReadDomainCredentialsW),
        IX_MODULE_HOOK(L"advapi32.dll", "LsaOpenPolicy", "advapi32", LsaOpenPolicyHook, g_OriginalLsaOpenPolicy),
        IX_MODULE_HOOK(L"advapi32.dll",
                       "LsaQueryInformationPolicy",
                       "advapi32",
                       LsaQueryInformationPolicyHook,
                       g_OriginalLsaQueryInformationPolicy),
        IX_MODULE_HOOK(L"vaultcli.dll",
                       "VaultEnumerateVaults",
                       "vaultcli",
                       VaultEnumerateVaultsHook,
                       g_OriginalVaultEnumerateVaults),
        IX_MODULE_HOOK(L"vaultcli.dll", "VaultOpenVault", "vaultcli", VaultOpenVaultHook, g_OriginalVaultOpenVault),
        IX_MODULE_HOOK(
            L"vaultcli.dll", "VaultEnumerateItems", "vaultcli", VaultEnumerateItemsHook, g_OriginalVaultEnumerateItems),
        IX_MODULE_HOOK(L"vaultcli.dll", "VaultGetItem", "vaultcli", VaultGetItemHook, g_OriginalVaultGetItem),
        IX_MODULE_HOOK(
            L"crypt32.dll", "CryptUnprotectData", "crypt32", CryptUnprotectDataHook, g_OriginalCryptUnprotectData),
        IX_MODULE_HOOK(L"ncrypt.dll",
                       "NCryptUnprotectSecret",
                       "ncrypt",
                       NCryptUnprotectSecretHook,
                       g_OriginalNCryptUnprotectSecret),
        IX_MODULE_HOOK(L"ncrypt.dll",
                       "NCryptOpenStorageProvider",
                       "ncrypt",
                       NCryptOpenStorageProviderHook,
                       g_OriginalNCryptOpenStorageProvider),
        IX_MODULE_HOOK(L"ncrypt.dll", "NCryptOpenKey", "ncrypt", NCryptOpenKeyHook, g_OriginalNCryptOpenKey),
        IX_MODULE_HOOK(L"ncrypt.dll", "NCryptDecrypt", "ncrypt", NCryptDecryptHook, g_OriginalNCryptDecrypt),
        IX_MODULE_HOOK(L"cldapi.dll", "CfAbortOperation", "cldapi", CfAbortOperationHook, g_OriginalCfAbortOperation),
        IX_MODULE_HOOK(
            L"cldapi.dll", "CfRegisterSyncRoot", "cldapi", CfRegisterSyncRootHook, g_OriginalCfRegisterSyncRoot),
        IX_MODULE_HOOK(
            L"cldapi.dll", "CfConnectSyncRoot", "cldapi", CfConnectSyncRootHook, g_OriginalCfConnectSyncRoot),
        IX_MODULE_HOOK(
            L"cldapi.dll", "CfCreatePlaceholders", "cldapi", CfCreatePlaceholdersHook, g_OriginalCfCreatePlaceholders),
        IX_MODULE_HOOK(L"amsi.dll", "AmsiInitialize", "amsi", AmsiInitializeHook, g_OriginalAmsiInitialize),
        IX_MODULE_HOOK(L"amsi.dll", "AmsiUninitialize", "amsi", AmsiUninitializeHook, g_OriginalAmsiUninitialize),
        IX_MODULE_HOOK(L"amsi.dll", "AmsiOpenSession", "amsi", AmsiOpenSessionHook, g_OriginalAmsiOpenSession),
        IX_MODULE_HOOK(L"amsi.dll", "AmsiCloseSession", "amsi", AmsiCloseSessionHook, g_OriginalAmsiCloseSession),
        IX_MODULE_HOOK(L"amsi.dll", "AmsiScanBuffer", "amsi", AmsiScanBufferHook, g_OriginalAmsiScanBuffer),
        IX_MODULE_HOOK(L"amsi.dll", "AmsiScanString", "amsi", AmsiScanStringHook, g_OriginalAmsiScanString),
        IX_MODULE_HOOK(
            L"amsi.dll", "AmsiNotifyOperation", "amsi", AmsiNotifyOperationHook, g_OriginalAmsiNotifyOperation),
        IX_MODULE_HOOK(L"winhttp.dll", "WinHttpConnect", "winhttp", WinHttpConnectHook, g_OriginalWinHttpConnect),
        IX_MODULE_HOOK(
            L"winhttp.dll", "WinHttpOpenRequest", "winhttp", WinHttpOpenRequestHook, g_OriginalWinHttpOpenRequest),
        IX_MODULE_HOOK(
            L"winhttp.dll", "WinHttpSendRequest", "winhttp", WinHttpSendRequestHook, g_OriginalWinHttpSendRequest),
        IX_MODULE_HOOK(L"wininet.dll", "InternetConnectW", "wininet", InternetConnectWHook, g_OriginalInternetConnectW),
        IX_MODULE_HOOK(L"wininet.dll", "InternetConnectA", "wininet", InternetConnectAHook, g_OriginalInternetConnectA),
        IX_MODULE_HOOK(L"wininet.dll", "HttpOpenRequestW", "wininet", HttpOpenRequestWHook, g_OriginalHttpOpenRequestW),
        IX_MODULE_HOOK(L"wininet.dll", "HttpOpenRequestA", "wininet", HttpOpenRequestAHook, g_OriginalHttpOpenRequestA),
        IX_MODULE_HOOK(L"wininet.dll", "HttpSendRequestW", "wininet", HttpSendRequestWHook, g_OriginalHttpSendRequestW),
        IX_MODULE_HOOK(L"wininet.dll", "HttpSendRequestA", "wininet", HttpSendRequestAHook, g_OriginalHttpSendRequestA),
        IX_MODULE_HOOK(L"secur32.dll", "EncryptMessage", "secur32", EncryptMessageHook, g_OriginalEncryptMessage),
        IX_MODULE_HOOK(L"secur32.dll", "DecryptMessage", "secur32", DecryptMessageHook, g_OriginalDecryptMessage),
#undef IX_MODULE_HOOK
    };

    extern const GUID CLSID_WbemLocatorValue = {
        0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};

    const std::size_t g_HookCount = RTL_NUMBER_OF(g_Hooks);
} // namespace IX_MODULE_INTERNAL
