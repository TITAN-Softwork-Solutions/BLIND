#pragma once

#include <cstddef>
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

enum class ModuleHookOperation : std::uint32_t
{
    LoadLibraryA = 0,
    LoadLibraryW = 1,
    LoadLibraryExA = 2,
    LoadLibraryExW = 3,
    LdrLoadDll = 4,
    RtlAddFunctionTable = 5,
    RtlInstallFunctionTableCallback = 6,
    RtlDeleteFunctionTable = 7,
    CoInitializeEx = 8,
    CoInitializeSecurity = 9,
    CoCreateInstance = 10,
    EventRegister = 11,
    EventUnregister = 12,
    StartTraceW = 13,
    EnableTraceEx2 = 14,
    EtwEventWrite = 15,
    EtwEventWriteEx = 16,
    EtwEventWriteFull = 17,
    EtwEventWriteTransfer = 18,
    CreateJobObjectW = 19,
    OpenJobObjectW = 20,
    AssignProcessToJobObject = 21,
    SetInformationJobObject = 22,
    LsaConnectUntrusted = 23,
    LsaLookupAuthenticationPackage = 24,
    LsaCallAuthenticationPackage = 25,
    AcquireCredentialsHandleA = 26,
    AcquireCredentialsHandleW = 27,
    InitializeSecurityContextA = 28,
    InitializeSecurityContextW = 29,
    AcceptSecurityContext = 30,
    CredReadA = 31,
    CredReadW = 32,
    CredEnumerateA = 33,
    CredEnumerateW = 34,
    CredReadDomainCredentialsA = 35,
    CredReadDomainCredentialsW = 36,
    LsaOpenPolicy = 37,
    LsaQueryInformationPolicy = 38,
    VaultEnumerateVaults = 39,
    VaultOpenVault = 40,
    VaultEnumerateItems = 41,
    VaultGetItem = 42,
    CryptUnprotectData = 43,
    NCryptUnprotectSecret = 44,
    NCryptOpenStorageProvider = 45,
    NCryptOpenKey = 46,
    NCryptDecrypt = 47,
    CfAbortOperation = 48,
    CfRegisterSyncRoot = 49,
    CfConnectSyncRoot = 50,
    CfCreatePlaceholders = 51,
    AmsiScanBuffer = 52,
    WinHttpSendRequest = 53,
    HttpSendRequestW = 54,
    HttpSendRequestA = 55,
    SchannelEncryptMessage = 56,
    SchannelDecryptMessage = 57,
    RtlAddVectoredExceptionHandler = 58,
    RtlRemoveVectoredExceptionHandler = 59,
    SetUnhandledExceptionFilter = 60,
    AmsiInitialize = 61,
    AmsiUninitialize = 62,
    AmsiOpenSession = 63,
    AmsiCloseSession = 64,
    AmsiScanString = 65,
    AmsiNotifyOperation = 66,
    WinHttpConnect = 67,
    WinHttpOpenRequest = 68,
    InternetConnectW = 69,
    InternetConnectA = 70,
    HttpOpenRequestW = 71,
    HttpOpenRequestA = 72
};

struct ModuleHookContext
{
    ModuleHookOperation Operation;
    const char *FunctionName;
    const char *SourceModule;
    void *Caller;
    HMODULE ModuleHandle;
    const void *NameBuffer;
    std::size_t NameLength;
    std::uint64_t Args[4];
};

using ModuleHookCallback = void (*)(const ModuleHookContext &context) noexcept;

enum class ModuleHookInitFaultCode : std::uint32_t
{
    None = 0,
    ModuleMissing,
    ExportMissing,
    ExportOutsideImage,
    ExportRedirectedOutsideImage,
    PatchInstallFailed,
};

struct ModuleHookInitFault
{
    ModuleHookInitFaultCode Code;
    const wchar_t *ModuleName;
    const char *ExportName;
    void *Address;
    void *RedirectTarget;
    std::uint8_t Sample[16];
};

bool IxSetModuleHook(ModuleHookCallback callback) noexcept;
void IxRemoveModuleHook() noexcept;
bool IxRefreshModuleHooks(HMODULE moduleHandle) noexcept;

bool IxCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept;
bool IxGetLastModuleHookInitFault(ModuleHookInitFault *faultOut) noexcept;

struct ModuleHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
    std::uint32_t Flags;
};

std::size_t IxCollectModuleHookPatchInfos(_Out_writes_(capacity) ModuleHookPatchInfo *out,
                                          _In_ std::size_t capacity) noexcept;
