#include "module.h"
#include "runtime_private.h"
#include "../../../ABI/blind_ipc.h"

#include "ws.h"

#include <evntprov.h>
#include <evntrace.h>
#include <objbase.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <wininet.h>
#include <winternl.h>
#include <intrin.h>

#include <cstring>

#pragma intrinsic(_ReturnAddress)

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef SEC_E_INTERNAL_ERROR
#define SEC_E_INTERNAL_ERROR ((LONG)0x80090304L)
#endif

using LSA_HANDLE = HANDLE;
using PLSA_HANDLE = HANDLE *;
using LSA_STRING = STRING;
using PLSA_STRING = PSTRING;
using LSA_UNICODE_STRING = UNICODE_STRING;
using PLSA_UNICODE_STRING = PUNICODE_STRING;
using POLICY_INFORMATION_CLASS = ULONG;

struct LSA_OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PLSA_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

using PLSA_OBJECT_ATTRIBUTES = LSA_OBJECT_ATTRIBUTES *;

namespace
{
    static ModuleHookInitFault g_LastModuleHookInitFault{};

    struct ModuleRange
    {
        std::uintptr_t Base = 0;
        std::uintptr_t End = 0;
    };

    static void ResetModuleHookInitFault() noexcept
    {
        std::memset(&g_LastModuleHookInitFault, 0, sizeof(g_LastModuleHookInitFault));
        g_LastModuleHookInitFault.Code = ModuleHookInitFaultCode::None;
    }

    static void CaptureFaultSample(const void *address, std::uint8_t sample[16]) noexcept
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

    static void SetModuleHookInitFault(ModuleHookInitFaultCode code, const wchar_t *moduleName, const char *exportName,
                                       void *address, void *redirectTarget = nullptr) noexcept
    {
        ResetModuleHookInitFault();
        g_LastModuleHookInitFault.Code = code;
        g_LastModuleHookInitFault.ModuleName = moduleName;
        g_LastModuleHookInitFault.ExportName = exportName;
        g_LastModuleHookInitFault.Address = address;
        g_LastModuleHookInitFault.RedirectTarget = redirectTarget;
        CaptureFaultSample(address, g_LastModuleHookInitFault.Sample);
    }

    static bool TryResolveModuleImageRange(HMODULE module, ModuleRange &range) noexcept
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

    static bool AddressWithinRange(void *address, const ModuleRange &range) noexcept
    {
        std::uintptr_t value = reinterpret_cast<std::uintptr_t>(address);
        return value >= range.Base && value < range.End;
    }

    static bool TryDecodeAbsoluteTarget(void *entry, void *&target) noexcept
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

    using LoadLibraryAFn = HMODULE(WINAPI *)(LPCSTR);
    using LoadLibraryWFn = HMODULE(WINAPI *)(LPCWSTR);
    using LoadLibraryExAFn = HMODULE(WINAPI *)(LPCSTR, HANDLE, DWORD);
    using LoadLibraryExWFn = HMODULE(WINAPI *)(LPCWSTR, HANDLE, DWORD);
    using LdrLoadDllFn = NTSTATUS(NTAPI *)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
    using RtlAddFunctionTableFn = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    using RtlInstallFunctionTableCallbackFn = BOOLEAN(WINAPI *)(DWORD64, DWORD64, DWORD, PGET_RUNTIME_FUNCTION_CALLBACK,
                                                                PVOID, PCWSTR);
    using RtlDeleteFunctionTableFn = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION);
    using RtlAddVectoredExceptionHandlerFn = PVOID(NTAPI *)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    using RtlRemoveVectoredExceptionHandlerFn = ULONG(NTAPI *)(PVOID);
    using SetUnhandledExceptionFilterFn = LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI *)(LPTOP_LEVEL_EXCEPTION_FILTER);
    using CoInitializeExFn = HRESULT(WINAPI *)(LPVOID, DWORD);
    using CoInitializeSecurityFn = HRESULT(WINAPI *)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE *, void *,
                                                     DWORD, DWORD, void *, DWORD, void *);
    using CoCreateInstanceFn = HRESULT(WINAPI *)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
    using EventRegisterFn = ULONG(WINAPI *)(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE);
    using EventUnregisterFn = ULONG(WINAPI *)(REGHANDLE);
    using StartTraceWFn = ULONG(WINAPI *)(PTRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES);
    using EnableTraceEx2Fn = ULONG(WINAPI *)(TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG,
                                             PENABLE_TRACE_PARAMETERS);
    using CreateJobObjectWFn = HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, LPCWSTR);
    using OpenJobObjectWFn = HANDLE(WINAPI *)(DWORD, BOOL, LPCWSTR);
    using AssignProcessToJobObjectFn = BOOL(WINAPI *)(HANDLE, HANDLE);
    using SetInformationJobObjectFn = BOOL(WINAPI *)(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
    using LsaConnectUntrustedFn = NTSTATUS(WINAPI *)(PHANDLE);
    using LsaLookupAuthenticationPackageFn = NTSTATUS(WINAPI *)(HANDLE, PLSA_STRING, PULONG);
    using LsaCallAuthenticationPackageFn = NTSTATUS(WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
    using AcquireCredentialsHandleAFn = LONG(WINAPI *)(LPSTR, LPSTR, ULONG, PLUID, PVOID, PVOID, PVOID, PVOID, PVOID);
    using AcquireCredentialsHandleWFn = LONG(WINAPI *)(LPWSTR, LPWSTR, ULONG, PLUID, PVOID, PVOID, PVOID, PVOID, PVOID);
    using InitializeSecurityContextAFn = LONG(WINAPI *)(PVOID, PVOID, LPSTR, ULONG, ULONG, ULONG, PVOID, ULONG, PVOID,
                                                        PVOID, PULONG, PVOID);
    using InitializeSecurityContextWFn = LONG(WINAPI *)(PVOID, PVOID, LPWSTR, ULONG, ULONG, ULONG, PVOID, ULONG, PVOID,
                                                        PVOID, PULONG, PVOID);
    using AcceptSecurityContextFn = LONG(WINAPI *)(PVOID, PVOID, PVOID, ULONG, ULONG, PVOID, PVOID, PULONG, PVOID);
    using CredReadAFn = BOOL(WINAPI *)(LPCSTR, DWORD, DWORD, PVOID *);
    using CredReadWFn = BOOL(WINAPI *)(LPCWSTR, DWORD, DWORD, PVOID *);
    using CredEnumerateAFn = BOOL(WINAPI *)(LPCSTR, DWORD, DWORD *, PVOID *);
    using CredEnumerateWFn = BOOL(WINAPI *)(LPCWSTR, DWORD, DWORD *, PVOID *);
    using CredReadDomainCredentialsAFn = BOOL(WINAPI *)(PVOID, DWORD, DWORD *, PVOID *);
    using CredReadDomainCredentialsWFn = BOOL(WINAPI *)(PVOID, DWORD, DWORD *, PVOID *);
    using LsaOpenPolicyFn = NTSTATUS(WINAPI *)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
    using LsaQueryInformationPolicyFn = NTSTATUS(WINAPI *)(LSA_HANDLE, POLICY_INFORMATION_CLASS, PVOID *);
    using VaultEnumerateVaultsFn = DWORD(WINAPI *)(DWORD, DWORD *, GUID **);
    using VaultOpenVaultFn = DWORD(WINAPI *)(const GUID *, DWORD, HANDLE *);
    using VaultEnumerateItemsFn = DWORD(WINAPI *)(HANDLE, DWORD, DWORD *, PVOID *);
    using VaultGetItemFn = DWORD(WINAPI *)(HANDLE, const GUID *, PVOID, PVOID, PVOID, HWND, DWORD, PVOID *);
    using CryptUnprotectDataFn = BOOL(WINAPI *)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *,
                                                DWORD, DATA_BLOB *);
    using NCryptUnprotectSecretFn = LONG(WINAPI *)(PVOID *, DWORD, const BYTE *, ULONG, PVOID, HWND, BYTE **, ULONG *);
    using NCryptOpenStorageProviderFn = LONG(WINAPI *)(PVOID *, LPCWSTR, DWORD);
    using NCryptOpenKeyFn = LONG(WINAPI *)(PVOID, PVOID *, LPCWSTR, DWORD, DWORD);
    using NCryptDecryptFn = LONG(WINAPI *)(PVOID, PBYTE, DWORD, PVOID, PBYTE, DWORD, DWORD *, DWORD);
    using CfAbortOperationFn = DWORD(WINAPI *)(DWORD, PVOID, DWORD);
    using CfRegisterSyncRootFn = HRESULT(WINAPI *)(LPCWSTR, const void *, const void *, DWORD);
    using CfConnectSyncRootFn = HRESULT(WINAPI *)(LPCWSTR, const void *, void *, DWORD, void *);
    using CfCreatePlaceholdersFn = HRESULT(WINAPI *)(LPCWSTR, void *, DWORD, DWORD, DWORD *);
    using AmsiScanBufferFn = HRESULT(WINAPI *)(PVOID, PVOID, ULONG, LPCWSTR, PVOID, PVOID);
    using WinHttpConnectFn = PVOID(WINAPI *)(PVOID, LPCWSTR, INTERNET_PORT, DWORD);
    using WinHttpOpenRequestFn = PVOID(WINAPI *)(PVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
    using WinHttpSendRequestFn = BOOL(WINAPI *)(PVOID, LPCWSTR, DWORD, PVOID, DWORD, DWORD, DWORD_PTR);
    using InternetConnectWFn =
        PVOID(WINAPI *)(PVOID, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
    using InternetConnectAFn =
        PVOID(WINAPI *)(PVOID, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    using HttpOpenRequestWFn =
        PVOID(WINAPI *)(PVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD, DWORD_PTR);
    using HttpOpenRequestAFn =
        PVOID(WINAPI *)(PVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR);
    using HttpSendRequestWFn = BOOL(WINAPI *)(PVOID, LPCWSTR, DWORD, PVOID, DWORD);
    using HttpSendRequestAFn = BOOL(WINAPI *)(PVOID, LPCSTR, DWORD, PVOID, DWORD);
    using EncryptMessageFn = LONG(WINAPI *)(PVOID, ULONG, PVOID, ULONG);
    using DecryptMessageFn = LONG(WINAPI *)(PVOID, PVOID, ULONG, PULONG);

    struct InlineHook
    {
        const wchar_t *ModuleName;
        const char *ExportName;
        const char *SourceModule;
        void *HookEntry;
        void **OriginalFunction;
        void *TargetAddress;
        void *Trampoline;
        std::uint8_t OriginalBytes[16];
        bool Installed;
    };

    static ModuleHookCallback g_ActiveCallback = nullptr;
    static __declspec(thread) bool g_InHook = false;

    static LoadLibraryAFn g_OriginalLoadLibraryA = nullptr;
    static LoadLibraryWFn g_OriginalLoadLibraryW = nullptr;
    static LoadLibraryExAFn g_OriginalLoadLibraryExA = nullptr;
    static LoadLibraryExWFn g_OriginalLoadLibraryExW = nullptr;
    static LdrLoadDllFn g_OriginalLdrLoadDll = nullptr;
    static RtlAddFunctionTableFn g_OriginalRtlAddFunctionTable = nullptr;
    static RtlInstallFunctionTableCallbackFn g_OriginalRtlInstallFunctionTableCallback = nullptr;
    static RtlDeleteFunctionTableFn g_OriginalRtlDeleteFunctionTable = nullptr;
    static RtlAddVectoredExceptionHandlerFn g_OriginalRtlAddVectoredExceptionHandler = nullptr;
    static RtlRemoveVectoredExceptionHandlerFn g_OriginalRtlRemoveVectoredExceptionHandler = nullptr;
    static SetUnhandledExceptionFilterFn g_OriginalSetUnhandledExceptionFilter = nullptr;
    static CoInitializeExFn g_OriginalCoInitializeEx = nullptr;
    static CoInitializeSecurityFn g_OriginalCoInitializeSecurity = nullptr;
    static CoCreateInstanceFn g_OriginalCoCreateInstance = nullptr;
    static EventRegisterFn g_OriginalEventRegister = nullptr;
    static EventUnregisterFn g_OriginalEventUnregister = nullptr;
    static StartTraceWFn g_OriginalStartTraceW = nullptr;
    static EnableTraceEx2Fn g_OriginalEnableTraceEx2 = nullptr;
    static CreateJobObjectWFn g_OriginalCreateJobObjectW = nullptr;
    static OpenJobObjectWFn g_OriginalOpenJobObjectW = nullptr;
    static AssignProcessToJobObjectFn g_OriginalAssignProcessToJobObject = nullptr;
    static SetInformationJobObjectFn g_OriginalSetInformationJobObject = nullptr;
    static LsaConnectUntrustedFn g_OriginalLsaConnectUntrusted = nullptr;
    static LsaLookupAuthenticationPackageFn g_OriginalLsaLookupAuthenticationPackage = nullptr;
    static LsaCallAuthenticationPackageFn g_OriginalLsaCallAuthenticationPackage = nullptr;
    static AcquireCredentialsHandleAFn g_OriginalAcquireCredentialsHandleA = nullptr;
    static AcquireCredentialsHandleWFn g_OriginalAcquireCredentialsHandleW = nullptr;
    static InitializeSecurityContextAFn g_OriginalInitializeSecurityContextA = nullptr;
    static InitializeSecurityContextWFn g_OriginalInitializeSecurityContextW = nullptr;
    static AcceptSecurityContextFn g_OriginalAcceptSecurityContext = nullptr;
    static CredReadAFn g_OriginalCredReadA = nullptr;
    static CredReadWFn g_OriginalCredReadW = nullptr;
    static CredEnumerateAFn g_OriginalCredEnumerateA = nullptr;
    static CredEnumerateWFn g_OriginalCredEnumerateW = nullptr;
    static CredReadDomainCredentialsAFn g_OriginalCredReadDomainCredentialsA = nullptr;
    static CredReadDomainCredentialsWFn g_OriginalCredReadDomainCredentialsW = nullptr;
    static LsaOpenPolicyFn g_OriginalLsaOpenPolicy = nullptr;
    static LsaQueryInformationPolicyFn g_OriginalLsaQueryInformationPolicy = nullptr;
    static VaultEnumerateVaultsFn g_OriginalVaultEnumerateVaults = nullptr;
    static VaultOpenVaultFn g_OriginalVaultOpenVault = nullptr;
    static VaultEnumerateItemsFn g_OriginalVaultEnumerateItems = nullptr;
    static VaultGetItemFn g_OriginalVaultGetItem = nullptr;
    static CryptUnprotectDataFn g_OriginalCryptUnprotectData = nullptr;
    static NCryptUnprotectSecretFn g_OriginalNCryptUnprotectSecret = nullptr;
    static NCryptOpenStorageProviderFn g_OriginalNCryptOpenStorageProvider = nullptr;
    static NCryptOpenKeyFn g_OriginalNCryptOpenKey = nullptr;
    static NCryptDecryptFn g_OriginalNCryptDecrypt = nullptr;
    static CfAbortOperationFn g_OriginalCfAbortOperation = nullptr;
    static CfRegisterSyncRootFn g_OriginalCfRegisterSyncRoot = nullptr;
    static CfConnectSyncRootFn g_OriginalCfConnectSyncRoot = nullptr;
    static CfCreatePlaceholdersFn g_OriginalCfCreatePlaceholders = nullptr;
    static AmsiScanBufferFn g_OriginalAmsiScanBuffer = nullptr;
    static WinHttpConnectFn g_OriginalWinHttpConnect = nullptr;
    static WinHttpOpenRequestFn g_OriginalWinHttpOpenRequest = nullptr;
    static WinHttpSendRequestFn g_OriginalWinHttpSendRequest = nullptr;
    static InternetConnectWFn g_OriginalInternetConnectW = nullptr;
    static InternetConnectAFn g_OriginalInternetConnectA = nullptr;
    static HttpOpenRequestWFn g_OriginalHttpOpenRequestW = nullptr;
    static HttpOpenRequestAFn g_OriginalHttpOpenRequestA = nullptr;
    static HttpSendRequestWFn g_OriginalHttpSendRequestW = nullptr;
    static HttpSendRequestAFn g_OriginalHttpSendRequestA = nullptr;
    static EncryptMessageFn g_OriginalEncryptMessage = nullptr;
    static DecryptMessageFn g_OriginalDecryptMessage = nullptr;

    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath, PULONG loadFlags, PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle);
    BOOLEAN WINAPI RtlAddFunctionTableHook(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress);
    BOOLEAN WINAPI RtlInstallFunctionTableCallbackHook(DWORD64 tableIdentifier, DWORD64 baseAddress, DWORD length,
                                                       PGET_RUNTIME_FUNCTION_CALLBACK callback, PVOID context,
                                                       PCWSTR outOfProcessCallbackDll);
    BOOLEAN WINAPI RtlDeleteFunctionTableHook(PRUNTIME_FUNCTION functionTable);
    PVOID NTAPI RtlAddVectoredExceptionHandlerHook(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);
    ULONG NTAPI RtlRemoveVectoredExceptionHandlerHook(PVOID handle);
    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilterHook(LPTOP_LEVEL_EXCEPTION_FILTER filter);
    HRESULT WINAPI CoInitializeExHook(LPVOID pvReserved, DWORD dwCoInit);
    HRESULT WINAPI CoInitializeSecurityHook(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc,
                                            SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1,
                                            DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities,
                                            void *pReserved3);
    HRESULT WINAPI CoCreateInstanceHook(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid,
                                        LPVOID *ppv);
    ULONG WINAPI EventRegisterHook(LPCGUID providerId, PENABLECALLBACK enableCallback, PVOID callbackContext,
                                   PREGHANDLE regHandle);
    ULONG WINAPI EventUnregisterHook(REGHANDLE regHandle);
    ULONG WINAPI StartTraceWHook(PTRACEHANDLE sessionHandle, LPCWSTR sessionName, PEVENT_TRACE_PROPERTIES properties);
    ULONG WINAPI EnableTraceEx2Hook(TRACEHANDLE traceHandle, LPCGUID providerId, ULONG controlCode, UCHAR level,
                                    ULONGLONG matchAnyKeyword, ULONGLONG matchAllKeyword, ULONG timeout,
                                    PENABLE_TRACE_PARAMETERS enableParameters);
    HANDLE WINAPI CreateJobObjectWHook(LPSECURITY_ATTRIBUTES securityAttributes, LPCWSTR name);
    HANDLE WINAPI OpenJobObjectWHook(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name);
    BOOL WINAPI AssignProcessToJobObjectHook(HANDLE job, HANDLE process);
    BOOL WINAPI SetInformationJobObjectHook(HANDLE job, JOBOBJECTINFOCLASS infoClass, LPVOID info, DWORD infoLength);
    NTSTATUS WINAPI LsaConnectUntrustedHook(PHANDLE lsaHandle);
    NTSTATUS WINAPI LsaLookupAuthenticationPackageHook(HANDLE lsaHandle, PLSA_STRING packageName,
                                                       PULONG authenticationPackage);
    NTSTATUS WINAPI LsaCallAuthenticationPackageHook(HANDLE lsaHandle, ULONG authenticationPackage, PVOID submitBuffer,
                                                     ULONG submitBufferLength, PVOID *returnBuffer,
                                                     PULONG returnBufferLength, PNTSTATUS protocolStatus);
    LONG WINAPI AcquireCredentialsHandleAHook(LPSTR principal, LPSTR package, ULONG credentialUse, PLUID logonId,
                                              PVOID authData, PVOID getKeyFn, PVOID getKeyArgument, PVOID credential,
                                              PVOID expiry);
    LONG WINAPI AcquireCredentialsHandleWHook(LPWSTR principal, LPWSTR package, ULONG credentialUse, PLUID logonId,
                                              PVOID authData, PVOID getKeyFn, PVOID getKeyArgument, PVOID credential,
                                              PVOID expiry);
    LONG WINAPI InitializeSecurityContextAHook(PVOID credential, PVOID context, LPSTR targetName, ULONG contextReq,
                                               ULONG reserved1, ULONG targetDataRep, PVOID input, ULONG reserved2,
                                               PVOID newContext, PVOID output, PULONG contextAttr, PVOID expiry);
    LONG WINAPI InitializeSecurityContextWHook(PVOID credential, PVOID context, LPWSTR targetName, ULONG contextReq,
                                               ULONG reserved1, ULONG targetDataRep, PVOID input, ULONG reserved2,
                                               PVOID newContext, PVOID output, PULONG contextAttr, PVOID expiry);
    LONG WINAPI AcceptSecurityContextHook(PVOID credential, PVOID context, PVOID input, ULONG contextReq,
                                          ULONG targetDataRep, PVOID newContext, PVOID output, PULONG contextAttr,
                                          PVOID expiry);
    BOOL WINAPI CredReadAHook(LPCSTR targetName, DWORD type, DWORD flags, PVOID *credential);
    BOOL WINAPI CredReadWHook(LPCWSTR targetName, DWORD type, DWORD flags, PVOID *credential);
    BOOL WINAPI CredEnumerateAHook(LPCSTR filter, DWORD flags, DWORD *count, PVOID *credential);
    BOOL WINAPI CredEnumerateWHook(LPCWSTR filter, DWORD flags, DWORD *count, PVOID *credential);
    BOOL WINAPI CredReadDomainCredentialsAHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential);
    BOOL WINAPI CredReadDomainCredentialsWHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential);
    NTSTATUS WINAPI LsaOpenPolicyHook(PLSA_UNICODE_STRING systemName, PLSA_OBJECT_ATTRIBUTES objectAttributes,
                                      ACCESS_MASK desiredAccess, PLSA_HANDLE policyHandle);
    NTSTATUS WINAPI LsaQueryInformationPolicyHook(LSA_HANDLE policyHandle, POLICY_INFORMATION_CLASS informationClass,
                                                  PVOID *buffer);
    DWORD WINAPI VaultEnumerateVaultsHook(DWORD flags, DWORD *count, GUID **vaultGuids);
    DWORD WINAPI VaultOpenVaultHook(const GUID *vaultGuid, DWORD flags, HANDLE *vaultHandle);
    DWORD WINAPI VaultEnumerateItemsHook(HANDLE vaultHandle, DWORD flags, DWORD *count, PVOID *items);
    DWORD WINAPI VaultGetItemHook(HANDLE vaultHandle, const GUID *schemaId, PVOID resource, PVOID identity,
                                  PVOID packageSid, HWND hwndOwner, DWORD flags, PVOID *item);
    BOOL WINAPI CryptUnprotectDataHook(DATA_BLOB *dataIn, LPWSTR *dataDescription, DATA_BLOB *optionalEntropy,
                                       PVOID reserved, CRYPTPROTECT_PROMPTSTRUCT *promptStruct, DWORD flags,
                                       DATA_BLOB *dataOut);
    LONG WINAPI NCryptUnprotectSecretHook(PVOID *descriptor, DWORD flags, const BYTE *protectedBlob,
                                          ULONG protectedBlobSize, PVOID memPara, HWND hwnd, BYTE **data,
                                          ULONG *dataSize);
    LONG WINAPI NCryptOpenStorageProviderHook(PVOID *provider, LPCWSTR providerName, DWORD flags);
    LONG WINAPI NCryptOpenKeyHook(PVOID provider, PVOID *key, LPCWSTR keyName, DWORD legacyKeySpec, DWORD flags);
    LONG WINAPI NCryptDecryptHook(PVOID key, PBYTE input, DWORD inputSize, PVOID paddingInfo, PBYTE output,
                                  DWORD outputSize, DWORD *resultSize, DWORD flags);
    DWORD WINAPI CfAbortOperationHook(DWORD processId, PVOID unknown, DWORD flags);
    HRESULT WINAPI CfRegisterSyncRootHook(LPCWSTR syncRootPath, const void *registration, const void *policies,
                                          DWORD registerFlags);
    HRESULT WINAPI CfConnectSyncRootHook(LPCWSTR syncRootPath, const void *callbackTable, void *callbackContext,
                                         DWORD connectFlags, void *connectionKey);
    HRESULT WINAPI CfCreatePlaceholdersHook(LPCWSTR baseDirectoryPath, void *placeholderArray, DWORD placeholderCount,
                                            DWORD createFlags, DWORD *entriesProcessed);
    HRESULT WINAPI AmsiScanBufferHook(PVOID amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName,
                                      PVOID session, PVOID result);
    PVOID WINAPI WinHttpConnectHook(PVOID session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved);
    PVOID WINAPI WinHttpOpenRequestHook(PVOID connect, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version,
                                        LPCWSTR referrer, LPCWSTR *acceptTypes, DWORD flags);
    BOOL WINAPI WinHttpSendRequestHook(PVOID request, LPCWSTR headers, DWORD headersLength, PVOID optional,
                                       DWORD optionalLength, DWORD totalLength, DWORD_PTR context);
    PVOID WINAPI InternetConnectWHook(PVOID internet, LPCWSTR serverName, INTERNET_PORT serverPort, LPCWSTR userName,
                                      LPCWSTR password, DWORD service, DWORD flags, DWORD_PTR context);
    PVOID WINAPI InternetConnectAHook(PVOID internet, LPCSTR serverName, INTERNET_PORT serverPort, LPCSTR userName,
                                      LPCSTR password, DWORD service, DWORD flags, DWORD_PTR context);
    PVOID WINAPI HttpOpenRequestWHook(PVOID connect, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version,
                                      LPCWSTR referrer, LPCWSTR *acceptTypes, DWORD flags, DWORD_PTR context);
    PVOID WINAPI HttpOpenRequestAHook(PVOID connect, LPCSTR verb, LPCSTR objectName, LPCSTR version, LPCSTR referrer,
                                      LPCSTR *acceptTypes, DWORD flags, DWORD_PTR context);
    BOOL WINAPI HttpSendRequestWHook(PVOID request, LPCWSTR headers, DWORD headersLength, PVOID optional,
                                     DWORD optionalLength);
    BOOL WINAPI HttpSendRequestAHook(PVOID request, LPCSTR headers, DWORD headersLength, PVOID optional,
                                     DWORD optionalLength);
    LONG WINAPI EncryptMessageHook(PVOID context, ULONG qualityOfProtection, PVOID message, ULONG sequenceNumber);
    LONG WINAPI DecryptMessageHook(PVOID context, PVOID message, ULONG sequenceNumber, PULONG qualityOfProtection);
    static void PublishModuleEvent(ModuleHookOperation operation, const char *functionName, const char *sourceModule,
                                   HMODULE moduleHandle, const void *nameBuffer, std::size_t nameLength,
                                   std::uint64_t arg0 = 0, std::uint64_t arg1 = 0, std::uint64_t arg2 = 0,
                                   std::uint64_t arg3 = 0) noexcept;

    struct HttpHandleEntry
    {
        PVOID Handle;
        PVOID Parent;
        INTERNET_PORT Port;
        bool Request;
        bool Secure;
        WCHAR Host[128];
        WCHAR Method[16];
        WCHAR Path[160];
    };

    static SRWLOCK g_HttpHandleLock = SRWLOCK_INIT;
    static HttpHandleEntry g_HttpHandles[128]{};
    static std::uint32_t g_HttpHandleHead = 0;

    static void CopyWideTruncated(WCHAR *dst, std::size_t dstCount, LPCWSTR src) noexcept
    {
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (src != nullptr && src[0] != L'\0')
        {
            (void)wcsncpy_s(dst, dstCount, src, _TRUNCATE);
        }
    }

    static void CopyAnsiToWideTruncated(WCHAR *dst, std::size_t dstCount, LPCSTR src) noexcept
    {
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (src == nullptr || src[0] == '\0')
        {
            return;
        }
        MultiByteToWideChar(CP_ACP, 0, src, -1, dst, static_cast<int>(dstCount));
        dst[dstCount - 1] = L'\0';
    }

    static void HttpCacheStoreConnect(PVOID handle, LPCWSTR host, INTERNET_PORT port) noexcept
    {
        if (handle == nullptr)
        {
            return;
        }
        AcquireSRWLockExclusive(&g_HttpHandleLock);
        HttpHandleEntry &entry = g_HttpHandles[g_HttpHandleHead++ % RTL_NUMBER_OF(g_HttpHandles)];
        std::memset(&entry, 0, sizeof(entry));
        entry.Handle = handle;
        entry.Port = port;
        entry.Request = false;
        entry.Secure = (port == 443);
        CopyWideTruncated(entry.Host, RTL_NUMBER_OF(entry.Host), host);
        ReleaseSRWLockExclusive(&g_HttpHandleLock);
    }

    static bool HttpCacheLookup(PVOID handle, HttpHandleEntry &out) noexcept
    {
        bool found = false;
        if (handle == nullptr)
        {
            return false;
        }
        AcquireSRWLockShared(&g_HttpHandleLock);
        for (const auto &entry : g_HttpHandles)
        {
            if (entry.Handle == handle)
            {
                out = entry;
                found = true;
                break;
            }
        }
        ReleaseSRWLockShared(&g_HttpHandleLock);
        return found;
    }

    static void HttpCacheStoreRequest(PVOID request, PVOID connect, LPCWSTR method, LPCWSTR path, bool secure) noexcept
    {
        if (request == nullptr)
        {
            return;
        }

        HttpHandleEntry parent{};
        (void)HttpCacheLookup(connect, parent);

        AcquireSRWLockExclusive(&g_HttpHandleLock);
        HttpHandleEntry &entry = g_HttpHandles[g_HttpHandleHead++ % RTL_NUMBER_OF(g_HttpHandles)];
        std::memset(&entry, 0, sizeof(entry));
        entry.Handle = request;
        entry.Parent = connect;
        entry.Port = parent.Port;
        entry.Request = true;
        entry.Secure = secure || parent.Secure;
        CopyWideTruncated(entry.Host, RTL_NUMBER_OF(entry.Host), parent.Host);
        CopyWideTruncated(entry.Method, RTL_NUMBER_OF(entry.Method), method != nullptr && method[0] != L'\0' ? method
                                                                                                             : L"GET");
        CopyWideTruncated(entry.Path, RTL_NUMBER_OF(entry.Path), path != nullptr && path[0] != L'\0' ? path : L"/");
        ReleaseSRWLockExclusive(&g_HttpHandleLock);
    }

    static void CopyPrintableBytesToWide(WCHAR *dst, std::size_t dstCount, const void *bytes, DWORD byteCount) noexcept
    {
        auto *src = static_cast<const unsigned char *>(bytes);
        std::size_t out = 0;
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (src == nullptr || byteCount == 0)
        {
            return;
        }
        for (DWORD i = 0; i < byteCount && out + 1 < dstCount; ++i)
        {
            unsigned char ch = src[i];
            if (ch == '\r')
            {
                continue;
            }
            dst[out++] = (ch == '\n') ? L'|' : (ch >= 0x20 && ch < 0x7F) ? static_cast<WCHAR>(ch) : L'.';
        }
        dst[out] = L'\0';
    }

    static void CopyWidePrintableToWide(WCHAR *dst, std::size_t dstCount, LPCWSTR text, DWORD chars) noexcept
    {
        std::size_t out = 0;
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (text == nullptr)
        {
            return;
        }
        if (chars == 0xFFFFFFFFu)
        {
            chars = static_cast<DWORD>(wcsnlen_s(text, dstCount * 4));
        }
        for (DWORD i = 0; i < chars && text[i] != L'\0' && out + 1 < dstCount; ++i)
        {
            WCHAR ch = text[i];
            if (ch == L'\r')
            {
                continue;
            }
            dst[out++] = (ch == L'\n') ? L'|' : (ch >= 0x20 && ch < 0x7F) ? ch : L'.';
        }
        dst[out] = L'\0';
    }

    static bool BufferLooksUtf16LeText(const void *buffer, ULONG byteCount) noexcept
    {
        auto *bytes = static_cast<const unsigned char *>(buffer);
        ULONG pairs = 0;
        ULONG wideAsciiPairs = 0;
        if (bytes == nullptr || byteCount < sizeof(WCHAR))
        {
            return false;
        }

        ULONG limit = byteCount < 128u ? byteCount : 128u;
        limit &= ~1u;
        for (ULONG i = 0; i + 1 < limit; i += 2)
        {
            unsigned char low = bytes[i];
            unsigned char high = bytes[i + 1];
            if (low == 0 && high == 0)
            {
                continue;
            }

            ++pairs;
            if (high == 0 && (low == '\r' || low == '\n' || low == '\t' || (low >= 0x20 && low < 0x7F)))
            {
                ++wideAsciiPairs;
            }
        }

        return pairs != 0 && (wideAsciiPairs * 2u) >= pairs;
    }

    static void PublishHttpLibraryRequest(ModuleHookOperation op, const char *apiName, const char *sourceModule,
                                          PVOID request, LPCWSTR headers, DWORD headerChars, PVOID optional,
                                          DWORD optionalBytes, bool secureHint) noexcept
    {
        HttpHandleEntry requestInfo{};
        WCHAR headerSample[96];
        WCHAR contentSample[64];
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];

        std::memset(headerSample, 0, sizeof(headerSample));
        std::memset(contentSample, 0, sizeof(contentSample));
        std::memset(reason, 0, sizeof(reason));

        (void)HttpCacheLookup(request, requestInfo);
        if (requestInfo.Method[0] == L'\0')
        {
            CopyWideTruncated(requestInfo.Method, RTL_NUMBER_OF(requestInfo.Method), L"GET");
        }
        if (requestInfo.Path[0] == L'\0')
        {
            CopyWideTruncated(requestInfo.Path, RTL_NUMBER_OF(requestInfo.Path), L"/");
        }
        if (secureHint)
        {
            requestInfo.Secure = true;
        }

        CopyWidePrintableToWide(headerSample, RTL_NUMBER_OF(headerSample), headers, headerChars);
        CopyPrintableBytesToWide(contentSample, RTL_NUMBER_OF(contentSample), optional, optionalBytes);

        (void)swprintf_s(reason, RTL_NUMBER_OF(reason),
                         L"http.request method=%s url=%s://%s%s cn=%s pid=%lu api=%S bytes=%lu ms=0 rep=unknown content=%s headers=\"%s\"",
                         requestInfo.Method, requestInfo.Secure ? L"https" : L"http",
                         requestInfo.Host[0] != L'\0' ? requestInfo.Host : L"<unknown>", requestInfo.Path,
                         requestInfo.Host[0] != L'\0' ? requestInfo.Host : L"<unknown>",
                         static_cast<unsigned long>(GetCurrentProcessId()), apiName,
                         static_cast<unsigned long>(optionalBytes), contentSample[0] != L'\0' ? contentSample : L"-",
                         headerSample[0] != L'\0' ? headerSample : L"-");

        PublishModuleEvent(op, apiName, sourceModule, nullptr, reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR));
    }

    static bool BufferLooksHttp(const unsigned char *data, DWORD size) noexcept
    {
        if (data == nullptr || size < 4)
        {
            return false;
        }
        const char *text = reinterpret_cast<const char *>(data);
        return (size >= 4 && _strnicmp(text, "GET ", 4) == 0) ||
               (size >= 5 && _strnicmp(text, "POST ", 5) == 0) ||
               (size >= 4 && _strnicmp(text, "PUT ", 4) == 0) ||
               (size >= 5 && _strnicmp(text, "HEAD ", 5) == 0) ||
               (size >= 7 && _strnicmp(text, "DELETE ", 7) == 0) ||
               (size >= 6 && _strnicmp(text, "PATCH ", 6) == 0) ||
               (size >= 8 && _strnicmp(text, "OPTIONS ", 8) == 0) ||
               (size >= 5 && _strnicmp(text, "HTTP/", 5) == 0);
    }

    static void PublishSchannelPlaintext(ModuleHookOperation op, const char *apiName, const void *message) noexcept
    {
        struct LocalSecBuffer
        {
            unsigned long cbBuffer;
            unsigned long BufferType;
            void *pvBuffer;
        };
        struct LocalSecBufferDesc
        {
            unsigned long ulVersion;
            unsigned long cBuffers;
            LocalSecBuffer *pBuffers;
        };

        auto *desc = static_cast<const LocalSecBufferDesc *>(message);
        if (desc == nullptr || desc->pBuffers == nullptr || desc->cBuffers > 16)
        {
            return;
        }

        for (unsigned long i = 0; i < desc->cBuffers; ++i)
        {
            const LocalSecBuffer &buffer = desc->pBuffers[i];
            if (buffer.BufferType != 1u || buffer.pvBuffer == nullptr || buffer.cbBuffer == 0)
            {
                continue;
            }
            auto *bytes = static_cast<const unsigned char *>(buffer.pvBuffer);
            if (!BufferLooksHttp(bytes, buffer.cbBuffer))
            {
                continue;
            }
            PublishModuleEvent(op, apiName, "secur32", nullptr, bytes, buffer.cbBuffer);
            break;
        }
    }

    static InlineHook g_Hooks[] = {
        {L"KernelBase.dll",
         "LoadLibraryA",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryAHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryA),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "LoadLibraryW",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryWHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryW),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "LoadLibraryExA",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryExAHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryExA),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "LoadLibraryExW",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryExWHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryExW),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "LdrLoadDll",
         "ntdll",
         reinterpret_cast<void *>(&LdrLoadDllHook),
         reinterpret_cast<void **>(&g_OriginalLdrLoadDll),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlAddFunctionTable",
         "ntdll",
         reinterpret_cast<void *>(&RtlAddFunctionTableHook),
         reinterpret_cast<void **>(&g_OriginalRtlAddFunctionTable),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlInstallFunctionTableCallback",
         "ntdll",
         reinterpret_cast<void *>(&RtlInstallFunctionTableCallbackHook),
         reinterpret_cast<void **>(&g_OriginalRtlInstallFunctionTableCallback),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlDeleteFunctionTable",
         "ntdll",
         reinterpret_cast<void *>(&RtlDeleteFunctionTableHook),
         reinterpret_cast<void **>(&g_OriginalRtlDeleteFunctionTable),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlAddVectoredExceptionHandler",
         "ntdll",
         reinterpret_cast<void *>(&RtlAddVectoredExceptionHandlerHook),
         reinterpret_cast<void **>(&g_OriginalRtlAddVectoredExceptionHandler),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlRemoveVectoredExceptionHandler",
         "ntdll",
         reinterpret_cast<void *>(&RtlRemoveVectoredExceptionHandlerHook),
         reinterpret_cast<void **>(&g_OriginalRtlRemoveVectoredExceptionHandler),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "SetUnhandledExceptionFilter",
         "KernelBase",
         reinterpret_cast<void *>(&SetUnhandledExceptionFilterHook),
         reinterpret_cast<void **>(&g_OriginalSetUnhandledExceptionFilter),
         nullptr,
         nullptr,
         {},
         false},
        {L"combase.dll",
         "CoInitializeEx",
         "combase",
         reinterpret_cast<void *>(&CoInitializeExHook),
         reinterpret_cast<void **>(&g_OriginalCoInitializeEx),
         nullptr,
         nullptr,
         {},
         false},
        {L"combase.dll",
         "CoInitializeSecurity",
         "combase",
         reinterpret_cast<void *>(&CoInitializeSecurityHook),
         reinterpret_cast<void **>(&g_OriginalCoInitializeSecurity),
         nullptr,
         nullptr,
         {},
         false},
        {L"combase.dll",
         "CoCreateInstance",
         "combase",
         reinterpret_cast<void *>(&CoCreateInstanceHook),
         reinterpret_cast<void **>(&g_OriginalCoCreateInstance),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "EventRegister",
         "advapi32",
         reinterpret_cast<void *>(&EventRegisterHook),
         reinterpret_cast<void **>(&g_OriginalEventRegister),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "EventUnregister",
         "advapi32",
         reinterpret_cast<void *>(&EventUnregisterHook),
         reinterpret_cast<void **>(&g_OriginalEventUnregister),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "StartTraceW",
         "advapi32",
         reinterpret_cast<void *>(&StartTraceWHook),
         reinterpret_cast<void **>(&g_OriginalStartTraceW),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "EnableTraceEx2",
         "advapi32",
         reinterpret_cast<void *>(&EnableTraceEx2Hook),
         reinterpret_cast<void **>(&g_OriginalEnableTraceEx2),
         nullptr,
         nullptr,
         {},
         false},
        {L"kernel32.dll",
         "CreateJobObjectW",
         "KERNEL32",
         reinterpret_cast<void *>(&CreateJobObjectWHook),
         reinterpret_cast<void **>(&g_OriginalCreateJobObjectW),
         nullptr,
         nullptr,
         {},
         false},
        {L"kernel32.dll",
         "OpenJobObjectW",
         "KERNEL32",
         reinterpret_cast<void *>(&OpenJobObjectWHook),
         reinterpret_cast<void **>(&g_OriginalOpenJobObjectW),
         nullptr,
         nullptr,
         {},
         false},
        {L"kernel32.dll",
         "AssignProcessToJobObject",
         "KERNEL32",
         reinterpret_cast<void *>(&AssignProcessToJobObjectHook),
         reinterpret_cast<void **>(&g_OriginalAssignProcessToJobObject),
         nullptr,
         nullptr,
         {},
         false},
        {L"kernel32.dll",
         "SetInformationJobObject",
         "KERNEL32",
         reinterpret_cast<void *>(&SetInformationJobObjectHook),
         reinterpret_cast<void **>(&g_OriginalSetInformationJobObject),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "LsaConnectUntrusted",
         "sspicli",
         reinterpret_cast<void *>(&LsaConnectUntrustedHook),
         reinterpret_cast<void **>(&g_OriginalLsaConnectUntrusted),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "LsaLookupAuthenticationPackage",
         "sspicli",
         reinterpret_cast<void *>(&LsaLookupAuthenticationPackageHook),
         reinterpret_cast<void **>(&g_OriginalLsaLookupAuthenticationPackage),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "LsaCallAuthenticationPackage",
         "sspicli",
         reinterpret_cast<void *>(&LsaCallAuthenticationPackageHook),
         reinterpret_cast<void **>(&g_OriginalLsaCallAuthenticationPackage),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "AcquireCredentialsHandleA",
         "sspicli",
         reinterpret_cast<void *>(&AcquireCredentialsHandleAHook),
         reinterpret_cast<void **>(&g_OriginalAcquireCredentialsHandleA),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "AcquireCredentialsHandleW",
         "sspicli",
         reinterpret_cast<void *>(&AcquireCredentialsHandleWHook),
         reinterpret_cast<void **>(&g_OriginalAcquireCredentialsHandleW),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "InitializeSecurityContextA",
         "sspicli",
         reinterpret_cast<void *>(&InitializeSecurityContextAHook),
         reinterpret_cast<void **>(&g_OriginalInitializeSecurityContextA),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "InitializeSecurityContextW",
         "sspicli",
         reinterpret_cast<void *>(&InitializeSecurityContextWHook),
         reinterpret_cast<void **>(&g_OriginalInitializeSecurityContextW),
         nullptr,
         nullptr,
         {},
         false},
        {L"sspicli.dll",
         "AcceptSecurityContext",
         "sspicli",
         reinterpret_cast<void *>(&AcceptSecurityContextHook),
         reinterpret_cast<void **>(&g_OriginalAcceptSecurityContext),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "CredReadA",
         "advapi32",
         reinterpret_cast<void *>(&CredReadAHook),
         reinterpret_cast<void **>(&g_OriginalCredReadA),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "CredReadW",
         "advapi32",
         reinterpret_cast<void *>(&CredReadWHook),
         reinterpret_cast<void **>(&g_OriginalCredReadW),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "CredEnumerateA",
         "advapi32",
         reinterpret_cast<void *>(&CredEnumerateAHook),
         reinterpret_cast<void **>(&g_OriginalCredEnumerateA),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "CredEnumerateW",
         "advapi32",
         reinterpret_cast<void *>(&CredEnumerateWHook),
         reinterpret_cast<void **>(&g_OriginalCredEnumerateW),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "CredReadDomainCredentialsA",
         "advapi32",
         reinterpret_cast<void *>(&CredReadDomainCredentialsAHook),
         reinterpret_cast<void **>(&g_OriginalCredReadDomainCredentialsA),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "CredReadDomainCredentialsW",
         "advapi32",
         reinterpret_cast<void *>(&CredReadDomainCredentialsWHook),
         reinterpret_cast<void **>(&g_OriginalCredReadDomainCredentialsW),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "LsaOpenPolicy",
         "advapi32",
         reinterpret_cast<void *>(&LsaOpenPolicyHook),
         reinterpret_cast<void **>(&g_OriginalLsaOpenPolicy),
         nullptr,
         nullptr,
         {},
         false},
        {L"advapi32.dll",
         "LsaQueryInformationPolicy",
         "advapi32",
         reinterpret_cast<void *>(&LsaQueryInformationPolicyHook),
         reinterpret_cast<void **>(&g_OriginalLsaQueryInformationPolicy),
         nullptr,
         nullptr,
         {},
         false},
        {L"vaultcli.dll",
         "VaultEnumerateVaults",
         "vaultcli",
         reinterpret_cast<void *>(&VaultEnumerateVaultsHook),
         reinterpret_cast<void **>(&g_OriginalVaultEnumerateVaults),
         nullptr,
         nullptr,
         {},
         false},
        {L"vaultcli.dll",
         "VaultOpenVault",
         "vaultcli",
         reinterpret_cast<void *>(&VaultOpenVaultHook),
         reinterpret_cast<void **>(&g_OriginalVaultOpenVault),
         nullptr,
         nullptr,
         {},
         false},
        {L"vaultcli.dll",
         "VaultEnumerateItems",
         "vaultcli",
         reinterpret_cast<void *>(&VaultEnumerateItemsHook),
         reinterpret_cast<void **>(&g_OriginalVaultEnumerateItems),
         nullptr,
         nullptr,
         {},
         false},
        {L"vaultcli.dll",
         "VaultGetItem",
         "vaultcli",
         reinterpret_cast<void *>(&VaultGetItemHook),
         reinterpret_cast<void **>(&g_OriginalVaultGetItem),
         nullptr,
         nullptr,
         {},
         false},
        {L"crypt32.dll",
         "CryptUnprotectData",
         "crypt32",
         reinterpret_cast<void *>(&CryptUnprotectDataHook),
         reinterpret_cast<void **>(&g_OriginalCryptUnprotectData),
         nullptr,
         nullptr,
         {},
         false},
        {L"ncrypt.dll",
         "NCryptUnprotectSecret",
         "ncrypt",
         reinterpret_cast<void *>(&NCryptUnprotectSecretHook),
         reinterpret_cast<void **>(&g_OriginalNCryptUnprotectSecret),
         nullptr,
         nullptr,
         {},
         false},
        {L"ncrypt.dll",
         "NCryptOpenStorageProvider",
         "ncrypt",
         reinterpret_cast<void *>(&NCryptOpenStorageProviderHook),
         reinterpret_cast<void **>(&g_OriginalNCryptOpenStorageProvider),
         nullptr,
         nullptr,
         {},
         false},
        {L"ncrypt.dll",
         "NCryptOpenKey",
         "ncrypt",
         reinterpret_cast<void *>(&NCryptOpenKeyHook),
         reinterpret_cast<void **>(&g_OriginalNCryptOpenKey),
         nullptr,
         nullptr,
         {},
         false},
        {L"ncrypt.dll",
         "NCryptDecrypt",
         "ncrypt",
         reinterpret_cast<void *>(&NCryptDecryptHook),
         reinterpret_cast<void **>(&g_OriginalNCryptDecrypt),
         nullptr,
         nullptr,
         {},
         false},
        {L"cldapi.dll",
         "CfAbortOperation",
         "cldapi",
         reinterpret_cast<void *>(&CfAbortOperationHook),
         reinterpret_cast<void **>(&g_OriginalCfAbortOperation),
         nullptr,
         nullptr,
         {},
         false},
        {L"cldapi.dll",
         "CfRegisterSyncRoot",
         "cldapi",
         reinterpret_cast<void *>(&CfRegisterSyncRootHook),
         reinterpret_cast<void **>(&g_OriginalCfRegisterSyncRoot),
         nullptr,
         nullptr,
         {},
         false},
        {L"cldapi.dll",
         "CfConnectSyncRoot",
         "cldapi",
         reinterpret_cast<void *>(&CfConnectSyncRootHook),
         reinterpret_cast<void **>(&g_OriginalCfConnectSyncRoot),
         nullptr,
         nullptr,
         {},
         false},
        {L"cldapi.dll",
         "CfCreatePlaceholders",
         "cldapi",
         reinterpret_cast<void *>(&CfCreatePlaceholdersHook),
         reinterpret_cast<void **>(&g_OriginalCfCreatePlaceholders),
         nullptr,
         nullptr,
         {},
         false},
        {L"amsi.dll",
         "AmsiScanBuffer",
         "amsi",
         reinterpret_cast<void *>(&AmsiScanBufferHook),
         reinterpret_cast<void **>(&g_OriginalAmsiScanBuffer),
         nullptr,
         nullptr,
         {},
         false},
        {L"winhttp.dll",
         "WinHttpConnect",
         "winhttp",
         reinterpret_cast<void *>(&WinHttpConnectHook),
         reinterpret_cast<void **>(&g_OriginalWinHttpConnect),
         nullptr,
         nullptr,
         {},
         false},
        {L"winhttp.dll",
         "WinHttpOpenRequest",
         "winhttp",
         reinterpret_cast<void *>(&WinHttpOpenRequestHook),
         reinterpret_cast<void **>(&g_OriginalWinHttpOpenRequest),
         nullptr,
         nullptr,
         {},
         false},
        {L"winhttp.dll",
         "WinHttpSendRequest",
         "winhttp",
         reinterpret_cast<void *>(&WinHttpSendRequestHook),
         reinterpret_cast<void **>(&g_OriginalWinHttpSendRequest),
         nullptr,
         nullptr,
         {},
         false},
        {L"wininet.dll",
         "InternetConnectW",
         "wininet",
         reinterpret_cast<void *>(&InternetConnectWHook),
         reinterpret_cast<void **>(&g_OriginalInternetConnectW),
         nullptr,
         nullptr,
         {},
         false},
        {L"wininet.dll",
         "InternetConnectA",
         "wininet",
         reinterpret_cast<void *>(&InternetConnectAHook),
         reinterpret_cast<void **>(&g_OriginalInternetConnectA),
         nullptr,
         nullptr,
         {},
         false},
        {L"wininet.dll",
         "HttpOpenRequestW",
         "wininet",
         reinterpret_cast<void *>(&HttpOpenRequestWHook),
         reinterpret_cast<void **>(&g_OriginalHttpOpenRequestW),
         nullptr,
         nullptr,
         {},
         false},
        {L"wininet.dll",
         "HttpOpenRequestA",
         "wininet",
         reinterpret_cast<void *>(&HttpOpenRequestAHook),
         reinterpret_cast<void **>(&g_OriginalHttpOpenRequestA),
         nullptr,
         nullptr,
         {},
         false},
        {L"wininet.dll",
         "HttpSendRequestW",
         "wininet",
         reinterpret_cast<void *>(&HttpSendRequestWHook),
         reinterpret_cast<void **>(&g_OriginalHttpSendRequestW),
         nullptr,
         nullptr,
         {},
         false},
        {L"wininet.dll",
         "HttpSendRequestA",
         "wininet",
         reinterpret_cast<void *>(&HttpSendRequestAHook),
         reinterpret_cast<void **>(&g_OriginalHttpSendRequestA),
         nullptr,
         nullptr,
         {},
         false},
        {L"secur32.dll",
         "EncryptMessage",
         "secur32",
         reinterpret_cast<void *>(&EncryptMessageHook),
         reinterpret_cast<void **>(&g_OriginalEncryptMessage),
         nullptr,
         nullptr,
         {},
         false},
        {L"secur32.dll",
         "DecryptMessage",
         "secur32",
         reinterpret_cast<void *>(&DecryptMessageHook),
         reinterpret_cast<void **>(&g_OriginalDecryptMessage),
         nullptr,
         nullptr,
         {},
         false},
    };

    static const GUID CLSID_WbemLocatorValue = {
        0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};

    static void CopyLiteralWide(wchar_t buffer[32], const wchar_t *value) noexcept
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

    static bool TryFormatGuid(const GUID *guid, wchar_t buffer[32]) noexcept
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
            int chars = swprintf_s(buffer, 32, L"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX",
                                   static_cast<unsigned long>(guid->Data1), guid->Data2, guid->Data3, guid->Data4[0],
                                   guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5]);
            return chars > 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            buffer[0] = L'\0';
            return false;
        }
    }

    static void FormatCoInitMode(DWORD coInit, wchar_t buffer[32]) noexcept
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

    static void FormatJobInfoClass(JOBOBJECTINFOCLASS infoClass, wchar_t buffer[32]) noexcept
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

    static bool InstallInlineHook(void *target, void *hook, std::uint8_t original[16], void **trampolineOut) noexcept
    {
        constexpr std::size_t kPatchSize = 16;
        constexpr std::size_t kTrampolineSize = 32;

        if (target == nullptr || hook == nullptr || original == nullptr || trampolineOut == nullptr)
        {
            return false;
        }

        void *trampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (trampoline == nullptr)
        {
            return false;
        }

        auto *dst = static_cast<std::uint8_t *>(target);
        auto *gate = static_cast<std::uint8_t *>(trampoline);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(original, dst, kPatchSize);
        std::memcpy(gate, dst, kPatchSize);
        gate[16] = 0x48;
        gate[17] = 0xB8;
        *reinterpret_cast<void **>(&gate[18]) = dst + kPatchSize;
        gate[26] = 0xFF;
        gate[27] = 0xE0;
        for (std::size_t i = 28; i < kTrampolineSize; ++i)
        {
            gate[i] = 0xCC;
        }

        DWORD trampolineProtect = 0;
        if (!VirtualProtect(trampoline, kTrampolineSize, PAGE_EXECUTE_READ, &trampolineProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }
        FlushInstructionCache(GetCurrentProcess(), trampoline, kTrampolineSize);
        if (!IX_RUNTIME_INTERNAL::RegisterControlFlowGuardCallTarget(
                trampoline, IX_RUNTIME_INTERNAL::IxCfgCallTargetMode::CfgOnly, "rt.mod.trampoline"))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }
        if (!IX_RUNTIME_INTERNAL::RegisterIxDynamicInstrumentationRange(
                trampoline, kTrampolineSize, IX_INSTRUMENTATION_FLAG_EXECUTABLE_HELPER, "rt.mod.trampoline"))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD temp = 0;
        VirtualProtect(dst, kPatchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, kPatchSize);

        *trampolineOut = trampoline;
        return true;
    }

    static void RemoveInlineHook(void *target, const std::uint8_t original[16], void *trampoline) noexcept
    {
        if (target == nullptr || original == nullptr)
        {
            return;
        }

        DWORD oldProtect = 0;
        if (VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            std::memcpy(target, original, 16);
            DWORD temp = 0;
            VirtualProtect(target, 16, oldProtect, &temp);
            FlushInstructionCache(GetCurrentProcess(), target, 16);
        }

        if (trampoline != nullptr)
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
        }
    }

    static void PublishModuleEvent(ModuleHookOperation operation, const char *functionName, const char *sourceModule,
                                   HMODULE moduleHandle, const void *nameBuffer, std::size_t nameLength,
                                   std::uint64_t arg0, std::uint64_t arg1, std::uint64_t arg2,
                                   std::uint64_t arg3) noexcept
    {
        if (g_InHook || IxIsInternalCall() || g_ActiveCallback == nullptr)
        {
            return;
        }

        g_InHook = true;
        if (moduleHandle != nullptr)
        {
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
        context.Caller = _ReturnAddress();
        context.ModuleHandle = moduleHandle;
        context.NameBuffer = nameBuffer;
        context.NameLength = nameLength;
        context.Args[0] = arg0;
        context.Args[1] = arg1;
        context.Args[2] = arg2;
        context.Args[3] = arg3;
        g_ActiveCallback(context);
        g_InHook = false;
    }

    static std::size_t CopyAnsiLength(LPCSTR value) noexcept
    {
        return (value != nullptr) ? strnlen_s(value, 31) : 0;
    }

    static std::size_t CopyWideLength(LPCWSTR value) noexcept
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

    static bool WideContainsInsensitive(const wchar_t *value, const wchar_t *needle) noexcept
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

    static bool LooksSensitiveName(const wchar_t *value) noexcept
    {
        return WideContainsInsensitive(value, L"password") || WideContainsInsensitive(value, L"passwd") ||
               WideContainsInsensitive(value, L"secret") || WideContainsInsensitive(value, L"token") ||
               WideContainsInsensitive(value, L"cookie") || WideContainsInsensitive(value, L"privatekey");
    }

    static void CopyRedactedWide(wchar_t buffer[32], LPCWSTR value) noexcept
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

    static void CopyRedactedAnsiToWide(wchar_t buffer[32], LPCSTR value) noexcept
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

    static void CopyLsaStringToWide(wchar_t buffer[32], PLSA_STRING value) noexcept
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

    static void CopyLsaUnicodeStringToWide(wchar_t buffer[32], PLSA_UNICODE_STRING value) noexcept
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

    static std::uint32_t SafeReadDword(const DWORD *value) noexcept
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

    static std::uint32_t SafeReadUlong(const ULONG *value) noexcept
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

    static NTSTATUS SafeReadNtStatus(const NTSTATUS *value) noexcept
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

    static void *SafeReadPointer(void *const *value) noexcept
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

    static std::uint32_t SafeReadFirstU32(const void *buffer, ULONG length) noexcept
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

    static std::uint32_t SafeBlobSize(const DATA_BLOB *blob) noexcept
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

    static SRWLOCK g_LsaPackageCacheLock = SRWLOCK_INIT;
    static LsaPackageCacheEntry g_LsaPackageCache[16]{};
    static std::uint32_t g_LsaPackageCacheNext = 0;

    static void StoreLsaPackageName(ULONG packageId, const wchar_t *name) noexcept
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

    static void LookupLsaPackageName(ULONG packageId, wchar_t buffer[32]) noexcept
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

    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName)
    {
        if (g_OriginalLoadLibraryA == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryA(lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryA, "LoadLibraryA", "KERNELBASE", moduleHandle, lpLibFileName,
                           CopyAnsiLength(lpLibFileName));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName)
    {
        if (g_OriginalLoadLibraryW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryW(lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryW, "LoadLibraryW", "KERNELBASE", moduleHandle, lpLibFileName,
                           CopyWideLength(lpLibFileName));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        if (g_OriginalLoadLibraryExA == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryExA(lpLibFileName, hFile, dwFlags);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryExA, "LoadLibraryExA", "KERNELBASE", moduleHandle,
                           lpLibFileName, CopyAnsiLength(lpLibFileName), static_cast<std::uint64_t>(dwFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(hFile)));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        if (g_OriginalLoadLibraryExW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryExW, "LoadLibraryExW", "KERNELBASE", moduleHandle,
                           lpLibFileName, CopyWideLength(lpLibFileName), static_cast<std::uint64_t>(dwFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(hFile)));
        return moduleHandle;
    }

    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath, PULONG loadFlags, PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle)
    {
        if (g_OriginalLdrLoadDll == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = g_OriginalLdrLoadDll(searchPath, loadFlags, moduleFileName, moduleHandle);
        HMODULE resolved = nullptr;
        if (NT_SUCCESS(status) && moduleHandle != nullptr)
        {
            resolved = reinterpret_cast<HMODULE>(*moduleHandle);
        }

        PublishModuleEvent(ModuleHookOperation::LdrLoadDll, "LdrLoadDll", "ntdll", resolved,
                           (moduleFileName != nullptr) ? moduleFileName->Buffer : nullptr,
                           (moduleFileName != nullptr && moduleFileName->Length > 0) ? moduleFileName->Length : 0,
                           static_cast<std::uint64_t>((loadFlags != nullptr) ? *loadFlags : 0),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(searchPath)),
                           static_cast<std::uint64_t>((moduleFileName != nullptr) ? moduleFileName->Length : 0));
        return status;
    }

    BOOLEAN WINAPI RtlAddFunctionTableHook(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress)
    {
        if (g_OriginalRtlAddFunctionTable == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = g_OriginalRtlAddFunctionTable(functionTable, entryCount, baseAddress);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlAddFunctionTable, "RtlAddFunctionTable", "ntdll", nullptr,
                               nullptr, 0, static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(functionTable)),
                               static_cast<std::uint64_t>(entryCount), static_cast<std::uint64_t>(baseAddress), 0);
        }
        return ok;
    }

    BOOLEAN WINAPI RtlInstallFunctionTableCallbackHook(DWORD64 tableIdentifier, DWORD64 baseAddress, DWORD length,
                                                       PGET_RUNTIME_FUNCTION_CALLBACK callback, PVOID context,
                                                       PCWSTR outOfProcessCallbackDll)
    {
        if (g_OriginalRtlInstallFunctionTableCallback == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = g_OriginalRtlInstallFunctionTableCallback(tableIdentifier, baseAddress, length, callback, context,
                                                               outOfProcessCallbackDll);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlInstallFunctionTableCallback, "RtlInstallFunctionTableCallback",
                               "ntdll", nullptr, outOfProcessCallbackDll, CopyWideLength(outOfProcessCallbackDll),
                               static_cast<std::uint64_t>(tableIdentifier), static_cast<std::uint64_t>(baseAddress),
                               static_cast<std::uint64_t>(length),
                               static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(callback)));
        }
        return ok;
    }

    BOOLEAN WINAPI RtlDeleteFunctionTableHook(PRUNTIME_FUNCTION functionTable)
    {
        if (g_OriginalRtlDeleteFunctionTable == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = g_OriginalRtlDeleteFunctionTable(functionTable);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlDeleteFunctionTable, "RtlDeleteFunctionTable", "ntdll", nullptr,
                               nullptr, 0, static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(functionTable)), 0, 0,
                               0);
        }
        return ok;
    }

    PVOID NTAPI RtlAddVectoredExceptionHandlerHook(ULONG first, PVECTORED_EXCEPTION_HANDLER handler)
    {
        if (g_OriginalRtlAddVectoredExceptionHandler == nullptr)
        {
            return nullptr;
        }

        PVOID handle = g_OriginalRtlAddVectoredExceptionHandler(first, handler);
        PublishModuleEvent(ModuleHookOperation::RtlAddVectoredExceptionHandler, "RtlAddVectoredExceptionHandler",
                           "ntdll", nullptr, nullptr, 0, static_cast<std::uint64_t>(first),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handler)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)), 0);
        return handle;
    }

    ULONG NTAPI RtlRemoveVectoredExceptionHandlerHook(PVOID handle)
    {
        if (g_OriginalRtlRemoveVectoredExceptionHandler == nullptr)
        {
            return 0;
        }

        ULONG status = g_OriginalRtlRemoveVectoredExceptionHandler(handle);
        PublishModuleEvent(ModuleHookOperation::RtlRemoveVectoredExceptionHandler,
                           "RtlRemoveVectoredExceptionHandler", "ntdll", nullptr, nullptr, 0,
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)),
                           static_cast<std::uint64_t>(status), 0, 0);
        return status;
    }

    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilterHook(LPTOP_LEVEL_EXCEPTION_FILTER filter)
    {
        if (g_OriginalSetUnhandledExceptionFilter == nullptr)
        {
            return nullptr;
        }

        LPTOP_LEVEL_EXCEPTION_FILTER previous = g_OriginalSetUnhandledExceptionFilter(filter);
        PublishModuleEvent(ModuleHookOperation::SetUnhandledExceptionFilter, "SetUnhandledExceptionFilter",
                           "KernelBase", nullptr, nullptr, 0,
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(filter)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(previous)), 0, 0);
        return previous;
    }

    HRESULT WINAPI CoInitializeExHook(LPVOID pvReserved, DWORD dwCoInit)
    {
        if (g_OriginalCoInitializeEx == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = g_OriginalCoInitializeEx(pvReserved, dwCoInit);
        wchar_t mode[32];
        FormatCoInitMode(dwCoInit, mode);
        PublishModuleEvent(ModuleHookOperation::CoInitializeEx, "CoInitializeEx", "combase", nullptr, mode,
                           CopyWideLength(mode), static_cast<std::uint64_t>(dwCoInit),
                           static_cast<std::uint64_t>(static_cast<unsigned long>(hr)), 0, 0);
        return hr;
    }

    HRESULT WINAPI CoInitializeSecurityHook(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc,
                                            SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1,
                                            DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities,
                                            void *pReserved3)
    {
        if (g_OriginalCoInitializeSecurity == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = g_OriginalCoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel,
                                                    pAuthList, dwCapabilities, pReserved3);
        wchar_t label[32];
        CopyLiteralWide(label, L"SecurityInit");
        PublishModuleEvent(ModuleHookOperation::CoInitializeSecurity, "CoInitializeSecurity", "combase", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(static_cast<std::int64_t>(cAuthSvc)),
                           static_cast<std::uint64_t>(dwAuthnLevel), static_cast<std::uint64_t>(dwImpLevel),
                           static_cast<std::uint64_t>(dwCapabilities));
        return hr;
    }

    HRESULT WINAPI CoCreateInstanceHook(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid,
                                        LPVOID *ppv)
    {
        if (g_OriginalCoCreateInstance == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = g_OriginalCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
        wchar_t className[32];
        if (InlineIsEqualGUID(rclsid, CLSID_WbemLocatorValue))
        {
            CopyLiteralWide(className, L"WMI:WbemLocator");
        }
        else if (!TryFormatGuid(&rclsid, className))
        {
            CopyLiteralWide(className, L"COMClass");
        }

        PublishModuleEvent(ModuleHookOperation::CoCreateInstance, "CoCreateInstance", "combase", nullptr, className,
                           CopyWideLength(className), static_cast<std::uint64_t>(dwClsContext),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(pUnkOuter)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(ppv)),
                           static_cast<std::uint64_t>(static_cast<unsigned long>(hr)));
        return hr;
    }

    ULONG WINAPI EventRegisterHook(LPCGUID providerId, PENABLECALLBACK enableCallback, PVOID callbackContext,
                                   PREGHANDLE regHandle)
    {
        if (g_OriginalEventRegister == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = g_OriginalEventRegister(providerId, enableCallback, callbackContext, regHandle);
        wchar_t provider[32];
        if (!TryFormatGuid(providerId, provider))
        {
            CopyLiteralWide(provider, L"ETWProvider");
        }

        PublishModuleEvent(
            ModuleHookOperation::EventRegister, "EventRegister", "advapi32", nullptr, provider,
            CopyWideLength(provider), static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(enableCallback)),
            static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(callbackContext)),
            static_cast<std::uint64_t>((regHandle != nullptr) ? *regHandle : 0), static_cast<std::uint64_t>(status));
        return status;
    }

    ULONG WINAPI EventUnregisterHook(REGHANDLE regHandle)
    {
        if (g_OriginalEventUnregister == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = g_OriginalEventUnregister(regHandle);
        PublishModuleEvent(ModuleHookOperation::EventUnregister, "EventUnregister", "advapi32", nullptr, nullptr, 0,
                           static_cast<std::uint64_t>(regHandle), static_cast<std::uint64_t>(status), 0, 0);
        return status;
    }

    ULONG WINAPI StartTraceWHook(PTRACEHANDLE sessionHandle, LPCWSTR sessionName, PEVENT_TRACE_PROPERTIES properties)
    {
        if (g_OriginalStartTraceW == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = g_OriginalStartTraceW(sessionHandle, sessionName, properties);
        PublishModuleEvent(
            ModuleHookOperation::StartTraceW, "StartTraceW", "advapi32", nullptr, sessionName,
            CopyWideLength(sessionName), static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(sessionHandle)),
            static_cast<std::uint64_t>((sessionHandle != nullptr) ? *sessionHandle : 0),
            static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(properties)), static_cast<std::uint64_t>(status));
        return status;
    }

    ULONG WINAPI EnableTraceEx2Hook(TRACEHANDLE traceHandle, LPCGUID providerId, ULONG controlCode, UCHAR level,
                                    ULONGLONG matchAnyKeyword, ULONGLONG matchAllKeyword, ULONG timeout,
                                    PENABLE_TRACE_PARAMETERS enableParameters)
    {
        if (g_OriginalEnableTraceEx2 == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = g_OriginalEnableTraceEx2(traceHandle, providerId, controlCode, level, matchAnyKeyword,
                                                matchAllKeyword, timeout, enableParameters);
        wchar_t provider[32];
        if (!TryFormatGuid(providerId, provider))
        {
            CopyLiteralWide(provider, L"ETWControl");
        }

        PublishModuleEvent(ModuleHookOperation::EnableTraceEx2, "EnableTraceEx2", "advapi32", nullptr, provider,
                           CopyWideLength(provider), static_cast<std::uint64_t>(traceHandle),
                           static_cast<std::uint64_t>(controlCode), static_cast<std::uint64_t>(level),
                           static_cast<std::uint64_t>(status));
        return status;
    }

    HANDLE WINAPI CreateJobObjectWHook(LPSECURITY_ATTRIBUTES securityAttributes, LPCWSTR name)
    {
        if (g_OriginalCreateJobObjectW == nullptr)
        {
            return nullptr;
        }

        HANDLE handle = g_OriginalCreateJobObjectW(securityAttributes, name);
        PublishModuleEvent(ModuleHookOperation::CreateJobObjectW, "CreateJobObjectW", "kernel32", nullptr, name,
                           CopyWideLength(name), static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(securityAttributes)), 0, 0);
        return handle;
    }

    HANDLE WINAPI OpenJobObjectWHook(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name)
    {
        if (g_OriginalOpenJobObjectW == nullptr)
        {
            return nullptr;
        }

        HANDLE handle = g_OriginalOpenJobObjectW(desiredAccess, inheritHandle, name);
        PublishModuleEvent(ModuleHookOperation::OpenJobObjectW, "OpenJobObjectW", "kernel32", nullptr, name,
                           CopyWideLength(name), static_cast<std::uint64_t>(desiredAccess),
                           static_cast<std::uint64_t>(inheritHandle),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)), 0);
        return handle;
    }

    BOOL WINAPI AssignProcessToJobObjectHook(HANDLE job, HANDLE process)
    {
        if (g_OriginalAssignProcessToJobObject == nullptr)
        {
            return FALSE;
        }

        BOOL ok = g_OriginalAssignProcessToJobObject(job, process);
        wchar_t label[32];
        CopyLiteralWide(label, L"AssignProcess");
        PublishModuleEvent(
            ModuleHookOperation::AssignProcessToJobObject, "AssignProcessToJobObject", "kernel32", nullptr, label,
            CopyWideLength(label), static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(job)),
            static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(process)), static_cast<std::uint64_t>(ok), 0);
        return ok;
    }

    BOOL WINAPI SetInformationJobObjectHook(HANDLE job, JOBOBJECTINFOCLASS infoClass, LPVOID info, DWORD infoLength)
    {
        if (g_OriginalSetInformationJobObject == nullptr)
        {
            return FALSE;
        }

        BOOL ok = g_OriginalSetInformationJobObject(job, infoClass, info, infoLength);
        wchar_t label[32];
        FormatJobInfoClass(infoClass, label);
        PublishModuleEvent(ModuleHookOperation::SetInformationJobObject, "SetInformationJobObject", "kernel32", nullptr,
                           label, CopyWideLength(label), static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(job)),
                           static_cast<std::uint64_t>(infoClass), static_cast<std::uint64_t>(infoLength),
                           static_cast<std::uint64_t>(ok));
        return ok;
    }

    NTSTATUS WINAPI LsaConnectUntrustedHook(PHANDLE lsaHandle)
    {
        if (g_OriginalLsaConnectUntrusted == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = g_OriginalLsaConnectUntrusted(lsaHandle);
        wchar_t label[32];
        CopyLiteralWide(label, L"LsaUntrusted");
        PublishModuleEvent(ModuleHookOperation::LsaConnectUntrusted, "LsaConnectUntrusted", "sspicli", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(lsaHandle))), 0, 0);
        return status;
    }

    NTSTATUS WINAPI LsaLookupAuthenticationPackageHook(HANDLE lsaHandle, PLSA_STRING packageName,
                                                       PULONG authenticationPackage)
    {
        if (g_OriginalLsaLookupAuthenticationPackage == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        wchar_t package[32];
        CopyLsaStringToWide(package, packageName);
        NTSTATUS status = g_OriginalLsaLookupAuthenticationPackage(lsaHandle, packageName, authenticationPackage);
        ULONG packageId = SafeReadUlong(authenticationPackage);
        if (status >= 0 && packageId != 0 && package[0] != L'\0')
        {
            StoreLsaPackageName(packageId, package);
        }

        PublishModuleEvent(ModuleHookOperation::LsaLookupAuthenticationPackage, "LsaLookupAuthenticationPackage",
                           "sspicli", nullptr, package, CopyWideLength(package),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(packageId),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(lsaHandle)), 0);
        return status;
    }

    NTSTATUS WINAPI LsaCallAuthenticationPackageHook(HANDLE lsaHandle, ULONG authenticationPackage, PVOID submitBuffer,
                                                     ULONG submitBufferLength, PVOID *returnBuffer,
                                                     PULONG returnBufferLength, PNTSTATUS protocolStatus)
    {
        if (g_OriginalLsaCallAuthenticationPackage == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        std::uint32_t messageType = SafeReadFirstU32(submitBuffer, submitBufferLength);
        NTSTATUS status =
            g_OriginalLsaCallAuthenticationPackage(lsaHandle, authenticationPackage, submitBuffer, submitBufferLength,
                                                   returnBuffer, returnBufferLength, protocolStatus);
        ULONG outputLength = SafeReadUlong(returnBufferLength);
        NTSTATUS protocol = SafeReadNtStatus(protocolStatus);
        wchar_t package[32];
        LookupLsaPackageName(authenticationPackage, package);
        PublishModuleEvent(ModuleHookOperation::LsaCallAuthenticationPackage, "LsaCallAuthenticationPackage", "sspicli",
                           nullptr, package, CopyWideLength(package),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(authenticationPackage),
                           (static_cast<std::uint64_t>(messageType) << 32u) | submitBufferLength,
                           (static_cast<std::uint64_t>(static_cast<ULONG>(protocol)) << 32u) | outputLength);
        return status;
    }

    LONG WINAPI AcquireCredentialsHandleAHook(LPSTR principal, LPSTR package, ULONG credentialUse, PLUID logonId,
                                              PVOID authData, PVOID getKeyFn, PVOID getKeyArgument, PVOID credential,
                                              PVOID expiry)
    {
        if (g_OriginalAcquireCredentialsHandleA == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedAnsiToWide(label, package);
        LONG status = g_OriginalAcquireCredentialsHandleA(principal, package, credentialUse, logonId, authData,
                                                          getKeyFn, getKeyArgument, credential, expiry);
        PublishModuleEvent(ModuleHookOperation::AcquireCredentialsHandleA, "AcquireCredentialsHandleA", "sspicli",
                           nullptr, label, CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(credentialUse),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(principal)), 0);
        return status;
    }

    LONG WINAPI AcquireCredentialsHandleWHook(LPWSTR principal, LPWSTR package, ULONG credentialUse, PLUID logonId,
                                              PVOID authData, PVOID getKeyFn, PVOID getKeyArgument, PVOID credential,
                                              PVOID expiry)
    {
        if (g_OriginalAcquireCredentialsHandleW == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedWide(label, package);
        LONG status = g_OriginalAcquireCredentialsHandleW(principal, package, credentialUse, logonId, authData,
                                                          getKeyFn, getKeyArgument, credential, expiry);
        PublishModuleEvent(ModuleHookOperation::AcquireCredentialsHandleW, "AcquireCredentialsHandleW", "sspicli",
                           nullptr, label, CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(credentialUse),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(principal)), 0);
        return status;
    }

    LONG WINAPI InitializeSecurityContextAHook(PVOID credential, PVOID context, LPSTR targetName, ULONG contextReq,
                                               ULONG reserved1, ULONG targetDataRep, PVOID input, ULONG reserved2,
                                               PVOID newContext, PVOID output, PULONG contextAttr, PVOID expiry)
    {
        if (g_OriginalInitializeSecurityContextA == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedAnsiToWide(label, targetName);
        LONG status =
            g_OriginalInitializeSecurityContextA(credential, context, targetName, contextReq, reserved1, targetDataRep,
                                                 input, reserved2, newContext, output, contextAttr, expiry);
        PublishModuleEvent(ModuleHookOperation::InitializeSecurityContextA, "InitializeSecurityContextA", "sspicli",
                           nullptr, label, CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(contextReq), static_cast<std::uint64_t>(targetDataRep),
                           static_cast<std::uint64_t>(SafeReadUlong(contextAttr)));
        return status;
    }

    LONG WINAPI InitializeSecurityContextWHook(PVOID credential, PVOID context, LPWSTR targetName, ULONG contextReq,
                                               ULONG reserved1, ULONG targetDataRep, PVOID input, ULONG reserved2,
                                               PVOID newContext, PVOID output, PULONG contextAttr, PVOID expiry)
    {
        if (g_OriginalInitializeSecurityContextW == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedWide(label, targetName);
        LONG status =
            g_OriginalInitializeSecurityContextW(credential, context, targetName, contextReq, reserved1, targetDataRep,
                                                 input, reserved2, newContext, output, contextAttr, expiry);
        PublishModuleEvent(ModuleHookOperation::InitializeSecurityContextW, "InitializeSecurityContextW", "sspicli",
                           nullptr, label, CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(contextReq), static_cast<std::uint64_t>(targetDataRep),
                           static_cast<std::uint64_t>(SafeReadUlong(contextAttr)));
        return status;
    }

    LONG WINAPI AcceptSecurityContextHook(PVOID credential, PVOID context, PVOID input, ULONG contextReq,
                                          ULONG targetDataRep, PVOID newContext, PVOID output, PULONG contextAttr,
                                          PVOID expiry)
    {
        if (g_OriginalAcceptSecurityContext == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        LONG status = g_OriginalAcceptSecurityContext(credential, context, input, contextReq, targetDataRep, newContext,
                                                      output, contextAttr, expiry);
        wchar_t label[32];
        CopyLiteralWide(label, L"AcceptSecurityContext");
        PublishModuleEvent(ModuleHookOperation::AcceptSecurityContext, "AcceptSecurityContext", "sspicli", nullptr,
                           label, CopyWideLength(label), static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(contextReq), static_cast<std::uint64_t>(targetDataRep),
                           static_cast<std::uint64_t>(SafeReadUlong(contextAttr)));
        return status;
    }

    BOOL WINAPI CredReadAHook(LPCSTR targetName, DWORD type, DWORD flags, PVOID *credential)
    {
        if (g_OriginalCredReadA == nullptr)
        {
            return FALSE;
        }

        wchar_t label[32];
        CopyRedactedAnsiToWide(label, targetName);
        BOOL ok = g_OriginalCredReadA(targetName, type, flags, credential);
        PublishModuleEvent(ModuleHookOperation::CredReadA, "CredReadA", "advapi32", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(ok), static_cast<std::uint64_t>(type),
                           static_cast<std::uint64_t>(flags), 0);
        return ok;
    }

    BOOL WINAPI CredReadWHook(LPCWSTR targetName, DWORD type, DWORD flags, PVOID *credential)
    {
        if (g_OriginalCredReadW == nullptr)
        {
            return FALSE;
        }

        wchar_t label[32];
        CopyRedactedWide(label, targetName);
        BOOL ok = g_OriginalCredReadW(targetName, type, flags, credential);
        PublishModuleEvent(ModuleHookOperation::CredReadW, "CredReadW", "advapi32", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(ok), static_cast<std::uint64_t>(type),
                           static_cast<std::uint64_t>(flags), 0);
        return ok;
    }

    BOOL WINAPI CredEnumerateAHook(LPCSTR filter, DWORD flags, DWORD *count, PVOID *credential)
    {
        if (g_OriginalCredEnumerateA == nullptr)
        {
            return FALSE;
        }

        wchar_t label[32];
        CopyRedactedAnsiToWide(label, filter);
        BOOL ok = g_OriginalCredEnumerateA(filter, flags, count, credential);
        PublishModuleEvent(ModuleHookOperation::CredEnumerateA, "CredEnumerateA", "advapi32", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(ok), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)), 0);
        return ok;
    }

    BOOL WINAPI CredEnumerateWHook(LPCWSTR filter, DWORD flags, DWORD *count, PVOID *credential)
    {
        if (g_OriginalCredEnumerateW == nullptr)
        {
            return FALSE;
        }

        wchar_t label[32];
        CopyRedactedWide(label, filter);
        BOOL ok = g_OriginalCredEnumerateW(filter, flags, count, credential);
        PublishModuleEvent(ModuleHookOperation::CredEnumerateW, "CredEnumerateW", "advapi32", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(ok), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)), 0);
        return ok;
    }

    BOOL WINAPI CredReadDomainCredentialsAHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential)
    {
        if (g_OriginalCredReadDomainCredentialsA == nullptr)
        {
            return FALSE;
        }

        BOOL ok = g_OriginalCredReadDomainCredentialsA(targetInfo, flags, count, credential);
        wchar_t label[32];
        CopyLiteralWide(label, L"DomainCredentials");
        PublishModuleEvent(ModuleHookOperation::CredReadDomainCredentialsA, "CredReadDomainCredentialsA", "advapi32",
                           nullptr, label, CopyWideLength(label), static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags), static_cast<std::uint64_t>(SafeReadDword(count)), 0);
        return ok;
    }

    BOOL WINAPI CredReadDomainCredentialsWHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential)
    {
        if (g_OriginalCredReadDomainCredentialsW == nullptr)
        {
            return FALSE;
        }

        BOOL ok = g_OriginalCredReadDomainCredentialsW(targetInfo, flags, count, credential);
        wchar_t label[32];
        CopyLiteralWide(label, L"DomainCredentials");
        PublishModuleEvent(ModuleHookOperation::CredReadDomainCredentialsW, "CredReadDomainCredentialsW", "advapi32",
                           nullptr, label, CopyWideLength(label), static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags), static_cast<std::uint64_t>(SafeReadDword(count)), 0);
        return ok;
    }

    NTSTATUS WINAPI LsaOpenPolicyHook(PLSA_UNICODE_STRING systemName, PLSA_OBJECT_ATTRIBUTES objectAttributes,
                                      ACCESS_MASK desiredAccess, PLSA_HANDLE policyHandle)
    {
        if (g_OriginalLsaOpenPolicy == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        wchar_t label[32];
        CopyLsaUnicodeStringToWide(label, systemName);
        NTSTATUS status = g_OriginalLsaOpenPolicy(systemName, objectAttributes, desiredAccess, policyHandle);
        PublishModuleEvent(ModuleHookOperation::LsaOpenPolicy, "LsaOpenPolicy", "advapi32", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(desiredAccess),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(policyHandle))), 0);
        return status;
    }

    NTSTATUS WINAPI LsaQueryInformationPolicyHook(LSA_HANDLE policyHandle, POLICY_INFORMATION_CLASS informationClass,
                                                  PVOID *buffer)
    {
        if (g_OriginalLsaQueryInformationPolicy == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = g_OriginalLsaQueryInformationPolicy(policyHandle, informationClass, buffer);
        wchar_t label[32];
        CopyLiteralWide(label, L"LsaPolicy");
        PublishModuleEvent(ModuleHookOperation::LsaQueryInformationPolicy, "LsaQueryInformationPolicy", "advapi32",
                           nullptr, label, CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(informationClass),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(policyHandle)), 0);
        return status;
    }

    DWORD WINAPI VaultEnumerateVaultsHook(DWORD flags, DWORD *count, GUID **vaultGuids)
    {
        if (g_OriginalVaultEnumerateVaults == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = g_OriginalVaultEnumerateVaults(flags, count, vaultGuids);
        wchar_t label[32];
        CopyLiteralWide(label, L"Vaults");
        PublishModuleEvent(ModuleHookOperation::VaultEnumerateVaults, "VaultEnumerateVaults", "vaultcli", nullptr,
                           label, CopyWideLength(label), static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(flags), static_cast<std::uint64_t>(SafeReadDword(count)), 0);
        return status;
    }

    DWORD WINAPI VaultOpenVaultHook(const GUID *vaultGuid, DWORD flags, HANDLE *vaultHandle)
    {
        if (g_OriginalVaultOpenVault == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = g_OriginalVaultOpenVault(vaultGuid, flags, vaultHandle);
        wchar_t label[32];
        if (!TryFormatGuid(vaultGuid, label))
        {
            CopyLiteralWide(label, L"Vault");
        }
        PublishModuleEvent(ModuleHookOperation::VaultOpenVault, "VaultOpenVault", "vaultcli", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(status), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(vaultHandle))), 0);
        return status;
    }

    DWORD WINAPI VaultEnumerateItemsHook(HANDLE vaultHandle, DWORD flags, DWORD *count, PVOID *items)
    {
        if (g_OriginalVaultEnumerateItems == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = g_OriginalVaultEnumerateItems(vaultHandle, flags, count, items);
        wchar_t label[32];
        CopyLiteralWide(label, L"VaultItems");
        PublishModuleEvent(ModuleHookOperation::VaultEnumerateItems, "VaultEnumerateItems", "vaultcli", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(status), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(vaultHandle)));
        return status;
    }

    DWORD WINAPI VaultGetItemHook(HANDLE vaultHandle, const GUID *schemaId, PVOID resource, PVOID identity,
                                  PVOID packageSid, HWND hwndOwner, DWORD flags, PVOID *item)
    {
        if (g_OriginalVaultGetItem == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status =
            g_OriginalVaultGetItem(vaultHandle, schemaId, resource, identity, packageSid, hwndOwner, flags, item);
        wchar_t label[32];
        if (!TryFormatGuid(schemaId, label))
        {
            CopyLiteralWide(label, L"VaultItem");
        }
        PublishModuleEvent(ModuleHookOperation::VaultGetItem, "VaultGetItem", "vaultcli", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(status), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(vaultHandle)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(resource)));
        return status;
    }

    BOOL WINAPI CryptUnprotectDataHook(DATA_BLOB *dataIn, LPWSTR *dataDescription, DATA_BLOB *optionalEntropy,
                                       PVOID reserved, CRYPTPROTECT_PROMPTSTRUCT *promptStruct, DWORD flags,
                                       DATA_BLOB *dataOut)
    {
        if (g_OriginalCryptUnprotectData == nullptr)
        {
            return FALSE;
        }

        DWORD promptFlags = 0;
        if (promptStruct != nullptr)
        {
            __try
            {
                promptFlags = promptStruct->dwPromptFlags;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                promptFlags = 0;
            }
        }

        BOOL ok = g_OriginalCryptUnprotectData(dataIn, dataDescription, optionalEntropy, reserved, promptStruct, flags,
                                               dataOut);
        wchar_t label[32];
        CopyLiteralWide(label, L"DPAPI");
        PublishModuleEvent(ModuleHookOperation::CryptUnprotectData, "CryptUnprotectData", "crypt32", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(ok), static_cast<std::uint64_t>(flags),
                           (static_cast<std::uint64_t>(promptFlags) << 32u) |
                               ((optionalEntropy != nullptr && SafeBlobSize(optionalEntropy) != 0) ? 1ull : 0ull),
                           static_cast<std::uint64_t>(SafeBlobSize(dataOut)));
        return ok;
    }

    LONG WINAPI NCryptUnprotectSecretHook(PVOID *descriptor, DWORD flags, const BYTE *protectedBlob,
                                          ULONG protectedBlobSize, PVOID memPara, HWND hwnd, BYTE **data,
                                          ULONG *dataSize)
    {
        if (g_OriginalNCryptUnprotectSecret == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        LONG status = g_OriginalNCryptUnprotectSecret(descriptor, flags, protectedBlob, protectedBlobSize, memPara,
                                                      hwnd, data, dataSize);
        wchar_t label[32];
        CopyLiteralWide(label, L"NCryptSecret");
        PublishModuleEvent(ModuleHookOperation::NCryptUnprotectSecret, "NCryptUnprotectSecret", "ncrypt", nullptr,
                           label, CopyWideLength(label), static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(flags), static_cast<std::uint64_t>(protectedBlobSize),
                           static_cast<std::uint64_t>(SafeReadUlong(dataSize)));
        return status;
    }

    LONG WINAPI NCryptOpenStorageProviderHook(PVOID *provider, LPCWSTR providerName, DWORD flags)
    {
        if (g_OriginalNCryptOpenStorageProvider == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        wchar_t label[32];
        CopyRedactedWide(label, providerName);
        LONG status = g_OriginalNCryptOpenStorageProvider(provider, providerName, flags);
        PublishModuleEvent(ModuleHookOperation::NCryptOpenStorageProvider, "NCryptOpenStorageProvider", "ncrypt",
                           nullptr, label, CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(provider))), 0);
        return status;
    }

    LONG WINAPI NCryptOpenKeyHook(PVOID provider, PVOID *key, LPCWSTR keyName, DWORD legacyKeySpec, DWORD flags)
    {
        if (g_OriginalNCryptOpenKey == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        wchar_t label[32];
        CopyRedactedWide(label, keyName);
        LONG status = g_OriginalNCryptOpenKey(provider, key, keyName, legacyKeySpec, flags);
        PublishModuleEvent(ModuleHookOperation::NCryptOpenKey, "NCryptOpenKey", "ncrypt", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(legacyKeySpec), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(key))));
        return status;
    }

    LONG WINAPI NCryptDecryptHook(PVOID key, PBYTE input, DWORD inputSize, PVOID paddingInfo, PBYTE output,
                                  DWORD outputSize, DWORD *resultSize, DWORD flags)
    {
        if (g_OriginalNCryptDecrypt == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        LONG status =
            g_OriginalNCryptDecrypt(key, input, inputSize, paddingInfo, output, outputSize, resultSize, flags);
        wchar_t label[32];
        CopyLiteralWide(label, L"NCryptDecrypt");
        PublishModuleEvent(ModuleHookOperation::NCryptDecrypt, "NCryptDecrypt", "ncrypt", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(flags), static_cast<std::uint64_t>(inputSize),
                           static_cast<std::uint64_t>(SafeReadDword(resultSize)));
        return status;
    }

    DWORD WINAPI CfAbortOperationHook(DWORD processId, PVOID unknown, DWORD flags)
    {
        if (g_OriginalCfAbortOperation == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = g_OriginalCfAbortOperation(processId, unknown, flags);
        wchar_t label[32];
        CopyLiteralWide(label, L"AbortHydration");
        PublishModuleEvent(ModuleHookOperation::CfAbortOperation, "CfAbortOperation", "cldapi", nullptr, label,
                           CopyWideLength(label), static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(processId), static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(unknown)));
        return status;
    }

    HRESULT WINAPI CfRegisterSyncRootHook(LPCWSTR syncRootPath, const void *registration, const void *policies,
                                          DWORD registerFlags)
    {
        if (g_OriginalCfRegisterSyncRoot == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = g_OriginalCfRegisterSyncRoot(syncRootPath, registration, policies, registerFlags);
        PublishModuleEvent(ModuleHookOperation::CfRegisterSyncRoot, "CfRegisterSyncRoot", "cldapi", nullptr,
                           syncRootPath, CopyWideLength(syncRootPath),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(registerFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(registration)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(policies)));
        return hr;
    }

    HRESULT WINAPI CfConnectSyncRootHook(LPCWSTR syncRootPath, const void *callbackTable, void *callbackContext,
                                         DWORD connectFlags, void *connectionKey)
    {
        if (g_OriginalCfConnectSyncRoot == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr =
            g_OriginalCfConnectSyncRoot(syncRootPath, callbackTable, callbackContext, connectFlags, connectionKey);
        PublishModuleEvent(ModuleHookOperation::CfConnectSyncRoot, "CfConnectSyncRoot", "cldapi", nullptr,
                           syncRootPath, CopyWideLength(syncRootPath),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(connectFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(callbackTable)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(connectionKey)));
        return hr;
    }

    HRESULT WINAPI CfCreatePlaceholdersHook(LPCWSTR baseDirectoryPath, void *placeholderArray, DWORD placeholderCount,
                                            DWORD createFlags, DWORD *entriesProcessed)
    {
        if (g_OriginalCfCreatePlaceholders == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = g_OriginalCfCreatePlaceholders(baseDirectoryPath, placeholderArray, placeholderCount, createFlags,
                                                    entriesProcessed);
        PublishModuleEvent(ModuleHookOperation::CfCreatePlaceholders, "CfCreatePlaceholders", "cldapi", nullptr,
                           baseDirectoryPath, CopyWideLength(baseDirectoryPath),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(placeholderCount), static_cast<std::uint64_t>(createFlags),
                           static_cast<std::uint64_t>(SafeReadDword(entriesProcessed)));
        return hr;
    }

    HRESULT WINAPI AmsiScanBufferHook(PVOID amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName,
                                      PVOID session, PVOID result)
    {
        if (g_OriginalAmsiScanBuffer == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = g_OriginalAmsiScanBuffer(amsiContext, buffer, length, contentName, session, result);
        WCHAR scriptSample[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        std::memset(scriptSample, 0, sizeof(scriptSample));
        std::memset(reason, 0, sizeof(reason));
        if (buffer != nullptr && length != 0)
        {
            if (BufferLooksUtf16LeText(buffer, length))
            {
                CopyWidePrintableToWide(scriptSample, RTL_NUMBER_OF(scriptSample), static_cast<LPCWSTR>(buffer),
                                        length / sizeof(WCHAR));
            }
            else
            {
                CopyPrintableBytesToWide(scriptSample, RTL_NUMBER_OF(scriptSample), buffer, length);
            }
        }
        (void)swprintf_s(reason, RTL_NUMBER_OF(reason),
                         L"powershell.amsi.script contentName=%s bytes=%lu status=0x%08lX result=0x%08lX script=\"%s\"",
                         contentName != nullptr && contentName[0] != L'\0' ? contentName : L"<unknown>",
                         static_cast<unsigned long>(length), static_cast<unsigned long>(hr),
                         static_cast<unsigned long>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                         scriptSample[0] != L'\0' ? scriptSample : L"-");
        PublishModuleEvent(ModuleHookOperation::AmsiScanBuffer, "AmsiScanBuffer", "amsi", nullptr, reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)), static_cast<std::uint64_t>(length),
                           static_cast<std::uint64_t>(
                               result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                           0);
        return hr;
    }

    PVOID WINAPI WinHttpConnectHook(PVOID session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved)
    {
        if (g_OriginalWinHttpConnect == nullptr)
        {
            return nullptr;
        }

        PVOID handle = g_OriginalWinHttpConnect(session, serverName, serverPort, reserved);
        HttpCacheStoreConnect(handle, serverName, serverPort);
        return handle;
    }

    PVOID WINAPI WinHttpOpenRequestHook(PVOID connect, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version,
                                        LPCWSTR referrer, LPCWSTR *acceptTypes, DWORD flags)
    {
        if (g_OriginalWinHttpOpenRequest == nullptr)
        {
            return nullptr;
        }

        PVOID request = g_OriginalWinHttpOpenRequest(connect, verb, objectName, version, referrer, acceptTypes, flags);
        HttpCacheStoreRequest(request, connect, verb, objectName, (flags & WINHTTP_FLAG_SECURE) != 0);
        return request;
    }

    BOOL WINAPI WinHttpSendRequestHook(PVOID request, LPCWSTR headers, DWORD headersLength, PVOID optional,
                                       DWORD optionalLength, DWORD totalLength, DWORD_PTR context)
    {
        if (g_OriginalWinHttpSendRequest == nullptr)
        {
            return FALSE;
        }

        PublishHttpLibraryRequest(ModuleHookOperation::WinHttpSendRequest, "WinHttpSendRequest", "winhttp", request,
                                  headers, headersLength, optional, optionalLength, false);
        return g_OriginalWinHttpSendRequest(request, headers, headersLength, optional, optionalLength, totalLength,
                                            context);
    }

    PVOID WINAPI InternetConnectWHook(PVOID internet, LPCWSTR serverName, INTERNET_PORT serverPort, LPCWSTR userName,
                                      LPCWSTR password, DWORD service, DWORD flags, DWORD_PTR context)
    {
        if (g_OriginalInternetConnectW == nullptr)
        {
            return nullptr;
        }

        PVOID handle =
            g_OriginalInternetConnectW(internet, serverName, serverPort, userName, password, service, flags, context);
        if (service == INTERNET_SERVICE_HTTP)
        {
            HttpCacheStoreConnect(handle, serverName, serverPort);
        }
        return handle;
    }

    PVOID WINAPI InternetConnectAHook(PVOID internet, LPCSTR serverName, INTERNET_PORT serverPort, LPCSTR userName,
                                      LPCSTR password, DWORD service, DWORD flags, DWORD_PTR context)
    {
        if (g_OriginalInternetConnectA == nullptr)
        {
            return nullptr;
        }

        PVOID handle =
            g_OriginalInternetConnectA(internet, serverName, serverPort, userName, password, service, flags, context);
        if (service == INTERNET_SERVICE_HTTP)
        {
            WCHAR host[128];
            CopyAnsiToWideTruncated(host, RTL_NUMBER_OF(host), serverName);
            HttpCacheStoreConnect(handle, host, serverPort);
        }
        return handle;
    }

    PVOID WINAPI HttpOpenRequestWHook(PVOID connect, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version,
                                      LPCWSTR referrer, LPCWSTR *acceptTypes, DWORD flags, DWORD_PTR context)
    {
        if (g_OriginalHttpOpenRequestW == nullptr)
        {
            return nullptr;
        }

        PVOID request =
            g_OriginalHttpOpenRequestW(connect, verb, objectName, version, referrer, acceptTypes, flags, context);
        HttpCacheStoreRequest(request, connect, verb, objectName, (flags & INTERNET_FLAG_SECURE) != 0);
        return request;
    }

    PVOID WINAPI HttpOpenRequestAHook(PVOID connect, LPCSTR verb, LPCSTR objectName, LPCSTR version, LPCSTR referrer,
                                      LPCSTR *acceptTypes, DWORD flags, DWORD_PTR context)
    {
        if (g_OriginalHttpOpenRequestA == nullptr)
        {
            return nullptr;
        }

        PVOID request =
            g_OriginalHttpOpenRequestA(connect, verb, objectName, version, referrer, acceptTypes, flags, context);
        WCHAR method[16];
        WCHAR path[160];
        CopyAnsiToWideTruncated(method, RTL_NUMBER_OF(method), verb);
        CopyAnsiToWideTruncated(path, RTL_NUMBER_OF(path), objectName);
        HttpCacheStoreRequest(request, connect, method, path, (flags & INTERNET_FLAG_SECURE) != 0);
        return request;
    }

    BOOL WINAPI HttpSendRequestWHook(PVOID request, LPCWSTR headers, DWORD headersLength, PVOID optional,
                                     DWORD optionalLength)
    {
        if (g_OriginalHttpSendRequestW == nullptr)
        {
            return FALSE;
        }

        PublishHttpLibraryRequest(ModuleHookOperation::HttpSendRequestW, "HttpSendRequestW", "wininet", request,
                                  headers, headersLength, optional, optionalLength, false);
        return g_OriginalHttpSendRequestW(request, headers, headersLength, optional, optionalLength);
    }

    BOOL WINAPI HttpSendRequestAHook(PVOID request, LPCSTR headers, DWORD headersLength, PVOID optional,
                                     DWORD optionalLength)
    {
        if (g_OriginalHttpSendRequestA == nullptr)
        {
            return FALSE;
        }

        WCHAR wideHeaders[96];
        CopyAnsiToWideTruncated(wideHeaders, RTL_NUMBER_OF(wideHeaders), headers);
        PublishHttpLibraryRequest(ModuleHookOperation::HttpSendRequestA, "HttpSendRequestA", "wininet", request,
                                  wideHeaders, headersLength == 0xFFFFFFFFu
                                                   ? static_cast<DWORD>(wcsnlen_s(wideHeaders, RTL_NUMBER_OF(wideHeaders)))
                                                   : static_cast<DWORD>(wcsnlen_s(wideHeaders, RTL_NUMBER_OF(wideHeaders))),
                                  optional, optionalLength, false);
        return g_OriginalHttpSendRequestA(request, headers, headersLength, optional, optionalLength);
    }

    LONG WINAPI EncryptMessageHook(PVOID context, ULONG qualityOfProtection, PVOID message, ULONG sequenceNumber)
    {
        if (g_OriginalEncryptMessage == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        PublishSchannelPlaintext(ModuleHookOperation::SchannelEncryptMessage, "EncryptMessage", message);
        return g_OriginalEncryptMessage(context, qualityOfProtection, message, sequenceNumber);
    }

    LONG WINAPI DecryptMessageHook(PVOID context, PVOID message, ULONG sequenceNumber, PULONG qualityOfProtection)
    {
        if (g_OriginalDecryptMessage == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        LONG status = g_OriginalDecryptMessage(context, message, sequenceNumber, qualityOfProtection);
        if (status >= 0)
        {
            PublishSchannelPlaintext(ModuleHookOperation::SchannelDecryptMessage, "DecryptMessage", message);
        }
        return status;
    }

} // namespace

bool IxSetModuleHook(ModuleHookCallback callback) noexcept
{
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveCallback = callback;
    ResetModuleHookInitFault();

    bool anyInstalled = false;
    for (auto &hook : g_Hooks)
    {
        if (hook.Installed)
        {
            anyInstalled = true;
            continue;
        }

        HMODULE moduleHandle = GetModuleHandleW(hook.ModuleName);
        if (moduleHandle == nullptr)
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ModuleMissing, hook.ModuleName, hook.ExportName, nullptr);
            continue;
        }

        ModuleRange moduleRange{};
        if (!TryResolveModuleImageRange(moduleHandle, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportOutsideImage, hook.ModuleName, hook.ExportName,
                                   moduleHandle);
            continue;
        }

        FARPROC exportAddress = GetProcAddress(moduleHandle, hook.ExportName);
        if (exportAddress == nullptr)
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportMissing, hook.ModuleName, hook.ExportName, nullptr);
            continue;
        }

        hook.TargetAddress = reinterpret_cast<void *>(exportAddress);
        if (!AddressWithinRange(hook.TargetAddress, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportOutsideImage, hook.ModuleName, hook.ExportName,
                                   hook.TargetAddress);
            continue;
        }

        void *redirectTarget = nullptr;
        if (TryDecodeAbsoluteTarget(hook.TargetAddress, redirectTarget) && redirectTarget != nullptr &&
            !AddressWithinRange(redirectTarget, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportRedirectedOutsideImage, hook.ModuleName,
                                   hook.ExportName, hook.TargetAddress, redirectTarget);
            continue;
        }

        if (!InstallInlineHook(hook.TargetAddress, hook.HookEntry, hook.OriginalBytes, &hook.Trampoline))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::PatchInstallFailed, hook.ModuleName, hook.ExportName,
                                   hook.TargetAddress);
            continue;
        }

        *hook.OriginalFunction = hook.Trampoline;
        hook.Installed = true;
        anyInstalled = true;
    }

    if (!anyInstalled)
    {
        g_ActiveCallback = nullptr;
    }

    return anyInstalled;
}

void IxRemoveModuleHook() noexcept
{
    for (auto &hook : g_Hooks)
    {
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        RemoveInlineHook(hook.TargetAddress, hook.OriginalBytes, hook.Trampoline);
        hook.TargetAddress = nullptr;
        hook.Trampoline = nullptr;
        *hook.OriginalFunction = nullptr;
        hook.Installed = false;
    }

    g_ActiveCallback = nullptr;
}

bool IxRefreshModuleHooks(HMODULE moduleHandle) noexcept
{
    if (moduleHandle == nullptr || g_ActiveCallback == nullptr)
    {
        return false;
    }

    bool anyInstalled = false;
    for (auto &hook : g_Hooks)
    {
        if (hook.Installed)
        {
            continue;
        }

        HMODULE expectedModule = GetModuleHandleW(hook.ModuleName);
        if (expectedModule == nullptr)
        {
            continue;
        }

        ModuleRange moduleRange{};
        if (!TryResolveModuleImageRange(expectedModule, moduleRange))
        {
            continue;
        }

        FARPROC exportAddress = GetProcAddress(expectedModule, hook.ExportName);
        if (exportAddress == nullptr)
        {
            continue;
        }

        hook.TargetAddress = reinterpret_cast<void *>(exportAddress);
        if (!AddressWithinRange(hook.TargetAddress, moduleRange))
        {
            hook.TargetAddress = nullptr;
            continue;
        }

        void *redirectTarget = nullptr;
        if (TryDecodeAbsoluteTarget(hook.TargetAddress, redirectTarget) && redirectTarget != nullptr &&
            !AddressWithinRange(redirectTarget, moduleRange))
        {
            hook.TargetAddress = nullptr;
            continue;
        }

        if (!InstallInlineHook(hook.TargetAddress, hook.HookEntry, hook.OriginalBytes, &hook.Trampoline))
        {
            hook.TargetAddress = nullptr;
            hook.Trampoline = nullptr;
            continue;
        }

        *hook.OriginalFunction = hook.Trampoline;
        hook.Installed = true;
        anyInstalled = true;
    }

    return anyInstalled;
}

bool IxCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
    std::uint32_t mismatches = 0;

    for (const auto &hook : g_Hooks)
    {
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        const auto *bytes = static_cast<const std::uint8_t *>(hook.TargetAddress);
        void *patchedTarget = nullptr;
        std::memcpy(&patchedTarget, &bytes[2], sizeof(patchedTarget));
        bool intact = bytes[0] == 0x48 && bytes[1] == 0xB8 && patchedTarget == hook.HookEntry && bytes[10] == 0xFF &&
                      bytes[11] == 0xE0;
        if (!intact)
        {
            ++mismatches;
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

bool IxGetLastModuleHookInitFault(ModuleHookInitFault *faultOut) noexcept
{
    if (faultOut == nullptr)
    {
        return false;
    }

    *faultOut = g_LastModuleHookInitFault;
    return faultOut->Code != ModuleHookInitFaultCode::None;
}

std::size_t IxCollectModuleHookPatchInfos(ModuleHookPatchInfo *out, std::size_t capacity) noexcept
{
    if (out == nullptr || capacity == 0)
    {
        return 0;
    }

    std::size_t count = 0;
    for (const auto &hook : g_Hooks)
    {
        if (count >= capacity)
        {
            break;
        }
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        out[count].PatchAddress = hook.TargetAddress;
        out[count].PatchSize = sizeof(hook.OriginalBytes);
        std::memcpy(out[count].OriginalBytes, hook.OriginalBytes, sizeof(hook.OriginalBytes));
        out[count].HookName = hook.ExportName;
        out[count].Flags = IX_HOOK_PATCH_FLAG_MODULE_INLINE;
        ++count;
    }

    return count;
}
