#pragma once

#include "module.h"
#include "../runtime/runtime_internal.h"
#include "../ws.h"
#include "../../../ABI/blind_ipc.h"

#include <evntprov.h>
#include <evntrace.h>
#include <intrin.h>
#include <objbase.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <wininet.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef SEC_E_INTERNAL_ERROR
#define SEC_E_INTERNAL_ERROR ((LONG)0x80090304L)
#endif

namespace IX_MODULE_INTERNAL
{
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

    struct ModuleRange
    {
        std::uintptr_t Base = 0;
        std::uintptr_t End = 0;
    };

    using LoadLibraryAFn = HMODULE(WINAPI *)(LPCSTR);
    using LoadLibraryWFn = HMODULE(WINAPI *)(LPCWSTR);
    using LoadLibraryExAFn = HMODULE(WINAPI *)(LPCSTR, HANDLE, DWORD);
    using LoadLibraryExWFn = HMODULE(WINAPI *)(LPCWSTR, HANDLE, DWORD);
    using LdrLoadDllFn = NTSTATUS(NTAPI *)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
    using RtlAddFunctionTableFn = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    using RtlInstallFunctionTableCallbackFn =
        BOOLEAN(WINAPI *)(DWORD64, DWORD64, DWORD, PGET_RUNTIME_FUNCTION_CALLBACK, PVOID, PCWSTR);
    using RtlDeleteFunctionTableFn = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION);
    using RtlAddVectoredExceptionHandlerFn = PVOID(NTAPI *)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    using RtlRemoveVectoredExceptionHandlerFn = ULONG(NTAPI *)(PVOID);
    using SetUnhandledExceptionFilterFn = LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI *)(LPTOP_LEVEL_EXCEPTION_FILTER);
    using CoInitializeExFn = HRESULT(WINAPI *)(LPVOID, DWORD);
    using CoInitializeSecurityFn = HRESULT(WINAPI *)(
        PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE *, void *, DWORD, DWORD, void *, DWORD, void *);
    using CoCreateInstanceFn = HRESULT(WINAPI *)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
    using EventRegisterFn = ULONG(WINAPI *)(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE);
    using EventUnregisterFn = ULONG(WINAPI *)(REGHANDLE);
    using StartTraceWFn = ULONG(WINAPI *)(PTRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES);
    using EnableTraceEx2Fn =
        ULONG(WINAPI *)(TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, PENABLE_TRACE_PARAMETERS);
    using EtwEventWriteFn = ULONG(NTAPI *)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
    using EtwEventWriteExFn =
        ULONG(NTAPI *)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG64, ULONG, LPCGUID, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR);
    using EtwEventWriteFullFn =
        ULONG(NTAPI *)(REGHANDLE, PCEVENT_DESCRIPTOR, USHORT, LPCGUID, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR);
    using EtwEventWriteTransferFn =
        ULONG(NTAPI *)(REGHANDLE, PCEVENT_DESCRIPTOR, LPCGUID, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR);
    using CreateJobObjectWFn = HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, LPCWSTR);
    using OpenJobObjectWFn = HANDLE(WINAPI *)(DWORD, BOOL, LPCWSTR);
    using AssignProcessToJobObjectFn = BOOL(WINAPI *)(HANDLE, HANDLE);
    using SetInformationJobObjectFn = BOOL(WINAPI *)(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
    using LsaConnectUntrustedFn = NTSTATUS(WINAPI *)(PHANDLE);
    using LsaLookupAuthenticationPackageFn = NTSTATUS(WINAPI *)(HANDLE, PLSA_STRING, PULONG);
    using LsaCallAuthenticationPackageFn = NTSTATUS(WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
    using AcquireCredentialsHandleAFn = LONG(WINAPI *)(LPSTR, LPSTR, ULONG, PLUID, PVOID, PVOID, PVOID, PVOID, PVOID);
    using AcquireCredentialsHandleWFn = LONG(WINAPI *)(LPWSTR, LPWSTR, ULONG, PLUID, PVOID, PVOID, PVOID, PVOID, PVOID);
    using InitializeSecurityContextAFn =
        LONG(WINAPI *)(PVOID, PVOID, LPSTR, ULONG, ULONG, ULONG, PVOID, ULONG, PVOID, PVOID, PULONG, PVOID);
    using InitializeSecurityContextWFn =
        LONG(WINAPI *)(PVOID, PVOID, LPWSTR, ULONG, ULONG, ULONG, PVOID, ULONG, PVOID, PVOID, PULONG, PVOID);
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
    using CryptUnprotectDataFn =
        BOOL(WINAPI *)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *);
    using NCryptUnprotectSecretFn = LONG(WINAPI *)(PVOID *, DWORD, const BYTE *, ULONG, PVOID, HWND, BYTE **, ULONG *);
    using NCryptOpenStorageProviderFn = LONG(WINAPI *)(PVOID *, LPCWSTR, DWORD);
    using NCryptOpenKeyFn = LONG(WINAPI *)(PVOID, PVOID *, LPCWSTR, DWORD, DWORD);
    using NCryptDecryptFn = LONG(WINAPI *)(PVOID, PBYTE, DWORD, PVOID, PBYTE, DWORD, DWORD *, DWORD);
    using CfAbortOperationFn = DWORD(WINAPI *)(DWORD, PVOID, DWORD);
    using CfRegisterSyncRootFn = HRESULT(WINAPI *)(LPCWSTR, const void *, const void *, DWORD);
    using CfConnectSyncRootFn = HRESULT(WINAPI *)(LPCWSTR, const void *, void *, DWORD, void *);
    using CfCreatePlaceholdersFn = HRESULT(WINAPI *)(LPCWSTR, void *, DWORD, DWORD, DWORD *);
    using AmsiInitializeFn = HRESULT(WINAPI *)(LPCWSTR, PVOID *);
    using AmsiUninitializeFn = VOID(WINAPI *)(PVOID);
    using AmsiOpenSessionFn = HRESULT(WINAPI *)(PVOID, PVOID *);
    using AmsiCloseSessionFn = VOID(WINAPI *)(PVOID, PVOID);
    using AmsiScanBufferFn = HRESULT(WINAPI *)(PVOID, PVOID, ULONG, LPCWSTR, PVOID, PVOID);
    using AmsiScanStringFn = HRESULT(WINAPI *)(PVOID, LPCWSTR, LPCWSTR, PVOID, PVOID);
    using AmsiNotifyOperationFn = HRESULT(WINAPI *)(PVOID, PVOID, ULONG, LPCWSTR, PVOID);
    using WinHttpConnectFn = PVOID(WINAPI *)(PVOID, LPCWSTR, INTERNET_PORT, DWORD);
    using WinHttpOpenRequestFn = PVOID(WINAPI *)(PVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
    using WinHttpSendRequestFn = BOOL(WINAPI *)(PVOID, LPCWSTR, DWORD, PVOID, DWORD, DWORD, DWORD_PTR);
    using InternetConnectWFn =
        PVOID(WINAPI *)(PVOID, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
    using InternetConnectAFn = PVOID(WINAPI *)(PVOID, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    using HttpOpenRequestWFn = PVOID(WINAPI *)(PVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD, DWORD_PTR);
    using HttpOpenRequestAFn = PVOID(WINAPI *)(PVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR);
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
        std::uint32_t HookMethod = IXIPC_HOOK_METHOD_INLINE;
        void **IatSlots[256]{};
        void *IatOriginals[256]{};
        std::size_t IatSlotCount = 0;
        void *IatThunk = nullptr;
    };

    struct ModuleHookReentryScope
    {
        bool Active = false;

        ModuleHookReentryScope() noexcept;
        ~ModuleHookReentryScope() noexcept;

        ModuleHookReentryScope(const ModuleHookReentryScope &) = delete;
        ModuleHookReentryScope &operator=(const ModuleHookReentryScope &) = delete;
    };

    extern ModuleHookInitFault g_LastModuleHookInitFault;
    extern ModuleHookCallback g_ActiveCallback;
    extern volatile LONG g_ModuleHookTls;
    extern SRWLOCK g_ModuleOriginalCallLock;
    extern InlineHook g_Hooks[];
    extern const std::size_t g_HookCount;
    extern const GUID CLSID_WbemLocatorValue;

    extern LoadLibraryAFn g_OriginalLoadLibraryA;
    extern LoadLibraryWFn g_OriginalLoadLibraryW;
    extern LoadLibraryExAFn g_OriginalLoadLibraryExA;
    extern LoadLibraryExWFn g_OriginalLoadLibraryExW;
    extern LdrLoadDllFn g_OriginalLdrLoadDll;
    extern RtlAddFunctionTableFn g_OriginalRtlAddFunctionTable;
    extern RtlInstallFunctionTableCallbackFn g_OriginalRtlInstallFunctionTableCallback;
    extern RtlDeleteFunctionTableFn g_OriginalRtlDeleteFunctionTable;
    extern RtlAddVectoredExceptionHandlerFn g_OriginalRtlAddVectoredExceptionHandler;
    extern RtlRemoveVectoredExceptionHandlerFn g_OriginalRtlRemoveVectoredExceptionHandler;
    extern SetUnhandledExceptionFilterFn g_OriginalSetUnhandledExceptionFilter;
    extern CoInitializeExFn g_OriginalCoInitializeEx;
    extern CoInitializeSecurityFn g_OriginalCoInitializeSecurity;
    extern CoCreateInstanceFn g_OriginalCoCreateInstance;
    extern EventRegisterFn g_OriginalEventRegister;
    extern EventUnregisterFn g_OriginalEventUnregister;
    extern StartTraceWFn g_OriginalStartTraceW;
    extern EnableTraceEx2Fn g_OriginalEnableTraceEx2;
    extern EtwEventWriteFn g_OriginalEtwEventWrite;
    extern EtwEventWriteExFn g_OriginalEtwEventWriteEx;
    extern EtwEventWriteFullFn g_OriginalEtwEventWriteFull;
    extern EtwEventWriteTransferFn g_OriginalEtwEventWriteTransfer;
    extern CreateJobObjectWFn g_OriginalCreateJobObjectW;
    extern OpenJobObjectWFn g_OriginalOpenJobObjectW;
    extern AssignProcessToJobObjectFn g_OriginalAssignProcessToJobObject;
    extern SetInformationJobObjectFn g_OriginalSetInformationJobObject;
    extern LsaConnectUntrustedFn g_OriginalLsaConnectUntrusted;
    extern LsaLookupAuthenticationPackageFn g_OriginalLsaLookupAuthenticationPackage;
    extern LsaCallAuthenticationPackageFn g_OriginalLsaCallAuthenticationPackage;
    extern AcquireCredentialsHandleAFn g_OriginalAcquireCredentialsHandleA;
    extern AcquireCredentialsHandleWFn g_OriginalAcquireCredentialsHandleW;
    extern InitializeSecurityContextAFn g_OriginalInitializeSecurityContextA;
    extern InitializeSecurityContextWFn g_OriginalInitializeSecurityContextW;
    extern AcceptSecurityContextFn g_OriginalAcceptSecurityContext;
    extern CredReadAFn g_OriginalCredReadA;
    extern CredReadWFn g_OriginalCredReadW;
    extern CredEnumerateAFn g_OriginalCredEnumerateA;
    extern CredEnumerateWFn g_OriginalCredEnumerateW;
    extern CredReadDomainCredentialsAFn g_OriginalCredReadDomainCredentialsA;
    extern CredReadDomainCredentialsWFn g_OriginalCredReadDomainCredentialsW;
    extern LsaOpenPolicyFn g_OriginalLsaOpenPolicy;
    extern LsaQueryInformationPolicyFn g_OriginalLsaQueryInformationPolicy;
    extern VaultEnumerateVaultsFn g_OriginalVaultEnumerateVaults;
    extern VaultOpenVaultFn g_OriginalVaultOpenVault;
    extern VaultEnumerateItemsFn g_OriginalVaultEnumerateItems;
    extern VaultGetItemFn g_OriginalVaultGetItem;
    extern CryptUnprotectDataFn g_OriginalCryptUnprotectData;
    extern NCryptUnprotectSecretFn g_OriginalNCryptUnprotectSecret;
    extern NCryptOpenStorageProviderFn g_OriginalNCryptOpenStorageProvider;
    extern NCryptOpenKeyFn g_OriginalNCryptOpenKey;
    extern NCryptDecryptFn g_OriginalNCryptDecrypt;
    extern CfAbortOperationFn g_OriginalCfAbortOperation;
    extern CfRegisterSyncRootFn g_OriginalCfRegisterSyncRoot;
    extern CfConnectSyncRootFn g_OriginalCfConnectSyncRoot;
    extern CfCreatePlaceholdersFn g_OriginalCfCreatePlaceholders;
    extern AmsiInitializeFn g_OriginalAmsiInitialize;
    extern AmsiUninitializeFn g_OriginalAmsiUninitialize;
    extern AmsiOpenSessionFn g_OriginalAmsiOpenSession;
    extern AmsiCloseSessionFn g_OriginalAmsiCloseSession;
    extern AmsiScanBufferFn g_OriginalAmsiScanBuffer;
    extern AmsiScanStringFn g_OriginalAmsiScanString;
    extern AmsiNotifyOperationFn g_OriginalAmsiNotifyOperation;
    extern WinHttpConnectFn g_OriginalWinHttpConnect;
    extern WinHttpOpenRequestFn g_OriginalWinHttpOpenRequest;
    extern WinHttpSendRequestFn g_OriginalWinHttpSendRequest;
    extern InternetConnectWFn g_OriginalInternetConnectW;
    extern InternetConnectAFn g_OriginalInternetConnectA;
    extern HttpOpenRequestWFn g_OriginalHttpOpenRequestW;
    extern HttpOpenRequestAFn g_OriginalHttpOpenRequestA;
    extern HttpSendRequestWFn g_OriginalHttpSendRequestW;
    extern HttpSendRequestAFn g_OriginalHttpSendRequestA;
    extern EncryptMessageFn g_OriginalEncryptMessage;
    extern DecryptMessageFn g_OriginalDecryptMessage;

    DWORD EnsureModuleHookTls() noexcept;
    bool IsModuleHookReentered() noexcept;
    void ResetModuleHookInitFault() noexcept;
    void SetModuleHookInitFault(ModuleHookInitFaultCode code,
                                const wchar_t *moduleName,
                                const char *exportName,
                                void *address,
                                void *redirectTarget = nullptr) noexcept;
    bool TryResolveModuleImageRange(HMODULE module, ModuleRange &range) noexcept;
    bool AddressWithinRange(void *address, const ModuleRange &range) noexcept;
    bool TryDecodeAbsoluteTarget(void *entry, void *&target) noexcept;
    InlineHook *FindHookByOriginalFunction(void **originalFunction) noexcept;
    bool RestoreHookOriginalBytes(InlineHook &hook) noexcept;
    bool ReinstallHookJump(InlineHook &hook) noexcept;
    bool InstallInlineHook(void *target, void *hook, std::uint8_t original[16], void **trampolineOut) noexcept;
    void RemoveInlineHook(void *target, const std::uint8_t original[16], void *trampoline) noexcept;
    bool InstallModuleIatHook(InlineHook &hook, bool shadowCopy) noexcept;
    bool RefreshModuleIatHook(InlineHook &hook, HMODULE moduleHandle) noexcept;
    void RemoveModuleIatHook(InlineHook &hook) noexcept;
    bool CheckModuleIatHookIntegrity(const InlineHook &hook) noexcept;
    void PublishModuleEvent(ModuleHookOperation operation,
                            const char *functionName,
                            const char *sourceModule,
                            HMODULE moduleHandle,
                            const void *nameBuffer,
                            std::size_t nameLength,
                            std::uint64_t arg0 = 0,
                            std::uint64_t arg1 = 0,
                            std::uint64_t arg2 = 0,
                            std::uint64_t arg3 = 0,
                            void *caller = nullptr) noexcept;
    std::size_t CopyAnsiLength(LPCSTR value) noexcept;
    std::size_t CopyWideLength(LPCWSTR value) noexcept;
    void CopyLiteralWide(wchar_t buffer[32], const wchar_t *value) noexcept;
    bool TryFormatGuid(const GUID *guid, wchar_t buffer[32]) noexcept;
    void FormatCoInitMode(DWORD coInit, wchar_t buffer[32]) noexcept;
    void FormatJobInfoClass(JOBOBJECTINFOCLASS infoClass, wchar_t buffer[32]) noexcept;
    void CopyRedactedWide(wchar_t buffer[32], LPCWSTR value) noexcept;
    void CopyRedactedAnsiToWide(wchar_t buffer[32], LPCSTR value) noexcept;
    void CopyLsaStringToWide(wchar_t buffer[32], PLSA_STRING value) noexcept;
    void CopyLsaUnicodeStringToWide(wchar_t buffer[32], PLSA_UNICODE_STRING value) noexcept;
    void CopyPrintableBytesToWide(WCHAR *dst, std::size_t dstCount, const void *bytes, DWORD byteCount) noexcept;
    void CopyWidePrintableToWide(WCHAR *dst, std::size_t dstCount, LPCWSTR text, DWORD chars) noexcept;
    bool BufferLooksUtf16LeText(const void *buffer, ULONG byteCount) noexcept;
    std::uint32_t SafeReadDword(const DWORD *value) noexcept;
    std::uint32_t SafeReadUlong(const ULONG *value) noexcept;
    NTSTATUS SafeReadNtStatus(const NTSTATUS *value) noexcept;
    void *SafeReadPointer(void *const *value) noexcept;
    std::uint32_t SafeReadFirstU32(const void *buffer, ULONG length) noexcept;
    std::uint32_t SafeBlobSize(const DATA_BLOB *blob) noexcept;
    void StoreLsaPackageName(ULONG packageId, const wchar_t *name) noexcept;
    void LookupLsaPackageName(ULONG packageId, wchar_t buffer[32]) noexcept;

    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath,
                                  PULONG loadFlags,
                                  PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle);
    BOOLEAN WINAPI RtlAddFunctionTableHook(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress);
    BOOLEAN WINAPI RtlInstallFunctionTableCallbackHook(DWORD64 tableIdentifier,
                                                       DWORD64 baseAddress,
                                                       DWORD length,
                                                       PGET_RUNTIME_FUNCTION_CALLBACK callback,
                                                       PVOID context,
                                                       PCWSTR outOfProcessCallbackDll);
    BOOLEAN WINAPI RtlDeleteFunctionTableHook(PRUNTIME_FUNCTION functionTable);
    PVOID NTAPI RtlAddVectoredExceptionHandlerHook(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);
    ULONG NTAPI RtlRemoveVectoredExceptionHandlerHook(PVOID handle);
    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilterHook(LPTOP_LEVEL_EXCEPTION_FILTER filter);
    HRESULT WINAPI CoInitializeExHook(LPVOID pvReserved, DWORD dwCoInit);
    HRESULT WINAPI CoInitializeSecurityHook(PSECURITY_DESCRIPTOR pSecDesc,
                                            LONG cAuthSvc,
                                            SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
                                            void *pReserved1,
                                            DWORD dwAuthnLevel,
                                            DWORD dwImpLevel,
                                            void *pAuthList,
                                            DWORD dwCapabilities,
                                            void *pReserved3);
    HRESULT WINAPI
    CoCreateInstanceHook(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
    ULONG WINAPI EventRegisterHook(LPCGUID providerId,
                                   PENABLECALLBACK enableCallback,
                                   PVOID callbackContext,
                                   PREGHANDLE regHandle);
    ULONG WINAPI EventUnregisterHook(REGHANDLE regHandle);
    ULONG WINAPI StartTraceWHook(PTRACEHANDLE sessionHandle, LPCWSTR sessionName, PEVENT_TRACE_PROPERTIES properties);
    ULONG WINAPI EnableTraceEx2Hook(TRACEHANDLE traceHandle,
                                    LPCGUID providerId,
                                    ULONG controlCode,
                                    UCHAR level,
                                    ULONGLONG matchAnyKeyword,
                                    ULONGLONG matchAllKeyword,
                                    ULONG timeout,
                                    PENABLE_TRACE_PARAMETERS enableParameters);
    ULONG NTAPI EtwEventWriteHook(REGHANDLE regHandle,
                                  PCEVENT_DESCRIPTOR eventDescriptor,
                                  ULONG userDataCount,
                                  PEVENT_DATA_DESCRIPTOR userData);
    ULONG NTAPI EtwEventWriteExHook(REGHANDLE regHandle,
                                    PCEVENT_DESCRIPTOR eventDescriptor,
                                    ULONG64 filter,
                                    ULONG flags,
                                    LPCGUID activityId,
                                    LPCGUID relatedActivityId,
                                    ULONG userDataCount,
                                    PEVENT_DATA_DESCRIPTOR userData);
    ULONG NTAPI EtwEventWriteFullHook(REGHANDLE regHandle,
                                      PCEVENT_DESCRIPTOR eventDescriptor,
                                      USHORT eventProperty,
                                      LPCGUID activityId,
                                      LPCGUID relatedActivityId,
                                      ULONG userDataCount,
                                      PEVENT_DATA_DESCRIPTOR userData);
    ULONG NTAPI EtwEventWriteTransferHook(REGHANDLE regHandle,
                                          PCEVENT_DESCRIPTOR eventDescriptor,
                                          LPCGUID activityId,
                                          LPCGUID relatedActivityId,
                                          ULONG userDataCount,
                                          PEVENT_DATA_DESCRIPTOR userData);
    HANDLE WINAPI CreateJobObjectWHook(LPSECURITY_ATTRIBUTES securityAttributes, LPCWSTR name);
    HANDLE WINAPI OpenJobObjectWHook(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name);
    BOOL WINAPI AssignProcessToJobObjectHook(HANDLE job, HANDLE process);
    BOOL WINAPI SetInformationJobObjectHook(HANDLE job, JOBOBJECTINFOCLASS infoClass, LPVOID info, DWORD infoLength);
    NTSTATUS WINAPI LsaConnectUntrustedHook(PHANDLE lsaHandle);
    NTSTATUS WINAPI LsaLookupAuthenticationPackageHook(HANDLE lsaHandle,
                                                       PLSA_STRING packageName,
                                                       PULONG authenticationPackage);
    NTSTATUS WINAPI LsaCallAuthenticationPackageHook(HANDLE lsaHandle,
                                                     ULONG authenticationPackage,
                                                     PVOID submitBuffer,
                                                     ULONG submitBufferLength,
                                                     PVOID *returnBuffer,
                                                     PULONG returnBufferLength,
                                                     PNTSTATUS protocolStatus);
    LONG WINAPI AcquireCredentialsHandleAHook(LPSTR principal,
                                              LPSTR package,
                                              ULONG credentialUse,
                                              PLUID logonId,
                                              PVOID authData,
                                              PVOID getKeyFn,
                                              PVOID getKeyArgument,
                                              PVOID credential,
                                              PVOID expiry);
    LONG WINAPI AcquireCredentialsHandleWHook(LPWSTR principal,
                                              LPWSTR package,
                                              ULONG credentialUse,
                                              PLUID logonId,
                                              PVOID authData,
                                              PVOID getKeyFn,
                                              PVOID getKeyArgument,
                                              PVOID credential,
                                              PVOID expiry);
    LONG WINAPI InitializeSecurityContextAHook(PVOID credential,
                                               PVOID context,
                                               LPSTR targetName,
                                               ULONG contextReq,
                                               ULONG reserved1,
                                               ULONG targetDataRep,
                                               PVOID input,
                                               ULONG reserved2,
                                               PVOID newContext,
                                               PVOID output,
                                               PULONG contextAttr,
                                               PVOID expiry);
    LONG WINAPI InitializeSecurityContextWHook(PVOID credential,
                                               PVOID context,
                                               LPWSTR targetName,
                                               ULONG contextReq,
                                               ULONG reserved1,
                                               ULONG targetDataRep,
                                               PVOID input,
                                               ULONG reserved2,
                                               PVOID newContext,
                                               PVOID output,
                                               PULONG contextAttr,
                                               PVOID expiry);
    LONG WINAPI AcceptSecurityContextHook(PVOID credential,
                                          PVOID context,
                                          PVOID input,
                                          ULONG contextReq,
                                          ULONG targetDataRep,
                                          PVOID newContext,
                                          PVOID output,
                                          PULONG contextAttr,
                                          PVOID expiry);
    BOOL WINAPI CredReadAHook(LPCSTR targetName, DWORD type, DWORD flags, PVOID *credential);
    BOOL WINAPI CredReadWHook(LPCWSTR targetName, DWORD type, DWORD flags, PVOID *credential);
    BOOL WINAPI CredEnumerateAHook(LPCSTR filter, DWORD flags, DWORD *count, PVOID *credential);
    BOOL WINAPI CredEnumerateWHook(LPCWSTR filter, DWORD flags, DWORD *count, PVOID *credential);
    BOOL WINAPI CredReadDomainCredentialsAHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential);
    BOOL WINAPI CredReadDomainCredentialsWHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential);
    NTSTATUS WINAPI LsaOpenPolicyHook(PLSA_UNICODE_STRING systemName,
                                      PLSA_OBJECT_ATTRIBUTES objectAttributes,
                                      ACCESS_MASK desiredAccess,
                                      PLSA_HANDLE policyHandle);
    NTSTATUS WINAPI LsaQueryInformationPolicyHook(LSA_HANDLE policyHandle,
                                                  POLICY_INFORMATION_CLASS informationClass,
                                                  PVOID *buffer);
    DWORD WINAPI VaultEnumerateVaultsHook(DWORD flags, DWORD *count, GUID **vaultGuids);
    DWORD WINAPI VaultOpenVaultHook(const GUID *vaultGuid, DWORD flags, HANDLE *vaultHandle);
    DWORD WINAPI VaultEnumerateItemsHook(HANDLE vaultHandle, DWORD flags, DWORD *count, PVOID *items);
    DWORD WINAPI VaultGetItemHook(HANDLE vaultHandle,
                                  const GUID *schemaId,
                                  PVOID resource,
                                  PVOID identity,
                                  PVOID packageSid,
                                  HWND hwndOwner,
                                  DWORD flags,
                                  PVOID *item);
    BOOL WINAPI CryptUnprotectDataHook(DATA_BLOB *dataIn,
                                       LPWSTR *dataDescription,
                                       DATA_BLOB *optionalEntropy,
                                       PVOID reserved,
                                       CRYPTPROTECT_PROMPTSTRUCT *promptStruct,
                                       DWORD flags,
                                       DATA_BLOB *dataOut);
    LONG WINAPI NCryptUnprotectSecretHook(PVOID *descriptor,
                                          DWORD flags,
                                          const BYTE *protectedBlob,
                                          ULONG protectedBlobSize,
                                          PVOID memPara,
                                          HWND hwnd,
                                          BYTE **data,
                                          ULONG *dataSize);
    LONG WINAPI NCryptOpenStorageProviderHook(PVOID *provider, LPCWSTR providerName, DWORD flags);
    LONG WINAPI NCryptOpenKeyHook(PVOID provider, PVOID *key, LPCWSTR keyName, DWORD legacyKeySpec, DWORD flags);
    LONG WINAPI NCryptDecryptHook(PVOID key,
                                  PBYTE input,
                                  DWORD inputSize,
                                  PVOID paddingInfo,
                                  PBYTE output,
                                  DWORD outputSize,
                                  DWORD *resultSize,
                                  DWORD flags);
    DWORD WINAPI CfAbortOperationHook(DWORD processId, PVOID unknown, DWORD flags);
    HRESULT WINAPI CfRegisterSyncRootHook(LPCWSTR syncRootPath,
                                          const void *registration,
                                          const void *policies,
                                          DWORD registerFlags);
    HRESULT WINAPI CfConnectSyncRootHook(LPCWSTR syncRootPath,
                                         const void *callbackTable,
                                         void *callbackContext,
                                         DWORD connectFlags,
                                         void *connectionKey);
    HRESULT WINAPI CfCreatePlaceholdersHook(LPCWSTR baseDirectoryPath,
                                            void *placeholderArray,
                                            DWORD placeholderCount,
                                            DWORD createFlags,
                                            DWORD *entriesProcessed);
    HRESULT WINAPI AmsiInitializeHook(LPCWSTR appName, PVOID *amsiContext);
    VOID WINAPI AmsiUninitializeHook(PVOID amsiContext);
    HRESULT WINAPI AmsiOpenSessionHook(PVOID amsiContext, PVOID *session);
    VOID WINAPI AmsiCloseSessionHook(PVOID amsiContext, PVOID session);
    HRESULT WINAPI
    AmsiScanBufferHook(PVOID amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, PVOID session, PVOID result);
    HRESULT WINAPI
    AmsiScanStringHook(PVOID amsiContext, LPCWSTR string, LPCWSTR contentName, PVOID session, PVOID result);
    HRESULT WINAPI
    AmsiNotifyOperationHook(PVOID amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, PVOID result);
    PVOID WINAPI WinHttpConnectHook(PVOID session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved);
    PVOID WINAPI WinHttpOpenRequestHook(PVOID connect,
                                        LPCWSTR verb,
                                        LPCWSTR objectName,
                                        LPCWSTR version,
                                        LPCWSTR referrer,
                                        LPCWSTR *acceptTypes,
                                        DWORD flags);
    BOOL WINAPI WinHttpSendRequestHook(PVOID request,
                                       LPCWSTR headers,
                                       DWORD headersLength,
                                       PVOID optional,
                                       DWORD optionalLength,
                                       DWORD totalLength,
                                       DWORD_PTR context);
    PVOID WINAPI InternetConnectWHook(PVOID internet,
                                      LPCWSTR serverName,
                                      INTERNET_PORT serverPort,
                                      LPCWSTR userName,
                                      LPCWSTR password,
                                      DWORD service,
                                      DWORD flags,
                                      DWORD_PTR context);
    PVOID WINAPI InternetConnectAHook(PVOID internet,
                                      LPCSTR serverName,
                                      INTERNET_PORT serverPort,
                                      LPCSTR userName,
                                      LPCSTR password,
                                      DWORD service,
                                      DWORD flags,
                                      DWORD_PTR context);
    PVOID WINAPI HttpOpenRequestWHook(PVOID connect,
                                      LPCWSTR verb,
                                      LPCWSTR objectName,
                                      LPCWSTR version,
                                      LPCWSTR referrer,
                                      LPCWSTR *acceptTypes,
                                      DWORD flags,
                                      DWORD_PTR context);
    PVOID WINAPI HttpOpenRequestAHook(PVOID connect,
                                      LPCSTR verb,
                                      LPCSTR objectName,
                                      LPCSTR version,
                                      LPCSTR referrer,
                                      LPCSTR *acceptTypes,
                                      DWORD flags,
                                      DWORD_PTR context);
    BOOL WINAPI
    HttpSendRequestWHook(PVOID request, LPCWSTR headers, DWORD headersLength, PVOID optional, DWORD optionalLength);
    BOOL WINAPI
    HttpSendRequestAHook(PVOID request, LPCSTR headers, DWORD headersLength, PVOID optional, DWORD optionalLength);
    LONG WINAPI EncryptMessageHook(PVOID context, ULONG qualityOfProtection, PVOID message, ULONG sequenceNumber);
    LONG WINAPI DecryptMessageHook(PVOID context, PVOID message, ULONG sequenceNumber, PULONG qualityOfProtection);

    template <typename Fn, typename... Args>
    auto CallOriginalTemporarilyUnhooked(void **originalFunction, Fn fallback, Args... args) noexcept
        -> decltype(fallback(args...))
    {
        InlineHook *hook = FindHookByOriginalFunction(originalFunction);
        if (hook == nullptr || !hook->Installed || hook->TargetAddress == nullptr ||
            hook->HookMethod != IXIPC_HOOK_METHOD_INLINE)
        {
            return fallback(args...);
        }

        AcquireSRWLockExclusive(&g_ModuleOriginalCallLock);
        const bool restored = RestoreHookOriginalBytes(*hook);
        void *targetAddress = hook->TargetAddress;
        ReleaseSRWLockExclusive(&g_ModuleOriginalCallLock);

        if (!restored || targetAddress == nullptr)
        {
            return fallback(args...);
        }

        auto target = reinterpret_cast<Fn>(targetAddress);
        auto result = target(std::forward<Args>(args)...);

        AcquireSRWLockExclusive(&g_ModuleOriginalCallLock);
        if (hook->Installed && hook->TargetAddress == targetAddress)
        {
            (void)ReinstallHookJump(*hook);
        }
        ReleaseSRWLockExclusive(&g_ModuleOriginalCallLock);
        return result;
    }

    template <typename Fn, typename... Args>
    void CallOriginalVoidTemporarilyUnhooked(void **originalFunction, Fn fallback, Args... args) noexcept
    {
        InlineHook *hook = FindHookByOriginalFunction(originalFunction);
        if (hook == nullptr || !hook->Installed || hook->TargetAddress == nullptr ||
            hook->HookMethod != IXIPC_HOOK_METHOD_INLINE)
        {
            fallback(std::forward<Args>(args)...);
            return;
        }

        AcquireSRWLockExclusive(&g_ModuleOriginalCallLock);
        const bool restored = RestoreHookOriginalBytes(*hook);
        void *targetAddress = hook->TargetAddress;
        ReleaseSRWLockExclusive(&g_ModuleOriginalCallLock);

        if (!restored || targetAddress == nullptr)
        {
            fallback(std::forward<Args>(args)...);
            return;
        }

        auto target = reinterpret_cast<Fn>(targetAddress);
        target(std::forward<Args>(args)...);

        AcquireSRWLockExclusive(&g_ModuleOriginalCallLock);
        if (hook->Installed && hook->TargetAddress == targetAddress)
        {
            (void)ReinstallHookJump(*hook);
        }
        ReleaseSRWLockExclusive(&g_ModuleOriginalCallLock);
    }

    template <typename Fn, typename... Args>
    auto CallOriginalSafely(Fn &originalFunction, Args... args) noexcept -> decltype(originalFunction(args...))
    {
        return CallOriginalTemporarilyUnhooked(
            reinterpret_cast<void **>(&originalFunction), originalFunction, std::forward<Args>(args)...);
    }
} // namespace IX_MODULE_INTERNAL
