#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    HANDLE WINAPI CreateJobObjectWHook(LPSECURITY_ATTRIBUTES securityAttributes, LPCWSTR name)
    {
        if (g_OriginalCreateJobObjectW == nullptr)
        {
            return nullptr;
        }

        HANDLE handle = CallOriginalSafely(g_OriginalCreateJobObjectW, securityAttributes, name);
        PublishModuleEvent(ModuleHookOperation::CreateJobObjectW,
                           "CreateJobObjectW",
                           "kernel32",
                           nullptr,
                           name,
                           CopyWideLength(name),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(securityAttributes)),
                           0,
                           0);
        return handle;
    }

    HANDLE WINAPI OpenJobObjectWHook(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name)
    {
        if (g_OriginalOpenJobObjectW == nullptr)
        {
            return nullptr;
        }

        HANDLE handle = CallOriginalSafely(g_OriginalOpenJobObjectW, desiredAccess, inheritHandle, name);
        PublishModuleEvent(ModuleHookOperation::OpenJobObjectW,
                           "OpenJobObjectW",
                           "kernel32",
                           nullptr,
                           name,
                           CopyWideLength(name),
                           static_cast<std::uint64_t>(desiredAccess),
                           static_cast<std::uint64_t>(inheritHandle),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)),
                           0);
        return handle;
    }

    BOOL WINAPI AssignProcessToJobObjectHook(HANDLE job, HANDLE process)
    {
        if (g_OriginalAssignProcessToJobObject == nullptr)
        {
            return FALSE;
        }

        BOOL ok = CallOriginalSafely(g_OriginalAssignProcessToJobObject, job, process);
        wchar_t label[32];
        CopyLiteralWide(label, L"AssignProcess");
        PublishModuleEvent(ModuleHookOperation::AssignProcessToJobObject,
                           "AssignProcessToJobObject",
                           "kernel32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(job)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(process)),
                           static_cast<std::uint64_t>(ok),
                           0);
        return ok;
    }

    BOOL WINAPI SetInformationJobObjectHook(HANDLE job, JOBOBJECTINFOCLASS infoClass, LPVOID info, DWORD infoLength)
    {
        if (g_OriginalSetInformationJobObject == nullptr)
        {
            return FALSE;
        }

        BOOL ok = CallOriginalSafely(g_OriginalSetInformationJobObject, job, infoClass, info, infoLength);
        wchar_t label[32];
        FormatJobInfoClass(infoClass, label);
        PublishModuleEvent(ModuleHookOperation::SetInformationJobObject,
                           "SetInformationJobObject",
                           "kernel32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(job)),
                           static_cast<std::uint64_t>(infoClass),
                           static_cast<std::uint64_t>(infoLength),
                           static_cast<std::uint64_t>(ok));
        return ok;
    }

    NTSTATUS WINAPI LsaConnectUntrustedHook(PHANDLE lsaHandle)
    {
        if (g_OriginalLsaConnectUntrusted == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = CallOriginalSafely(g_OriginalLsaConnectUntrusted, lsaHandle);
        wchar_t label[32];
        CopyLiteralWide(label, L"LsaUntrusted");
        PublishModuleEvent(ModuleHookOperation::LsaConnectUntrusted,
                           "LsaConnectUntrusted",
                           "sspicli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(lsaHandle))),
                           0,
                           0);
        return status;
    }

    NTSTATUS WINAPI LsaLookupAuthenticationPackageHook(HANDLE lsaHandle,
                                                       PLSA_STRING packageName,
                                                       PULONG authenticationPackage)
    {
        if (g_OriginalLsaLookupAuthenticationPackage == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        wchar_t package[32];
        CopyLsaStringToWide(package, packageName);
        NTSTATUS status =
            CallOriginalSafely(g_OriginalLsaLookupAuthenticationPackage, lsaHandle, packageName, authenticationPackage);
        ULONG packageId = SafeReadUlong(authenticationPackage);
        if (status >= 0 && packageId != 0 && package[0] != L'\0')
        {
            StoreLsaPackageName(packageId, package);
        }

        PublishModuleEvent(ModuleHookOperation::LsaLookupAuthenticationPackage,
                           "LsaLookupAuthenticationPackage",
                           "sspicli",
                           nullptr,
                           package,
                           CopyWideLength(package),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(packageId),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(lsaHandle)),
                           0);
        return status;
    }

    NTSTATUS WINAPI LsaCallAuthenticationPackageHook(HANDLE lsaHandle,
                                                     ULONG authenticationPackage,
                                                     PVOID submitBuffer,
                                                     ULONG submitBufferLength,
                                                     PVOID *returnBuffer,
                                                     PULONG returnBufferLength,
                                                     PNTSTATUS protocolStatus)
    {
        if (g_OriginalLsaCallAuthenticationPackage == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        std::uint32_t messageType = SafeReadFirstU32(submitBuffer, submitBufferLength);
        NTSTATUS status = CallOriginalSafely(g_OriginalLsaCallAuthenticationPackage,
                                             lsaHandle,
                                             authenticationPackage,
                                             submitBuffer,
                                             submitBufferLength,
                                             returnBuffer,
                                             returnBufferLength,
                                             protocolStatus);
        ULONG outputLength = SafeReadUlong(returnBufferLength);
        NTSTATUS protocol = SafeReadNtStatus(protocolStatus);
        wchar_t package[32];
        LookupLsaPackageName(authenticationPackage, package);
        PublishModuleEvent(ModuleHookOperation::LsaCallAuthenticationPackage,
                           "LsaCallAuthenticationPackage",
                           "sspicli",
                           nullptr,
                           package,
                           CopyWideLength(package),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(authenticationPackage),
                           (static_cast<std::uint64_t>(messageType) << 32u) | submitBufferLength,
                           (static_cast<std::uint64_t>(static_cast<ULONG>(protocol)) << 32u) | outputLength);
        return status;
    }

    LONG WINAPI AcquireCredentialsHandleAHook(LPSTR principal,
                                              LPSTR package,
                                              ULONG credentialUse,
                                              PLUID logonId,
                                              PVOID authData,
                                              PVOID getKeyFn,
                                              PVOID getKeyArgument,
                                              PVOID credential,
                                              PVOID expiry)
    {
        if (g_OriginalAcquireCredentialsHandleA == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedAnsiToWide(label, package);
        LONG status = CallOriginalSafely(g_OriginalAcquireCredentialsHandleA,
                                         principal,
                                         package,
                                         credentialUse,
                                         logonId,
                                         authData,
                                         getKeyFn,
                                         getKeyArgument,
                                         credential,
                                         expiry);
        PublishModuleEvent(ModuleHookOperation::AcquireCredentialsHandleA,
                           "AcquireCredentialsHandleA",
                           "sspicli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(credentialUse),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(principal)),
                           0);
        return status;
    }

    LONG WINAPI AcquireCredentialsHandleWHook(LPWSTR principal,
                                              LPWSTR package,
                                              ULONG credentialUse,
                                              PLUID logonId,
                                              PVOID authData,
                                              PVOID getKeyFn,
                                              PVOID getKeyArgument,
                                              PVOID credential,
                                              PVOID expiry)
    {
        if (g_OriginalAcquireCredentialsHandleW == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedWide(label, package);
        LONG status = CallOriginalSafely(g_OriginalAcquireCredentialsHandleW,
                                         principal,
                                         package,
                                         credentialUse,
                                         logonId,
                                         authData,
                                         getKeyFn,
                                         getKeyArgument,
                                         credential,
                                         expiry);
        PublishModuleEvent(ModuleHookOperation::AcquireCredentialsHandleW,
                           "AcquireCredentialsHandleW",
                           "sspicli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(credentialUse),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(principal)),
                           0);
        return status;
    }

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
                                               PVOID expiry)
    {
        if (g_OriginalInitializeSecurityContextA == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        wchar_t label[32];
        CopyRedactedAnsiToWide(label, targetName);
        LONG status = CallOriginalSafely(g_OriginalInitializeSecurityContextA,
                                         credential,
                                         context,
                                         targetName,
                                         contextReq,
                                         reserved1,
                                         targetDataRep,
                                         input,
                                         reserved2,
                                         newContext,
                                         output,
                                         contextAttr,
                                         expiry);
        PublishModuleEvent(ModuleHookOperation::InitializeSecurityContextA,
                           "InitializeSecurityContextA",
                           "sspicli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(contextReq),
                           static_cast<std::uint64_t>(targetDataRep),
                           static_cast<std::uint64_t>(SafeReadUlong(contextAttr)));
        return status;
    }

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
                                               PVOID expiry)
    {
        if (g_OriginalInitializeSecurityContextW == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }
        wchar_t label[32];
        CopyRedactedWide(label, targetName);
        LONG status = CallOriginalSafely(g_OriginalInitializeSecurityContextW,
                                         credential,
                                         context,
                                         targetName,
                                         contextReq,
                                         reserved1,
                                         targetDataRep,
                                         input,
                                         reserved2,
                                         newContext,
                                         output,
                                         contextAttr,
                                         expiry);
        PublishModuleEvent(ModuleHookOperation::InitializeSecurityContextW,
                           "InitializeSecurityContextW",
                           "sspicli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(contextReq),
                           static_cast<std::uint64_t>(targetDataRep),
                           static_cast<std::uint64_t>(SafeReadUlong(contextAttr)));
        return status;
    }

    LONG WINAPI AcceptSecurityContextHook(PVOID credential,
                                          PVOID context,
                                          PVOID input,
                                          ULONG contextReq,
                                          ULONG targetDataRep,
                                          PVOID newContext,
                                          PVOID output,
                                          PULONG contextAttr,
                                          PVOID expiry)
    {
        if (g_OriginalAcceptSecurityContext == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        LONG status = CallOriginalSafely(g_OriginalAcceptSecurityContext,
                                         credential,
                                         context,
                                         input,
                                         contextReq,
                                         targetDataRep,
                                         newContext,
                                         output,
                                         contextAttr,
                                         expiry);
        wchar_t label[32];
        CopyLiteralWide(label, L"AcceptSecurityContext");
        PublishModuleEvent(ModuleHookOperation::AcceptSecurityContext,
                           "AcceptSecurityContext",
                           "sspicli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(contextReq),
                           static_cast<std::uint64_t>(targetDataRep),
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
        BOOL ok = CallOriginalSafely(g_OriginalCredReadA, targetName, type, flags, credential);
        PublishModuleEvent(ModuleHookOperation::CredReadA,
                           "CredReadA",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(type),
                           static_cast<std::uint64_t>(flags),
                           0);
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
        BOOL ok = CallOriginalSafely(g_OriginalCredReadW, targetName, type, flags, credential);
        PublishModuleEvent(ModuleHookOperation::CredReadW,
                           "CredReadW",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(type),
                           static_cast<std::uint64_t>(flags),
                           0);
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
        BOOL ok = CallOriginalSafely(g_OriginalCredEnumerateA, filter, flags, count, credential);
        PublishModuleEvent(ModuleHookOperation::CredEnumerateA,
                           "CredEnumerateA",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           0);
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
        BOOL ok = CallOriginalSafely(g_OriginalCredEnumerateW, filter, flags, count, credential);
        PublishModuleEvent(ModuleHookOperation::CredEnumerateW,
                           "CredEnumerateW",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           0);
        return ok;
    }

    BOOL WINAPI CredReadDomainCredentialsAHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential)
    {
        if (g_OriginalCredReadDomainCredentialsA == nullptr)
        {
            return FALSE;
        }

        BOOL ok = CallOriginalSafely(g_OriginalCredReadDomainCredentialsA, targetInfo, flags, count, credential);
        wchar_t label[32];
        CopyLiteralWide(label, L"DomainCredentials");
        PublishModuleEvent(ModuleHookOperation::CredReadDomainCredentialsA,
                           "CredReadDomainCredentialsA",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           0);
        return ok;
    }

    BOOL WINAPI CredReadDomainCredentialsWHook(PVOID targetInfo, DWORD flags, DWORD *count, PVOID *credential)
    {
        if (g_OriginalCredReadDomainCredentialsW == nullptr)
        {
            return FALSE;
        }

        BOOL ok = CallOriginalSafely(g_OriginalCredReadDomainCredentialsW, targetInfo, flags, count, credential);
        wchar_t label[32];
        CopyLiteralWide(label, L"DomainCredentials");
        PublishModuleEvent(ModuleHookOperation::CredReadDomainCredentialsW,
                           "CredReadDomainCredentialsW",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           0);
        return ok;
    }

    NTSTATUS WINAPI LsaOpenPolicyHook(PLSA_UNICODE_STRING systemName,
                                      PLSA_OBJECT_ATTRIBUTES objectAttributes,
                                      ACCESS_MASK desiredAccess,
                                      PLSA_HANDLE policyHandle)
    {
        if (g_OriginalLsaOpenPolicy == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        wchar_t label[32];
        CopyLsaUnicodeStringToWide(label, systemName);
        NTSTATUS status =
            CallOriginalSafely(g_OriginalLsaOpenPolicy, systemName, objectAttributes, desiredAccess, policyHandle);
        PublishModuleEvent(ModuleHookOperation::LsaOpenPolicy,
                           "LsaOpenPolicy",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(desiredAccess),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(policyHandle))),
                           0);
        return status;
    }

    NTSTATUS WINAPI LsaQueryInformationPolicyHook(LSA_HANDLE policyHandle,
                                                  POLICY_INFORMATION_CLASS informationClass,
                                                  PVOID *buffer)
    {
        if (g_OriginalLsaQueryInformationPolicy == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status =
            CallOriginalSafely(g_OriginalLsaQueryInformationPolicy, policyHandle, informationClass, buffer);
        wchar_t label[32];
        CopyLiteralWide(label, L"LsaPolicy");
        PublishModuleEvent(ModuleHookOperation::LsaQueryInformationPolicy,
                           "LsaQueryInformationPolicy",
                           "advapi32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(informationClass),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(buffer))),
                           0);
        return status;
    }
} // namespace IX_MODULE_INTERNAL
