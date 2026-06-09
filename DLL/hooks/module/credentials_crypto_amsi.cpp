#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    DWORD WINAPI VaultEnumerateVaultsHook(DWORD flags, DWORD *count, GUID **vaultGuids)
    {
        if (g_OriginalVaultEnumerateVaults == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = CallOriginalSafely(g_OriginalVaultEnumerateVaults, flags, count, vaultGuids);
        wchar_t label[32];
        CopyLiteralWide(label, L"Vaults");
        PublishModuleEvent(ModuleHookOperation::VaultEnumerateVaults,
                           "VaultEnumerateVaults",
                           "vaultcli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           0);
        return status;
    }

    DWORD WINAPI VaultOpenVaultHook(const GUID *vaultGuid, DWORD flags, HANDLE *vaultHandle)
    {
        if (g_OriginalVaultOpenVault == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = CallOriginalSafely(g_OriginalVaultOpenVault, vaultGuid, flags, vaultHandle);
        wchar_t label[32];
        if (!TryFormatGuid(vaultGuid, label))
        {
            CopyLiteralWide(label, L"Vault");
        }
        PublishModuleEvent(ModuleHookOperation::VaultOpenVault,
                           "VaultOpenVault",
                           "vaultcli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(vaultHandle))),
                           0);
        return status;
    }

    DWORD WINAPI VaultEnumerateItemsHook(HANDLE vaultHandle, DWORD flags, DWORD *count, PVOID *items)
    {
        if (g_OriginalVaultEnumerateItems == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = CallOriginalSafely(g_OriginalVaultEnumerateItems, vaultHandle, flags, count, items);
        wchar_t label[32];
        CopyLiteralWide(label, L"VaultItems");
        PublishModuleEvent(ModuleHookOperation::VaultEnumerateItems,
                           "VaultEnumerateItems",
                           "vaultcli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(SafeReadDword(count)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(vaultHandle)));
        return status;
    }

    DWORD WINAPI VaultGetItemHook(HANDLE vaultHandle,
                                  const GUID *schemaId,
                                  PVOID resource,
                                  PVOID identity,
                                  PVOID packageSid,
                                  HWND hwndOwner,
                                  DWORD flags,
                                  PVOID *item)
    {
        if (g_OriginalVaultGetItem == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = CallOriginalSafely(
            g_OriginalVaultGetItem, vaultHandle, schemaId, resource, identity, packageSid, hwndOwner, flags, item);
        wchar_t label[32];
        if (!TryFormatGuid(schemaId, label))
        {
            CopyLiteralWide(label, L"VaultItem");
        }
        PublishModuleEvent(ModuleHookOperation::VaultGetItem,
                           "VaultGetItem",
                           "vaultcli",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(vaultHandle)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(resource)));
        return status;
    }

    BOOL WINAPI CryptUnprotectDataHook(DATA_BLOB *dataIn,
                                       LPWSTR *dataDescription,
                                       DATA_BLOB *optionalEntropy,
                                       PVOID reserved,
                                       CRYPTPROTECT_PROMPTSTRUCT *promptStruct,
                                       DWORD flags,
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

        BOOL ok = CallOriginalSafely(g_OriginalCryptUnprotectData,
                                     dataIn,
                                     dataDescription,
                                     optionalEntropy,
                                     reserved,
                                     promptStruct,
                                     flags,
                                     dataOut);
        wchar_t label[32];
        CopyLiteralWide(label, L"DPAPI");
        PublishModuleEvent(ModuleHookOperation::CryptUnprotectData,
                           "CryptUnprotectData",
                           "crypt32",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(ok),
                           static_cast<std::uint64_t>(flags),
                           (static_cast<std::uint64_t>(promptFlags) << 32u) |
                               ((optionalEntropy != nullptr && SafeBlobSize(optionalEntropy) != 0) ? 1ull : 0ull),
                           static_cast<std::uint64_t>(SafeBlobSize(dataOut)));
        return ok;
    }

    LONG WINAPI NCryptUnprotectSecretHook(PVOID *descriptor,
                                          DWORD flags,
                                          const BYTE *protectedBlob,
                                          ULONG protectedBlobSize,
                                          PVOID memPara,
                                          HWND hwnd,
                                          BYTE **data,
                                          ULONG *dataSize)
    {
        if (g_OriginalNCryptUnprotectSecret == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        LONG status = CallOriginalSafely(g_OriginalNCryptUnprotectSecret,
                                         descriptor,
                                         flags,
                                         protectedBlob,
                                         protectedBlobSize,
                                         memPara,
                                         hwnd,
                                         data,
                                         dataSize);
        wchar_t label[32];
        CopyLiteralWide(label, L"NCryptSecret");
        PublishModuleEvent(ModuleHookOperation::NCryptUnprotectSecret,
                           "NCryptUnprotectSecret",
                           "ncrypt",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(protectedBlobSize),
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
        LONG status = CallOriginalSafely(g_OriginalNCryptOpenStorageProvider, provider, providerName, flags);
        PublishModuleEvent(ModuleHookOperation::NCryptOpenStorageProvider,
                           "NCryptOpenStorageProvider",
                           "ncrypt",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(provider))),
                           0);
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
        LONG status = CallOriginalSafely(g_OriginalNCryptOpenKey, provider, key, keyName, legacyKeySpec, flags);
        PublishModuleEvent(ModuleHookOperation::NCryptOpenKey,
                           "NCryptOpenKey",
                           "ncrypt",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(legacyKeySpec),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(SafeReadPointer(key))));
        return status;
    }

    LONG WINAPI NCryptDecryptHook(PVOID key,
                                  PBYTE input,
                                  DWORD inputSize,
                                  PVOID paddingInfo,
                                  PBYTE output,
                                  DWORD outputSize,
                                  DWORD *resultSize,
                                  DWORD flags)
    {
        if (g_OriginalNCryptDecrypt == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        LONG status = CallOriginalSafely(
            g_OriginalNCryptDecrypt, key, input, inputSize, paddingInfo, output, outputSize, resultSize, flags);
        wchar_t label[32];
        CopyLiteralWide(label, L"NCryptDecrypt");
        PublishModuleEvent(ModuleHookOperation::NCryptDecrypt,
                           "NCryptDecrypt",
                           "ncrypt",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(inputSize),
                           static_cast<std::uint64_t>(SafeReadDword(resultSize)));
        return status;
    }

    DWORD WINAPI CfAbortOperationHook(DWORD processId, PVOID unknown, DWORD flags)
    {
        if (g_OriginalCfAbortOperation == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        DWORD status = CallOriginalSafely(g_OriginalCfAbortOperation, processId, unknown, flags);
        wchar_t label[32];
        CopyLiteralWide(label, L"AbortHydration");
        PublishModuleEvent(ModuleHookOperation::CfAbortOperation,
                           "CfAbortOperation",
                           "cldapi",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(status),
                           static_cast<std::uint64_t>(processId),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(unknown)));
        return status;
    }

    HRESULT WINAPI CfRegisterSyncRootHook(LPCWSTR syncRootPath,
                                          const void *registration,
                                          const void *policies,
                                          DWORD registerFlags)
    {
        if (g_OriginalCfRegisterSyncRoot == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr =
            CallOriginalSafely(g_OriginalCfRegisterSyncRoot, syncRootPath, registration, policies, registerFlags);
        PublishModuleEvent(ModuleHookOperation::CfRegisterSyncRoot,
                           "CfRegisterSyncRoot",
                           "cldapi",
                           nullptr,
                           syncRootPath,
                           CopyWideLength(syncRootPath),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(registerFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(registration)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(policies)));
        return hr;
    }

    HRESULT WINAPI CfConnectSyncRootHook(
        LPCWSTR syncRootPath, const void *callbackTable, void *callbackContext, DWORD connectFlags, void *connectionKey)
    {
        if (g_OriginalCfConnectSyncRoot == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalSafely(
            g_OriginalCfConnectSyncRoot, syncRootPath, callbackTable, callbackContext, connectFlags, connectionKey);
        PublishModuleEvent(ModuleHookOperation::CfConnectSyncRoot,
                           "CfConnectSyncRoot",
                           "cldapi",
                           nullptr,
                           syncRootPath,
                           CopyWideLength(syncRootPath),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(connectFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(callbackTable)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(connectionKey)));
        return hr;
    }

    HRESULT WINAPI CfCreatePlaceholdersHook(LPCWSTR baseDirectoryPath,
                                            void *placeholderArray,
                                            DWORD placeholderCount,
                                            DWORD createFlags,
                                            DWORD *entriesProcessed)
    {
        if (g_OriginalCfCreatePlaceholders == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalSafely(g_OriginalCfCreatePlaceholders,
                                        baseDirectoryPath,
                                        placeholderArray,
                                        placeholderCount,
                                        createFlags,
                                        entriesProcessed);
        PublishModuleEvent(ModuleHookOperation::CfCreatePlaceholders,
                           "CfCreatePlaceholders",
                           "cldapi",
                           nullptr,
                           baseDirectoryPath,
                           CopyWideLength(baseDirectoryPath),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(placeholderCount),
                           static_cast<std::uint64_t>(createFlags),
                           static_cast<std::uint64_t>(SafeReadDword(entriesProcessed)));
        return hr;
    }

    HRESULT WINAPI AmsiInitializeHook(LPCWSTR appName, PVOID *amsiContext)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiInitialize == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalAmsiInitialize), g_OriginalAmsiInitialize, appName, amsiContext);
        PublishModuleEvent(
            ModuleHookOperation::AmsiInitialize,
            "AmsiInitialize",
            "amsi",
            nullptr,
            appName,
            CopyWideLength(appName),
            static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
            static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(amsiContext)),
            static_cast<std::uint64_t>(amsiContext != nullptr ? reinterpret_cast<ULONG_PTR>(*amsiContext) : 0),
            0,
            caller);
        return hr;
    }

    VOID WINAPI AmsiUninitializeHook(PVOID amsiContext)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiUninitialize == nullptr)
        {
            return;
        }

        CallOriginalVoidTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalAmsiUninitialize), g_OriginalAmsiUninitialize, amsiContext);
        wchar_t label[32];
        CopyLiteralWide(label, L"AmsiUninitialize");
        PublishModuleEvent(ModuleHookOperation::AmsiUninitialize,
                           "AmsiUninitialize",
                           "amsi",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           0,
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(amsiContext)),
                           0,
                           0,
                           caller);
    }

    HRESULT WINAPI AmsiOpenSessionHook(PVOID amsiContext, PVOID *session)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiOpenSession == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalAmsiOpenSession), g_OriginalAmsiOpenSession, amsiContext, session);
        wchar_t label[32];
        CopyLiteralWide(label, L"AmsiOpenSession");
        PublishModuleEvent(ModuleHookOperation::AmsiOpenSession,
                           "AmsiOpenSession",
                           "amsi",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(amsiContext)),
                           static_cast<std::uint64_t>(session != nullptr ? reinterpret_cast<ULONG_PTR>(*session) : 0),
                           0,
                           caller);
        return hr;
    }

    VOID WINAPI AmsiCloseSessionHook(PVOID amsiContext, PVOID session)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiCloseSession == nullptr)
        {
            return;
        }

        CallOriginalVoidTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalAmsiCloseSession), g_OriginalAmsiCloseSession, amsiContext, session);
        wchar_t label[32];
        CopyLiteralWide(label, L"AmsiCloseSession");
        PublishModuleEvent(ModuleHookOperation::AmsiCloseSession,
                           "AmsiCloseSession",
                           "amsi",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           0,
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(amsiContext)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(session)),
                           0,
                           caller);
    }

    HRESULT WINAPI
    AmsiScanBufferHook(PVOID amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, PVOID session, PVOID result)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiScanBuffer == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalAmsiScanBuffer),
                                                     g_OriginalAmsiScanBuffer,
                                                     amsiContext,
                                                     buffer,
                                                     length,
                                                     contentName,
                                                     session,
                                                     result);
        WCHAR scriptSample[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        std::memset(scriptSample, 0, sizeof(scriptSample));
        std::memset(reason, 0, sizeof(reason));
        if (buffer != nullptr && length != 0)
        {
            if (BufferLooksUtf16LeText(buffer, length))
            {
                CopyWidePrintableToWide(
                    scriptSample, RTL_NUMBER_OF(scriptSample), static_cast<LPCWSTR>(buffer), length / sizeof(WCHAR));
            }
            else
            {
                CopyPrintableBytesToWide(scriptSample, RTL_NUMBER_OF(scriptSample), buffer, length);
            }
        }
        (void)swprintf_s(reason,
                         RTL_NUMBER_OF(reason),
                         L"powershell.amsi.script contentName=%s bytes=%lu status=0x%08lX result=0x%08lX script=\"%s\"",
                         contentName != nullptr && contentName[0] != L'\0' ? contentName : L"<unknown>",
                         static_cast<unsigned long>(length),
                         static_cast<unsigned long>(hr),
                         static_cast<unsigned long>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                         scriptSample[0] != L'\0' ? scriptSample : L"-");
        PublishModuleEvent(ModuleHookOperation::AmsiScanBuffer,
                           "AmsiScanBuffer",
                           "amsi",
                           nullptr,
                           reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(length),
                           static_cast<std::uint64_t>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                           0,
                           caller);
        return hr;
    }

    HRESULT WINAPI
    AmsiScanStringHook(PVOID amsiContext, LPCWSTR string, LPCWSTR contentName, PVOID session, PVOID result)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiScanString == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalAmsiScanString),
                                                     g_OriginalAmsiScanString,
                                                     amsiContext,
                                                     string,
                                                     contentName,
                                                     session,
                                                     result);
        WCHAR scriptSample[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        std::memset(scriptSample, 0, sizeof(scriptSample));
        std::memset(reason, 0, sizeof(reason));
        ULONG stringChars = string != nullptr ? static_cast<ULONG>(wcsnlen_s(string, 512)) : 0;
        CopyWidePrintableToWide(scriptSample, RTL_NUMBER_OF(scriptSample), string, stringChars);
        (void)swprintf_s(reason,
                         RTL_NUMBER_OF(reason),
                         L"powershell.amsi.string contentName=%s status=0x%08lX result=0x%08lX string=\"%s\"",
                         contentName != nullptr && contentName[0] != L'\0' ? contentName : L"<unknown>",
                         static_cast<unsigned long>(hr),
                         static_cast<unsigned long>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                         scriptSample[0] != L'\0' ? scriptSample : L"-");
        PublishModuleEvent(ModuleHookOperation::AmsiScanString,
                           "AmsiScanString",
                           "amsi",
                           nullptr,
                           reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(session)),
                           0,
                           caller);
        return hr;
    }

    HRESULT WINAPI
    AmsiNotifyOperationHook(PVOID amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, PVOID result)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalAmsiNotifyOperation == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalAmsiNotifyOperation),
                                                     g_OriginalAmsiNotifyOperation,
                                                     amsiContext,
                                                     buffer,
                                                     length,
                                                     contentName,
                                                     result);
        WCHAR sample[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];
        std::memset(sample, 0, sizeof(sample));
        std::memset(reason, 0, sizeof(reason));
        if (buffer != nullptr && length != 0)
        {
            if (BufferLooksUtf16LeText(buffer, length))
            {
                CopyWidePrintableToWide(
                    sample, RTL_NUMBER_OF(sample), static_cast<LPCWSTR>(buffer), length / sizeof(WCHAR));
            }
            else
            {
                CopyPrintableBytesToWide(sample, RTL_NUMBER_OF(sample), buffer, length);
            }
        }
        (void)swprintf_s(reason,
                         RTL_NUMBER_OF(reason),
                         L"powershell.amsi.notify contentName=%s bytes=%lu status=0x%08lX result=0x%08lX data=\"%s\"",
                         contentName != nullptr && contentName[0] != L'\0' ? contentName : L"<unknown>",
                         static_cast<unsigned long>(length),
                         static_cast<unsigned long>(hr),
                         static_cast<unsigned long>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                         sample[0] != L'\0' ? sample : L"-");
        PublishModuleEvent(ModuleHookOperation::AmsiNotifyOperation,
                           "AmsiNotifyOperation",
                           "amsi",
                           nullptr,
                           reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR),
                           static_cast<std::uint64_t>(static_cast<ULONG>(hr)),
                           static_cast<std::uint64_t>(result != nullptr ? *static_cast<unsigned long *>(result) : 0ul),
                           static_cast<std::uint64_t>(length),
                           0,
                           caller);
        return hr;
    }
} // namespace IX_MODULE_INTERNAL
