#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    BOOLEAN WINAPI RtlAddFunctionTableHook(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress)
    {
        if (g_OriginalRtlAddFunctionTable == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalRtlAddFunctionTable),
                                                     g_OriginalRtlAddFunctionTable,
                                                     functionTable,
                                                     entryCount,
                                                     baseAddress);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlAddFunctionTable,
                               "RtlAddFunctionTable",
                               "ntdll",
                               nullptr,
                               nullptr,
                               0,
                               static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(functionTable)),
                               static_cast<std::uint64_t>(entryCount),
                               static_cast<std::uint64_t>(baseAddress),
                               0);
        }
        return ok;
    }

    BOOLEAN WINAPI RtlInstallFunctionTableCallbackHook(DWORD64 tableIdentifier,
                                                       DWORD64 baseAddress,
                                                       DWORD length,
                                                       PGET_RUNTIME_FUNCTION_CALLBACK callback,
                                                       PVOID context,
                                                       PCWSTR outOfProcessCallbackDll)
    {
        if (g_OriginalRtlInstallFunctionTableCallback == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok =
            CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalRtlInstallFunctionTableCallback),
                                            g_OriginalRtlInstallFunctionTableCallback,
                                            tableIdentifier,
                                            baseAddress,
                                            length,
                                            callback,
                                            context,
                                            outOfProcessCallbackDll);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlInstallFunctionTableCallback,
                               "RtlInstallFunctionTableCallback",
                               "ntdll",
                               nullptr,
                               outOfProcessCallbackDll,
                               CopyWideLength(outOfProcessCallbackDll),
                               static_cast<std::uint64_t>(tableIdentifier),
                               static_cast<std::uint64_t>(baseAddress),
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

        BOOLEAN ok = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalRtlDeleteFunctionTable),
                                                     g_OriginalRtlDeleteFunctionTable,
                                                     functionTable);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlDeleteFunctionTable,
                               "RtlDeleteFunctionTable",
                               "ntdll",
                               nullptr,
                               nullptr,
                               0,
                               static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(functionTable)),
                               0,
                               0,
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

        void *caller = _ReturnAddress();
        PVOID handle =
            CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalRtlAddVectoredExceptionHandler),
                                            g_OriginalRtlAddVectoredExceptionHandler,
                                            first,
                                            handler);
        PublishModuleEvent(ModuleHookOperation::RtlAddVectoredExceptionHandler,
                           "RtlAddVectoredExceptionHandler",
                           "ntdll",
                           nullptr,
                           nullptr,
                           0,
                           static_cast<std::uint64_t>(first),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handler)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)),
                           0,
                           caller);
        return handle;
    }

    ULONG NTAPI RtlRemoveVectoredExceptionHandlerHook(PVOID handle)
    {
        if (g_OriginalRtlRemoveVectoredExceptionHandler == nullptr)
        {
            return 0;
        }
        void *caller = _ReturnAddress();
        ULONG status =
            CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalRtlRemoveVectoredExceptionHandler),
                                            g_OriginalRtlRemoveVectoredExceptionHandler,
                                            handle);
        PublishModuleEvent(ModuleHookOperation::RtlRemoveVectoredExceptionHandler,
                           "RtlRemoveVectoredExceptionHandler",
                           "ntdll",
                           nullptr,
                           nullptr,
                           0,
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(handle)),
                           static_cast<std::uint64_t>(status),
                           0,
                           0,
                           caller);
        return status;
    }

    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilterHook(LPTOP_LEVEL_EXCEPTION_FILTER filter)
    {
        if (g_OriginalSetUnhandledExceptionFilter == nullptr)
        {
            return nullptr;
        }

        void *caller = _ReturnAddress();
        LPTOP_LEVEL_EXCEPTION_FILTER previous =
            CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalSetUnhandledExceptionFilter),
                                            g_OriginalSetUnhandledExceptionFilter,
                                            filter);
        PublishModuleEvent(ModuleHookOperation::SetUnhandledExceptionFilter,
                           "SetUnhandledExceptionFilter",
                           "KernelBase",
                           nullptr,
                           nullptr,
                           0,
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(filter)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(previous)),
                           0,
                           0,
                           caller);
        return previous;
    }

    HRESULT WINAPI CoInitializeExHook(LPVOID pvReserved, DWORD dwCoInit)
    {
        if (g_OriginalCoInitializeEx == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalSafely(g_OriginalCoInitializeEx, pvReserved, dwCoInit);
        wchar_t mode[32];
        FormatCoInitMode(dwCoInit, mode);
        PublishModuleEvent(ModuleHookOperation::CoInitializeEx,
                           "CoInitializeEx",
                           "combase",
                           nullptr,
                           mode,
                           CopyWideLength(mode),
                           static_cast<std::uint64_t>(dwCoInit),
                           static_cast<std::uint64_t>(static_cast<unsigned long>(hr)),
                           0,
                           0);
        return hr;
    }

    HRESULT WINAPI CoInitializeSecurityHook(PSECURITY_DESCRIPTOR pSecDesc,
                                            LONG cAuthSvc,
                                            SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
                                            void *pReserved1,
                                            DWORD dwAuthnLevel,
                                            DWORD dwImpLevel,
                                            void *pAuthList,
                                            DWORD dwCapabilities,
                                            void *pReserved3)
    {
        if (g_OriginalCoInitializeSecurity == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalSafely(g_OriginalCoInitializeSecurity,
                                        pSecDesc,
                                        cAuthSvc,
                                        asAuthSvc,
                                        pReserved1,
                                        dwAuthnLevel,
                                        dwImpLevel,
                                        pAuthList,
                                        dwCapabilities,
                                        pReserved3);
        wchar_t label[32];
        CopyLiteralWide(label, L"SecurityInit");
        PublishModuleEvent(ModuleHookOperation::CoInitializeSecurity,
                           "CoInitializeSecurity",
                           "combase",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(static_cast<std::int64_t>(cAuthSvc)),
                           static_cast<std::uint64_t>(dwAuthnLevel),
                           static_cast<std::uint64_t>(dwImpLevel),
                           static_cast<std::uint64_t>(dwCapabilities));
        return hr;
    }

    HRESULT WINAPI
    CoCreateInstanceHook(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv)
    {
        if (g_OriginalCoCreateInstance == nullptr)
        {
            return E_FAIL;
        }

        HRESULT hr = CallOriginalSafely(g_OriginalCoCreateInstance, rclsid, pUnkOuter, dwClsContext, riid, ppv);
        wchar_t className[32];
        if (InlineIsEqualGUID(rclsid, CLSID_WbemLocatorValue))
        {
            CopyLiteralWide(className, L"WMI:WbemLocator");
        }
        else if (!TryFormatGuid(&rclsid, className))
        {
            CopyLiteralWide(className, L"COMClass");
        }

        PublishModuleEvent(ModuleHookOperation::CoCreateInstance,
                           "CoCreateInstance",
                           "combase",
                           nullptr,
                           className,
                           CopyWideLength(className),
                           static_cast<std::uint64_t>(dwClsContext),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(pUnkOuter)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(ppv)),
                           static_cast<std::uint64_t>(static_cast<unsigned long>(hr)));
        return hr;
    }

    ULONG WINAPI EventRegisterHook(LPCGUID providerId,
                                   PENABLECALLBACK enableCallback,
                                   PVOID callbackContext,
                                   PREGHANDLE regHandle)
    {
        if (g_OriginalEventRegister == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalEventRegister),
                                                       g_OriginalEventRegister,
                                                       providerId,
                                                       enableCallback,
                                                       callbackContext,
                                                       regHandle);
        wchar_t provider[32];
        if (!TryFormatGuid(providerId, provider))
        {
            CopyLiteralWide(provider, L"ETWProvider");
        }

        PublishModuleEvent(ModuleHookOperation::EventRegister,
                           "EventRegister",
                           "advapi32",
                           nullptr,
                           provider,
                           CopyWideLength(provider),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(enableCallback)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(callbackContext)),
                           static_cast<std::uint64_t>((regHandle != nullptr) ? *regHandle : 0),
                           static_cast<std::uint64_t>(status));
        return status;
    }

    ULONG WINAPI EventUnregisterHook(REGHANDLE regHandle)
    {
        if (g_OriginalEventUnregister == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalTemporarilyUnhooked(
            reinterpret_cast<void **>(&g_OriginalEventUnregister), g_OriginalEventUnregister, regHandle);
        PublishModuleEvent(ModuleHookOperation::EventUnregister,
                           "EventUnregister",
                           "advapi32",
                           nullptr,
                           nullptr,
                           0,
                           static_cast<std::uint64_t>(regHandle),
                           static_cast<std::uint64_t>(status),
                           0,
                           0);
        return status;
    }

    ULONG WINAPI StartTraceWHook(PTRACEHANDLE sessionHandle, LPCWSTR sessionName, PEVENT_TRACE_PROPERTIES properties)
    {
        if (g_OriginalStartTraceW == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalSafely(g_OriginalStartTraceW, sessionHandle, sessionName, properties);
        PublishModuleEvent(ModuleHookOperation::StartTraceW,
                           "StartTraceW",
                           "advapi32",
                           nullptr,
                           sessionName,
                           CopyWideLength(sessionName),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(sessionHandle)),
                           static_cast<std::uint64_t>((sessionHandle != nullptr) ? *sessionHandle : 0),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(properties)),
                           static_cast<std::uint64_t>(status));
        return status;
    }

    ULONG WINAPI EnableTraceEx2Hook(TRACEHANDLE traceHandle,
                                    LPCGUID providerId,
                                    ULONG controlCode,
                                    UCHAR level,
                                    ULONGLONG matchAnyKeyword,
                                    ULONGLONG matchAllKeyword,
                                    ULONG timeout,
                                    PENABLE_TRACE_PARAMETERS enableParameters)
    {
        if (g_OriginalEnableTraceEx2 == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalSafely(g_OriginalEnableTraceEx2,
                                          traceHandle,
                                          providerId,
                                          controlCode,
                                          level,
                                          matchAnyKeyword,
                                          matchAllKeyword,
                                          timeout,
                                          enableParameters);
        wchar_t provider[32];
        if (!TryFormatGuid(providerId, provider))
        {
            CopyLiteralWide(provider, L"ETWControl");
        }

        PublishModuleEvent(ModuleHookOperation::EnableTraceEx2,
                           "EnableTraceEx2",
                           "advapi32",
                           nullptr,
                           provider,
                           CopyWideLength(provider),
                           static_cast<std::uint64_t>(traceHandle),
                           static_cast<std::uint64_t>(controlCode),
                           static_cast<std::uint64_t>(level),
                           static_cast<std::uint64_t>(status));
        return status;
    }

    static void FormatEtwDescriptor(PCEVENT_DESCRIPTOR eventDescriptor, wchar_t label[32]) noexcept
    {
        CopyLiteralWide(label, L"EtwEvent");
        if (eventDescriptor == nullptr)
        {
            return;
        }

        __try
        {
            (void)swprintf_s(label,
                             32,
                             L"EtwEvent id=%hu lvl=%hhu kw=0x%llX",
                             eventDescriptor->Id,
                             eventDescriptor->Level,
                             static_cast<unsigned long long>(eventDescriptor->Keyword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            CopyLiteralWide(label, L"EtwEvent");
        }
    }

    ULONG NTAPI EtwEventWriteHook(REGHANDLE regHandle,
                                  PCEVENT_DESCRIPTOR eventDescriptor,
                                  ULONG userDataCount,
                                  PEVENT_DATA_DESCRIPTOR userData)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalEtwEventWrite == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalEtwEventWrite),
                                                       g_OriginalEtwEventWrite,
                                                       regHandle,
                                                       eventDescriptor,
                                                       userDataCount,
                                                       userData);
        wchar_t label[32];
        FormatEtwDescriptor(eventDescriptor, label);
        PublishModuleEvent(ModuleHookOperation::EtwEventWrite,
                           "EtwEventWrite",
                           "ntdll",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(regHandle),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(eventDescriptor)),
                           static_cast<std::uint64_t>(userDataCount),
                           static_cast<std::uint64_t>(status),
                           caller);
        return status;
    }

    ULONG NTAPI EtwEventWriteExHook(REGHANDLE regHandle,
                                    PCEVENT_DESCRIPTOR eventDescriptor,
                                    ULONG64 filter,
                                    ULONG flags,
                                    LPCGUID activityId,
                                    LPCGUID relatedActivityId,
                                    ULONG userDataCount,
                                    PEVENT_DATA_DESCRIPTOR userData)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalEtwEventWriteEx == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalEtwEventWriteEx),
                                                       g_OriginalEtwEventWriteEx,
                                                       regHandle,
                                                       eventDescriptor,
                                                       filter,
                                                       flags,
                                                       activityId,
                                                       relatedActivityId,
                                                       userDataCount,
                                                       userData);
        wchar_t label[32];
        FormatEtwDescriptor(eventDescriptor, label);
        PublishModuleEvent(ModuleHookOperation::EtwEventWriteEx,
                           "EtwEventWriteEx",
                           "ntdll",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(regHandle),
                           static_cast<std::uint64_t>(filter),
                           static_cast<std::uint64_t>(flags),
                           static_cast<std::uint64_t>(status),
                           caller);
        return status;
    }

    ULONG NTAPI EtwEventWriteFullHook(REGHANDLE regHandle,
                                      PCEVENT_DESCRIPTOR eventDescriptor,
                                      USHORT eventProperty,
                                      LPCGUID activityId,
                                      LPCGUID relatedActivityId,
                                      ULONG userDataCount,
                                      PEVENT_DATA_DESCRIPTOR userData)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalEtwEventWriteFull == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalEtwEventWriteFull),
                                                       g_OriginalEtwEventWriteFull,
                                                       regHandle,
                                                       eventDescriptor,
                                                       eventProperty,
                                                       activityId,
                                                       relatedActivityId,
                                                       userDataCount,
                                                       userData);
        wchar_t label[32];
        FormatEtwDescriptor(eventDescriptor, label);
        PublishModuleEvent(ModuleHookOperation::EtwEventWriteFull,
                           "EtwEventWriteFull",
                           "ntdll",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(regHandle),
                           static_cast<std::uint64_t>(eventProperty),
                           static_cast<std::uint64_t>(userDataCount),
                           static_cast<std::uint64_t>(status),
                           caller);
        return status;
    }

    ULONG NTAPI EtwEventWriteTransferHook(REGHANDLE regHandle,
                                          PCEVENT_DESCRIPTOR eventDescriptor,
                                          LPCGUID activityId,
                                          LPCGUID relatedActivityId,
                                          ULONG userDataCount,
                                          PEVENT_DATA_DESCRIPTOR userData)
    {
        void *caller = _ReturnAddress();
        if (g_OriginalEtwEventWriteTransfer == nullptr)
        {
            return ERROR_INVALID_FUNCTION;
        }

        ULONG status = CallOriginalTemporarilyUnhooked(reinterpret_cast<void **>(&g_OriginalEtwEventWriteTransfer),
                                                       g_OriginalEtwEventWriteTransfer,
                                                       regHandle,
                                                       eventDescriptor,
                                                       activityId,
                                                       relatedActivityId,
                                                       userDataCount,
                                                       userData);
        wchar_t label[32];
        FormatEtwDescriptor(eventDescriptor, label);
        PublishModuleEvent(ModuleHookOperation::EtwEventWriteTransfer,
                           "EtwEventWriteTransfer",
                           "ntdll",
                           nullptr,
                           label,
                           CopyWideLength(label),
                           static_cast<std::uint64_t>(regHandle),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(activityId)),
                           static_cast<std::uint64_t>(userDataCount),
                           static_cast<std::uint64_t>(status),
                           caller);
        return status;
    }
} // namespace IX_MODULE_INTERNAL
