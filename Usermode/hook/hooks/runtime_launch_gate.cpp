#include "runtime_private.h"

#include <strsafe.h>
#include <cstring>

namespace IX_RUNTIME_INTERNAL
{
    enum LaunchGateTrapKind : std::uint32_t
    {
        LaunchGateTrapEntryPoint = 1,
        LaunchGateTrapTlsCallback = 2
    };

    const char *LaunchGateTrapTag(std::uint32_t kind) noexcept
    {
        return (kind == LaunchGateTrapTlsCallback) ? "rt.tls" : "rt.entry";
    }

    const char *LaunchGateTrapApiName(std::uint32_t kind) noexcept
    {
        return (kind == LaunchGateTrapTlsCallback) ? "TlsCallbackTrap" : "LaunchGateEntryTrap";
    }

    std::uint32_t LaunchGateTrapOperation(std::uint32_t kind) noexcept
    {
        return (kind == LaunchGateTrapTlsCallback) ? IX_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK
                                                   : IX_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY;
    }

    void PublishLaunchGateTrapEvent(const LaunchGateParkContext &park) noexcept
    {
        if (park.TrapAddress == nullptr)
        {
            return;
        }

        IXIPC_HOOK_EVENT record{};
        record.Kind = IxIpcHookEventIntegrity;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = park.ThreadId != 0 ? park.ThreadId : GetCurrentThreadId();
        record.Operation = LaunchGateTrapOperation(park.TrapKind);
        record.Caller = reinterpret_cast<std::uint64_t>(park.TrapAddress);
        record.Context0 = reinterpret_cast<std::uint64_t>(park.TrapAddress);
        record.Context1 = reinterpret_cast<std::uint64_t>(park.TrapPage);
        record.Context2 = park.TrapKind;
        record.Context3 = park.TrapIndex;
        record.ArgCount = 3;
        record.Args[0] = static_cast<std::uint64_t>(GetTickCount64());
        record.Args[1] = reinterpret_cast<std::uint64_t>(park.TrapPage);
        record.Args[2] = park.TrapIndex;
        record.CallerFlags =
            ((IX_HOOK_COMPONENT_INTEGRITY << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK);
        (void)strncpy_s(record.ApiName, LaunchGateTrapApiName(park.TrapKind), _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "Runtime", _TRUNCATE);

        IxInternalScope scope;
        (void)IXIPC::PublishHookEvent(record);
    }

    bool ShouldDeferLaunchGateOpen() noexcept
    {
        char value[8]{};
        static constexpr IxEncodedAnsiLiteral kEnvName{"IX_HOOK_LAUNCH_GATE_DEFER_OPEN", 0x99u};
        IxScopedAnsiLiteral envName(kEnvName);
        DWORD read = GetEnvironmentVariableA(envName.c_str(), value, (DWORD)RTL_NUMBER_OF(value));
        if (read == 0 || read >= RTL_NUMBER_OF(value))
        {
            return false;
        }

        return (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T');
    }

    bool BuildLaunchGateDeferredEventName(_Out_writes_z_(MAX_PATH) wchar_t *buffer, size_t cchBuffer) noexcept
    {
        if (buffer == nullptr || cchBuffer == 0)
        {
            return false;
        }

        static constexpr IxEncodedWideLiteral kEnvName{L"IX_HOOK_LAUNCH_GATE_EVENT", 0x1A9u};
        IxScopedWideLiteral envName(kEnvName);
        DWORD envRead = GetEnvironmentVariableW(envName.c_str(), buffer, (DWORD)cchBuffer);
        if (envRead > 0 && envRead < cchBuffer)
        {
            IxDbgLog("BuildLaunchGateDeferredEventName: using controller-provided name=%ls", buffer);
            return true;
        }

        IxDbgLog("BuildLaunchGateDeferredEventName: missing controller-provided event name envRead=%lu gle=%lu",
                 static_cast<unsigned long>(envRead), static_cast<unsigned long>(GetLastError()));
        buffer[0] = L'\0';
        return false;
    }

    void *AlignLaunchGatePage(void *address) noexcept
    {
        ULONG_PTR value = reinterpret_cast<ULONG_PTR>(address);
        return reinterpret_cast<void *>(value & ~static_cast<ULONG_PTR>(kLaunchGatePageSize - 1u));
    }

    void *ResolveLaunchGatePageBase(const LaunchGatePage &page) noexcept
    {
        IxIhrResolved resolved{};
        if (!ResolveIndirectHandle(page.BaseToken, IxIhrType::LaunchGatePage, resolved))
        {
            return nullptr;
        }
        return resolved.Pointer;
    }

    bool IsLaunchGatePageArmed(void *address) noexcept
    {
        void *pageBase = AlignLaunchGatePage(address);
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (ResolveLaunchGatePageBase(g_LaunchGatePages[i]) == pageBase)
            {
                return true;
            }
        }
        return false;
    }

    bool ArmLaunchGatePage(void *address, std::uint32_t kind, std::uint32_t index) noexcept
    {
        if (address == nullptr)
        {
            IxDbgLog("ArmLaunchGatePage: null address");
            return false;
        }

        void *pageBase = AlignLaunchGatePage(address);
        if (pageBase == nullptr)
        {
            IxDbgLog("ArmLaunchGatePage: null page base address=%p", address);
            return false;
        }

        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (ResolveLaunchGatePageBase(g_LaunchGatePages[i]) == pageBase)
            {
                if (kind == LaunchGateTrapTlsCallback && g_LaunchGatePages[i].TrapKind != LaunchGateTrapTlsCallback)
                {
                    g_LaunchGatePages[i].TrapAddress = address;
                    g_LaunchGatePages[i].TrapKind = kind;
                    g_LaunchGatePages[i].TrapIndex = index;
                }
                IxDbgLog("ArmLaunchGatePage: already armed address=%p page=%p kind=%lu index=%lu", address, pageBase,
                         static_cast<unsigned long>(kind), static_cast<unsigned long>(index));
                return true;
            }
        }

        if (g_LaunchGatePageCount >= kLaunchGateMaxPages)
        {
            IxDbgLog("ArmLaunchGatePage: page capacity reached address=%p page=%p count=%lu", address, pageBase,
                     static_cast<unsigned long>(g_LaunchGatePageCount));
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!NativeQueryMemory(pageBase, &mbi) || mbi.State != MEM_COMMIT)
        {
            IxDbgLog("ArmLaunchGatePage: query/commit failed address=%p page=%p state=0x%08lX gle=%lu", address,
                     pageBase, static_cast<unsigned long>(mbi.State), static_cast<unsigned long>(GetLastError()));
            return false;
        }

        DWORD baseProtect = mbi.Protect & ~PAGE_GUARD;
        if (baseProtect == 0 || baseProtect == PAGE_NOACCESS)
        {
            IxDbgLog("ArmLaunchGatePage: unusable protection address=%p page=%p protect=0x%08lX", address, pageBase,
                     static_cast<unsigned long>(mbi.Protect));
            return false;
        }

        ULONG oldProtect = 0;
        if (!NativeProtect(pageBase, kLaunchGatePageSize, baseProtect | PAGE_GUARD, &oldProtect))
        {
            IxDbgLog("ArmLaunchGatePage: protect failed address=%p page=%p baseProtect=0x%08lX gle=%lu", address,
                     pageBase, static_cast<unsigned long>(baseProtect), static_cast<unsigned long>(GetLastError()));
            return false;
        }

        IxIhrToken pageToken = RegisterIndirectHandle(
            pageBase, kLaunchGatePageSize, IxIhrType::LaunchGatePage,
            kIxIhrFlagExecutable | kIxIhrFlagOwned | kIxIhrFlagGuarded, LaunchGateTrapTag(kind));
        if (pageToken == 0)
        {
            ULONG ignored = 0;
            (void)NativeProtect(pageBase, kLaunchGatePageSize, baseProtect, &ignored);
            IxDbgLog("ArmLaunchGatePage: IHR token registration failed address=%p page=%p", address, pageBase);
            return false;
        }

        g_LaunchGatePages[g_LaunchGatePageCount].BaseToken = pageToken;
        g_LaunchGatePages[g_LaunchGatePageCount].OriginalProtect = baseProtect;
        g_LaunchGatePages[g_LaunchGatePageCount].TrapAddress = address;
        g_LaunchGatePages[g_LaunchGatePageCount].TrapKind = kind;
        g_LaunchGatePages[g_LaunchGatePageCount].TrapIndex = index;
        g_LaunchGatePageCount += 1;
        IxDbgLog(
            "ArmLaunchGatePage: armed address=%p page=%p kind=%lu index=%lu protect=0x%08lX oldProtect=0x%08lX token=0x%llX count=%lu",
            address, pageBase, static_cast<unsigned long>(kind), static_cast<unsigned long>(index),
            static_cast<unsigned long>(baseProtect), static_cast<unsigned long>(oldProtect),
            static_cast<unsigned long long>(pageToken), static_cast<unsigned long>(g_LaunchGatePageCount));
        return true;
    }

    void RestoreLaunchGatePages() noexcept
    {
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            void *pageBase = ResolveLaunchGatePageBase(g_LaunchGatePages[i]);
            if (pageBase == nullptr || g_LaunchGatePages[i].OriginalProtect == 0)
            {
                continue;
            }

            ULONG ignored = 0;
            (void)NativeProtect(pageBase, kLaunchGatePageSize, g_LaunchGatePages[i].OriginalProtect, &ignored);
        }
    }

    void SanitizeLaunchGateRestoreContext(_Inout_ CONTEXT &context) noexcept
    {
#if defined(_M_X64)
        context.ContextFlags = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER;
        context.Dr0 = 0;
        context.Dr1 = 0;
        context.Dr2 = 0;
        context.Dr3 = 0;
        context.Dr6 = 0;
        context.Dr7 = 0;
        context.EFlags &= ~0x100u;
#endif
    }

    [[noreturn]] void ResumeOriginalThread(_Inout_ LaunchGateParkContext *park, _In_ const char *source) noexcept
    {
        CONTEXT context{};
        NtContinueFn ntContinue = ResolveNtdllExport<NtContinueFn>("NtContinue");
        RtlRestoreContextFn restore = ResolveNtdllExport<RtlRestoreContextFn>("RtlRestoreContext");

        if (park == nullptr)
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateResumeRejected);
            IxRuntimeFailClosed(ERROR_INVALID_PARAMETER);
        }

        context = park->Context;
        park->State = 0;
        SanitizeLaunchGateRestoreContext(context);
        IxDbgLog("%s: resuming original thread tid=%lu rip=%p rsp=%p", source != nullptr ? source : "LaunchGate",
                 static_cast<unsigned long>(park->ThreadId), reinterpret_cast<void *>(context.Rip),
                 reinterpret_cast<void *>(context.Rsp));

        if (restore != nullptr)
        {
            restore(&context, nullptr);
        }

        if (ntContinue != nullptr)
        {
            NTSTATUS status = ntContinue(&context, FALSE);
            IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateResumeRejected, static_cast<std::uint32_t>(status),
                                 context.ContextFlags);
        }

        IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateResumeRejected, context.Rip, context.Rsp);
        IxRuntimeFailClosed(ERROR_INVALID_STATE);
    }

    __declspec(noinline) void WINAPI LaunchGateParkThunk(void *parameter) noexcept
    {
        auto *park = static_cast<LaunchGateParkContext *>(parameter);
        if (g_LaunchGateReadyEvent != nullptr)
        {
            (void)NativeWaitForSingleObject(g_LaunchGateReadyEvent);
        }
        PublishLaunchGateTrapEvent(*park);

        if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
        {
            bool expected = false;
            if (g_LaunchGateReady.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                RestoreLaunchGatePages();
            }
        }

        ResumeOriginalThread(park, "LaunchGateParkThunk");
    }

    __declspec(noinline) void WINAPI LaunchGateInitializeThunk(void *parameter) noexcept
    {
        auto *park = static_cast<LaunchGateParkContext *>(parameter);
        const bool deferredOpen = g_LaunchGateDeferredOpen.load(std::memory_order_acquire);

        if (g_LaunchGateCallbacks.InitializeRuntime == nullptr ||
            !g_LaunchGateCallbacks.InitializeRuntime(false, false))
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::RuntimeInitializeFailed);
            if (g_LaunchGateCallbacks.FailClosed != nullptr)
            {
                g_LaunchGateCallbacks.FailClosed(WAIT_TIMEOUT);
            }
            IxRuntimeFailClosed(WAIT_TIMEOUT);
        }

        if (park->TrapKind == LaunchGateTrapEntryPoint)
        {
            (void)EnsureProcessInstrumentationCallbackInstalled(true);
        }
        PublishLaunchGateTrapEvent(*park);

        if (deferredOpen)
        {
            if (g_LaunchGateReadyEvent != nullptr)
            {
                (void)NativeWaitForSingleObject(g_LaunchGateReadyEvent);
            }

            bool expected = false;
            if (g_LaunchGateReady.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                RestoreLaunchGatePages();
            }
        }
        else
        {
            LaunchGateRelease();
        }

        if (!EnsureRuntimeWorkerThreadStarted())
        {
            IxDbgLog("LaunchGateInitializeThunk: worker start deferred");
        }

        ResumeOriginalThread(park, "LaunchGateInitializeThunk");
    }

    LaunchGateParkContext *AcquireLaunchGateParkContext() noexcept
    {
        for (std::size_t i = 0; i < RTL_NUMBER_OF(g_LaunchGateParkContexts); ++i)
        {
            auto *park = &g_LaunchGateParkContexts[i];
            if (InterlockedCompareExchange(&park->State, 1, 0) == 0)
            {
                park->ThreadId = GetCurrentThreadId();
                return park;
            }
        }
        return nullptr;
    }

    bool ArmLaunchGateForProcessEntry() noexcept
    {
        void *processModule = FindProcessImageBase();
        if (processModule == nullptr)
        {
            IxDbgLog("ArmLaunchGateForProcessEntry: process image base not found");
            return false;
        }

        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(processModule);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            IxDbgLog("ArmLaunchGateForProcessEntry: invalid DOS header image=%p magic=0x%04X", processModule,
                     dos != nullptr ? dos->e_magic : 0u);
            return false;
        }

        const auto *ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
            reinterpret_cast<const std::uint8_t *>(processModule) + static_cast<std::size_t>(dos->e_lfanew));
        if (ntHeaders == nullptr || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            IxDbgLog("ArmLaunchGateForProcessEntry: invalid NT headers image=%p e_lfanew=0x%lX signature=0x%08lX",
                     processModule, static_cast<unsigned long>(dos->e_lfanew),
                     ntHeaders != nullptr ? static_cast<unsigned long>(ntHeaders->Signature) : 0ul);
            return false;
        }

        bool armedAny = false;
        IxDbgLog(
            "ArmLaunchGateForProcessEntry: image=%p entryRva=0x%lX tlsRva=0x%lX tlsSize=0x%lX", processModule,
            static_cast<unsigned long>(ntHeaders->OptionalHeader.AddressOfEntryPoint),
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS
                ? static_cast<unsigned long>(
                      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
                : 0ul,
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS
                ? static_cast<unsigned long>(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
                : 0ul);
        if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0)
        {
            armedAny |= ArmLaunchGatePage(reinterpret_cast<void *>(reinterpret_cast<ULONG_PTR>(processModule) +
                                                                   ntHeaders->OptionalHeader.AddressOfEntryPoint),
                                          LaunchGateTrapEntryPoint, 0);
        }

#ifdef _WIN64
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
        {
            const IMAGE_DATA_DIRECTORY &tlsDirectory =
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tlsDirectory.VirtualAddress != 0 && tlsDirectory.Size >= sizeof(IMAGE_TLS_DIRECTORY64))
            {
                __try
                {
                    const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64 *>(
                        reinterpret_cast<const std::uint8_t *>(processModule) + tlsDirectory.VirtualAddress);
                    auto **callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls->AddressOfCallBacks);
                    if (callbacks != nullptr)
                    {
                        std::size_t tlsCallbackCount = 0;
                        for (std::size_t i = 0; i < kLaunchGateMaxPages && callbacks[i] != nullptr; ++i)
                        {
                            tlsCallbackCount += 1;
                            IxDbgLog("ArmLaunchGateForProcessEntry: TLS callback[%zu]=%p", i,
                                     reinterpret_cast<void *>(callbacks[i]));
                            armedAny |= ArmLaunchGatePage(reinterpret_cast<void *>(callbacks[i]),
                                                          LaunchGateTrapTlsCallback, static_cast<std::uint32_t>(i));
                        }
                        IxDbgLog("ArmLaunchGateForProcessEntry: TLS callbacks armed=%zu", tlsCallbackCount);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    IxDbgLog("ArmLaunchGateForProcessEntry: TLS callback probe exception=0x%08lX",
                             static_cast<unsigned long>(GetExceptionCode()));
                }
            }
        }
#endif

        IxDbgLog("ArmLaunchGateForProcessEntry: armedAny=%u count=%lu", armedAny ? 1u : 0u,
                 static_cast<unsigned long>(g_LaunchGatePageCount));
        return armedAny;
    }

    bool LaunchGatePrepare() noexcept
    {
        bool expected = false;
        if (!g_LaunchGatePrepared.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return true;
        }

        g_LaunchGateDeferredOpen.store(ShouldDeferLaunchGateOpen(), std::memory_order_release);
        if (g_LaunchGateReadyEvent == nullptr)
        {
            if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
            {
                wchar_t eventName[MAX_PATH]{};
                if (!BuildLaunchGateDeferredEventName(eventName, RTL_NUMBER_OF(eventName)))
                {
                    IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateDeferredEventNameFailed);
                    g_LaunchGatePrepared.store(false, std::memory_order_release);
                    return false;
                }

                g_LaunchGateReadyEvent = NativeCreateEvent(true, false, eventName, SYNCHRONIZE);
            }
            else
            {
                g_LaunchGateReadyEvent = NativeCreateEvent(true, false);
            }

            if (g_LaunchGateReadyEvent == nullptr)
            {
                IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateReadyEventCreateFailed, GetLastError());
                g_LaunchGatePrepared.store(false, std::memory_order_release);
                return false;
            }
        }

        g_LaunchGateReady.store(false, std::memory_order_release);
        g_LaunchGatePageCount = 0;
        g_LaunchGateInitializerAssigned = 0;

        if (!ArmLaunchGateForProcessEntry())
        {
            RestoreLaunchGatePages();
            g_LaunchGatePageCount = 0;
            g_LaunchGatePrepared.store(false, std::memory_order_release);
            IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGatePrepareFailed);
            IxDbgLog("LaunchGatePrepare: failed to arm any launch-gate pages");
            return false;
        }

        IxDbgLog("LaunchGatePrepare: prepared count=%lu deferredOpen=%u",
                 static_cast<unsigned long>(g_LaunchGatePageCount),
                 g_LaunchGateDeferredOpen.load(std::memory_order_acquire) ? 1u : 0u);
        return true;
    }

    void LaunchGateRelease() noexcept
    {
        if (!g_LaunchGatePrepared.load(std::memory_order_acquire))
        {
            return;
        }

        if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
        {
            return;
        }

        g_LaunchGateReady.store(true, std::memory_order_release);
        RestoreLaunchGatePages();
        if (g_LaunchGateReadyEvent != nullptr)
        {
            (void)NativeSetEvent(g_LaunchGateReadyEvent);
        }
    }

    bool LaunchGateHandleFault(EXCEPTION_POINTERS *ep) noexcept
    {
        if (!g_LaunchGatePrepared.load(std::memory_order_acquire) ||
            g_LaunchGateReady.load(std::memory_order_acquire) || ep == nullptr || ep->ExceptionRecord == nullptr ||
            ep->ContextRecord == nullptr || ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        {
            return false;
        }

#if defined(_M_X64)
        void *faultAddress = ep->ExceptionRecord->ExceptionAddress;
        if (ep->ExceptionRecord->NumberParameters >= 2 && ep->ExceptionRecord->ExceptionInformation[1] != 0)
        {
            faultAddress = reinterpret_cast<void *>(ep->ExceptionRecord->ExceptionInformation[1]);
        }

        if (!IsLaunchGatePageArmed(faultAddress))
        {
            return false;
        }

        IxDbgLog("LaunchGateHandleFault: fault=%p exception=%p", faultAddress, ep->ExceptionRecord->ExceptionAddress);

        void *pageBase = AlignLaunchGatePage(faultAddress);
        LaunchGatePage *matchedPage = nullptr;
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (ResolveLaunchGatePageBase(g_LaunchGatePages[i]) == pageBase &&
                g_LaunchGatePages[i].OriginalProtect != 0)
            {
                matchedPage = &g_LaunchGatePages[i];
                ULONG ignored = 0;
                (void)NativeProtect(pageBase, kLaunchGatePageSize, g_LaunchGatePages[i].OriginalProtect | PAGE_GUARD,
                                    &ignored);
                break;
            }
        }

        LaunchGateParkContext *park = AcquireLaunchGateParkContext();
        if (park == nullptr)
        {
            IxDbgLog("LaunchGateHandleFault: no park slots available");
            IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateNoParkSlot);
            return false;
        }

        ULONG_PTR thunkRsp = (ep->ContextRecord->Rsp - 0x28ull) & ~static_cast<ULONG_PTR>(0x0full);
        thunkRsp |= 0x8ull;
        if (thunkRsp > (ep->ContextRecord->Rsp - 0x28ull))
        {
            thunkRsp -= 0x10ull;
        }

        __try
        {
            park->Context = *ep->ContextRecord;
            park->ThreadId = GetCurrentThreadId();
            park->InitializeRuntime = (InterlockedCompareExchange(&g_LaunchGateInitializerAssigned, 1, 0) == 0) ? 1 : 0;
            park->TrapAddress = (matchedPage != nullptr && matchedPage->TrapAddress != nullptr)
                                    ? matchedPage->TrapAddress
                                    : faultAddress;
            park->TrapPage = pageBase;
            park->TrapKind = matchedPage != nullptr ? matchedPage->TrapKind : LaunchGateTrapEntryPoint;
            park->TrapIndex = matchedPage != nullptr ? matchedPage->TrapIndex : 0;
            *reinterpret_cast<ULONG_PTR *>(thunkRsp) = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            park->State = 0;
            IxDbgLog("LaunchGateHandleFault: failed to stage park context");
            IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGateContextStageFailed, GetExceptionCode());
            return false;
        }

        ep->ContextRecord->Rsp = thunkRsp;
        ep->ContextRecord->Rip =
            reinterpret_cast<DWORD64>(park->InitializeRuntime ? &LaunchGateInitializeThunk : &LaunchGateParkThunk);
        ep->ContextRecord->Rcx = reinterpret_cast<DWORD64>(park);
        IxDbgLog("LaunchGateHandleFault: redirected park=%p slotTid=%lu init=%ld newRip=%p newRsp=%p", park,
                 (unsigned long)park->ThreadId, park->InitializeRuntime,
                 reinterpret_cast<void *>(ep->ContextRecord->Rip), reinterpret_cast<void *>(ep->ContextRecord->Rsp));
        return true;
#else
        UNREFERENCED_PARAMETER(ep);
        return false;
#endif
    }

    void LaunchGateShutdown() noexcept
    {
        LaunchGateRelease();
        if (g_LaunchGateReadyEvent != nullptr)
        {
            NativeCloseHandle(g_LaunchGateReadyEvent);
            g_LaunchGateReadyEvent = nullptr;
        }

        RestoreLaunchGatePages();
        g_LaunchGatePageCount = 0;
        g_LaunchGateInitializerAssigned = 0;
        g_LaunchGatePrepared.store(false, std::memory_order_release);
        g_LaunchGateReady.store(false, std::memory_order_release);
        g_LaunchGateDeferredOpen.store(false, std::memory_order_release);
        for (auto &park : g_LaunchGateParkContexts)
        {
            park = {};
        }
        ResetIndirectHandles();
    }

    bool LaunchGateIsPrepared() noexcept
    {
        return g_LaunchGatePrepared.load(std::memory_order_acquire);
    }
} // namespace IX_RUNTIME_INTERNAL
