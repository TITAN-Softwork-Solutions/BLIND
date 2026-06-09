#include "runtime_internal.h"

namespace IX_RUNTIME_INTERNAL
{
    const char *DescribeNtHookInitFaultCode(NtHookInitFaultCode code) noexcept
    {
        switch (code)
        {
        case NtHookInitFaultCode::None:
            return "none";
        case NtHookInitFaultCode::NtdllMissing:
            return "ntdll-missing";
        case NtHookInitFaultCode::NtdllTextMissing:
            return "ntdll-text-missing";
        case NtHookInitFaultCode::NtdllExportDirectoryMissing:
            return "ntdll-export-dir-missing";
        case NtHookInitFaultCode::ExportMissing:
            return "export-missing";
        case NtHookInitFaultCode::ExportOutsideImage:
            return "export-outside-image";
        case NtHookInitFaultCode::ExportOutsideText:
            return "export-outside-text";
        case NtHookInitFaultCode::ExportRedirectedOutsideImage:
            return "export-redirected-outside-image";
        case NtHookInitFaultCode::UnexpectedStubBytes:
            return "unexpected-stub-bytes";
        case NtHookInitFaultCode::SyscallStubAllocFailed:
            return "syscall-stub-alloc-failed";
        case NtHookInitFaultCode::HookEntryMissing:
            return "hook-entry-missing";
        case NtHookInitFaultCode::PatchInstallFailed:
            return "patch-install-failed";
        default:
            return "unknown";
        }
    }

    const char *DescribeModuleHookInitFaultCode(ModuleHookInitFaultCode code) noexcept
    {
        switch (code)
        {
        case ModuleHookInitFaultCode::None:
            return "none";
        case ModuleHookInitFaultCode::ModuleMissing:
            return "module-missing";
        case ModuleHookInitFaultCode::ExportMissing:
            return "export-missing";
        case ModuleHookInitFaultCode::ExportOutsideImage:
            return "export-outside-image";
        case ModuleHookInitFaultCode::ExportRedirectedOutsideImage:
            return "export-redirected-outside-image";
        case ModuleHookInitFaultCode::PatchInstallFailed:
            return "patch-install-failed";
        default:
            return "unknown";
        }
    }

    void LogNtHookInitFault() noexcept
    {
        NtHookInitFault fault{};
        if (!IxGetLastNtHookInitFault(&fault))
        {
            return;
        }

        IxDbgLog("EnsureCoreHookControllersReady: NtHook fault=%s function=%s address=%p redirect=%p syscall=%lu "
                 "sample=%02X %02X %02X %02X %02X %02X %02X %02X",
                 DescribeNtHookInitFaultCode(fault.Code),
                 fault.FunctionName != nullptr ? fault.FunctionName : "",
                 fault.Address,
                 fault.RedirectTarget,
                 static_cast<unsigned long>(fault.SyscallIndex),
                 fault.Sample[0],
                 fault.Sample[1],
                 fault.Sample[2],
                 fault.Sample[3],
                 fault.Sample[4],
                 fault.Sample[5],
                 fault.Sample[6],
                 fault.Sample[7]);
        IxRuntimeReportFault(IxRuntimeFaultCode::NtHookInitFault,
                             reinterpret_cast<std::uint64_t>(fault.Address),
                             static_cast<std::uint64_t>(fault.Code));
    }

    void LogModuleHookInitFault() noexcept
    {
        ModuleHookInitFault fault{};
        if (!IxGetLastModuleHookInitFault(&fault))
        {
            return;
        }

        IxDbgLog("EnsureCoreHookControllersReady: ModuleHook fault=%s module=%ws export=%s address=%p redirect=%p "
                 "sample=%02X %02X %02X %02X %02X %02X %02X %02X",
                 DescribeModuleHookInitFaultCode(fault.Code),
                 fault.ModuleName != nullptr ? fault.ModuleName : L"",
                 fault.ExportName != nullptr ? fault.ExportName : "",
                 fault.Address,
                 fault.RedirectTarget,
                 fault.Sample[0],
                 fault.Sample[1],
                 fault.Sample[2],
                 fault.Sample[3],
                 fault.Sample[4],
                 fault.Sample[5],
                 fault.Sample[6],
                 fault.Sample[7]);
        IxRuntimeReportFault(IxRuntimeFaultCode::ModuleHookInitFault,
                             reinterpret_cast<std::uint64_t>(fault.Address),
                             static_cast<std::uint64_t>(fault.Code));
    }

    bool EnsureNtHookControllerReady() noexcept
    {
        (void)QueryCurrentProcessControlFlowPolicy();

        if (!g_NtInitialized)
        {
            __try
            {
                IxDbgLog("EnsureNtHookControllerReady: begin");
                g_NtInitialized = g_NtHookController.Initialize();
                IxDbgLog("EnsureNtHookControllerReady: NtHook=%u", g_NtInitialized ? 1u : 0u);
                if (!g_NtInitialized)
                {
                    LogNtHookInitFault();
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_NtInitialized = false;
                IxDbgLog("EnsureNtHookControllerReady: NtHook exception=0x%08lX", (unsigned long)GetExceptionCode());
            }
        }
        return g_NtInitialized;
    }

    bool EnsureKiHookControllerReady() noexcept
    {
        if (!g_KiInitialized)
        {
            __try
            {
                IxDbgLog("EnsureKiHookControllerReady: begin");
                g_KiInitialized = g_KiHookController.Initialize();
                IxDbgLog("EnsureKiHookControllerReady: KiHook=%u", g_KiInitialized ? 1u : 0u);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_KiInitialized = false;
                IxDbgLog("EnsureKiHookControllerReady: KiHook exception=0x%08lX", (unsigned long)GetExceptionCode());
            }
            if (!g_KiInitialized && !IxIsKiHookSupported())
            {
                g_KiInitialized = true;
                IxDbgLog("EnsureKiHookControllerReady: KiHook unsupported, treating as ready");
            }
        }
        return g_KiInitialized;
    }

    bool EnsureModuleHookControllerReady() noexcept
    {
#if defined(BLIND_STANDALONE)
        if (!ShouldEnableModuleHookControllerByPolicy())
        {
            g_ModuleInitialized = false;
            return true;
        }
#endif
        if (!g_ModuleInitialized)
        {
            __try
            {
                IxDbgLog("EnsureModuleHookControllerReady: begin");
                g_ModuleInitialized = g_ModuleHookController.Initialize();
                IxDbgLog("EnsureModuleHookControllerReady: ModuleHook=%u", g_ModuleInitialized ? 1u : 0u);
                if (!g_ModuleInitialized)
                {
                    LogModuleHookInitFault();
                }
                else
                {
                    EnsureNtdllEatGuards();
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_ModuleInitialized = false;
                IxDbgLog("EnsureModuleHookControllerReady: ModuleHook exception=0x%08lX",
                         (unsigned long)GetExceptionCode());
            }
        }
        return g_ModuleInitialized;
    }

    bool EnsureCoreHookControllersReady() noexcept
    {
        const bool enableNtHooks = ShouldEnableNtHookControllerByPolicy();
        const bool ntReady = enableNtHooks ? EnsureNtHookControllerReady() : true;
        const bool kiReady = enableNtHooks ? EnsureKiHookControllerReady() : true;
        const bool moduleReady = EnsureModuleHookControllerReady();

        return ntReady && kiReady && moduleReady;
    }

    static HANDLE g_RuntimeWorkEvent = nullptr;

    static HANDLE EnsureRuntimeWorkEvent() noexcept
    {
        HANDLE existing = g_RuntimeWorkEvent;
        if (existing != nullptr)
        {
            return existing;
        }

        HANDLE created = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (created == nullptr)
        {
            return nullptr;
        }

        HANDLE prior = reinterpret_cast<HANDLE>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile *>(&g_RuntimeWorkEvent), created, nullptr));
        if (prior != nullptr)
        {
            CloseHandle(created);
            return prior;
        }

        return created;
    }

    void SignalHookEventsPending() noexcept
    {
        HANDLE event = g_RuntimeWorkEvent;
        if (event != nullptr)
        {
            SetEvent(event);
        }
    }

    DWORD WINAPI IxRuntimeEventLoopThreadProc(LPVOID) noexcept
    {
        IxDbgLog("IxRuntimeEventLoopThreadProc: start");
        HANDLE workEvent = EnsureRuntimeWorkEvent();

        for (;;)
        {
            IxEnterInternalCall();
            __try
            {
                (void)EnsureCoreHookControllersReady();
                (void)MaybeInitializeWinsockHookController();
                (void)EnsureProcessInstrumentationCallbackInstalled(true);
                FlushProcessInstrumentationCallbackSamples();
                PublishCurrentHookReadyMaskBestEffort();
                FlushHookEvents();
                PollHookIntegrityWatchdog();
                MaintainVectoredExceptionHandlerFront();
                PublishIxSelfMapSnapshotBestEffort();
                RearmGuardedDetections();
                MaintainGuardedDetections();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            IxLeaveInternalCall();
            if (workEvent != nullptr)
            {
                WaitForSingleObject(workEvent, 60);
            }
            else
            {
                NativeDelayMs(60);
            }
        }

        __assume(0);
    }

    bool EnsureRuntimeWorkerThreadStarted() noexcept
    {
        bool expected = false;
        if (!g_RuntimeWorkerStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return true;
        }

        HANDLE worker = CreateThread(nullptr, 0, &IxRuntimeEventLoopThreadProc, nullptr, 0, nullptr);
        if (worker == nullptr)
        {
            g_RuntimeWorkerStarted.store(false, std::memory_order_release);
            IxDbgLog("EnsureRuntimeWorkerThreadStarted: CreateThread failed gle=%lu", (unsigned long)GetLastError());
            return false;
        }

        IxDbgLog("EnsureRuntimeWorkerThreadStarted: started handle=%p", worker);
        NativeCloseHandle(worker);
        return true;
    }

    bool EnsureRuntimeInitializedForLaunch(bool signalLaunchGateReady, bool startWorkerAfterInit) noexcept
    {
        IxInternalScope scope;
        if (g_RuntimeInitialized.load(std::memory_order_acquire))
        {
            IxDbgLog("EnsureRuntimeInitializedForLaunch: already initialized");
            if (signalLaunchGateReady)
            {
                IxRuntimeSignalLaunchGateReady();
            }
            return true;
        }

        IxDbgLog("EnsureRuntimeInitializedForLaunch: begin");
        IxRuntimePrimeHooks();

        bool ipcReady = InitializeIpcWithRetry();
        IxDbgLog("EnsureRuntimeInitializedForLaunch: ipcReady=%u", ipcReady ? 1u : 0u);
        if (!ipcReady)
        {
            return false;
        }

        constexpr std::uint32_t kTransportReadyMask = IXIPC_HOOK_READY_FLAG_IPC_CONNECTED;
        if (!NotifyHookReadyWithRetry(kTransportReadyMask))
        {
            IxDbgLog("EnsureRuntimeInitializedForLaunch: initial transport notify failed");
            IxRuntimeReportFault(IxRuntimeFaultCode::HookReadyTimedOut, kTransportReadyMask);
            return false;
        }
        g_LastPublishedHookReadyMask.store(kTransportReadyMask, std::memory_order_release);
        (void)QueryCliHookPolicyFromHost();

        const bool enableNtHooks = ShouldEnableNtHookControllerByPolicy();
        bool ntReady = enableNtHooks ? EnsureNtHookControllerReady() : true;
        bool moduleReady = true;
        if (ShouldEnableModuleHookControllerByPolicy())
        {
            moduleReady = EnsureModuleHookControllerReady();
            (void)MaybeInitializeWinsockHookController();
        }
        IxDbgLog("EnsureRuntimeInitializedForLaunch: ntReady=%u moduleReady=%u readyMask=0x%08lX",
                 ntReady ? 1u : 0u,
                 moduleReady ? 1u : 0u,
                 (unsigned long)BuildHookReadyMask(true));
        if (!ntReady || !moduleReady)
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::CoreHookInitFailed, BuildHookReadyMask(true));
            return false;
        }
        RegisterIxOwnedRanges();
        PublishIxSelfMapSnapshotBestEffort();
        if (g_ModuleInitialized)
        {
            EnsureNtdllEatGuards();
        }
        RearmGuardedDetections();
        PublishCurrentHookReadyMaskBestEffort();

        g_RuntimeInitialized.store(true, std::memory_order_release);

        if (signalLaunchGateReady)
        {
            IxRuntimeSignalLaunchGateReady();
        }

        if (startWorkerAfterInit && !EnsureRuntimeWorkerThreadStarted())
        {
            IxDbgLog("EnsureRuntimeInitializedForLaunch: worker start deferred");
        }

        return true;
    }

    bool MaybeInitializeWinsockHookController() noexcept
    {
        if (g_WinsockInitialized)
        {
            return true;
        }

        const bool networkModuleLoaded = FindLoadedModuleBaseByName(L"ws2_32.dll") != nullptr ||
                                         FindLoadedModuleBaseByName(L"wsock32.dll") != nullptr ||
                                         FindLoadedModuleBaseByName(L"dnsapi.dll") != nullptr;
        if (!networkModuleLoaded && !IxIsWinsockHookRequired())
        {
            return false;
        }

        __try
        {
            g_WinsockInitialized = g_WinsockController.Initialize();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            g_WinsockInitialized = false;
        }

        return g_WinsockInitialized;
    }

    std::uint32_t BuildHookReadyMask(bool ipcConnected) noexcept
    {
        std::uint32_t mask = 0;
        if (ipcConnected)
        {
            mask |= IXIPC_HOOK_READY_FLAG_IPC_CONNECTED;
        }
        if (g_WinsockInitialized)
        {
            mask |= IXIPC_HOOK_READY_FLAG_WINSOCK;
        }
        if (g_NtInitialized)
        {
            mask |= IXIPC_HOOK_READY_FLAG_NT;
        }
        if (g_KiInitialized)
        {
            mask |= IXIPC_HOOK_READY_FLAG_KI;
        }
        if (g_ModuleInitialized)
        {
            mask |= IXIPC_HOOK_READY_FLAG_MODULE;
        }
        return mask;
    }

    bool InitializeIpcWithRetry() noexcept
    {
        ULONGLONG startTick = GetTickCount64();
        ULONGLONG lastStatusTick = startTick;
        IxDbgLog("InitializeIpcWithRetry: begin");

        for (;;)
        {
            if (IXIPC::Initialize(kIpcInitAttemptTimeoutMs))
            {
                IxDbgLog("InitializeIpcWithRetry: success elapsedMs=%llu",
                         (unsigned long long)(GetTickCount64() - startTick));
                return true;
            }

            ULONGLONG now = GetTickCount64();
            if ((now - lastStatusTick) >= 1000ull)
            {
                IxDbgLog("InitializeIpcWithRetry: waiting elapsedMs=%llu pipeStage=%lu pipeError=%lu",
                         (unsigned long long)(now - startTick),
                         (unsigned long)IXIPC::LastConnectStage(),
                         (unsigned long)IXIPC::LastConnectError());
                lastStatusTick = now;
            }

            if ((now - startTick) >= kIpcInitMaxWaitMs)
            {
                IxDbgLog("InitializeIpcWithRetry: timeout elapsedMs=%llu pipeStage=%lu pipeError=%lu",
                         (unsigned long long)(now - startTick),
                         (unsigned long)IXIPC::LastConnectStage(),
                         (unsigned long)IXIPC::LastConnectError());
                IxRuntimeReportFault(IxRuntimeFaultCode::IpcInitializeTimedOut,
                                     static_cast<std::uint64_t>(now - startTick),
                                     static_cast<std::uint64_t>(IXIPC::LastConnectError()));
                return false;
            }

            NativeYield();
            NativeDelayMs(kIpcInitRetrySleepMs);
        }
    }

    bool NotifyHookReadyWithRetry(std::uint32_t localMask) noexcept
    {
        ULONGLONG startTick = GetTickCount64();
        if (localMask == 0)
        {
            IxDbgLog("NotifyHookReadyWithRetry: refused empty mask");
            return false;
        }

        IxDbgLog("NotifyHookReadyWithRetry: begin localMask=0x%08lX", (unsigned long)localMask);

        for (;;)
        {
            std::uint32_t observedMask = 0;
            if (IXIPC::NotifyHookReady(localMask, &observedMask))
            {
                IxDbgLog("NotifyHookReadyWithRetry: success localMask=0x%08lX observedMask=0x%08lX elapsedMs=%llu",
                         (unsigned long)localMask,
                         (unsigned long)observedMask,
                         (unsigned long long)(GetTickCount64() - startTick));
                return true;
            }

            if ((GetTickCount64() - startTick) >= kHookReadyNotifyMaxWaitMs)
            {
                IxDbgLog("NotifyHookReadyWithRetry: timeout localMask=0x%08lX elapsedMs=%llu",
                         (unsigned long)localMask,
                         (unsigned long long)(GetTickCount64() - startTick));
                IxRuntimeReportFault(IxRuntimeFaultCode::HookReadyTimedOut,
                                     localMask,
                                     static_cast<std::uint64_t>(GetTickCount64() - startTick));
                return false;
            }

            NativeYield();
            NativeDelayMs(kHookReadyNotifyRetrySleepMs);
        }
    }

    void RegisterIxHookPatchOverlays() noexcept;

    void PublishCurrentHookReadyMaskBestEffort() noexcept
    {
        const std::uint32_t localMask = BuildHookReadyMask(true);
        if (localMask == 0)
        {
            return;
        }

        const std::uint32_t publishedMask = g_LastPublishedHookReadyMask.load(std::memory_order_acquire);
        if (publishedMask == localMask)
        {
            return;
        }

        std::uint32_t observedMask = 0;
        std::uint32_t pendingCmd = 0;
        if (!IXIPC::NotifyHookReady(localMask, &observedMask, &pendingCmd))
        {
            return;
        }

        g_LastPublishedHookReadyMask.store(localMask, std::memory_order_release);
        IxDbgLog("PublishCurrentHookReadyMaskBestEffort: localMask=0x%08lX observedMask=0x%08lX pendingCmd=%lu",
                 (unsigned long)localMask,
                 (unsigned long)observedMask,
                 (unsigned long)pendingCmd);

        if (pendingCmd == IxIpcCommandUpgradeWinsockHooks)
        {
            IxDbgLog("PublishCurrentHookReadyMaskBestEffort: controller requested inline Winsock hook upgrade");
            if (IxInstallWinsockInlineHooks())
            {
                RegisterIxHookPatchOverlays();
            }
        }
    }
} // namespace IX_RUNTIME_INTERNAL
