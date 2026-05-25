#include "runtime_private.h"
#include "../instrument/stacktrace.h"

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
                 DescribeNtHookInitFaultCode(fault.Code), fault.FunctionName != nullptr ? fault.FunctionName : "",
                 fault.Address, fault.RedirectTarget, static_cast<unsigned long>(fault.SyscallIndex), fault.Sample[0],
                 fault.Sample[1], fault.Sample[2], fault.Sample[3], fault.Sample[4], fault.Sample[5], fault.Sample[6],
                 fault.Sample[7]);
        IxRuntimeReportFault(IxRuntimeFaultCode::NtHookInitFault, reinterpret_cast<std::uint64_t>(fault.Address),
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
                 DescribeModuleHookInitFaultCode(fault.Code), fault.ModuleName != nullptr ? fault.ModuleName : L"",
                 fault.ExportName != nullptr ? fault.ExportName : "", fault.Address, fault.RedirectTarget,
                 fault.Sample[0], fault.Sample[1], fault.Sample[2], fault.Sample[3], fault.Sample[4], fault.Sample[5],
                 fault.Sample[6], fault.Sample[7]);
        IxRuntimeReportFault(IxRuntimeFaultCode::ModuleHookInitFault, reinterpret_cast<std::uint64_t>(fault.Address),
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
        /*
         * BLIND is the no-driver standalone profile. The BLIND module hook
         * controller installs generic inline trampolines over loader, ETW,
         * credential, HTTP and COM exports; without the kernel-backed protection
         * layer, a copied prologue that needs relocation can crash the owned test
         * process. Keep the standalone harness on deterministic IPC/NT/Winsock
         * coverage until BLIND has a relocation-aware module hooker or a
         * pure notification-based loader sensor.
         */
        g_ModuleInitialized = false;
        return true;
#else
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
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_ModuleInitialized = false;
                IxDbgLog("EnsureModuleHookControllerReady: ModuleHook exception=0x%08lX",
                         (unsigned long)GetExceptionCode());
            }
        }
        return g_ModuleInitialized;
#endif
    }

    bool EnsureCoreHookControllersReady() noexcept
    {
        const bool ntReady = EnsureNtHookControllerReady();
        const bool kiReady = EnsureKiHookControllerReady();
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
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
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

        bool ntReady = EnsureNtHookControllerReady();
        IxDbgLog("EnsureRuntimeInitializedForLaunch: ntReady=%u readyMask=0x%08lX", ntReady ? 1u : 0u,
                 (unsigned long)BuildHookReadyMask(true));
        if (!ntReady)
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::CoreHookInitFailed, BuildHookReadyMask(true));
            return false;
        }
        RegisterIxOwnedRanges();
        PublishCurrentHookReadyMaskBestEffort();
        PublishIxSelfMapSnapshotBestEffort();

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
                         (unsigned long long)(now - startTick), (unsigned long)IXIPC::LastConnectStage(),
                         (unsigned long)IXIPC::LastConnectError());
                lastStatusTick = now;
            }

            if ((now - startTick) >= kIpcInitMaxWaitMs)
            {
                IxDbgLog("InitializeIpcWithRetry: timeout elapsedMs=%llu pipeStage=%lu pipeError=%lu",
                         (unsigned long long)(now - startTick), (unsigned long)IXIPC::LastConnectStage(),
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
                         (unsigned long)localMask, (unsigned long)observedMask,
                         (unsigned long long)(GetTickCount64() - startTick));
                return true;
            }

            if ((GetTickCount64() - startTick) >= kHookReadyNotifyMaxWaitMs)
            {
                IxDbgLog("NotifyHookReadyWithRetry: timeout localMask=0x%08lX elapsedMs=%llu", (unsigned long)localMask,
                         (unsigned long long)(GetTickCount64() - startTick));
                IxRuntimeReportFault(IxRuntimeFaultCode::HookReadyTimedOut, localMask,
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
                 (unsigned long)localMask, (unsigned long)observedMask, (unsigned long)pendingCmd);

        if (pendingCmd == IxIpcCommandUpgradeWinsockHooks)
        {
            IxDbgLog("PublishCurrentHookReadyMaskBestEffort: controller requested inline Winsock hook upgrade");
            if (IxInstallWinsockInlineHooks())
            {
                RegisterIxHookPatchOverlays();
            }
        }
    }
    static volatile LONG g_InstrumentationRangesRegistered = 0;

    static bool TryGetImageSize(void *moduleBase, std::uint64_t &imageSize) noexcept
    {
        imageSize = 0;
        if (moduleBase == nullptr)
        {
            return false;
        }

        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(moduleBase);
        __try
        {
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return false;
            }

            auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(moduleBase) +
                                                                  dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
            {
                return false;
            }

            imageSize = nt->OptionalHeader.SizeOfImage;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            imageSize = 0;
            return false;
        }
    }

    static bool PublishIxInstrumentationRange(void *base, std::uint64_t size, std::uint32_t instrumentationFlags,
                                                const char *tag) noexcept
    {
        IC_STACKTRACE::RegisterOwnExecutableRange(base, static_cast<std::size_t>(size));

        std::uint32_t ihrFlags = kIxIhrFlagOwned;
        if ((instrumentationFlags & IX_INSTRUMENTATION_FLAG_SYSCALL_STUB) != 0 ||
            (instrumentationFlags & IX_INSTRUMENTATION_FLAG_LAUNCH_GATE) != 0 ||
            (instrumentationFlags & IX_INSTRUMENTATION_FLAG_PROCESS_CALLBACK) != 0 ||
            (instrumentationFlags & IX_INSTRUMENTATION_FLAG_EXECUTABLE_HELPER) != 0)
        {
            ihrFlags |= kIxIhrFlagExecutable;
        }
        if ((instrumentationFlags & IX_INSTRUMENTATION_FLAG_LAUNCH_GATE) != 0)
        {
            ihrFlags |= kIxIhrFlagGuarded;
        }

        IxIhrToken token = RegisterIndirectHandle(base, size, IxIhrType::InstrumentationRange, ihrFlags, tag);
        IxIhrResolved resolved{};
        if (token == 0 || !ResolveIndirectHandle(token, IxIhrType::InstrumentationRange, resolved))
        {
            return false;
        }

        bool ok = IXIPC::RegisterInstrumentationRange(reinterpret_cast<UINT64>(resolved.Pointer), resolved.Size,
                                                      instrumentationFlags, tag);
        if (!ok)
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::InstrumentationRangeRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(resolved.Pointer), resolved.Size);
        }
        return ok;
    }

    bool RegisterIxDynamicInstrumentationRange(void *base, std::uint64_t size,
                                                 std::uint32_t instrumentationFlags, const char *tag) noexcept
    {
        return PublishIxInstrumentationRange(base, size, instrumentationFlags, tag);
    }

    static void BuildHookPatchTag(const char *prefix, const char *name, char tag[IX_HOOK_PATCH_TAG_CHARS]) noexcept
    {
        std::size_t p = 0;
        if (prefix != nullptr)
        {
            while (prefix[p] && p < IX_HOOK_PATCH_TAG_CHARS - 1)
            {
                tag[p] = prefix[p];
                ++p;
            }
        }
        if (name != nullptr)
        {
            std::size_t n = 0;
            while (name[n] && p < IX_HOOK_PATCH_TAG_CHARS - 1)
            {
                tag[p++] = name[n++];
            }
        }
        tag[p] = '\0';
    }

    static void PublishIxHookPatch(void *patchAddress, std::size_t patchSize, const std::uint8_t originalBytes[16],
                                     std::uint32_t flags, const char *tagPrefix, const char *hookName) noexcept
    {
        if (patchAddress == nullptr || patchSize == 0 || patchSize > IX_MAX_HOOK_PATCH_BYTES ||
            originalBytes == nullptr)
        {
            return;
        }

        char tag[IX_HOOK_PATCH_TAG_CHARS]{};
        BuildHookPatchTag(tagPrefix, hookName, tag);
        if (!IXIPC::RegisterHookPatch(reinterpret_cast<UINT64>(patchAddress), static_cast<UINT32>(patchSize),
                                      originalBytes, IX_MAX_HOOK_PATCH_BYTES, flags, tag))
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::HookPatchRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(patchAddress), static_cast<std::uint64_t>(patchSize));
        }
    }

    void RegisterIxHookPatchOverlays() noexcept
    {
        std::size_t totalCount = 0;

        constexpr std::size_t kMaxNtPatches = 64;
        NtHookPatchInfo ntPatches[kMaxNtPatches]{};
        std::size_t ntPatchCount = IxCollectNtHookPatchInfos(ntPatches, kMaxNtPatches);
        for (std::size_t i = 0; i < ntPatchCount; ++i)
        {
            PublishIxHookPatch(ntPatches[i].PatchAddress, ntPatches[i].PatchSize, ntPatches[i].OriginalBytes,
                                 IX_HOOK_PATCH_FLAG_NT_INLINE, "rt.nt.", ntPatches[i].HookName);
        }
        totalCount += ntPatchCount;

        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockPatchCount = IxCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockPatchCount; ++i)
        {
            const char *prefix =
                (winsockPatches[i].Flags == IX_HOOK_PATCH_FLAG_WINSOCK_INLINE) ? "rt.ws.inline." : "rt.ws.iat.";
            PublishIxHookPatch(winsockPatches[i].PatchAddress, winsockPatches[i].PatchSize,
                                 winsockPatches[i].OriginalBytes, winsockPatches[i].Flags, prefix,
                                 winsockPatches[i].HookName);
        }
        totalCount += winsockPatchCount;

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiPatchCount = IxCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiPatchCount; ++i)
        {
            PublishIxHookPatch(kiPatches[i].PatchAddress, kiPatches[i].PatchSize, kiPatches[i].OriginalBytes,
                                 kiPatches[i].Flags, "rt.ki.", kiPatches[i].HookName);
        }
        totalCount += kiPatchCount;

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t modulePatchCount = IxCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < modulePatchCount; ++i)
        {
            PublishIxHookPatch(modulePatches[i].PatchAddress, modulePatches[i].PatchSize,
                                 modulePatches[i].OriginalBytes, modulePatches[i].Flags, "rt.mod.",
                                 modulePatches[i].HookName);
        }
        totalCount += modulePatchCount;

        IxDbgLog("RegisterIxHookPatchOverlays: registered nt=%zu winsock=%zu ki=%zu module=%zu total=%zu",
                 ntPatchCount, winsockPatchCount, kiPatchCount, modulePatchCount, totalCount);
    }

    void RegisterIxOwnedRanges() noexcept
    {
        if (InterlockedCompareExchange(&g_InstrumentationRangesRegistered, 1, 0) != 0)
            return;

        MEMORY_BASIC_INFORMATION selfMbi{};
        void *blindBase = nullptr;
        if (VirtualQuery(reinterpret_cast<const void *>(&RegisterIxOwnedRanges), &selfMbi, sizeof(selfMbi)) ==
            sizeof(selfMbi))
        {
            blindBase = selfMbi.AllocationBase;
        }
        if (blindBase == nullptr)
        {
            auto blindName = DecodeIxDllName();
            blindBase = FindLoadedModuleBaseByName(blindName.c_str());
        }
        std::uint64_t blindImageSize = 0;
        if (TryGetImageSize(blindBase, blindImageSize))
        {
            (void)PublishIxInstrumentationRange(blindBase, blindImageSize, 0u, "rt.image");
        }

        constexpr std::size_t kMaxStubs = 64;
        NtHookStubInfo stubs[kMaxStubs]{};
        std::size_t stubCount = IxCollectNtHookStubInfos(stubs, kMaxStubs);

        for (std::size_t i = 0; i < stubCount; ++i)
        {
            if (stubs[i].StubBase == nullptr || stubs[i].StubSize == 0)
                continue;

            char tag[IX_MAX_INSTRUMENTATION_TAG]{};
            const char *prefix = "rt.ntstub.";
            std::size_t p = 0;
            while (prefix[p] && p < IX_MAX_INSTRUMENTATION_TAG - 1)
            {
                tag[p] = prefix[p];
                ++p;
            }
            if (stubs[i].HookName)
            {
                std::size_t n = 0;
                while (stubs[i].HookName[n] && p < IX_MAX_INSTRUMENTATION_TAG - 1)
                {
                    tag[p++] = stubs[i].HookName[n++];
                }
            }
            tag[p] = '\0';

            (void)PublishIxInstrumentationRange(stubs[i].StubBase, static_cast<UINT64>(stubs[i].StubSize),
                                                  IX_INSTRUMENTATION_FLAG_SYSCALL_STUB, tag);
        }

        IxDbgLog("RegisterIxOwnedRanges: registered %zu NT-hook stubs", stubCount);

        RegisterIxHookPatchOverlays();

        for (std::size_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            const LaunchGatePage &page = g_LaunchGatePages[i];
            IxIhrResolved resolved{};
            if (!ResolveIndirectHandle(page.BaseToken, IxIhrType::LaunchGatePage, resolved))
                continue;
            if (!IXIPC::RegisterInstrumentationRange(
                    reinterpret_cast<UINT64>(resolved.Pointer), resolved.Size ? resolved.Size : 4096u,
                    IX_INSTRUMENTATION_FLAG_LAUNCH_GATE, page.TrapKind == 2u ? "rt.tls" : "rt.entry"))
            {
                IxRuntimeReportFault(IxRuntimeFaultCode::InstrumentationRangeRegisterFailed,
                                     reinterpret_cast<std::uint64_t>(resolved.Pointer),
                                     resolved.Size ? resolved.Size : 4096u);
            }
        }
    }
} // namespace IX_RUNTIME_INTERNAL
