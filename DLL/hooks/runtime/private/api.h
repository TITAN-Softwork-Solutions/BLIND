#pragma once

#include "types.h"

namespace IX_RUNTIME_INTERNAL
{
    inline bool NtSucceeded(NTSTATUS status) noexcept
    {
        return status >= 0;
    }

    inline HANDLE CurrentProcessHandle() noexcept
    {
        return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1));
    }

    PKH_PEB CurrentPeb() noexcept;
    bool UnicodeStringEqualsInsensitive(const KH_UNICODE_STRING &value, const wchar_t *literal) noexcept;
    const std::uint8_t *ImagePointerFromRva(const std::uint8_t *moduleBase,
                                            DWORD rva,
                                            std::size_t bytesNeeded) noexcept;
    void *FindProcessImageBase() noexcept;
    void *FindLoadedModuleBaseByName(const wchar_t *moduleName) noexcept;
    void *ResolveExportByName(void *moduleBase, const char *name) noexcept;

    template <typename T> inline T ResolveNtdllExport(const char *name) noexcept
    {
        auto ntdllName = DecodeNtdllDllName();
        HMODULE ntdll = GetModuleHandleW(ntdllName.c_str());
        if (ntdll != nullptr)
        {
            FARPROC proc = GetProcAddress(ntdll, name);
            if (proc != nullptr)
            {
                return reinterpret_cast<T>(proc);
            }
        }

        return reinterpret_cast<T>(ResolveExportByName(FindLoadedModuleBaseByName(ntdllName.c_str()), name));
    }

    bool NativeQueryMemory(void *address, MEMORY_BASIC_INFORMATION *memoryInfo) noexcept;
    bool NativeProtect(void *address, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect) noexcept;
    HANDLE NativeCreateEvent(bool manualReset,
                             bool initialState,
                             const wchar_t *name = nullptr,
                             DWORD desiredAccess = EVENT_MODIFY_STATE | SYNCHRONIZE) noexcept;
    void NativeCloseHandle(HANDLE handle) noexcept;
    bool NativeSetEvent(HANDLE handle) noexcept;
    bool NativeWaitForSingleObject(HANDLE handle) noexcept;
    void NativeDelayMs(DWORD milliseconds) noexcept;
    void NativeYield() noexcept;
    HANDLE NativeCreateThread(void *startRoutine, void *parameter) noexcept;
    [[noreturn]] void NativeTerminateCurrentProcess(DWORD exitStatus) noexcept;
    [[noreturn]] void NativeExitCurrentThread() noexcept;

    IxControlFlowPolicy QueryCurrentProcessControlFlowPolicy() noexcept;
    bool RegisterControlFlowGuardCallTarget(void *targetAddress,
                                            IxCfgCallTargetMode mode,
                                            const char *tag = nullptr) noexcept;
    void ResetControlFlowGuardPolicyCache() noexcept;

    template <typename TTrace> inline void CopyHookStack(const TTrace &trace, IXIPC_HOOK_EVENT &record) noexcept
    {
        const std::uint32_t safeCount = static_cast<std::uint32_t>(
            (trace.Count > IXIPC_MAX_HOOK_STACK_FRAMES) ? IXIPC_MAX_HOOK_STACK_FRAMES : trace.Count);
        record.StackCount = safeCount;
        for (std::uint32_t i = 0; i < safeCount; ++i)
        {
            record.Stack[i] = reinterpret_cast<std::uint64_t>(trace.Frames[i].Ip);
        }
    }

    void ResetIntegrityWatchdogState() noexcept;
    IxIhrToken RegisterIndirectHandle(
        void *pointer, std::uint64_t size, IxIhrType type, std::uint32_t flags, const char *tag) noexcept;
    bool ResolveIndirectHandle(IxIhrToken token, IxIhrType expectedType, IxIhrResolved &resolved) noexcept;
    void ReleaseIndirectHandle(IxIhrToken token) noexcept;
    void ResetIndirectHandles() noexcept;

    bool EnsureCoreHookControllersReady() noexcept;
    bool MaybeInitializeWinsockHookController() noexcept;
    std::uint32_t BuildHookReadyMask(bool ipcConnected) noexcept;
    bool InitializeIpcWithRetry() noexcept;
    bool QueryCliHookPolicyFromHost() noexcept;
    void ResetCliHookPolicy() noexcept;
    bool IsCliHookPolicyActive() noexcept;
    bool ShouldEnableNtHookControllerByPolicy() noexcept;
    bool ShouldInstallNtHookByPolicy(const char *name) noexcept;
    std::uint32_t HookMethodForNtHookByPolicy(const char *name) noexcept;
    bool ShouldEnableModuleHookControllerByPolicy() noexcept;
    bool ShouldInstallModuleHookByPolicy(const char *moduleName, const char *name) noexcept;
    std::uint32_t HookMethodForModuleHookByPolicy(const char *name) noexcept;
    bool ShouldSanitizeModuleHookStackByPolicy(const char *name) noexcept;
    bool ShouldInstallWinsockHookByPolicy(const char *name) noexcept;
    bool ShouldPublishModuleHookEvent(const char *name,
                                      void *caller,
                                      const IC_STACKTRACE::Trace *trace = nullptr) noexcept;
    bool ShouldPublishWinsockHookEvent(const char *name,
                                       void *caller,
                                       const IC_STACKTRACE::Trace *trace = nullptr) noexcept;
    bool ShouldGuardDirectSyscallPagesByPolicy() noexcept;
    bool EvaluateNtHookPolicy(const char *name, void *caller, IxNtHookPolicyDecision &decision) noexcept;
    bool NotifyHookReadyWithRetry(std::uint32_t localMask) noexcept;
    void PublishCurrentHookReadyMaskBestEffort() noexcept;
    void PublishIxSelfMapSnapshotBestEffort() noexcept;
    void SignalHookEventsPending() noexcept;
    void FlushHookEvents() noexcept;
    void PollHookIntegrityWatchdog() noexcept;
    void MaintainVectoredExceptionHandlerFront() noexcept;
    void EnsureNtdllEatGuards() noexcept;
    void ObserveLoadedModuleForNtdllEatGuard(HMODULE moduleHandle,
                                             const void *nameBuffer,
                                             std::size_t nameLength,
                                             void *caller) noexcept;
    bool RegisterDirectSyscallPage(void *pageBase,
                                   std::uint64_t pageSize,
                                   void *stubAddress,
                                   std::uint32_t syscallNumber,
                                   void *caller,
                                   const std::uint8_t *sample,
                                   std::uint32_t sampleSize,
                                   const char *sourceApi) noexcept;
    bool HandleGuardedDetectionFault(const ix::IX::Event &eventRecord, EXCEPTION_POINTERS *exceptionPointers) noexcept;
    bool HandleGuardedDetectionSingleStep(const ix::IX::Event &eventRecord,
                                          EXCEPTION_POINTERS *exceptionPointers) noexcept;
    void RearmGuardedDetections() noexcept;
    void ClearGuardedDetections() noexcept;
    void MaintainGuardedDetections() noexcept;
    void RegisterIxOwnedRanges() noexcept;
    void RegisterIxHookPatchOverlays() noexcept;
    bool RegisterIxDynamicInstrumentationRange(void *base,
                                               std::uint64_t size,
                                               std::uint32_t instrumentationFlags,
                                               const char *tag) noexcept;
    DWORD WINAPI IxRuntimeEventLoopThreadProc(LPVOID) noexcept;
    bool EnsureRuntimeWorkerThreadStarted() noexcept;
    bool EnsureRuntimeInitializedForLaunch(bool signalLaunchGateReady, bool startWorkerAfterInit) noexcept;
    bool EnsureProcessInstrumentationCallbackInstalled(bool allowInstallNow) noexcept;
    void FlushProcessInstrumentationCallbackSamples() noexcept;
    void ResetProcessInstrumentationCallbackState() noexcept;

    bool LaunchGateHandleFault(EXCEPTION_POINTERS *ep) noexcept;
    bool LaunchGateIsPrepared() noexcept;
    bool LaunchGatePrepare() noexcept;
    void LaunchGateRelease() noexcept;
    void LaunchGateShutdown() noexcept;
} // namespace IX_RUNTIME_INTERNAL
