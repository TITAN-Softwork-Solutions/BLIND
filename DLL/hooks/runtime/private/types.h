#pragma once

#include "../runtime.h"
#include "../controller.h"
#include "../encoded_literal.h"
#include "../../module/module.h"
#include "../nt.h"
#include "../ws.h"
#include "../../ipc/pipe.h"
#include "../../instrument/ix.h"
#include "../../instrument/stacktrace.h"
#include "../../include/native_peb.h"

#include <Windows.h>
#include <winternl.h>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace IX_RUNTIME_INTERNAL
{
    using IxIhrToken = std::uint64_t;

    enum class IxIhrType : std::uint32_t
    {
        Generic = 1,
        InstrumentationRange = 2,
        LaunchGatePage = 3,
        RuntimeCallback = 4,
        RuntimeState = 5,
        NtHookTarget = 6,
        NtSyscallStub = 7,
    };

    enum IxIhrFlags : std::uint32_t
    {
        kIxIhrFlagExecutable = 0x00000001u,
        kIxIhrFlagOwned = 0x00000002u,
        kIxIhrFlagGuarded = 0x00000004u,
    };

    enum class IxCfgCallTargetMode : std::uint32_t
    {
        CfgOnly = 0,
        CfgAndXfgWhenEnabled = 1,
    };

    struct IxControlFlowPolicy
    {
        bool QuerySucceeded = false;
        bool CfgEnabled = false;
        bool CfgStrictMode = false;
        bool XfgEnabled = false;
        bool XfgAuditMode = false;
        std::uint32_t Flags = 0;
        std::uint32_t LastError = 0;
    };

    struct IxIhrResolved
    {
        void *Pointer = nullptr;
        std::uint64_t Size = 0;
        std::uint32_t Flags = 0;
        std::uint32_t TagHash = 0;
    };

    using KH_UNICODE_STRING = UNICODE_STRING;
    using KH_LDR_DATA_TABLE_ENTRY = IX_LDR_DATA_TABLE_ENTRY;
    using PKH_LDR_DATA_TABLE_ENTRY = PIX_LDR_DATA_TABLE_ENTRY;
    using KH_PEB_LDR_DATA = IX_PEB_LDR_DATA;
    using PKH_PEB_LDR_DATA = PIX_PEB_LDR_DATA;
    using KH_PEB = IX_PEB;
    using PKH_PEB = PIX_PEB;
    using KH_CLIENT_ID = IX_CLIENT_ID;
    using PKH_CLIENT_ID = PIX_CLIENT_ID;

    using NtCreateThreadExFn = NTSTATUS(NTAPI *)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    using RtlCreateUserThreadFn = NTSTATUS(NTAPI *)(
        HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PKH_CLIENT_ID);
    using NtTerminateProcessFn = NTSTATUS(NTAPI *)(HANDLE, NTSTATUS);
    using RtlExitUserThreadFn = VOID(NTAPI *)(NTSTATUS);
    using RtlRestoreContextFn = VOID(WINAPI *)(PCONTEXT, PEXCEPTION_RECORD);
    using NtContinueFn = NTSTATUS(NTAPI *)(PCONTEXT, BOOLEAN);
    using NtDelayExecutionFn = NTSTATUS(NTAPI *)(BOOLEAN, PLARGE_INTEGER);
    using NtYieldExecutionFn = NTSTATUS(NTAPI *)(VOID);

    struct LaunchGateCallbacks
    {
        bool (*InitializeRuntime)(bool signalGateReady, bool startWorkerAfterInit) noexcept = nullptr;
        void (*FailClosed)(DWORD exitStatus) noexcept = nullptr;
    };

    inline constexpr DWORD kLaunchGatePageSize = 0x1000u;
    inline constexpr std::size_t kLaunchGateMaxPages = 16;
    inline constexpr std::size_t kLaunchGateMaxParkContexts = 16;
    struct LaunchGatePage
    {
        IxIhrToken BaseToken = 0;
        DWORD OriginalProtect = 0;
        void *TrapAddress = nullptr;
        std::uint32_t TrapKind = 0;
        std::uint32_t TrapIndex = 0;
    };

    struct LaunchGateParkContext
    {
        CONTEXT Context{};
        DWORD ThreadId = 0;
        LONG State = 0;
        LONG InitializeRuntime = 0;
        void *TrapAddress = nullptr;
        void *TrapPage = nullptr;
        std::uint32_t TrapKind = 0;
        std::uint32_t TrapIndex = 0;
    };

    struct ExportProbeCache
    {
        std::uint8_t Expected[16]{};
        bool ExpectedCaptured = false;
        wchar_t ModulePath[MAX_PATH]{};
    };

    struct IxNtHookPolicyDecision
    {
        bool Matched = false;
        bool Ignored = false;
        bool Log = false;
        bool StackTrace = false;
        bool Registers = false;
        bool StackFabricate = false;
        std::uint32_t Action = IXIPC_HOOK_ACTION_NONE;
        NTSTATUS Status = 0;
        IC_STACKTRACE::Trace Trace{};
    };

    inline constexpr std::uint32_t kIntegrityMaskWinsock = 0x00000001u;
    inline constexpr std::uint32_t kIntegrityMaskNt = 0x00000002u;
    inline constexpr std::uint32_t kIntegrityMaskKi = 0x00000004u;
    inline constexpr std::uint32_t kIntegrityMaskModule = 0x00000008u;
    inline constexpr std::uint32_t kIntegrityOperationHookIntegrity = IX_HOOK_EVENT_OP_HOOK_INTEGRITY;
    inline constexpr std::uint32_t kIntegrityOperationAmsiPatch = IX_HOOK_EVENT_OP_AMSI_PATCH;
    inline constexpr std::uint32_t kIntegrityOperationEtwPatch = IX_HOOK_EVENT_OP_ETW_PATCH;
    inline constexpr std::uint32_t kIntegrityOperationNtdllDoubleLoad = IX_HOOK_EVENT_OP_NTDLL_DOUBLE_LOAD;
    inline constexpr std::uint32_t kIntegrityOperationNtdllEatAccess = IX_HOOK_EVENT_OP_NTDLL_EAT_ACCESS;
    inline constexpr std::uint32_t kIntegrityOperationDirectSyscallPage = IX_HOOK_EVENT_OP_DIRECT_SYSCALL_PAGE;
    inline constexpr std::uint32_t kIntegrityOperationDirectSyscallAccess = IX_HOOK_EVENT_OP_DIRECT_SYSCALL_ACCESS;
    inline constexpr ULONGLONG kIntegrityCheckPeriodMs = 2000ull;
    inline constexpr ULONGLONG kIntegrityRepublishPeriodMs = 10000ull;
    inline constexpr ULONGLONG kPatchTamperRepublishPeriodMs = 60000ull;
    inline constexpr DWORD kIpcInitAttemptTimeoutMs = 64u;
    inline constexpr DWORD kIpcInitRetrySleepMs = 2u;
    inline constexpr DWORD kHookReadyNotifyRetrySleepMs = 1u;
    inline constexpr ULONGLONG kIpcInitMaxWaitMs = 15000ull;
    inline constexpr ULONGLONG kHookReadyNotifyMaxWaitMs = 15000ull;

    extern WinsockHookController g_WinsockController;
    extern NtHookController g_NtHookController;
    extern KiHookController g_KiHookController;
    extern ModuleHookController g_ModuleHookController;
    extern bool g_WinsockInitialized;
    extern bool g_NtInitialized;
    extern bool g_KiInitialized;
    extern bool g_ModuleInitialized;
    extern ULONGLONG g_LastIntegrityCheckTick;
    extern ULONGLONG g_LastIntegrityPublishTick;
    extern std::uint32_t g_LastIntegrityMask;
    extern std::uint64_t g_IntegrityCheckCount;
    extern ExportProbeCache g_AmsiProbe;
    extern ExportProbeCache g_EtwProbe;
    extern bool g_LastAmsiTampered;
    extern bool g_LastEtwTampered;
    extern bool g_AmsiFirstPoll;
    extern bool g_EtwFirstPoll;
    extern ULONGLONG g_LastAmsiPublishTick;
    extern ULONGLONG g_LastEtwPublishTick;
    extern std::atomic<bool> g_RuntimePrimed;
    extern std::atomic<bool> g_RuntimeInitialized;
    extern std::atomic<bool> g_RuntimeWorkerStarted;
    extern std::atomic<std::uint32_t> g_LastPublishedHookReadyMask;
    extern IxBlindTelemetryArguments g_RuntimeVehArgs;
    extern std::atomic<bool> g_LaunchGatePrepared;
    extern std::atomic<bool> g_LaunchGateReady;
    extern std::atomic<bool> g_LaunchGateDeferredOpen;
    extern HANDLE g_LaunchGateReadyEvent;
    extern LaunchGatePage g_LaunchGatePages[kLaunchGateMaxPages];
    extern LaunchGateParkContext g_LaunchGateParkContexts[kLaunchGateMaxParkContexts];
    extern std::uint32_t g_LaunchGatePageCount;
    extern LONG g_LaunchGateInitializerAssigned;
    extern LaunchGateCallbacks g_LaunchGateCallbacks;
} // namespace IX_RUNTIME_INTERNAL
