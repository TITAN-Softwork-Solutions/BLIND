#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "runtime_internal.h"

#include <intrin.h>
#include <strsafe.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <vector>

#pragma intrinsic(__readgsqword)
#pragma intrinsic(_ReturnAddress)

using namespace IX_RUNTIME_INTERNAL;

namespace
{
    std::atomic<DWORD> g_IxCallDepthTls{TLS_OUT_OF_INDEXES};

    DWORD EnsureIxInternalCallTls() noexcept
    {
        DWORD idx = g_IxCallDepthTls.load(std::memory_order_acquire);
        if (idx != TLS_OUT_OF_INDEXES)
        {
            return idx;
        }

        DWORD created = TlsAlloc();
        if (created == TLS_OUT_OF_INDEXES)
        {
            return TLS_OUT_OF_INDEXES;
        }

        DWORD expected = TLS_OUT_OF_INDEXES;
        if (!g_IxCallDepthTls.compare_exchange_strong(
                expected, created, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            TlsFree(created);
            return expected;
        }
        return created;
    }
} // namespace

bool IxIsInternalCall() noexcept
{
    DWORD idx = g_IxCallDepthTls.load(std::memory_order_acquire);
    if (idx == TLS_OUT_OF_INDEXES)
    {
        return false;
    }

    return reinterpret_cast<ULONG_PTR>(TlsGetValue(idx)) != 0;
}

void IxEnterInternalCall() noexcept
{
    DWORD idx = EnsureIxInternalCallTls();
    if (idx == TLS_OUT_OF_INDEXES)
    {
        return;
    }

    ULONG_PTR depth = reinterpret_cast<ULONG_PTR>(TlsGetValue(idx));
    if (depth != MAXULONG_PTR)
    {
        TlsSetValue(idx, reinterpret_cast<void *>(depth + 1));
    }
}

void IxLeaveInternalCall() noexcept
{
    DWORD idx = g_IxCallDepthTls.load(std::memory_order_acquire);
    if (idx == TLS_OUT_OF_INDEXES)
    {
        return;
    }

    ULONG_PTR depth = reinterpret_cast<ULONG_PTR>(TlsGetValue(idx));
    if (depth <= 1)
    {
        TlsSetValue(idx, nullptr);
        return;
    }
    TlsSetValue(idx, reinterpret_cast<void *>(depth - 1));
}

namespace
{
    static constexpr DWORD kStatusSingleStep = 0x80000004u;
    static constexpr std::uint64_t kEFlagsTrapFlag = 0x100ull;
    static constexpr ULONGLONG kVehFrontChainPromotePeriodMs = 1000ull;

    bool ShouldDeferVehTelemetry() noexcept
    {
        return IxIsInternalCall();
    }

    bool IsDebugPrintExceptionCode(DWORD code) noexcept
    {
        return code == 0x40010006u || code == 0x4001000Au;
    }

    bool IsTrapFlagOrSingleStep(const ix::IX::Event &e) noexcept
    {
        return e.exception_code == kStatusSingleStep || ((e.eflags & kEFlagsTrapFlag) != 0ull);
    }
} // namespace

void IxDbgLog(_In_z_ _Printf_format_string_ PCSTR format, ...) noexcept
{
    if (format == nullptr)
    {
        return;
    }

    char message[512]{};
    va_list args;
    va_start(args, format);
    (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), format, args);
    va_end(args);

    char line[768]{};
    const unsigned long pid = GetCurrentProcessId();
    const unsigned long tid = GetCurrentThreadId();
    const unsigned long long tick = static_cast<unsigned long long>(GetTickCount64());
    (void)StringCchPrintfA(line, RTL_NUMBER_OF(line), "[PID=%lu TID=%lu TICK=%llu] %s\n", pid, tid, tick, message);
    IxInternalScope scope;
    OutputDebugStringA(line);

    char disableFileLog[8]{};
    DWORD disableFileLogChars =
        GetEnvironmentVariableA("BLIND_DISABLE_FILE_LOG", disableFileLog, RTL_NUMBER_OF(disableFileLog));
    if (disableFileLogChars > 0 && disableFileLogChars < RTL_NUMBER_OF(disableFileLog) &&
        (lstrcmpiA(disableFileLog, "1") == 0 || lstrcmpiA(disableFileLog, "true") == 0 ||
         lstrcmpiA(disableFileLog, "yes") == 0))
    {
        return;
    }

    char programData[MAX_PATH]{};
#if defined(BLIND_STANDALONE)
    char logDir[MAX_PATH]{};
    DWORD logDirChars = GetEnvironmentVariableA("BLIND_LOG_DIR", logDir, RTL_NUMBER_OF(logDir));
    if (logDirChars == 0 || logDirChars >= RTL_NUMBER_OF(logDir))
    {
        DWORD programDataChars = GetEnvironmentVariableA("ProgramData", programData, RTL_NUMBER_OF(programData));
        if (programDataChars == 0 || programDataChars >= RTL_NUMBER_OF(programData))
        {
            (void)StringCchCopyA(programData, RTL_NUMBER_OF(programData), "C:\\ProgramData");
        }

        char rootDir[MAX_PATH]{};
        (void)StringCchPrintfA(rootDir, RTL_NUMBER_OF(rootDir), "%s\\BLIND", programData);
        (void)CreateDirectoryA(rootDir, nullptr);
        (void)StringCchPrintfA(logDir, RTL_NUMBER_OF(logDir), "%s\\logs", rootDir);
    }
    (void)CreateDirectoryA(logDir, nullptr);

    char logPath[MAX_PATH]{};
    (void)StringCchPrintfA(logPath, RTL_NUMBER_OF(logPath), "%s\\blind-runtime-%lu.log", logDir, pid);
#else
    static constexpr IxEncodedAnsiLiteral kProgramDataEnv{"ProgramData", 0x2Fu};
    {
        IxScopedAnsiLiteral programDataEnv(kProgramDataEnv);
        DWORD programDataChars =
            GetEnvironmentVariableA(programDataEnv.c_str(), programData, RTL_NUMBER_OF(programData));
        if (programDataChars == 0 || programDataChars >= RTL_NUMBER_OF(programData))
        {
            static constexpr IxEncodedAnsiLiteral kDefaultProgramData{"C:\\ProgramData", 0x39u};
            IxScopedAnsiLiteral defaultProgramData(kDefaultProgramData);
            (void)StringCchCopyA(programData, RTL_NUMBER_OF(programData), defaultProgramData.c_str());
        }
    }

    char logDir[MAX_PATH]{};
    char nodeDir[MAX_PATH]{};
    char rootDir[MAX_PATH]{};
    {
        static constexpr IxEncodedAnsiLiteral kRootFormat{"%s\\BLIND", 0x43u};
        IxScopedAnsiLiteral rootFormat(kRootFormat);
        (void)StringCchPrintfA(rootDir, RTL_NUMBER_OF(rootDir), rootFormat.c_str(), programData);
    }
    (void)CreateDirectoryA(rootDir, nullptr);
    {
        static constexpr IxEncodedAnsiLiteral kNodeFormat{"%s\\Node", 0x57u};
        IxScopedAnsiLiteral nodeFormat(kNodeFormat);
        (void)StringCchPrintfA(nodeDir, RTL_NUMBER_OF(nodeDir), nodeFormat.c_str(), rootDir);
    }
    (void)CreateDirectoryA(nodeDir, nullptr);
    {
        static constexpr IxEncodedAnsiLiteral kLogDirFormat{"%s\\logs", 0x63u};
        IxScopedAnsiLiteral logDirFormat(kLogDirFormat);
        (void)StringCchPrintfA(logDir, RTL_NUMBER_OF(logDir), logDirFormat.c_str(), nodeDir);
    }
    (void)CreateDirectoryA(logDir, nullptr);

    char logPath[MAX_PATH]{};
    {
        static constexpr IxEncodedAnsiLiteral kLogFileFormat{"%s\\blind-%lu.log", 0x7Fu};
        IxScopedAnsiLiteral logFileFormat(kLogFileFormat);
        (void)StringCchPrintfA(logPath, RTL_NUMBER_OF(logPath), logFileFormat.c_str(), logDir, pid);
    }
#endif
    HANDLE logFile = CreateFileA(logPath,
                                 FILE_APPEND_DATA,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr,
                                 OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
    if (logFile != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        (void)WriteFile(logFile, line, static_cast<DWORD>(strnlen(line, RTL_NUMBER_OF(line))), &written, nullptr);
        CloseHandle(logFile);
    }
}

void IxRuntimeReportFault(IxRuntimeFaultCode code, std::uint64_t arg0, std::uint64_t arg1) noexcept
{
    IxDbgLog("Fault code=%lu arg0=0x%llX arg1=0x%llX",
             static_cast<unsigned long>(code),
             static_cast<unsigned long long>(arg0),
             static_cast<unsigned long long>(arg1));
}

namespace IX_RUNTIME_INTERNAL
{
    namespace
    {
        inline constexpr std::uint16_t kInvalidIhrSlot = 0;
        inline constexpr std::size_t kMaxIndirectHandles = 256;

        struct IndirectHandleEntry
        {
            std::uint64_t EncodedPointer = 0;
            std::uint64_t Size = 0;
            std::uint32_t Flags = 0;
            std::uint32_t TagHash = 0;
            std::uint32_t Type = 0;
            std::uint32_t Generation = 0;
            bool Active = false;
        };

        SRWLOCK g_IndirectHandleLock = SRWLOCK_INIT;
        IndirectHandleEntry g_IndirectHandles[kMaxIndirectHandles]{};
        std::uint64_t g_IndirectHandleCookie = 0;
        volatile LONG g_IndirectHandleCookieState = 0;
        std::uint32_t g_IndirectHandleGeneration = 0x70000000u;
        inline constexpr std::size_t kIxSelfMapMaxEntries = 256;
        inline constexpr ULONGLONG kIxSelfMapScanPeriodMs = 5000ull;
        inline constexpr ULONGLONG kIxSelfMapUnchangedRepublishPeriodMs = 60000ull;

        struct IxSelfMapEntry
        {
            std::uint32_t Kind = 0;
            std::uint32_t Flags = 0;
            std::uint64_t Address = 0;
            std::uint64_t Size = 0;
            std::uint64_t Reference0 = 0;
            std::uint64_t Reference1 = 0;
            MEMORY_BASIC_INFORMATION Memory{};
            char Owner[IXIPC_MAX_HOOK_MODULE_NAME]{};
            char Name[IXIPC_MAX_HOOK_API_NAME]{};
        };
        volatile LONG g_IxSelfMapPublishing = 0;
        ULONGLONG g_LastIxSelfMapScanTick = 0;
        ULONGLONG g_LastIxSelfMapPublishTick = 0;
        std::uint64_t g_LastIxSelfMapSignature = 0;

        std::uint64_t RotateLeft64(std::uint64_t value, unsigned int bits) noexcept
        {
            bits &= 63u;
            return bits == 0 ? value : ((value << bits) | (value >> (64u - bits)));
        }

        std::uint32_t HashTag(const char *tag) noexcept
        {
            std::uint32_t hash = 2166136261u;
            if (tag == nullptr)
            {
                return hash;
            }

            while (*tag != '\0')
            {
                hash ^= static_cast<std::uint8_t>(*tag++);
                hash *= 16777619u;
            }
            return hash;
        }

        std::uint64_t BuildIndirectHandleCookie() noexcept
        {
            LARGE_INTEGER counter{};
            (void)QueryPerformanceCounter(&counter);
            std::uintptr_t localAddress = reinterpret_cast<std::uintptr_t>(&counter);
            std::uint64_t cookie = static_cast<std::uint64_t>(counter.QuadPart);
            cookie ^= (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32);
            cookie ^= static_cast<std::uint64_t>(GetCurrentThreadId());
            cookie ^= static_cast<std::uint64_t>(localAddress);
            cookie ^= __rdtsc();
            cookie = RotateLeft64(cookie, 17) ^ 0xA71C5D79B31F420Bull;
            return cookie != 0 ? cookie : 0x5D1B11D700000071ull;
        }

        std::uint64_t IndirectHandleCookie() noexcept
        {
            LONG state = InterlockedCompareExchange(&g_IndirectHandleCookieState, 0, 0);
            if (state == 2)
            {
                return g_IndirectHandleCookie;
            }

            if (state == 0 && InterlockedCompareExchange(&g_IndirectHandleCookieState, 1, 0) == 0)
            {
                g_IndirectHandleCookie = BuildIndirectHandleCookie();
                MemoryBarrier();
                InterlockedExchange(&g_IndirectHandleCookieState, 2);
                return g_IndirectHandleCookie;
            }

            for (;;)
            {
                state = InterlockedCompareExchange(&g_IndirectHandleCookieState, 0, 0);
                if (state == 2)
                {
                    return g_IndirectHandleCookie;
                }
                YieldProcessor();
            }
        }

        IxIhrToken EncodeToken(std::uint16_t slot, std::uint32_t type, std::uint32_t generation) noexcept
        {
            const std::uint64_t raw = (static_cast<std::uint64_t>(generation) << 32) |
                                      ((static_cast<std::uint64_t>(type) & 0xffffull) << 16) |
                                      static_cast<std::uint64_t>(slot);
            return raw ^ RotateLeft64(IndirectHandleCookie(), 29);
        }

        bool DecodeToken(IxIhrToken token, std::uint16_t &slot, std::uint32_t &type, std::uint32_t &generation) noexcept
        {
            if (token == 0)
            {
                return false;
            }

            const std::uint64_t raw = token ^ RotateLeft64(IndirectHandleCookie(), 29);
            slot = static_cast<std::uint16_t>(raw & 0xffffu);
            type = static_cast<std::uint32_t>((raw >> 16) & 0xffffu);
            generation = static_cast<std::uint32_t>(raw >> 32);
            return slot != kInvalidIhrSlot && slot <= kMaxIndirectHandles;
        }

        std::uint64_t EncodePointer(void *pointer, std::uint64_t size, std::uint32_t generation) noexcept
        {
            std::uint64_t value = reinterpret_cast<std::uint64_t>(pointer);
            value ^= IndirectHandleCookie();
            value ^= RotateLeft64(size, 11);
            value ^= (static_cast<std::uint64_t>(generation) << 7);
            return value;
        }

        void *DecodePointer(std::uint64_t encoded, std::uint64_t size, std::uint32_t generation) noexcept
        {
            std::uint64_t value = encoded;
            value ^= (static_cast<std::uint64_t>(generation) << 7);
            value ^= RotateLeft64(size, 11);
            value ^= IndirectHandleCookie();
            return reinterpret_cast<void *>(value);
        }

        bool IxSelfMapProtectExecutable(std::uint32_t protect) noexcept
        {
            protect &= 0xFFu;
            return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE ||
                   protect == PAGE_EXECUTE_WRITECOPY;
        }

        bool IxSelfMapProtectWritable(std::uint32_t protect) noexcept
        {
            protect &= 0xFFu;
            return protect == PAGE_READWRITE || protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_READWRITE ||
                   protect == PAGE_EXECUTE_WRITECOPY;
        }

        std::uint32_t IxSelfMapMemoryFlags(const MEMORY_BASIC_INFORMATION &memoryInfo) noexcept
        {
            std::uint32_t flags = 0;
            if (memoryInfo.State == MEM_COMMIT)
            {
                flags |= IX_SELF_MAP_FLAG_MEMORY_COMMIT;
            }
            if (memoryInfo.Type == MEM_PRIVATE)
            {
                flags |= IX_SELF_MAP_FLAG_MEMORY_PRIVATE;
            }
            else if (memoryInfo.Type == MEM_IMAGE)
            {
                flags |= IX_SELF_MAP_FLAG_MEMORY_IMAGE;
            }
            else if (memoryInfo.Type == MEM_MAPPED)
            {
                flags |= IX_SELF_MAP_FLAG_MEMORY_MAPPED;
            }
            if (IxSelfMapProtectExecutable(memoryInfo.Protect))
            {
                flags |= IX_SELF_MAP_FLAG_EXECUTABLE;
            }
            if (IxSelfMapProtectWritable(memoryInfo.Protect))
            {
                flags |= IX_SELF_MAP_FLAG_MEMORY_WRITE;
            }
            if ((memoryInfo.Protect & PAGE_GUARD) != 0)
            {
                flags |= IX_SELF_MAP_FLAG_MEMORY_GUARD;
            }
            return flags;
        }

        const char *IxSelfMapIhrTypeName(std::uint32_t type) noexcept
        {
            switch (static_cast<IxIhrType>(type))
            {
            case IxIhrType::InstrumentationRange:
                return "InstrumentationRange";
            case IxIhrType::LaunchGatePage:
                return "LaunchGatePage";
            case IxIhrType::RuntimeCallback:
                return "RuntimeCallback";
            case IxIhrType::RuntimeState:
                return "RuntimeState";
            case IxIhrType::NtHookTarget:
                return "NtHookTarget";
            case IxIhrType::NtSyscallStub:
                return "NtSyscallStub";
            case IxIhrType::Generic:
            default:
                return "Generic";
            }
        }

        void IxSelfMapHashValue(std::uint64_t &hash, std::uint64_t value) noexcept
        {
            hash ^= value;
            hash *= 1099511628211ull;
        }

        void IxSelfMapHashString(std::uint64_t &hash, const char *value) noexcept
        {
            if (value == nullptr)
            {
                return;
            }
            while (*value != '\0')
            {
                hash ^= static_cast<std::uint8_t>(*value++);
                hash *= 1099511628211ull;
            }
        }
    } // namespace

    WinsockHookController g_WinsockController;
    NtHookController g_NtHookController;
    KiHookController g_KiHookController;
    ModuleHookController g_ModuleHookController;
    bool g_WinsockInitialized = false;
    bool g_NtInitialized = false;
    bool g_KiInitialized = false;
    bool g_ModuleInitialized = false;
    ULONGLONG g_LastIntegrityCheckTick = 0;
    ULONGLONG g_LastIntegrityPublishTick = 0;
    std::uint32_t g_LastIntegrityMask = UINT32_MAX;
    std::uint64_t g_IntegrityCheckCount = 0;
    ExportProbeCache g_AmsiProbe;
    ExportProbeCache g_EtwProbe;
    bool g_LastAmsiTampered = false;
    bool g_LastEtwTampered = false;
    bool g_AmsiFirstPoll = true;
    bool g_EtwFirstPoll = true;
    ULONGLONG g_LastAmsiPublishTick = 0;
    ULONGLONG g_LastEtwPublishTick = 0;
    ULONGLONG g_LastVehPromoteTick = 0;
    std::atomic<bool> g_RuntimePrimed{false};
    std::atomic<bool> g_RuntimeInitialized{false};
    std::atomic<bool> g_RuntimeWorkerStarted{false};
    std::atomic<std::uint32_t> g_LastPublishedHookReadyMask{0};
    IxBlindTelemetryArguments g_RuntimeVehArgs{};
    std::atomic<bool> g_LaunchGatePrepared{false};
    std::atomic<bool> g_LaunchGateReady{false};
    std::atomic<bool> g_LaunchGateDeferredOpen{false};
    HANDLE g_LaunchGateReadyEvent = nullptr;
    LaunchGatePage g_LaunchGatePages[kLaunchGateMaxPages]{};
    LaunchGateParkContext g_LaunchGateParkContexts[kLaunchGateMaxParkContexts]{};
    std::uint32_t g_LaunchGatePageCount = 0;
    LONG g_LaunchGateInitializerAssigned = 0;
    LaunchGateCallbacks g_LaunchGateCallbacks{};

    IxIhrToken RegisterIndirectHandle(
        void *pointer, std::uint64_t size, IxIhrType type, std::uint32_t flags, const char *tag) noexcept
    {
        IxDbgLog("RegisterIndirectHandle: begin pointer=%p size=0x%llX type=%lu flags=0x%08lX tag=%s",
                 pointer,
                 static_cast<unsigned long long>(size),
                 static_cast<unsigned long>(type),
                 static_cast<unsigned long>(flags),
                 tag != nullptr ? tag : "<null>");
        if (pointer == nullptr)
        {
            IxDbgLog("RegisterIndirectHandle: null pointer");
            return 0;
        }

        const auto numericType = static_cast<std::uint32_t>(type);
        const std::uint32_t tagHash = HashTag(tag);
        IxDbgLog("RegisterIndirectHandle: tag hash=0x%08lX", static_cast<unsigned long>(tagHash));
        (void)IndirectHandleCookie();
        IxDbgLog("RegisterIndirectHandle: cookie ready");

        AcquireSRWLockExclusive(&g_IndirectHandleLock);
        IxDbgLog("RegisterIndirectHandle: lock acquired");

        std::size_t freeIndex = kMaxIndirectHandles;
        for (std::size_t i = 0; i < kMaxIndirectHandles; ++i)
        {
            auto &entry = g_IndirectHandles[i];
            if (!entry.Active)
            {
                if (freeIndex == kMaxIndirectHandles)
                {
                    freeIndex = i;
                }
                continue;
            }

            if (entry.Type != numericType)
            {
                continue;
            }

            if (DecodePointer(entry.EncodedPointer, entry.Size, entry.Generation) == pointer)
            {
                entry.EncodedPointer = EncodePointer(pointer, size, entry.Generation);
                entry.Size = size;
                entry.Flags = flags;
                entry.TagHash = tagHash;
                IxIhrToken token = EncodeToken(static_cast<std::uint16_t>(i + 1), numericType, entry.Generation);
                ReleaseSRWLockExclusive(&g_IndirectHandleLock);
                IxDbgLog("RegisterIndirectHandle: updated slot=%zu token=0x%llX",
                         i + 1,
                         static_cast<unsigned long long>(token));
                return token;
            }
        }

        if (freeIndex == kMaxIndirectHandles)
        {
            ReleaseSRWLockExclusive(&g_IndirectHandleLock);
            IxDbgLog("RegisterIndirectHandle: no free slot");
            return 0;
        }

        std::uint32_t generation = ++g_IndirectHandleGeneration;
        if (generation == 0)
        {
            generation = ++g_IndirectHandleGeneration;
        }

        auto &entry = g_IndirectHandles[freeIndex];
        entry.Size = size;
        entry.Flags = flags;
        entry.TagHash = tagHash;
        entry.Type = numericType;
        entry.Generation = generation;
        entry.EncodedPointer = EncodePointer(pointer, size, generation);
        entry.Active = true;

        IxIhrToken token = EncodeToken(static_cast<std::uint16_t>(freeIndex + 1), numericType, generation);
        ReleaseSRWLockExclusive(&g_IndirectHandleLock);
        IxDbgLog("RegisterIndirectHandle: created slot=%zu generation=0x%08lX token=0x%llX",
                 freeIndex + 1,
                 static_cast<unsigned long>(generation),
                 static_cast<unsigned long long>(token));
        return token;
    }

    bool ResolveIndirectHandle(IxIhrToken token, IxIhrType expectedType, IxIhrResolved &resolved) noexcept
    {
        resolved = {};
        std::uint16_t slot = 0;
        std::uint32_t type = 0;
        std::uint32_t generation = 0;
        if (!DecodeToken(token, slot, type, generation) || type != static_cast<std::uint32_t>(expectedType))
        {
            return false;
        }

        AcquireSRWLockShared(&g_IndirectHandleLock);
        const auto &entry = g_IndirectHandles[slot - 1];
        if (!entry.Active || entry.Type != type || entry.Generation != generation)
        {
            ReleaseSRWLockShared(&g_IndirectHandleLock);
            return false;
        }

        resolved.Pointer = DecodePointer(entry.EncodedPointer, entry.Size, entry.Generation);
        resolved.Size = entry.Size;
        resolved.Flags = entry.Flags;
        resolved.TagHash = entry.TagHash;
        ReleaseSRWLockShared(&g_IndirectHandleLock);
        return resolved.Pointer != nullptr;
    }

    void ReleaseIndirectHandle(IxIhrToken token) noexcept
    {
        std::uint16_t slot = 0;
        std::uint32_t type = 0;
        std::uint32_t generation = 0;
        if (!DecodeToken(token, slot, type, generation))
        {
            return;
        }

        AcquireSRWLockExclusive(&g_IndirectHandleLock);
        auto &entry = g_IndirectHandles[slot - 1];
        if (entry.Active && entry.Type == type && entry.Generation == generation)
        {
            entry = {};
        }
        ReleaseSRWLockExclusive(&g_IndirectHandleLock);
    }

    void ResetIndirectHandles() noexcept
    {
        AcquireSRWLockExclusive(&g_IndirectHandleLock);
        std::memset(g_IndirectHandles, 0, sizeof(g_IndirectHandles));
        ++g_IndirectHandleGeneration;
        ReleaseSRWLockExclusive(&g_IndirectHandleLock);
    }

    static bool AddIxSelfMapEntry(IxSelfMapEntry *entries,
                                  std::size_t capacity,
                                  std::uint32_t &count,
                                  std::uint32_t &truncated,
                                  std::uint32_t kind,
                                  const char *owner,
                                  const char *name,
                                  std::uint64_t address,
                                  std::uint64_t size,
                                  std::uint32_t flags,
                                  std::uint64_t reference0 = 0,
                                  std::uint64_t reference1 = 0) noexcept
    {
        if (entries == nullptr || capacity == 0)
        {
            return false;
        }
        if (count >= capacity)
        {
            ++truncated;
            return false;
        }

        IxSelfMapEntry &entry = entries[count++];
        entry.Kind = kind;
        entry.Flags = flags;
        entry.Address = address;
        entry.Size = size;
        entry.Reference0 = reference0;
        entry.Reference1 = reference1;
        if (owner != nullptr && owner[0] != '\0')
        {
            (void)StringCchCopyA(entry.Owner, RTL_NUMBER_OF(entry.Owner), owner);
        }
        if (name != nullptr && name[0] != '\0')
        {
            (void)StringCchCopyA(entry.Name, RTL_NUMBER_OF(entry.Name), name);
        }

        if (address != 0)
        {
            MEMORY_BASIC_INFORMATION memoryInfo{};
            if (NativeQueryMemory(reinterpret_cast<void *>(static_cast<ULONG_PTR>(address)), &memoryInfo))
            {
                entry.Memory = memoryInfo;
                entry.Flags |= IxSelfMapMemoryFlags(memoryInfo);
            }
        }
        return true;
    }

    static std::uint64_t ComputeIxSelfMapSignature(const IxSelfMapEntry *entries, std::uint32_t count) noexcept
    {
        std::uint64_t hash = 1469598103934665603ull;
        IxSelfMapHashValue(hash, count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            const IxSelfMapEntry &entry = entries[i];
            IxSelfMapHashValue(hash, entry.Kind);
            IxSelfMapHashValue(hash, entry.Flags);
            IxSelfMapHashValue(hash, entry.Address);
            IxSelfMapHashValue(hash, entry.Size);
            IxSelfMapHashValue(hash, entry.Reference0);
            IxSelfMapHashValue(hash, entry.Reference1);
            IxSelfMapHashValue(hash, reinterpret_cast<std::uint64_t>(entry.Memory.AllocationBase));
            IxSelfMapHashValue(hash, static_cast<std::uint64_t>(entry.Memory.RegionSize));
            IxSelfMapHashString(hash, entry.Owner);
            IxSelfMapHashString(hash, entry.Name);
        }
        return hash != 0 ? hash : 1ull;
    }

    static void PublishIxSelfMapEntry(const IxSelfMapEntry &entry,
                                      std::uint32_t index,
                                      std::uint32_t total,
                                      std::uint32_t truncated) noexcept
    {
        IXIPC_HOOK_EVENT record{};
        record.Kind = IxIpcHookEventIntegrity;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = GetCurrentThreadId();
        record.Operation = IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY;
        record.Caller = entry.Address;
        record.Context0 = entry.Kind;
        record.Context1 = entry.Address;
        record.Context2 = entry.Size;
        record.Context3 = entry.Flags;
        record.ArgCount = 8;
        record.Args[0] = entry.Reference0;
        record.Args[1] = entry.Reference1;
        record.Args[2] = reinterpret_cast<std::uint64_t>(entry.Memory.AllocationBase);
        record.Args[3] = static_cast<std::uint64_t>(entry.Memory.RegionSize);
        record.Args[4] =
            (static_cast<std::uint64_t>(entry.Memory.Protect) << 32) | static_cast<std::uint64_t>(entry.Memory.State);
        record.Args[5] = static_cast<std::uint64_t>(entry.Memory.Type);
        record.Args[6] = index;
        record.Args[7] = (static_cast<std::uint64_t>(total) << 32) | truncated;
        record.CallerFlags =
            ((IX_HOOK_COMPONENT_INTEGRITY << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK);
        (void)StringCchCopyA(record.ApiName, RTL_NUMBER_OF(record.ApiName), "IxSelfMap");
        (void)StringCchCopyA(
            record.ModuleName, RTL_NUMBER_OF(record.ModuleName), entry.Owner[0] != '\0' ? entry.Owner : "Runtime");

        const std::size_t sampleChars = strnlen_s(entry.Name, RTL_NUMBER_OF(entry.Name));
        if (sampleChars != 0)
        {
            const std::size_t sampleBytes = std::min<std::size_t>(sampleChars, RTL_NUMBER_OF(record.DataSample));
            CopyMemory(record.DataSample, entry.Name, sampleBytes);
            record.DataSize = static_cast<std::uint32_t>(sampleBytes);
        }
        (void)IXIPC::PublishHookEvent(record);
    }

    static void CollectIxIndirectHandleSelfMap(IxSelfMapEntry *entries,
                                               std::size_t capacity,
                                               std::uint32_t &count,
                                               std::uint32_t &truncated) noexcept
    {
        AcquireSRWLockShared(&g_IndirectHandleLock);
        for (std::size_t i = 0; i < kMaxIndirectHandles; ++i)
        {
            const IndirectHandleEntry &handle = g_IndirectHandles[i];
            if (!handle.Active)
            {
                continue;
            }

            void *pointer = DecodePointer(handle.EncodedPointer, handle.Size, handle.Generation);
            if (pointer == nullptr)
            {
                continue;
            }

            char name[IXIPC_MAX_HOOK_API_NAME]{};
            (void)StringCchPrintfA(name,
                                   RTL_NUMBER_OF(name),
                                   "ihr.%s slot=%zu tag=0x%08lX gen=0x%08lX",
                                   IxSelfMapIhrTypeName(handle.Type),
                                   i + 1,
                                   static_cast<unsigned long>(handle.TagHash),
                                   static_cast<unsigned long>(handle.Generation));
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_INDIRECT_HANDLE,
                                    "IHR",
                                    name,
                                    reinterpret_cast<std::uint64_t>(pointer),
                                    handle.Size,
                                    handle.Flags | IX_SELF_MAP_FLAG_REFERENCE,
                                    static_cast<std::uint64_t>(i + 1),
                                    (static_cast<std::uint64_t>(handle.Type) << 32) | handle.TagHash);
        }
        ReleaseSRWLockShared(&g_IndirectHandleLock);
    }

    static void CollectIxHookPatchSelfMap(IxSelfMapEntry *entries,
                                          std::size_t capacity,
                                          std::uint32_t &count,
                                          std::uint32_t &truncated) noexcept
    {
        constexpr std::size_t kMaxNtPatches = 64;
        NtHookPatchInfo ntPatches[kMaxNtPatches]{};
        std::size_t ntPatchCount = IxCollectNtHookPatchInfos(ntPatches, kMaxNtPatches);
        for (std::size_t i = 0; i < ntPatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_HOOK_PATCH,
                                    "HookPatch",
                                    ntPatches[i].HookName ? ntPatches[i].HookName : "nt",
                                    reinterpret_cast<std::uint64_t>(ntPatches[i].PatchAddress),
                                    static_cast<std::uint64_t>(ntPatches[i].PatchSize),
                                    IX_HOOK_PATCH_FLAG_NT_INLINE | IX_SELF_MAP_FLAG_GUARDED,
                                    0,
                                    IX_HOOK_PATCH_FLAG_NT_INLINE);
        }

        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockPatchCount = IxCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockPatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_HOOK_PATCH,
                                    "HookPatch",
                                    winsockPatches[i].HookName ? winsockPatches[i].HookName : "winsock",
                                    reinterpret_cast<std::uint64_t>(winsockPatches[i].PatchAddress),
                                    static_cast<std::uint64_t>(winsockPatches[i].PatchSize),
                                    winsockPatches[i].Flags | IX_SELF_MAP_FLAG_GUARDED,
                                    0,
                                    winsockPatches[i].Flags);
        }

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiPatchCount = IxCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiPatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_HOOK_PATCH,
                                    "HookPatch",
                                    kiPatches[i].HookName ? kiPatches[i].HookName : "ki",
                                    reinterpret_cast<std::uint64_t>(kiPatches[i].PatchAddress),
                                    static_cast<std::uint64_t>(kiPatches[i].PatchSize),
                                    kiPatches[i].Flags | IX_SELF_MAP_FLAG_GUARDED,
                                    0,
                                    kiPatches[i].Flags);
        }

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t modulePatchCount = IxCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < modulePatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_HOOK_PATCH,
                                    "HookPatch",
                                    modulePatches[i].HookName ? modulePatches[i].HookName : "module",
                                    reinterpret_cast<std::uint64_t>(modulePatches[i].PatchAddress),
                                    static_cast<std::uint64_t>(modulePatches[i].PatchSize),
                                    modulePatches[i].Flags | IX_SELF_MAP_FLAG_GUARDED,
                                    0,
                                    modulePatches[i].Flags);
        }
    }

    static void CollectIxRuntimeSelfMap(IxSelfMapEntry *entries,
                                        std::size_t capacity,
                                        std::uint32_t &count,
                                        std::uint32_t &truncated) noexcept
    {
        auto addRuntime = [&](const char *name,
                              const void *address,
                              std::uint64_t size,
                              std::uint32_t flags = 0,
                              std::uint64_t reference0 = 0,
                              std::uint64_t reference1 = 0) noexcept
        {
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_RUNTIME_STATE,
                                    "Runtime",
                                    name,
                                    reinterpret_cast<std::uint64_t>(address),
                                    size,
                                    flags | IX_SELF_MAP_FLAG_OWNED,
                                    reference0,
                                    reference1);
        };

        addRuntime("runtime.primed", &g_RuntimePrimed, sizeof(g_RuntimePrimed));
        addRuntime("runtime.initialized", &g_RuntimeInitialized, sizeof(g_RuntimeInitialized));
        addRuntime("runtime.workerStarted", &g_RuntimeWorkerStarted, sizeof(g_RuntimeWorkerStarted));
        addRuntime("runtime.readyMask",
                   &g_LastPublishedHookReadyMask,
                   sizeof(g_LastPublishedHookReadyMask),
                   0,
                   g_LastPublishedHookReadyMask.load(std::memory_order_acquire),
                   IXIPC_HOOK_READY_REQUIRED_MASK);
        addRuntime("runtime.vehArgs", &g_RuntimeVehArgs, sizeof(g_RuntimeVehArgs));
        addRuntime("runtime.winsockController",
                   &g_WinsockController,
                   sizeof(g_WinsockController),
                   g_WinsockInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.ntController",
                   &g_NtHookController,
                   sizeof(g_NtHookController),
                   g_NtInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.kiController",
                   &g_KiHookController,
                   sizeof(g_KiHookController),
                   g_KiInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.moduleController",
                   &g_ModuleHookController,
                   sizeof(g_ModuleHookController),
                   g_ModuleInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.indirectHandleTable",
                   &g_IndirectHandles,
                   sizeof(g_IndirectHandles),
                   IX_SELF_MAP_FLAG_GUARDED,
                   kMaxIndirectHandles,
                   g_IndirectHandleGeneration);
        addRuntime("runtime.launchGateCallbacks", &g_LaunchGateCallbacks, sizeof(g_LaunchGateCallbacks));
        addRuntime("runtime.launchGatePages",
                   &g_LaunchGatePages,
                   sizeof(g_LaunchGatePages),
                   IX_SELF_MAP_FLAG_GUARDED,
                   g_LaunchGatePageCount,
                   kLaunchGateMaxPages);
        addRuntime("runtime.launchGateParkContexts",
                   &g_LaunchGateParkContexts,
                   sizeof(g_LaunchGateParkContexts),
                   IX_SELF_MAP_FLAG_GUARDED,
                   kLaunchGateMaxParkContexts,
                   0);
        addRuntime("runtime.launchGateReadyEvent",
                   &g_LaunchGateReadyEvent,
                   sizeof(g_LaunchGateReadyEvent),
                   0,
                   reinterpret_cast<std::uint64_t>(g_LaunchGateReadyEvent),
                   0);

        for (std::size_t i = 0; i < g_LaunchGatePageCount && i < kLaunchGateMaxPages; ++i)
        {
            const LaunchGatePage &page = g_LaunchGatePages[i];
            IxIhrResolved resolved{};
            if (!ResolveIndirectHandle(page.BaseToken, IxIhrType::LaunchGatePage, resolved))
            {
                continue;
            }

            char name[IXIPC_MAX_HOOK_API_NAME]{};
            (void)StringCchPrintfA(name,
                                   RTL_NUMBER_OF(name),
                                   "launchGate.page%zu trap=0x%p kind=%lu",
                                   i,
                                   page.TrapAddress,
                                   static_cast<unsigned long>(page.TrapKind));
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_LAUNCH_GATE_PAGE,
                                    "LaunchGate",
                                    name,
                                    reinterpret_cast<std::uint64_t>(resolved.Pointer),
                                    resolved.Size ? resolved.Size : kLaunchGatePageSize,
                                    resolved.Flags | IX_SELF_MAP_FLAG_GUARDED,
                                    reinterpret_cast<std::uint64_t>(page.TrapAddress),
                                    page.TrapIndex);
        }

        for (std::size_t i = 0; i < kLaunchGateMaxParkContexts; ++i)
        {
            const LaunchGateParkContext &park = g_LaunchGateParkContexts[i];
            LONG state = park.State;
            if (state == 0 && park.ThreadId == 0 && park.TrapAddress == nullptr && park.TrapPage == nullptr)
            {
                continue;
            }

            char name[IXIPC_MAX_HOOK_API_NAME]{};
            (void)StringCchPrintfA(name,
                                   RTL_NUMBER_OF(name),
                                   "launchGate.park%zu tid=%lu state=%ld",
                                   i,
                                   static_cast<unsigned long>(park.ThreadId),
                                   static_cast<long>(state));
            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_LAUNCH_GATE_CONTEXT,
                                    "LaunchGate",
                                    name,
                                    reinterpret_cast<std::uint64_t>(&park),
                                    sizeof(park),
                                    IX_SELF_MAP_FLAG_OWNED | IX_SELF_MAP_FLAG_REFERENCE,
                                    reinterpret_cast<std::uint64_t>(park.TrapAddress),
                                    reinterpret_cast<std::uint64_t>(park.TrapPage));
        }

        constexpr std::size_t kMaxStubs = 64;
        NtHookStubInfo stubs[kMaxStubs]{};
        std::size_t stubCount = IxCollectNtHookStubInfos(stubs, kMaxStubs);
        for (std::size_t i = 0; i < stubCount; ++i)
        {
            if (stubs[i].StubBase == nullptr || stubs[i].StubSize == 0)
            {
                continue;
            }

            (void)AddIxSelfMapEntry(entries,
                                    capacity,
                                    count,
                                    truncated,
                                    IX_SELF_MAP_KIND_SYSCALL_STUB,
                                    "NtStub",
                                    stubs[i].HookName ? stubs[i].HookName : "ntStub",
                                    reinterpret_cast<std::uint64_t>(stubs[i].StubBase),
                                    static_cast<std::uint64_t>(stubs[i].StubSize),
                                    IX_SELF_MAP_FLAG_EXECUTABLE | IX_SELF_MAP_FLAG_OWNED | IX_SELF_MAP_FLAG_GUARDED,
                                    i + 1,
                                    0);
        }
    }

    void PublishIxSelfMapSnapshotBestEffort() noexcept
    {
        ULONGLONG now = GetTickCount64();
        if (g_LastIxSelfMapScanTick != 0 && (now - g_LastIxSelfMapScanTick) < kIxSelfMapScanPeriodMs)
        {
            return;
        }
        g_LastIxSelfMapScanTick = now;

        if (InterlockedCompareExchange(&g_IxSelfMapPublishing, 1, 0) != 0)
        {
            return;
        }

        IxSelfMapEntry entries[kIxSelfMapMaxEntries]{};
        std::uint32_t count = 0;
        std::uint32_t truncated = 0;
        const std::size_t normalCapacity = RTL_NUMBER_OF(entries) - 1u;

        __try
        {
            CollectIxRuntimeSelfMap(entries, normalCapacity, count, truncated);
            CollectIxIndirectHandleSelfMap(entries, normalCapacity, count, truncated);
            CollectIxHookPatchSelfMap(entries, normalCapacity, count, truncated);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ++truncated;
        }

        const std::uint64_t signature = ComputeIxSelfMapSignature(entries, count);
        const bool publish = (g_LastIxSelfMapPublishTick == 0) || (signature != g_LastIxSelfMapSignature) ||
                             ((now - g_LastIxSelfMapPublishTick) >= kIxSelfMapUnchangedRepublishPeriodMs);
        if (!publish)
        {
            InterlockedExchange(&g_IxSelfMapPublishing, 0);
            return;
        }

        char summaryName[IXIPC_MAX_HOOK_API_NAME]{};
        const std::uint32_t initMask = BuildHookReadyMask(true);
        (void)StringCchPrintfA(summaryName,
                               RTL_NUMBER_OF(summaryName),
                               "summary entries=%lu truncated=%lu ready=0x%08lX signature=0x%llX",
                               static_cast<unsigned long>(count),
                               static_cast<unsigned long>(truncated),
                               static_cast<unsigned long>(initMask),
                               static_cast<unsigned long long>(signature));
        (void)AddIxSelfMapEntry(entries,
                                RTL_NUMBER_OF(entries),
                                count,
                                truncated,
                                IX_SELF_MAP_KIND_SNAPSHOT_SUMMARY,
                                "Runtime",
                                summaryName,
                                reinterpret_cast<std::uint64_t>(&PublishIxSelfMapSnapshotBestEffort),
                                count,
                                (truncated != 0 ? IX_SELF_MAP_FLAG_TRUNCATED : 0u) | IX_SELF_MAP_FLAG_OWNED,
                                signature,
                                initMask);

        const std::uint32_t total = count;
        for (std::uint32_t i = 0; i < total; ++i)
        {
            PublishIxSelfMapEntry(entries[i], i + 1u, total, truncated);
        }

        g_LastIxSelfMapSignature = signature;
        g_LastIxSelfMapPublishTick = now;
        InterlockedExchange(&g_IxSelfMapPublishing, 0);
    }

    PKH_PEB CurrentPeb() noexcept
    {
        return IxCurrentPeb();
    }

    bool UnicodeStringEqualsInsensitive(const KH_UNICODE_STRING &value, const wchar_t *literal) noexcept
    {
        if (literal == nullptr || value.Buffer == nullptr)
        {
            return false;
        }

        std::size_t literalChars = std::wcslen(literal);
        std::size_t valueChars = static_cast<std::size_t>(value.Length / sizeof(wchar_t));
        if (literalChars != valueChars)
        {
            return false;
        }

        for (std::size_t i = 0; i < literalChars; ++i)
        {
            wchar_t left = value.Buffer[i];
            wchar_t right = literal[i];
            if (left >= L'A' && left <= L'Z')
            {
                left = static_cast<wchar_t>(left + (L'a' - L'A'));
            }
            if (right >= L'A' && right <= L'Z')
            {
                right = static_cast<wchar_t>(right + (L'a' - L'A'));
            }
            if (left != right)
            {
                return false;
            }
        }

        return true;
    }

    const std::uint8_t *ImagePointerFromRva(const std::uint8_t *moduleBase, DWORD rva, std::size_t bytesNeeded) noexcept
    {
        if (moduleBase == nullptr || rva == 0)
        {
            return nullptr;
        }

        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(moduleBase);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return nullptr;
        }

        const auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(moduleBase + static_cast<std::size_t>(dos->e_lfanew));
        if (nt == nullptr || nt->Signature != IMAGE_NT_SIGNATURE)
        {
            return nullptr;
        }

        const auto *section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            DWORD sectionRva = section->VirtualAddress;
            DWORD sectionSize = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
            if (rva >= sectionRva && rva < (sectionRva + sectionSize))
            {
                std::size_t offset = static_cast<std::size_t>(rva - sectionRva);
                if (offset + bytesNeeded > sectionSize)
                {
                    return nullptr;
                }
                return moduleBase + sectionRva + offset;
            }
        }

        return moduleBase + rva;
    }

    void *FindProcessImageBase() noexcept
    {
        HMODULE module = GetModuleHandleW(nullptr);
        if (module != nullptr)
        {
            return module;
        }

        PKH_PEB peb = CurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr)
        {
            return (peb != nullptr) ? peb->ImageBaseAddress : nullptr;
        }

        if (peb->ImageBaseAddress != nullptr)
        {
            return peb->ImageBaseAddress;
        }

        LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
        if (head->Flink == nullptr || head->Flink == head)
        {
            return nullptr;
        }

        auto *entry = CONTAINING_RECORD(head->Flink, KH_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        return entry->DllBase;
    }

    void *FindLoadedModuleBaseByName(const wchar_t *moduleName) noexcept
    {
        PKH_PEB peb = CurrentPeb();
        if (moduleName == nullptr || peb == nullptr || peb->Ldr == nullptr)
        {
            return nullptr;
        }

        LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
        for (LIST_ENTRY *cursor = head->Flink; cursor != nullptr && cursor != head; cursor = cursor->Flink)
        {
            auto *entry = CONTAINING_RECORD(cursor, KH_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (UnicodeStringEqualsInsensitive(entry->BaseDllName, moduleName))
            {
                return entry->DllBase;
            }
        }

        return nullptr;
    }

    void *ResolveExportByName(void *moduleBase, const char *name) noexcept
    {
        if (moduleBase == nullptr || name == nullptr || name[0] == '\0')
        {
            return nullptr;
        }

        const auto *base = static_cast<const std::uint8_t *>(moduleBase);
        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return nullptr;
        }

        const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + static_cast<std::size_t>(dos->e_lfanew));
        if (nt == nullptr || nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return nullptr;
        }

        const IMAGE_DATA_DIRECTORY &exportDirEntry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        {
            return nullptr;
        }

        const auto *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(
            ImagePointerFromRva(base, exportDirEntry.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)));
        if (exportDir == nullptr)
        {
            return nullptr;
        }

        const auto *nameRvAs = reinterpret_cast<const DWORD *>(
            ImagePointerFromRva(base, exportDir->AddressOfNames, exportDir->NumberOfNames * sizeof(DWORD)));
        const auto *ordinals = reinterpret_cast<const WORD *>(
            ImagePointerFromRva(base, exportDir->AddressOfNameOrdinals, exportDir->NumberOfNames * sizeof(WORD)));
        const auto *functions = reinterpret_cast<const DWORD *>(
            ImagePointerFromRva(base, exportDir->AddressOfFunctions, exportDir->NumberOfFunctions * sizeof(DWORD)));
        if (nameRvAs == nullptr || ordinals == nullptr || functions == nullptr)
        {
            return nullptr;
        }

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
        {
            const char *exportName =
                reinterpret_cast<const char *>(ImagePointerFromRva(base, nameRvAs[i], std::strlen(name) + 1));
            if (exportName == nullptr || std::strcmp(exportName, name) != 0)
            {
                continue;
            }

            WORD ordinal = ordinals[i];
            if (ordinal >= exportDir->NumberOfFunctions)
            {
                return nullptr;
            }

            return const_cast<std::uint8_t *>(base) + functions[ordinal];
        }

        return nullptr;
    }

    bool NativeQueryMemory(void *address, MEMORY_BASIC_INFORMATION *memoryInfo) noexcept
    {
        if (memoryInfo == nullptr)
        {
            return false;
        }
        return VirtualQuery(address, memoryInfo, sizeof(*memoryInfo)) == sizeof(*memoryInfo);
    }

    bool NativeProtect(void *address, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect) noexcept
    {
        if (address == nullptr || regionSize == 0 || oldProtect == nullptr)
        {
            return false;
        }

        DWORD previous = 0;
        if (!VirtualProtect(address, regionSize, newProtect, &previous))
        {
            return false;
        }

        *oldProtect = previous;
        return true;
    }

    namespace
    {
        enum class GuardedDetectionKind : std::uint32_t
        {
            OriginalNtdllEat = 1,
            DoubleLoadedNtdllEat = 2,
            DirectSyscallPage = 3,
        };

        struct GuardedDetectionRange
        {
            bool Active = false;
            bool GuardArmed = false;
            GuardedDetectionKind Kind = GuardedDetectionKind::OriginalNtdllEat;
            void *ModuleBase = nullptr;
            void *GuardBase = nullptr;
            SIZE_T GuardSize = 0;
            void *ExportBase = nullptr;
            SIZE_T ExportSize = 0;
            std::uint32_t ExportFunctionCount = 0;
            std::uint32_t NtZwSlotCount = 0;
            std::uint64_t NtZwSlotBits[64]{};
            ULONG BaseProtect = 0;
            void *StubAddress = nullptr;
            std::uint32_t SyscallNumber = 0xFFFFFFFFu;
            void *CreatorCaller = nullptr;
            std::uint32_t HitCount = 0;
            std::uint32_t SampleSize = 0;
            ULONGLONG LastPublishedTick = 0;
            char SourceApi[IXIPC_MAX_HOOK_MODULE_NAME]{};
            char Label[IXIPC_MAX_HOOK_API_NAME]{};
            std::uint8_t Sample[IXIPC_MAX_HOOK_DATA_SAMPLE]{};
        };

        struct GuardRearmEntry
        {
            bool Active = false;
            DWORD ThreadId = 0;
            void *GuardBase = nullptr;
            SIZE_T GuardSize = 0;
            ULONG BaseProtect = 0;
        };

        constexpr std::size_t kMaxGuardedDetectionRanges = 96;
        constexpr std::size_t kMaxGuardRearmEntries = 64;
        constexpr SIZE_T kMaxGuardSpanBytes = 256 * 1024;
        constexpr std::uint32_t kMaxTrackedEatSlots = 4096;
        SRWLOCK g_GuardedDetectionLock = SRWLOCK_INIT;
        GuardedDetectionRange g_GuardedDetectionRanges[kMaxGuardedDetectionRanges]{};
        GuardRearmEntry g_GuardRearmEntries[kMaxGuardRearmEntries]{};
        ULONGLONG g_LastGuardMaintainTick = 0;
        std::uintptr_t g_ProcessImageBase = 0;
        std::uintptr_t g_ProcessImageEnd = 0;

        SIZE_T RuntimePageSize() noexcept
        {
            static SIZE_T pageSize = 0;
            if (pageSize != 0)
            {
                return pageSize;
            }

            SYSTEM_INFO info{};
            GetSystemInfo(&info);
            pageSize = info.dwPageSize != 0 ? info.dwPageSize : 0x1000u;
            return pageSize;
        }

        std::uintptr_t AlignDown(std::uintptr_t value, SIZE_T alignment) noexcept
        {
            return value & ~(static_cast<std::uintptr_t>(alignment) - 1u);
        }

        std::uintptr_t AlignUp(std::uintptr_t value, SIZE_T alignment) noexcept
        {
            return AlignDown(value + static_cast<std::uintptr_t>(alignment) - 1u, alignment);
        }

        bool IsGuardableProtect(ULONG protect) noexcept
        {
            ULONG baseProtect = protect & 0xFFu;
            return baseProtect != 0 && baseProtect != PAGE_NOACCESS;
        }

        const wchar_t *WideBaseName(const wchar_t *path) noexcept
        {
            if (path == nullptr)
            {
                return L"";
            }

            const wchar_t *lastSlash = wcsrchr(path, L'\\');
            const wchar_t *lastAltSlash = wcsrchr(path, L'/');
            const wchar_t *base = lastSlash;
            if (lastAltSlash != nullptr && (base == nullptr || lastAltSlash > base))
            {
                base = lastAltSlash;
            }
            return base != nullptr ? base + 1 : path;
        }

        bool WideContainsInsensitiveBounded(const wchar_t *value, std::size_t chars, const wchar_t *needle) noexcept
        {
            if (value == nullptr || needle == nullptr || chars == 0)
            {
                return false;
            }

            const std::size_t needleLen = wcslen(needle);
            if (needleLen == 0 || needleLen > chars)
            {
                return false;
            }

            for (std::size_t i = 0; i + needleLen <= chars; ++i)
            {
                if (_wcsnicmp(value + i, needle, needleLen) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        bool RequestedNameLooksLikeNtdll(const void *nameBuffer, std::size_t nameLength) noexcept
        {
            if (nameBuffer == nullptr || nameLength == 0)
            {
                return false;
            }

            const auto *wide = static_cast<const wchar_t *>(nameBuffer);
            std::size_t chars = nameLength / sizeof(wchar_t);
            if (chars == 0)
            {
                return false;
            }
            if (chars > 512)
            {
                chars = 512;
            }
            return WideContainsInsensitiveBounded(wide, chars, L"ntdll.dll") ||
                   WideContainsInsensitiveBounded(wide, chars, L"ntdll");
        }

        bool TryReadPeImageSize(const std::uint8_t *base, std::uintptr_t *imageSize) noexcept
        {
            if (base == nullptr || imageSize == nullptr)
            {
                return false;
            }

            *imageSize = 0;
            __try
            {
                const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                {
                    return false;
                }

                const auto *nt =
                    reinterpret_cast<const IMAGE_NT_HEADERS *>(base + static_cast<std::size_t>(dos->e_lfanew));
                if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
                {
                    return false;
                }

                *imageSize = static_cast<std::uintptr_t>(nt->OptionalHeader.SizeOfImage);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                *imageSize = 0;
                return false;
            }
        }

        void EnsureProcessImageRange() noexcept
        {
            if (g_ProcessImageBase != 0 && g_ProcessImageEnd > g_ProcessImageBase)
            {
                return;
            }

            HMODULE image = GetModuleHandleW(nullptr);
            std::uintptr_t imageSize = 0;
            if (image == nullptr || !TryReadPeImageSize(reinterpret_cast<const std::uint8_t *>(image), &imageSize) ||
                imageSize == 0)
            {
                return;
            }

            g_ProcessImageBase = reinterpret_cast<std::uintptr_t>(image);
            g_ProcessImageEnd = g_ProcessImageBase + imageSize;
        }

        bool AddressInProcessImage(std::uint64_t address) noexcept
        {
            return address != 0 && g_ProcessImageBase != 0 && g_ProcessImageEnd > g_ProcessImageBase &&
                   address >= g_ProcessImageBase && address < g_ProcessImageEnd;
        }

        bool IsExecutableProtectValue(ULONG protect) noexcept
        {
            ULONG baseProtect = protect & 0xFFu;
            return baseProtect == PAGE_EXECUTE || baseProtect == PAGE_EXECUTE_READ ||
                   baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsExecutablePrivateAddress(std::uint64_t address) noexcept
        {
            if (address == 0)
            {
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!NativeQueryMemory(reinterpret_cast<void *>(static_cast<ULONG_PTR>(address)), &mbi) ||
                mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE)
            {
                return false;
            }
            return IsExecutableProtectValue(mbi.Protect);
        }

        bool StackHasImageOrPrivateOrigin(const ix::IX::Event &eventRecord) noexcept
        {
            if (AddressInProcessImage(reinterpret_cast<std::uint64_t>(eventRecord.exception_address)))
            {
                return true;
            }
#if defined(_M_X64)
            if (AddressInProcessImage(eventRecord.rip))
            {
                return true;
            }
#endif

            std::uint16_t count = eventRecord.stack_frame_count;
            if (count > ix::IX::kMaxStackFrames)
            {
                count = static_cast<std::uint16_t>(ix::IX::kMaxStackFrames);
            }

            for (std::uint16_t i = 0; i < count; ++i)
            {
                std::uint64_t frame = reinterpret_cast<std::uint64_t>(eventRecord.stack[i]);
                if (AddressInProcessImage(frame) || IsExecutablePrivateAddress(frame))
                {
                    return true;
                }
            }
            return false;
        }

        bool FaultingInstructionHasImageOrPrivateOrigin(const ix::IX::Event &eventRecord) noexcept
        {
            if (AddressInProcessImage(reinterpret_cast<std::uint64_t>(eventRecord.exception_address)) ||
                IsExecutablePrivateAddress(reinterpret_cast<std::uint64_t>(eventRecord.exception_address)))
            {
                return true;
            }
#if defined(_M_X64)
            return AddressInProcessImage(eventRecord.rip) || IsExecutablePrivateAddress(eventRecord.rip);
#else
            return false;
#endif
        }

        void SetNtZwSlotBit(std::uint64_t (&bits)[64], std::uint32_t slot) noexcept
        {
            if (slot >= kMaxTrackedEatSlots)
            {
                return;
            }
            bits[slot / 64u] |= (1ull << (slot % 64u));
        }

        bool TestNtZwSlotBit(const std::uint64_t (&bits)[64], std::uint32_t slot) noexcept
        {
            if (slot >= kMaxTrackedEatSlots)
            {
                return false;
            }
            return (bits[slot / 64u] & (1ull << (slot % 64u))) != 0;
        }

        bool ExportNameLooksLikeNtZw(const char *name) noexcept
        {
            if (name == nullptr)
            {
                return false;
            }
            return (name[0] == 'N' && name[1] == 't') || (name[0] == 'Z' && name[1] == 'w');
        }

        bool FaultHitsNtZwEatSlot(const GuardedDetectionRange &range, std::uint64_t faultAddress) noexcept
        {
            if (range.ExportBase == nullptr || range.ExportSize < sizeof(DWORD) || faultAddress == 0)
            {
                return false;
            }

            const std::uint64_t eatStart = reinterpret_cast<std::uint64_t>(range.ExportBase);
            const std::uint64_t eatEnd = eatStart + static_cast<std::uint64_t>(range.ExportSize);
            if (eatEnd <= eatStart || faultAddress < eatStart || faultAddress >= eatEnd)
            {
                return false;
            }

            const std::uint64_t offset = faultAddress - eatStart;
            const std::uint32_t slot = static_cast<std::uint32_t>(offset / sizeof(DWORD));
            return TestNtZwSlotBit(range.NtZwSlotBits, slot);
        }

        bool GuardPageHasNtZwEatSlot(const GuardedDetectionRange &range,
                                     std::uintptr_t guardBase,
                                     SIZE_T guardSize) noexcept
        {
            if (range.ExportBase == nullptr || range.ExportSize == 0 || guardSize == 0)
            {
                return false;
            }

            const std::uintptr_t eatStart = reinterpret_cast<std::uintptr_t>(range.ExportBase);
            const std::uintptr_t eatEnd = eatStart + static_cast<std::uintptr_t>(range.ExportSize);
            const std::uintptr_t guardEnd = guardBase + static_cast<std::uintptr_t>(guardSize);
            if (eatEnd <= eatStart || guardEnd <= guardBase || guardBase >= eatEnd || guardEnd <= eatStart)
            {
                return false;
            }

            std::uintptr_t first = guardBase > eatStart ? guardBase : eatStart;
            std::uintptr_t last = guardEnd < eatEnd ? guardEnd : eatEnd;
            std::uint32_t firstSlot = static_cast<std::uint32_t>((first - eatStart) / sizeof(DWORD));
            std::uint32_t lastSlot = static_cast<std::uint32_t>((last - eatStart + sizeof(DWORD) - 1) / sizeof(DWORD));
            if (lastSlot > range.ExportFunctionCount)
            {
                lastSlot = range.ExportFunctionCount;
            }

            for (std::uint32_t slot = firstSlot; slot < lastSlot; ++slot)
            {
                if (TestNtZwSlotBit(range.NtZwSlotBits, slot))
                {
                    return true;
                }
            }
            return false;
        }

        bool ResolveExportDirectoryRange(HMODULE moduleHandle, GuardedDetectionRange &range) noexcept
        {
            if (moduleHandle == nullptr)
            {
                return false;
            }

            const auto *base = reinterpret_cast<const std::uint8_t *>(moduleHandle);
            __try
            {
                const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
                if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                {
                    return false;
                }

                const auto *nt =
                    reinterpret_cast<const IMAGE_NT_HEADERS *>(base + static_cast<std::size_t>(dos->e_lfanew));
                if (nt == nullptr || nt->Signature != IMAGE_NT_SIGNATURE ||
                    nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
                {
                    return false;
                }

                const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
                    dir.Size > kMaxGuardSpanBytes)
                {
                    return false;
                }

                const auto *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + dir.VirtualAddress);
                if (exportDir->AddressOfFunctions == 0 || exportDir->NumberOfFunctions == 0 ||
                    exportDir->NumberOfFunctions > kMaxTrackedEatSlots || exportDir->AddressOfNames == 0 ||
                    exportDir->AddressOfNameOrdinals == 0)
                {
                    return false;
                }

                const std::uint64_t tableSize64 =
                    static_cast<std::uint64_t>(exportDir->NumberOfFunctions) * sizeof(DWORD);
                const std::uint64_t tableEnd64 =
                    static_cast<std::uint64_t>(exportDir->AddressOfFunctions) + tableSize64;
                const std::uint64_t namesSize64 = static_cast<std::uint64_t>(exportDir->NumberOfNames) * sizeof(DWORD);
                const std::uint64_t namesEnd64 = static_cast<std::uint64_t>(exportDir->AddressOfNames) + namesSize64;
                const std::uint64_t ordinalsSize64 =
                    static_cast<std::uint64_t>(exportDir->NumberOfNames) * sizeof(WORD);
                const std::uint64_t ordinalsEnd64 =
                    static_cast<std::uint64_t>(exportDir->AddressOfNameOrdinals) + ordinalsSize64;
                const std::uint64_t imageSize = static_cast<std::uint64_t>(nt->OptionalHeader.SizeOfImage);
                if (tableSize64 == 0 || tableSize64 > kMaxGuardSpanBytes || tableEnd64 > imageSize ||
                    namesEnd64 > imageSize || ordinalsEnd64 > imageSize)
                {
                    return false;
                }

                auto *functions = reinterpret_cast<const DWORD *>(base + exportDir->AddressOfFunctions);
                auto *names = reinterpret_cast<const DWORD *>(base + exportDir->AddressOfNames);
                auto *ordinals = reinterpret_cast<const WORD *>(base + exportDir->AddressOfNameOrdinals);

                std::uint64_t bits[64]{};
                std::uint32_t ntZwSlots = 0;
                for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
                {
                    DWORD nameRva = names[i];
                    if (nameRva == 0 || nameRva >= imageSize)
                    {
                        continue;
                    }

                    const char *name = reinterpret_cast<const char *>(base + nameRva);
                    if (!ExportNameLooksLikeNtZw(name))
                    {
                        continue;
                    }

                    WORD ordinal = ordinals[i];
                    if (ordinal >= exportDir->NumberOfFunctions)
                    {
                        continue;
                    }

                    (void)functions[ordinal];
                    SetNtZwSlotBit(bits, ordinal);
                    ++ntZwSlots;
                }

                if (ntZwSlots == 0)
                {
                    return false;
                }

                void *candidate = const_cast<std::uint8_t *>(base) + exportDir->AddressOfFunctions;
                MEMORY_BASIC_INFORMATION mbi{};
                if (!NativeQueryMemory(candidate, &mbi) || mbi.State != MEM_COMMIT)
                {
                    return false;
                }

                range.ExportBase = candidate;
                range.ExportSize = static_cast<SIZE_T>(tableSize64);
                range.ExportFunctionCount = exportDir->NumberOfFunctions;
                range.NtZwSlotCount = ntZwSlots;
                std::memcpy(range.NtZwSlotBits, bits, sizeof(range.NtZwSlotBits));
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool IsAddressInBlindModule(void *address) noexcept
        {
            if (address == nullptr)
            {
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!NativeQueryMemory(address, &mbi) || mbi.AllocationBase == nullptr)
            {
                return false;
            }

            wchar_t path[MAX_PATH]{};
            DWORD chars = GetModuleFileNameW(static_cast<HMODULE>(mbi.AllocationBase), path, RTL_NUMBER_OF(path));
            if (chars == 0 || chars >= RTL_NUMBER_OF(path))
            {
                return false;
            }

            return _wcsicmp(WideBaseName(path), L"BLIND.dll") == 0;
        }

        bool CopyMemorySample(const void *address,
                              std::uint8_t *sample,
                              std::uint32_t *sampleSize,
                              std::uint32_t maxSample) noexcept
        {
            if (sample == nullptr || sampleSize == nullptr || maxSample == 0)
            {
                return false;
            }
            *sampleSize = 0;
            if (address == nullptr)
            {
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!NativeQueryMemory(const_cast<void *>(address), &mbi) || mbi.State != MEM_COMMIT ||
                !IsGuardableProtect(mbi.Protect) || (mbi.Protect & PAGE_GUARD) != 0)
            {
                return false;
            }

            auto start = reinterpret_cast<std::uintptr_t>(address);
            auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            std::size_t readable = static_cast<std::size_t>(regionEnd > start ? regionEnd - start : 0);
            readable = std::min<std::size_t>(readable, maxSample);
            if (readable == 0)
            {
                return false;
            }

            __try
            {
                std::memcpy(sample, address, readable);
                *sampleSize = static_cast<std::uint32_t>(readable);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                *sampleSize = 0;
                return false;
            }
        }

        bool ApplyGuardToRange(void *guardBase, SIZE_T guardSize, ULONG *baseProtect) noexcept
        {
            if (guardBase == nullptr || guardSize == 0 || baseProtect == nullptr)
            {
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!NativeQueryMemory(guardBase, &mbi) || mbi.State != MEM_COMMIT || !IsGuardableProtect(mbi.Protect))
            {
                return false;
            }

            ULONG current = mbi.Protect;
            if ((current & PAGE_GUARD) != 0)
            {
                *baseProtect = current & ~static_cast<ULONG>(PAGE_GUARD);
                return true;
            }

            ULONG oldProtect = 0;
            IxInternalScope scope;
            if (!NativeProtect(
                    guardBase, guardSize, (current & ~static_cast<ULONG>(PAGE_GUARD)) | PAGE_GUARD, &oldProtect))
            {
                return false;
            }

            *baseProtect = oldProtect & ~static_cast<ULONG>(PAGE_GUARD);
            return true;
        }

        void CopyEventStackFromVeh(const ix::IX::Event &eventRecord, IXIPC_HOOK_EVENT &record) noexcept
        {
            record.StackCount = static_cast<UINT32>(eventRecord.stack_frame_count > IXIPC_MAX_HOOK_STACK_FRAMES
                                                        ? IXIPC_MAX_HOOK_STACK_FRAMES
                                                        : eventRecord.stack_frame_count);
            for (UINT32 i = 0; i < record.StackCount; ++i)
            {
                record.Stack[i] = reinterpret_cast<UINT64>(eventRecord.stack[i]);
            }
        }

        void CopyEventStackFromTrace(const IC_STACKTRACE::Trace &trace, IXIPC_HOOK_EVENT &record) noexcept
        {
            CopyHookStack(trace, record);
        }

        bool PublishNtdllDoubleLoadEvent(const GuardedDetectionRange &range, const wchar_t *path, void *caller) noexcept
        {
            IXIPC_HOOK_EVENT record{};
            record.Kind = IxIpcHookEventIntegrity;
            record.ProcessId = GetCurrentProcessId();
            record.ThreadId = GetCurrentThreadId();
            record.Operation = kIntegrityOperationNtdllDoubleLoad;
            record.Caller = reinterpret_cast<UINT64>(caller);
            record.Context0 = reinterpret_cast<UINT64>(range.ModuleBase);
            record.Context1 = reinterpret_cast<UINT64>(range.ExportBase);
            record.Context2 = reinterpret_cast<UINT64>(range.GuardBase);
            record.Context3 = static_cast<UINT64>(range.GuardSize);
            record.ArgCount = 3;
            record.Args[0] = static_cast<UINT64>(range.ExportSize);
            record.Args[1] = reinterpret_cast<UINT64>(range.CreatorCaller);
            record.Args[2] = static_cast<UINT64>(GetTickCount64());
            record.CallerFlags =
                ((IX_HOOK_COMPONENT_INTEGRITY << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK);
            (void)strncpy_s(record.ApiName, "NtdllDoubleLoad", _TRUNCATE);
            (void)strncpy_s(record.ModuleName, "ntdll", _TRUNCATE);
            if (path != nullptr && path[0] != L'\0')
            {
                int bytes = WideCharToMultiByte(CP_UTF8,
                                                0,
                                                path,
                                                -1,
                                                reinterpret_cast<char *>(record.DataSample),
                                                RTL_NUMBER_OF(record.DataSample),
                                                nullptr,
                                                nullptr);
                if (bytes > 0)
                {
                    record.DataSize = static_cast<UINT32>(bytes - 1);
                }
            }

            IC_STACKTRACE::Trace trace{};
            (void)IC_STACKTRACE::Capture(trace, 1);
            CopyEventStackFromTrace(trace, record);
            return IXIPC::PublishHookEvent(record);
        }

        bool PublishNtdllEatAccessEvent(const GuardedDetectionRange &range,
                                        const ix::IX::Event &eventRecord,
                                        std::uint64_t faultAddress,
                                        std::uint64_t accessKind) noexcept
        {
            IXIPC_HOOK_EVENT record{};
            record.Kind = IxIpcHookEventIntegrity;
            record.ProcessId = eventRecord.pid;
            record.ThreadId = eventRecord.tid;
            record.Operation = kIntegrityOperationNtdllEatAccess;
            record.Caller = reinterpret_cast<UINT64>(eventRecord.exception_address);
            record.Context0 = reinterpret_cast<UINT64>(range.ModuleBase);
            record.Context1 = reinterpret_cast<UINT64>(range.ExportBase);
            record.Context2 = faultAddress;
#if defined(_M_X64)
            record.Context3 = eventRecord.rip;
#else
            record.Context3 = reinterpret_cast<UINT64>(eventRecord.exception_address);
#endif
            record.ArgCount = 7;
            record.Args[0] = static_cast<UINT64>(range.Kind);
            record.Args[1] = reinterpret_cast<UINT64>(range.GuardBase);
            record.Args[2] = static_cast<UINT64>(range.GuardSize);
            record.Args[3] = accessKind;
            record.Args[4] = range.HitCount;
            record.Args[5] = static_cast<UINT64>(range.ExportSize);
            record.Args[6] = static_cast<UINT64>(GetTickCount64());
            record.CallerFlags =
                ((IX_HOOK_COMPONENT_INTEGRITY << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK);
            (void)strncpy_s(record.ApiName, "NtdllEatAccess", _TRUNCATE);
            (void)strncpy_s(record.ModuleName, "ntdll", _TRUNCATE);
            const char *label = range.Kind == GuardedDetectionKind::DoubleLoadedNtdllEat
                                    ? "double-loaded-ntdll-export-table"
                                    : "original-ntdll-export-table";
            (void)strncpy_s(
                reinterpret_cast<char *>(record.DataSample), RTL_NUMBER_OF(record.DataSample), label, _TRUNCATE);
            record.DataSize = static_cast<UINT32>(
                strnlen_s(reinterpret_cast<char *>(record.DataSample), RTL_NUMBER_OF(record.DataSample)));
            CopyEventStackFromVeh(eventRecord, record);
            return IXIPC::PublishHookEvent(record);
        }

        void DumpDirectSyscallPage(const void *pageBase,
                                   SIZE_T pageSize,
                                   const void *stubAddress,
                                   std::uint32_t syscallNumber,
                                   const char *sourceApi) noexcept
        {
            char logDir[MAX_PATH]{};
            DWORD chars = GetEnvironmentVariableA("BLIND_LOG_DIR", logDir, RTL_NUMBER_OF(logDir));
            if (chars == 0 || chars >= RTL_NUMBER_OF(logDir))
            {
                return;
            }

            char path[MAX_PATH]{};
            (void)StringCchPrintfA(path,
                                   RTL_NUMBER_OF(path),
                                   "%s\\direct-syscall-%lu-%p.bin",
                                   logDir,
                                   static_cast<unsigned long>(GetCurrentProcessId()),
                                   pageBase);
            HANDLE file = CreateFileA(path,
                                      GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_DELETE,
                                      nullptr,
                                      CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL,
                                      nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                return;
            }

            DWORD toWrite = static_cast<DWORD>(std::min<SIZE_T>(pageSize, 64 * 1024));
            DWORD written = 0;
            __try
            {
                (void)WriteFile(file, pageBase, toWrite, &written, nullptr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            CloseHandle(file);
            IxDbgLog("direct-syscall page dump=%s page=%p size=0x%llX stub=%p ssn=0x%08lX source=%s",
                     path,
                     pageBase,
                     static_cast<unsigned long long>(pageSize),
                     stubAddress,
                     static_cast<unsigned long>(syscallNumber),
                     sourceApi != nullptr ? sourceApi : "unknown");
        }

        bool PublishDirectSyscallEvent(const GuardedDetectionRange &range,
                                       bool accessEvent,
                                       const ix::IX::Event *vehEvent,
                                       std::uint64_t faultAddress,
                                       std::uint64_t accessKind) noexcept
        {
            IXIPC_HOOK_EVENT record{};
            record.Kind = IxIpcHookEventIntegrity;
            record.ProcessId = vehEvent != nullptr ? vehEvent->pid : GetCurrentProcessId();
            record.ThreadId = vehEvent != nullptr ? vehEvent->tid : GetCurrentThreadId();
            record.Operation =
                accessEvent ? kIntegrityOperationDirectSyscallAccess : kIntegrityOperationDirectSyscallPage;
            record.Caller = accessEvent && vehEvent != nullptr ? reinterpret_cast<UINT64>(vehEvent->exception_address)
                                                               : reinterpret_cast<UINT64>(range.CreatorCaller);
            record.Context0 = reinterpret_cast<UINT64>(range.GuardBase);
            record.Context1 = static_cast<UINT64>(range.GuardSize);
            record.Context2 = reinterpret_cast<UINT64>(range.StubAddress);
            record.Context3 = accessEvent && vehEvent != nullptr
#if defined(_M_X64)
                                  ? vehEvent->rip
#else
                                  ? reinterpret_cast<UINT64>(vehEvent->exception_address)
#endif
                                  : reinterpret_cast<UINT64>(range.CreatorCaller);
            record.ArgCount = 8;
            record.Args[0] = range.SyscallNumber;
            record.Args[1] =
                reinterpret_cast<std::uintptr_t>(range.StubAddress) - reinterpret_cast<std::uintptr_t>(range.GuardBase);
            record.Args[2] = accessEvent ? accessKind : range.SampleSize;
            record.Args[3] = accessEvent ? range.HitCount : range.BaseProtect;
            record.Args[4] = reinterpret_cast<UINT64>(range.CreatorCaller);
            record.Args[5] = faultAddress;
            record.Args[6] = static_cast<UINT64>(GetTickCount64());
            record.Args[7] = range.ExportSize;
            record.CallerFlags =
                ((IX_HOOK_COMPONENT_INTEGRITY << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK);
            (void)strncpy_s(record.ApiName, accessEvent ? "DirectSyscallAccess" : "DirectSyscallPage", _TRUNCATE);
            (void)strncpy_s(record.ModuleName, range.SourceApi[0] != '\0' ? range.SourceApi : "memory", _TRUNCATE);
            record.DataSize = range.SampleSize > RTL_NUMBER_OF(record.DataSample) ? RTL_NUMBER_OF(record.DataSample)
                                                                                  : range.SampleSize;
            if (record.DataSize != 0)
            {
                std::memcpy(record.DataSample, range.Sample, record.DataSize);
            }
            if (vehEvent != nullptr)
            {
                CopyEventStackFromVeh(*vehEvent, record);
            }
            else
            {
                IC_STACKTRACE::Trace trace{};
                (void)IC_STACKTRACE::Capture(trace, 1);
                CopyEventStackFromTrace(trace, record);
            }
            return IXIPC::PublishHookEvent(record);
        }

        bool RangesOverlap(std::uintptr_t leftBase,
                           SIZE_T leftSize,
                           std::uintptr_t rightBase,
                           SIZE_T rightSize) noexcept
        {
            std::uintptr_t leftEnd = leftBase + static_cast<std::uintptr_t>(leftSize);
            std::uintptr_t rightEnd = rightBase + static_cast<std::uintptr_t>(rightSize);
            return leftBase < rightEnd && rightBase < leftEnd;
        }

        GuardedDetectionRange *FindGuardedRangeLocked(std::uintptr_t address) noexcept
        {
            for (auto &range : g_GuardedDetectionRanges)
            {
                if (!range.Active || !range.GuardArmed || range.GuardBase == nullptr || range.GuardSize == 0)
                {
                    continue;
                }

                auto base = reinterpret_cast<std::uintptr_t>(range.GuardBase);
                if (address >= base && address < base + static_cast<std::uintptr_t>(range.GuardSize))
                {
                    return &range;
                }
            }
            return nullptr;
        }

        GuardedDetectionRange *FindAnyGuardedRangeLocked(std::uintptr_t address) noexcept
        {
            for (auto &range : g_GuardedDetectionRanges)
            {
                if (!range.Active || range.GuardBase == nullptr || range.GuardSize == 0)
                {
                    continue;
                }

                auto base = reinterpret_cast<std::uintptr_t>(range.GuardBase);
                if (address >= base && address < base + static_cast<std::uintptr_t>(range.GuardSize))
                {
                    return &range;
                }
            }
            return nullptr;
        }

        GuardedDetectionRange *FindGuardedRangeByKeyLocked(GuardedDetectionKind kind,
                                                           void *moduleBase,
                                                           void *guardBase) noexcept
        {
            for (auto &range : g_GuardedDetectionRanges)
            {
                if (range.Active && range.Kind == kind && range.ModuleBase == moduleBase &&
                    range.GuardBase == guardBase)
                {
                    return &range;
                }
            }
            return nullptr;
        }

        std::uintptr_t DirectSyscallStubOffset(const GuardedDetectionRange &range) noexcept
        {
            return reinterpret_cast<std::uintptr_t>(range.StubAddress) -
                   reinterpret_cast<std::uintptr_t>(range.GuardBase);
        }

        bool DirectSyscallShapesEquivalent(const GuardedDetectionRange &left,
                                           const GuardedDetectionRange &right) noexcept
        {
            if (!left.Active || !right.Active || left.Kind != GuardedDetectionKind::DirectSyscallPage ||
                right.Kind != GuardedDetectionKind::DirectSyscallPage)
            {
                return false;
            }

            if (left.CreatorCaller != right.CreatorCaller || left.SyscallNumber != right.SyscallNumber ||
                DirectSyscallStubOffset(left) != DirectSyscallStubOffset(right) ||
                _stricmp(left.SourceApi, right.SourceApi) != 0)
            {
                return false;
            }

            const std::uint32_t compareSize = std::min<std::uint32_t>(16u, std::min(left.SampleSize, right.SampleSize));
            return compareSize == 0 || std::memcmp(left.Sample, right.Sample, compareSize) == 0;
        }

        GuardedDetectionRange *FindDirectSyscallShapeLocked(const GuardedDetectionRange &needle) noexcept
        {
            for (auto &range : g_GuardedDetectionRanges)
            {
                if (DirectSyscallShapesEquivalent(range, needle))
                {
                    return &range;
                }
            }
            return nullptr;
        }

        GuardedDetectionRange *AllocateGuardedRangeLocked() noexcept
        {
            for (auto &range : g_GuardedDetectionRanges)
            {
                if (!range.Active)
                {
                    return &range;
                }
            }
            return nullptr;
        }

        void ArmGuardReapplyAfterSingleStep(const GuardedDetectionRange &range, EXCEPTION_POINTERS *ep) noexcept
        {
            if (ep == nullptr || ep->ContextRecord == nullptr || range.GuardBase == nullptr || range.GuardSize == 0)
            {
                return;
            }

            DWORD tid = GetCurrentThreadId();
            GuardRearmEntry rearm{};
            rearm.Active = true;
            rearm.ThreadId = tid;
            rearm.GuardBase = range.GuardBase;
            rearm.GuardSize = range.GuardSize;
            rearm.BaseProtect = range.BaseProtect;

            AcquireSRWLockExclusive(&g_GuardedDetectionLock);
            GuardRearmEntry *slot = nullptr;
            for (auto &entry : g_GuardRearmEntries)
            {
                if (entry.Active && entry.ThreadId == tid)
                {
                    slot = &entry;
                    break;
                }
                if (slot == nullptr && !entry.Active)
                {
                    slot = &entry;
                }
            }
            if (slot != nullptr)
            {
                *slot = rearm;
            }
            ReleaseSRWLockExclusive(&g_GuardedDetectionLock);

#if defined(_M_X64)
            ep->ContextRecord->EFlags |= 0x100u;
#elif defined(_M_IX86)
            ep->ContextRecord->EFlags |= 0x100u;
#endif
        }

        bool ConsumeGuardRearmForCurrentThread(GuardRearmEntry &out) noexcept
        {
            out = {};
            DWORD tid = GetCurrentThreadId();
            AcquireSRWLockExclusive(&g_GuardedDetectionLock);
            for (auto &entry : g_GuardRearmEntries)
            {
                if (entry.Active && entry.ThreadId == tid)
                {
                    out = entry;
                    entry = {};
                    ReleaseSRWLockExclusive(&g_GuardedDetectionLock);
                    return true;
                }
            }
            ReleaseSRWLockExclusive(&g_GuardedDetectionLock);
            return false;
        }

        bool AnyGuardedDetectionActive() noexcept
        {
            bool active = false;
            AcquireSRWLockShared(&g_GuardedDetectionLock);
            for (const auto &range : g_GuardedDetectionRanges)
            {
                if (range.Active && range.GuardArmed)
                {
                    active = true;
                    break;
                }
            }
            ReleaseSRWLockShared(&g_GuardedDetectionLock);
            return active;
        }

        bool RegisterGuardedExportRange(HMODULE moduleHandle,
                                        GuardedDetectionKind kind,
                                        const wchar_t *modulePath,
                                        void *caller) noexcept
        {
            GuardedDetectionRange baseRange{};
            baseRange.Active = true;
            baseRange.Kind = kind;
            baseRange.ModuleBase = moduleHandle;
            baseRange.CreatorCaller = caller;
            if (!ResolveExportDirectoryRange(moduleHandle, baseRange))
            {
                return false;
            }

            SIZE_T pageSize = RuntimePageSize();
            auto exportStart = reinterpret_cast<std::uintptr_t>(baseRange.ExportBase);
            auto guardStart = AlignDown(exportStart, pageSize);
            auto guardEnd = AlignUp(exportStart + static_cast<std::uintptr_t>(baseRange.ExportSize), pageSize);
            if (guardEnd <= guardStart || (guardEnd - guardStart) > kMaxGuardSpanBytes)
            {
                return false;
            }

            bool insertedAny = false;
            bool appliedAny = false;
            GuardedDetectionRange firstInserted{};
            for (auto page = guardStart; page < guardEnd; page += pageSize)
            {
                if (!GuardPageHasNtZwEatSlot(baseRange, page, pageSize))
                {
                    continue;
                }

                GuardedDetectionRange local = baseRange;
                local.GuardBase = reinterpret_cast<void *>(page);
                local.GuardSize = pageSize;
                (void)strncpy_s(local.SourceApi,
                                kind == GuardedDetectionKind::DoubleLoadedNtdllEat ? "ntdll-double" : "ntdll-original",
                                _TRUNCATE);
                (void)strncpy_s(local.Label,
                                kind == GuardedDetectionKind::DoubleLoadedNtdllEat ? "double-loaded-ntdll-ntzw-eat"
                                                                                   : "original-ntdll-ntzw-eat",
                                _TRUNCATE);

                bool alreadyCompleted = false;
                AcquireSRWLockShared(&g_GuardedDetectionLock);
                GuardedDetectionRange *current = FindGuardedRangeByKeyLocked(kind, moduleHandle, local.GuardBase);
                if (current != nullptr && !current->GuardArmed && current->LastPublishedTick != 0)
                {
                    alreadyCompleted = true;
                }
                ReleaseSRWLockShared(&g_GuardedDetectionLock);
                if (alreadyCompleted)
                {
                    continue;
                }

                bool inserted = false;
                bool trackingAvailable = false;
                AcquireSRWLockExclusive(&g_GuardedDetectionLock);
                GuardedDetectionRange *existing = FindGuardedRangeByKeyLocked(kind, moduleHandle, local.GuardBase);
                if (existing == nullptr)
                {
                    GuardedDetectionRange *slot = AllocateGuardedRangeLocked();
                    if (slot != nullptr)
                    {
                        *slot = local;
                        inserted = true;
                        trackingAvailable = true;
                        insertedAny = true;
                        if (firstInserted.GuardBase == nullptr)
                        {
                            firstInserted = local;
                        }
                    }
                }
                else
                {
                    trackingAvailable = true;
                }
                ReleaseSRWLockExclusive(&g_GuardedDetectionLock);

                if (!trackingAvailable)
                {
                    continue;
                }

                if (!ApplyGuardToRange(local.GuardBase, local.GuardSize, &local.BaseProtect))
                {
                    if (inserted)
                    {
                        AcquireSRWLockExclusive(&g_GuardedDetectionLock);
                        GuardedDetectionRange *slot = FindGuardedRangeByKeyLocked(kind, moduleHandle, local.GuardBase);
                        if (slot != nullptr && !slot->GuardArmed)
                        {
                            *slot = {};
                        }
                        ReleaseSRWLockExclusive(&g_GuardedDetectionLock);
                    }
                    continue;
                }
                local.GuardArmed = true;
                appliedAny = true;

                AcquireSRWLockExclusive(&g_GuardedDetectionLock);
                GuardedDetectionRange *armed = FindGuardedRangeByKeyLocked(kind, moduleHandle, local.GuardBase);
                if (armed != nullptr)
                {
                    armed->ExportBase = local.ExportBase;
                    armed->ExportSize = local.ExportSize;
                    armed->ExportFunctionCount = local.ExportFunctionCount;
                    armed->NtZwSlotCount = local.NtZwSlotCount;
                    std::memcpy(armed->NtZwSlotBits, local.NtZwSlotBits, sizeof(armed->NtZwSlotBits));
                    armed->GuardSize = local.GuardSize;
                    armed->BaseProtect = local.BaseProtect;
                    armed->GuardArmed = true;
                    armed->CreatorCaller = caller;
                }
                ReleaseSRWLockExclusive(&g_GuardedDetectionLock);

                if (inserted)
                {
                    IxDbgLog("guarded ntdll Nt/Zw EAT page kind=%lu module=%p eat=%p slots=%lu guard=%p",
                             static_cast<unsigned long>(kind),
                             moduleHandle,
                             local.ExportBase,
                             static_cast<unsigned long>(local.NtZwSlotCount),
                             local.GuardBase);
                }
            }

            if (insertedAny && kind == GuardedDetectionKind::DoubleLoadedNtdllEat)
            {
                (void)PublishNtdllDoubleLoadEvent(firstInserted, modulePath, caller);
            }
            return appliedAny;
        }
    } // namespace

    void EnsureNtdllEatGuards() noexcept
    {
        if (!g_ModuleInitialized)
        {
            return;
        }

        EnsureProcessImageRange();

        if (IxIsInternalCall())
        {
            // The caller already owns the recursion guard; still allow the guard install.
        }

        IxInternalScope scope;
        HMODULE ntdll = static_cast<HMODULE>(FindLoadedModuleBaseByName(L"ntdll.dll"));
        if (ntdll == nullptr)
        {
            ntdll = GetModuleHandleW(L"ntdll.dll");
        }
        if (ntdll == nullptr)
        {
            return;
        }

        wchar_t path[MAX_PATH]{};
        (void)GetModuleFileNameW(ntdll, path, RTL_NUMBER_OF(path));
        (void)RegisterGuardedExportRange(ntdll, GuardedDetectionKind::OriginalNtdllEat, path, nullptr);
    }

    void ObserveLoadedModuleForNtdllEatGuard(HMODULE moduleHandle,
                                             const void *nameBuffer,
                                             std::size_t nameLength,
                                             void *caller) noexcept
    {
        if (moduleHandle == nullptr)
        {
            return;
        }

        IxInternalScope scope;
        wchar_t path[MAX_PATH]{};
        DWORD pathChars = GetModuleFileNameW(moduleHandle, path, RTL_NUMBER_OF(path));
        bool pathLooksLikeNtdll =
            pathChars != 0 && pathChars < RTL_NUMBER_OF(path) && _wcsicmp(WideBaseName(path), L"ntdll.dll") == 0;
        bool requestedNtdll = RequestedNameLooksLikeNtdll(nameBuffer, nameLength);
        if (!pathLooksLikeNtdll && !requestedNtdll)
        {
            return;
        }

        EnsureNtdllEatGuards();

        HMODULE original = static_cast<HMODULE>(FindLoadedModuleBaseByName(L"ntdll.dll"));
        if (original == nullptr)
        {
            original = GetModuleHandleW(L"ntdll.dll");
        }
        if (original == nullptr || moduleHandle == original)
        {
            return;
        }

        (void)RegisterGuardedExportRange(moduleHandle,
                                         GuardedDetectionKind::DoubleLoadedNtdllEat,
                                         pathChars != 0 && pathChars < RTL_NUMBER_OF(path) ? path : nullptr,
                                         caller);
    }

    bool RegisterDirectSyscallPage(void *pageBase,
                                   std::uint64_t pageSize64,
                                   void *stubAddress,
                                   std::uint32_t syscallNumber,
                                   void *caller,
                                   const std::uint8_t *sample,
                                   std::uint32_t sampleSize,
                                   const char *sourceApi) noexcept
    {
        if (IxIsInternalCall() || pageBase == nullptr || pageSize64 == 0 || stubAddress == nullptr ||
            IsAddressInBlindModule(caller))
        {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!NativeQueryMemory(pageBase, &mbi) || mbi.State != MEM_COMMIT || mbi.Type == MEM_IMAGE ||
            !IsGuardableProtect(mbi.Protect))
        {
            return false;
        }

        SIZE_T pageSize = static_cast<SIZE_T>(std::min<std::uint64_t>(pageSize64, RuntimePageSize()));
        void *guardBase =
            reinterpret_cast<void *>(AlignDown(reinterpret_cast<std::uintptr_t>(pageBase), RuntimePageSize()));
        if (!RangesOverlap(reinterpret_cast<std::uintptr_t>(guardBase),
                           pageSize,
                           reinterpret_cast<std::uintptr_t>(stubAddress),
                           1))
        {
            return false;
        }

        GuardedDetectionRange local{};
        local.Active = true;
        local.Kind = GuardedDetectionKind::DirectSyscallPage;
        local.ModuleBase = nullptr;
        local.GuardBase = guardBase;
        local.GuardSize = pageSize;
        local.ExportBase = nullptr;
        local.ExportSize = pageSize64;
        local.StubAddress = stubAddress;
        local.SyscallNumber = syscallNumber;
        local.CreatorCaller = caller;
        local.HitCount = 1;
        (void)strncpy_s(local.SourceApi, sourceApi != nullptr ? sourceApi : "memory", _TRUNCATE);
        (void)strncpy_s(local.Label, "direct-syscall-page", _TRUNCATE);
        local.BaseProtect = mbi.Protect & ~static_cast<ULONG>(PAGE_GUARD);
        local.SampleSize = sampleSize > RTL_NUMBER_OF(local.Sample) ? RTL_NUMBER_OF(local.Sample) : sampleSize;
        if (local.SampleSize != 0 && sample != nullptr)
        {
            std::memcpy(local.Sample, sample, local.SampleSize);
        }
        else
        {
            (void)CopyMemorySample(
                guardBase, local.Sample, &local.SampleSize, static_cast<std::uint32_t>(RTL_NUMBER_OF(local.Sample)));
        }

        const bool guardDirectSyscallPage = ShouldGuardDirectSyscallPagesByPolicy();
        if (guardDirectSyscallPage)
        {
            if (!ApplyGuardToRange(local.GuardBase, local.GuardSize, &local.BaseProtect))
            {
                return false;
            }
            local.GuardArmed = true;
        }

        bool inserted = false;
        GuardedDetectionRange published{};
        AcquireSRWLockExclusive(&g_GuardedDetectionLock);
        GuardedDetectionRange *existing =
            FindGuardedRangeByKeyLocked(GuardedDetectionKind::DirectSyscallPage, nullptr, local.GuardBase);
        if (existing != nullptr)
        {
            ++existing->HitCount;
            existing->StubAddress = local.StubAddress;
            existing->SyscallNumber = local.SyscallNumber;
            existing->CreatorCaller = local.CreatorCaller;
            existing->BaseProtect = local.BaseProtect;
            existing->ExportSize = local.ExportSize;
            existing->GuardArmed = existing->GuardArmed || local.GuardArmed;
            existing->SampleSize = local.SampleSize;
            std::memcpy(existing->Sample, local.Sample, sizeof(existing->Sample));
            (void)strncpy_s(existing->SourceApi, local.SourceApi, _TRUNCATE);
        }
        else if (!guardDirectSyscallPage && (existing = FindDirectSyscallShapeLocked(local)) != nullptr)
        {
            ++existing->HitCount;
            existing->ExportSize += local.ExportSize;
        }
        else
        {
            GuardedDetectionRange *slot = AllocateGuardedRangeLocked();
            if (slot != nullptr)
            {
                *slot = local;
                published = *slot;
                inserted = true;
            }
        }
        ReleaseSRWLockExclusive(&g_GuardedDetectionLock);

        if (inserted)
        {
            DumpDirectSyscallPage(
                local.GuardBase, local.GuardSize, local.StubAddress, local.SyscallNumber, local.SourceApi);
            (void)PublishDirectSyscallEvent(published, false, nullptr, 0, 0);
        }
        return true;
    }

    bool HandleGuardedDetectionFault(const ix::IX::Event &eventRecord, EXCEPTION_POINTERS *exceptionPointers) noexcept
    {
        if (eventRecord.exception_code != STATUS_GUARD_PAGE_VIOLATION)
        {
            return false;
        }

        std::uint64_t faultAddress = eventRecord.exception_info_count > 1
                                         ? eventRecord.exception_info[1]
                                         : reinterpret_cast<std::uint64_t>(eventRecord.exception_address);
        std::uint64_t accessKind = eventRecord.exception_info_count > 0 ? eventRecord.exception_info[0] : 0;
        if (faultAddress == 0)
        {
#if defined(_M_X64)
            faultAddress = eventRecord.rip;
#else
            faultAddress = reinterpret_cast<std::uint64_t>(eventRecord.exception_address);
#endif
        }

        const bool internalFault =
            IxIsInternalCall() || IsAddressInBlindModule(reinterpret_cast<void *>(eventRecord.exception_address));

        GuardedDetectionRange local{};
        bool found = false;
        AcquireSRWLockExclusive(&g_GuardedDetectionLock);
        GuardedDetectionRange *range = FindGuardedRangeLocked(static_cast<std::uintptr_t>(faultAddress));
        if (range == nullptr)
        {
#if defined(_M_X64)
            range = FindGuardedRangeLocked(static_cast<std::uintptr_t>(eventRecord.rip));
#endif
        }
        if (range == nullptr)
        {
            range = FindAnyGuardedRangeLocked(static_cast<std::uintptr_t>(faultAddress));
        }
        if (range == nullptr)
        {
#if defined(_M_X64)
            range = FindAnyGuardedRangeLocked(static_cast<std::uintptr_t>(eventRecord.rip));
#endif
        }
        if (range != nullptr)
        {
            ++range->HitCount;
            local = *range;
            found = true;
        }
        ReleaseSRWLockExclusive(&g_GuardedDetectionLock);

        if (!found)
        {
            IxDbgLog("guarded detection fault missed code=0x%08lX fault=%p rip=%p infoCount=%lu active=%u",
                     static_cast<unsigned long>(eventRecord.exception_code),
                     reinterpret_cast<void *>(static_cast<ULONG_PTR>(faultAddress)),
#if defined(_M_X64)
                     reinterpret_cast<void *>(static_cast<ULONG_PTR>(eventRecord.rip)),
#else
                     eventRecord.exception_address,
#endif
                     static_cast<unsigned long>(eventRecord.exception_info_count),
                     AnyGuardedDetectionActive() ? 1u : 0u);
            return false;
        }

        if (!local.GuardArmed)
        {
            IxDbgLog("guarded detection fault hit unarmed range kind=%lu guard=%p fault=%p",
                     static_cast<unsigned long>(local.Kind),
                     local.GuardBase,
                     reinterpret_cast<void *>(static_cast<ULONG_PTR>(faultAddress)));
            return true;
        }

        if (local.Kind == GuardedDetectionKind::DirectSyscallPage)
        {
            ArmGuardReapplyAfterSingleStep(local, exceptionPointers);
        }

        const bool ntZwSlotHit =
            local.Kind == GuardedDetectionKind::DirectSyscallPage || FaultHitsNtZwEatSlot(local, faultAddress);
        const bool ntZwExportPageHit =
            local.Kind != GuardedDetectionKind::DirectSyscallPage &&
            GuardPageHasNtZwEatSlot(local, reinterpret_cast<std::uintptr_t>(local.GuardBase), local.GuardSize);
        const bool originLooksInteresting = local.Kind == GuardedDetectionKind::DirectSyscallPage ||
                                            FaultingInstructionHasImageOrPrivateOrigin(eventRecord);
        if (internalFault)
        {
            return true;
        }

        if (local.Kind == GuardedDetectionKind::DirectSyscallPage)
        {
            IxInternalScope scope;
            (void)PublishDirectSyscallEvent(local, true, &eventRecord, faultAddress, accessKind);
            return true;
        }

        if ((!ntZwSlotHit && !ntZwExportPageHit) || !originLooksInteresting)
        {
            return true;
        }

        ULONGLONG now = GetTickCount64();
        bool shouldPublish = true;
        AcquireSRWLockExclusive(&g_GuardedDetectionLock);
        GuardedDetectionRange *publishedRange =
            FindGuardedRangeByKeyLocked(local.Kind, local.ModuleBase, local.GuardBase);
        if (publishedRange != nullptr)
        {
            local.HitCount = publishedRange->HitCount;
            publishedRange->GuardArmed = false;
            if (publishedRange->LastPublishedTick != 0 && now - publishedRange->LastPublishedTick < 500u)
            {
                shouldPublish = false;
            }
            else
            {
                publishedRange->LastPublishedTick = now;
            }
        }
        ReleaseSRWLockExclusive(&g_GuardedDetectionLock);

        if (!shouldPublish)
        {
            return true;
        }

        IxInternalScope scope;
        (void)PublishNtdllEatAccessEvent(local, eventRecord, faultAddress, accessKind);
        return true;
    }

    bool HandleGuardedDetectionSingleStep(const ix::IX::Event &eventRecord,
                                          EXCEPTION_POINTERS *exceptionPointers) noexcept
    {
        if (eventRecord.exception_code != EXCEPTION_SINGLE_STEP)
        {
            return false;
        }

        GuardRearmEntry rearm{};
        if (!ConsumeGuardRearmForCurrentThread(rearm))
        {
            if (!AnyGuardedDetectionActive())
            {
                return false;
            }

            if (exceptionPointers != nullptr && exceptionPointers->ContextRecord != nullptr)
            {
#if defined(_M_X64)
                exceptionPointers->ContextRecord->EFlags &= ~0x100u;
#elif defined(_M_IX86)
                exceptionPointers->ContextRecord->EFlags &= ~0x100u;
#endif
            }
            return true;
        }

        if (exceptionPointers != nullptr && exceptionPointers->ContextRecord != nullptr)
        {
#if defined(_M_X64)
            exceptionPointers->ContextRecord->EFlags &= ~0x100u;
#elif defined(_M_IX86)
            exceptionPointers->ContextRecord->EFlags &= ~0x100u;
#endif
        }

        if (rearm.GuardBase == nullptr || rearm.GuardSize == 0)
        {
            return true;
        }

        IxInternalScope scope;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!NativeQueryMemory(rearm.GuardBase, &mbi) || mbi.State != MEM_COMMIT || !IsGuardableProtect(mbi.Protect))
        {
            return true;
        }

        if ((mbi.Protect & PAGE_GUARD) == 0)
        {
            ULONG oldProtect = 0;
            ULONG baseProtect = rearm.BaseProtect != 0 ? rearm.BaseProtect : mbi.Protect;
            (void)NativeProtect(rearm.GuardBase,
                                rearm.GuardSize,
                                (baseProtect & ~static_cast<ULONG>(PAGE_GUARD)) | PAGE_GUARD,
                                &oldProtect);
        }
        return true;
    }

    void RearmGuardedDetections() noexcept
    {
        IxInternalScope scope;
        AcquireSRWLockExclusive(&g_GuardedDetectionLock);
        for (auto &range : g_GuardedDetectionRanges)
        {
            if (!range.Active || !range.GuardArmed || range.GuardBase == nullptr || range.GuardSize == 0)
            {
                continue;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!NativeQueryMemory(range.GuardBase, &mbi) || mbi.State != MEM_COMMIT ||
                !IsGuardableProtect(mbi.Protect))
            {
                range.Active = false;
                continue;
            }

            if ((mbi.Protect & PAGE_GUARD) == 0)
            {
                ULONG oldProtect = 0;
                ULONG baseProtect = range.BaseProtect != 0 ? range.BaseProtect : mbi.Protect;
                if (NativeProtect(range.GuardBase,
                                  range.GuardSize,
                                  (baseProtect & ~static_cast<ULONG>(PAGE_GUARD)) | PAGE_GUARD,
                                  &oldProtect))
                {
                    range.BaseProtect = oldProtect & ~static_cast<ULONG>(PAGE_GUARD);
                }
            }
        }
        ReleaseSRWLockExclusive(&g_GuardedDetectionLock);
    }

    void ClearGuardedDetections() noexcept
    {
        IxInternalScope scope;
        AcquireSRWLockExclusive(&g_GuardedDetectionLock);
        for (auto &range : g_GuardedDetectionRanges)
        {
            if (!range.Active)
            {
                continue;
            }

            if (range.GuardBase != nullptr && range.GuardSize != 0)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (NativeQueryMemory(range.GuardBase, &mbi) && mbi.State == MEM_COMMIT &&
                    (mbi.Protect & PAGE_GUARD) != 0)
                {
                    ULONG oldProtect = 0;
                    ULONG baseProtect =
                        range.BaseProtect != 0 ? range.BaseProtect : (mbi.Protect & ~static_cast<ULONG>(PAGE_GUARD));
                    (void)NativeProtect(range.GuardBase, range.GuardSize, baseProtect, &oldProtect);
                }
            }

            range = {};
        }

        for (auto &entry : g_GuardRearmEntries)
        {
            entry = {};
        }
        ReleaseSRWLockExclusive(&g_GuardedDetectionLock);
    }

    void MaintainGuardedDetections() noexcept
    {
        ULONGLONG now = GetTickCount64();
        if (now - g_LastGuardMaintainTick < 200u)
        {
            return;
        }
        g_LastGuardMaintainTick = now;

        if (g_ModuleInitialized)
        {
            EnsureNtdllEatGuards();
        }

        RearmGuardedDetections();
    }

    HANDLE NativeCreateEvent(bool manualReset, bool initialState, const wchar_t *name, DWORD desiredAccess) noexcept
    {
        DWORD flags = 0;
        if (manualReset)
        {
            flags |= CREATE_EVENT_MANUAL_RESET;
        }
        if (initialState)
        {
            flags |= CREATE_EVENT_INITIAL_SET;
        }

        HANDLE eventHandle = CreateEventExW(nullptr, name, flags, desiredAccess);
        if (eventHandle == nullptr)
        {
            DWORD err = GetLastError();
            IxDbgLog("NativeCreateEvent: failed name=%ls manual=%u initial=%u access=0x%08lX gle=%lu",
                     name != nullptr ? name : L"<unnamed>",
                     manualReset ? 1u : 0u,
                     initialState ? 1u : 0u,
                     static_cast<unsigned long>(desiredAccess),
                     static_cast<unsigned long>(err));
            SetLastError(err);
        }
        else
        {
            IxDbgLog("NativeCreateEvent: success name=%ls handle=%p access=0x%08lX gle=%lu",
                     name != nullptr ? name : L"<unnamed>",
                     eventHandle,
                     static_cast<unsigned long>(desiredAccess),
                     static_cast<unsigned long>(GetLastError()));
        }
        return eventHandle;
    }

    void NativeCloseHandle(HANDLE handle) noexcept
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
        {
            (void)CloseHandle(handle);
        }
    }

    bool NativeSetEvent(HANDLE handle) noexcept
    {
        return SetEvent(handle) != FALSE;
    }

    bool NativeWaitForSingleObject(HANDLE handle) noexcept
    {
        return WaitForSingleObject(handle, INFINITE) == WAIT_OBJECT_0;
    }

    void NativeDelayMs(DWORD milliseconds) noexcept
    {
        Sleep(milliseconds);
    }

    void NativeYield() noexcept
    {
        if (!SwitchToThread())
        {
            Sleep(0);
        }
    }

    HANDLE NativeCreateThread(void *startRoutine, void *parameter) noexcept
    {
        HANDLE threadHandle = nullptr;
        auto fn = ResolveNtdllExport<NtCreateThreadExFn>("NtCreateThreadEx");
        if (fn == nullptr)
        {
            auto rtlCreateUserThread = ResolveNtdllExport<RtlCreateUserThreadFn>("RtlCreateUserThread");
            if (rtlCreateUserThread == nullptr)
            {
                return nullptr;
            }

            KH_CLIENT_ID clientId{};
            if (!NtSucceeded(rtlCreateUserThread(CurrentProcessHandle(),
                                                 nullptr,
                                                 FALSE,
                                                 0,
                                                 nullptr,
                                                 nullptr,
                                                 startRoutine,
                                                 parameter,
                                                 &threadHandle,
                                                 &clientId)))
            {
                return nullptr;
            }
            return threadHandle;
        }

        if (!NtSucceeded(fn(&threadHandle,
                            THREAD_ALL_ACCESS,
                            nullptr,
                            CurrentProcessHandle(),
                            startRoutine,
                            parameter,
                            0,
                            0,
                            0,
                            0,
                            nullptr)))
        {
            threadHandle =
                CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(startRoutine), parameter, 0, nullptr);
            return threadHandle;
        }

        return threadHandle;
    }

    [[noreturn]] void NativeTerminateCurrentProcess(DWORD exitStatus) noexcept
    {
        auto fn = ResolveNtdllExport<NtTerminateProcessFn>("NtTerminateProcess");
        if (fn != nullptr)
        {
            (void)fn(CurrentProcessHandle(), static_cast<NTSTATUS>(exitStatus));
        }

        for (;;)
        {
            NativeDelayMs(1000);
        }
    }

    [[noreturn]] void NativeExitCurrentThread() noexcept
    {
        auto fn = ResolveNtdllExport<RtlExitUserThreadFn>("RtlExitUserThread");
        if (fn != nullptr)
        {
            fn(0);
        }

        for (;;)
        {
            NativeDelayMs(1000);
        }
    }

    void ResetIntegrityWatchdogState() noexcept
    {
        g_LastIntegrityCheckTick = 0;
        g_LastIntegrityPublishTick = 0;
        g_LastVehPromoteTick = 0;
        g_LastIntegrityMask = UINT32_MAX;
        g_IntegrityCheckCount = 0;
        std::memset(&g_AmsiProbe, 0, sizeof(g_AmsiProbe));
        std::memset(&g_EtwProbe, 0, sizeof(g_EtwProbe));
        g_LastAmsiTampered = false;
        g_LastEtwTampered = false;
        g_LastAmsiPublishTick = 0;
        g_LastEtwPublishTick = 0;
        g_AmsiFirstPoll = true;
        g_EtwFirstPoll = true;
    }

    void MaintainVectoredExceptionHandlerFront() noexcept
    {
        if (!g_RuntimeVehArgs.install_first || !g_RuntimeVehArgs.auto_promote)
        {
            return;
        }

        ULONGLONG now = GetTickCount64();
        if (now - g_LastVehPromoteTick < kVehFrontChainPromotePeriodMs)
        {
            return;
        }

        g_LastVehPromoteTick = now;
        IxInternalScope scope;
        (void)IxPromoteVectoredExceptionHandlerToFront();
    }
} // namespace IX_RUNTIME_INTERNAL

namespace
{
    std::atomic<void *> g_GuardedDetectionVehHandle{nullptr};

    USHORT CaptureGuardedVehStack(const CONTEXT *context, std::uint16_t maxFrames, void **outFrames) noexcept
    {
        if (context == nullptr || outFrames == nullptr || maxFrames == 0)
        {
            return 0;
        }

        USHORT captured = 0;
#if defined(_M_X64)
        if (context->Rip != 0)
        {
            outFrames[captured++] = reinterpret_cast<void *>(context->Rip);
        }

        DWORD64 rsp = context->Rsp;
        for (USHORT i = 0; captured < maxFrames && i < 48; ++i)
        {
            DWORD64 candidate = 0;
            __try
            {
                candidate = *reinterpret_cast<DWORD64 *>(rsp + (static_cast<DWORD64>(i) * sizeof(DWORD64)));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }

            if (candidate != 0)
            {
                outFrames[captured++] = reinterpret_cast<void *>(candidate);
            }
        }
#else
        UNREFERENCED_PARAMETER(context);
#endif
        return captured;
    }

    void PopulateGuardedVehEvent(EXCEPTION_POINTERS *ep, ix::IX::Event &eventRecord) noexcept
    {
        eventRecord.exception_code = ep->ExceptionRecord->ExceptionCode;
        eventRecord.exception_flags = ep->ExceptionRecord->ExceptionFlags;
        eventRecord.exception_address = ep->ExceptionRecord->ExceptionAddress;
        eventRecord.pid = GetCurrentProcessId();
        eventRecord.tid = GetCurrentThreadId();
        eventRecord.is_memory_fault = eventRecord.exception_code == STATUS_GUARD_PAGE_VIOLATION;
        eventRecord.is_noncontinuable = (eventRecord.exception_flags & EXCEPTION_NONCONTINUABLE) != 0;
        eventRecord.exception_info_count = ep->ExceptionRecord->NumberParameters > ix::IX::kMaxExInfo
                                               ? static_cast<ULONG>(ix::IX::kMaxExInfo)
                                               : static_cast<ULONG>(ep->ExceptionRecord->NumberParameters);
        for (ULONG i = 0; i < eventRecord.exception_info_count; ++i)
        {
            eventRecord.exception_info[i] = ep->ExceptionRecord->ExceptionInformation[i];
        }
#if defined(_M_X64)
        if (ep->ContextRecord != nullptr)
        {
            eventRecord.rip = ep->ContextRecord->Rip;
            eventRecord.rsp = ep->ContextRecord->Rsp;
            eventRecord.rbp = ep->ContextRecord->Rbp;
            eventRecord.rax = ep->ContextRecord->Rax;
            eventRecord.rbx = ep->ContextRecord->Rbx;
            eventRecord.rcx = ep->ContextRecord->Rcx;
            eventRecord.rdx = ep->ContextRecord->Rdx;
            eventRecord.rsi = ep->ContextRecord->Rsi;
            eventRecord.rdi = ep->ContextRecord->Rdi;
            eventRecord.r8 = ep->ContextRecord->R8;
            eventRecord.r9 = ep->ContextRecord->R9;
            eventRecord.r10 = ep->ContextRecord->R10;
            eventRecord.r11 = ep->ContextRecord->R11;
            eventRecord.r12 = ep->ContextRecord->R12;
            eventRecord.r13 = ep->ContextRecord->R13;
            eventRecord.r14 = ep->ContextRecord->R14;
            eventRecord.r15 = ep->ContextRecord->R15;
            eventRecord.eflags = ep->ContextRecord->EFlags;
            eventRecord.stack_frame_count = CaptureGuardedVehStack(
                ep->ContextRecord, static_cast<std::uint16_t>(ix::IX::kMaxStackFrames), eventRecord.stack);
        }
#endif
    }

    LONG CALLBACK GuardedDetectionVeh(EXCEPTION_POINTERS *ep)
    {
        if (ep == nullptr || ep->ExceptionRecord == nullptr)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code != STATUS_GUARD_PAGE_VIOLATION && code != EXCEPTION_SINGLE_STEP)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        ix::IX::Event eventRecord{};
        PopulateGuardedVehEvent(ep, eventRecord);
        if (code == EXCEPTION_SINGLE_STEP)
        {
            return IX_RUNTIME_INTERNAL::HandleGuardedDetectionSingleStep(eventRecord, ep) ? EXCEPTION_CONTINUE_EXECUTION
                                                                                          : EXCEPTION_CONTINUE_SEARCH;
        }

        return IX_RUNTIME_INTERNAL::HandleGuardedDetectionFault(eventRecord, ep) ? EXCEPTION_CONTINUE_EXECUTION
                                                                                 : EXCEPTION_CONTINUE_SEARCH;
    }

    bool IxRuntimePrimeGuardedDetectionVeh() noexcept
    {
        void *existing = g_GuardedDetectionVehHandle.load(std::memory_order_acquire);
        if (existing != nullptr)
        {
            return true;
        }

        void *created = AddVectoredExceptionHandler(1, GuardedDetectionVeh);
        if (created == nullptr)
        {
            IxDbgLog("IxRuntimePrimeGuardedDetectionVeh: failed");
            return false;
        }

        void *expected = nullptr;
        if (!g_GuardedDetectionVehHandle.compare_exchange_strong(
                expected, created, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            RemoveVectoredExceptionHandler(created);
            return true;
        }

        IxDbgLog("IxRuntimePrimeGuardedDetectionVeh: result=1");
        return true;
    }

    void IxRuntimeUnregisterGuardedDetectionVeh() noexcept
    {
        void *handle = g_GuardedDetectionVehHandle.exchange(nullptr, std::memory_order_acq_rel);
        if (handle != nullptr)
        {
            RemoveVectoredExceptionHandler(handle);
        }
    }

    static void InitializeAnalysisSubjectClassifier() noexcept
    {
        wchar_t kind[32]{};
        wchar_t subjectPath[1024]{};
        wchar_t hostPath[1024]{};
        std::uint32_t subjectKind = 0;

        static constexpr IxEncodedWideLiteral kSubjectKindEnv{L"IX_ANALYSIS_SUBJECT_KIND", 0x105u};
        IxScopedWideLiteral subjectKindEnv(kSubjectKindEnv);
        DWORD kindChars = GetEnvironmentVariableW(subjectKindEnv.c_str(), kind, RTL_NUMBER_OF(kind));
        if (kindChars != 0 && kindChars < RTL_NUMBER_OF(kind) && _wcsicmp(kind, L"DLL") == 0)
        {
            subjectKind = 1;
            static constexpr IxEncodedWideLiteral kSubjectPathEnv{L"IX_ANALYSIS_SUBJECT_PATH", 0x12Fu};
            static constexpr IxEncodedWideLiteral kHostPathEnv{L"IX_ANALYSIS_HOST_PATH", 0x155u};
            IxScopedWideLiteral subjectPathEnv(kSubjectPathEnv);
            IxScopedWideLiteral hostPathEnv(kHostPathEnv);
            (void)GetEnvironmentVariableW(subjectPathEnv.c_str(), subjectPath, RTL_NUMBER_OF(subjectPath));
            (void)GetEnvironmentVariableW(hostPathEnv.c_str(), hostPath, RTL_NUMBER_OF(hostPath));
            subjectPath[RTL_NUMBER_OF(subjectPath) - 1] = L'\0';
            hostPath[RTL_NUMBER_OF(hostPath) - 1] = L'\0';
        }

        IC_STACKTRACE::SetAnalysisSubjectMetadata(
            subjectKind, subjectKind == 1 ? subjectPath : nullptr, subjectKind == 1 ? hostPath : nullptr);
        if (subjectKind == 1)
        {
            IxDbgLog("InitializeAnalysisSubjectClassifier: kind=DLL subject=%ls host=%ls",
                     subjectPath[0] != L'\0' ? subjectPath : L"<unset>",
                     hostPath[0] != L'\0' ? hostPath : L"<unset>");
        }
    }

    static void SuppressWindowsFaultDialogs() noexcept
    {
        UINT mode = GetErrorMode();
        mode |= SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
        (void)SetErrorMode(mode);
    }

    static void FormatVehStackSummary(const ix::IX::Event &e,
                                      char *stackSummary,
                                      std::size_t stackSummaryChars) noexcept
    {
        if (stackSummary == nullptr || stackSummaryChars == 0)
        {
            return;
        }

        stackSummary[0] = '\0';
        std::size_t offset = 0;
        for (USHORT i = 0; i < e.stack_frame_count && i < 6; ++i)
        {
            int written = 0;
            if (offset != 0 && offset < stackSummaryChars)
            {
                stackSummary[offset++] = ',';
            }

            if (offset >= stackSummaryChars)
            {
                break;
            }

            HRESULT hr = StringCchPrintfExA(stackSummary + offset,
                                            stackSummaryChars - offset,
                                            nullptr,
                                            nullptr,
                                            STRSAFE_IGNORE_NULLS,
                                            "%p",
                                            e.stack[i]);
            if (FAILED(hr))
            {
                break;
            }

            written = lstrlenA(stackSummary + offset);
            offset += static_cast<std::size_t>(written);
        }
    }

    static void EmitVehCrashDebugLine(const char *channel, const ix::IX::Event &e, const char *moduleName) noexcept
    {
        char stackSummary[256]{};
        FormatVehStackSummary(e, stackSummary, RTL_NUMBER_OF(stackSummary));

        char line[1024]{};
        (void)StringCchPrintfA(
            line,
            RTL_NUMBER_OF(line),
            "[VEH] crash-exception channel=%s code=0x%08lX flags=0x%08lX fault=%p pid=%lu tid=%lu "
            "module=%s info0=0x%llX info1=0x%llX rip=0x%llX rsp=0x%llX rbp=0x%llX rax=0x%llX rcx=0x%llX "
            "rdx=0x%llX r10=0x%llX eflags=0x%llX frames=%hu stack=%s\n",
            channel ? channel : "unknown",
            static_cast<unsigned long>(e.exception_code),
            static_cast<unsigned long>(e.exception_flags),
            e.exception_address,
            static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid),
            (moduleName && moduleName[0] != '\0') ? moduleName : "unknown",
            static_cast<unsigned long long>(e.exception_info_count > 0 ? e.exception_info[0] : 0),
            static_cast<unsigned long long>(e.exception_info_count > 1 ? e.exception_info[1] : 0),
#if defined(_M_X64)
            static_cast<unsigned long long>(e.rip),
            static_cast<unsigned long long>(e.rsp),
            static_cast<unsigned long long>(e.rbp),
            static_cast<unsigned long long>(e.rax),
            static_cast<unsigned long long>(e.rcx),
            static_cast<unsigned long long>(e.rdx),
            static_cast<unsigned long long>(e.r10),
            static_cast<unsigned long long>(e.eflags),
#else
            0ull,
            0ull,
            0ull,
            0ull,
            0ull,
            0ull,
            0ull,
            0ull,
#endif
            e.stack_frame_count,
            stackSummary[0] != '\0' ? stackSummary : "none");

        IxInternalScope scope;
        OutputDebugStringA(line);
    }

    static void PublishVehExceptionEventInternal(const char *channel,
                                                 const ix::IX::Event &e,
                                                 const char *moduleName) noexcept
    {
        if (e.exception_code == STATUS_GUARD_PAGE_VIOLATION || IsDebugPrintExceptionCode(e.exception_code))
        {
            return;
        }

        IXIPC_HOOK_EVENT record{};
        record.Kind = e.is_target_module ? IxIpcHookEventExceptionLowNoise : IxIpcHookEventExceptionHighPriv;
        record.ProcessId = e.pid;
        record.ThreadId = e.tid;
        record.Operation = e.exception_code;
        record.Caller = reinterpret_cast<UINT64>(e.exception_address);
        record.Context0 = e.exception_code;
        record.Context1 = e.exception_flags;
        record.Context2 = e.exception_info_count > 0 ? static_cast<UINT64>(e.exception_info[0]) : 0ull;
        record.Context3 = e.exception_info_count > 1 ? static_cast<UINT64>(e.exception_info[1]) : 0ull;
        record.ArgCount = 8;
#if defined(_M_X64)
        record.Args[0] = e.rip;
        record.Args[1] = e.rsp;
        record.Args[2] = e.rbp;
        record.Args[3] = e.rax;
        record.Args[4] = e.rcx;
        record.Args[5] = e.rdx;
        record.Args[6] = e.r10;
        record.Args[7] = e.eflags;
#endif
        record.StackCount = static_cast<UINT32>(
            (e.stack_frame_count > IXIPC_MAX_HOOK_STACK_FRAMES) ? IXIPC_MAX_HOOK_STACK_FRAMES : e.stack_frame_count);
        for (UINT32 i = 0; i < record.StackCount; ++i)
        {
            record.Stack[i] = reinterpret_cast<UINT64>(e.stack[i]);
        }
        record.CallerFlags =
            ((IX_HOOK_COMPONENT_UNKNOWN << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK) |
            ((IX_HOOK_CALLER_KIND_UNKNOWN << IX_HOOK_CALLER_IMMED_SHIFT) & IX_HOOK_CALLER_IMMED_MASK);
        (void)StringCchCopyA(record.ApiName,
                             RTL_NUMBER_OF(record.ApiName),
                             e.is_memory_fault           ? "UsermodeMemoryFault"
                             : IsTrapFlagOrSingleStep(e) ? "UsermodeSingleStep"
                                                         : "UsermodeException");
        (void)StringCchCopyA(record.ModuleName,
                             RTL_NUMBER_OF(record.ModuleName),
                             (moduleName && moduleName[0] != '\0') ? moduleName : "unknown");

        EmitVehCrashDebugLine(channel, e, moduleName);
        (void)IXIPC::PublishHookEventSynchronously(record);
    }

    static void PublishVehExceptionEvent(const char *channel, const ix::IX::Event &e, const char *moduleName) noexcept
    {
        if (ShouldDeferVehTelemetry())
        {
            return;
        }

        IxInternalScope telemetryScope;
        PublishVehExceptionEventInternal(channel, e, moduleName);
    }

    static void LogVehExceptionEvent(const char *channel, const ix::IX::Event &e) noexcept
    {
        if (e.exception_code == STATUS_GUARD_PAGE_VIOLATION || IsDebugPrintExceptionCode(e.exception_code))
        {
            return;
        }
        if (ShouldDeferVehTelemetry())
        {
            return;
        }

        IxInternalScope telemetryScope;
        char moduleName[96]{};
        if (e.module_basename_lower[0] != L'\0')
        {
            (void)WideCharToMultiByte(
                CP_UTF8, 0, e.module_basename_lower, -1, moduleName, RTL_NUMBER_OF(moduleName), nullptr, nullptr);
        }
        else
        {
            (void)StringCchCopyA(moduleName, RTL_NUMBER_OF(moduleName), "unknown");
        }

        char stackSummary[256]{};
        FormatVehStackSummary(e, stackSummary, RTL_NUMBER_OF(stackSummary));

        IxDbgLog(
            "[VEH] veh-exception channel=%s code=0x%08lX flags=0x%08lX addr=%p pid=%lu tid=%lu target=%u memory=%u "
            "noncontinuable=%u module=%s infoCount=%lu info0=0x%llX info1=0x%llX stack=%s",
            channel ? channel : "unknown",
            static_cast<unsigned long>(e.exception_code),
            static_cast<unsigned long>(e.exception_flags),
            e.exception_address,
            static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid),
            e.is_target_module ? 1u : 0u,
            e.is_memory_fault ? 1u : 0u,
            e.is_noncontinuable ? 1u : 0u,
            moduleName,
            static_cast<unsigned long>(e.exception_info_count),
            static_cast<unsigned long long>(e.exception_info_count > 0 ? e.exception_info[0] : 0),
            static_cast<unsigned long long>(e.exception_info_count > 1 ? e.exception_info[1] : 0),
            stackSummary[0] != '\0' ? stackSummary : "none");
#if defined(_M_X64)
        IxDbgLog(
            "[VEH] context rip=0x%llX rsp=0x%llX rbp=0x%llX rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rsi=0x%llX "
            "rdi=0x%llX r8=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX r12=0x%llX r13=0x%llX r14=0x%llX r15=0x%llX "
            "eflags=0x%llX",
            static_cast<unsigned long long>(e.rip),
            static_cast<unsigned long long>(e.rsp),
            static_cast<unsigned long long>(e.rbp),
            static_cast<unsigned long long>(e.rax),
            static_cast<unsigned long long>(e.rbx),
            static_cast<unsigned long long>(e.rcx),
            static_cast<unsigned long long>(e.rdx),
            static_cast<unsigned long long>(e.rsi),
            static_cast<unsigned long long>(e.rdi),
            static_cast<unsigned long long>(e.r8),
            static_cast<unsigned long long>(e.r9),
            static_cast<unsigned long long>(e.r10),
            static_cast<unsigned long long>(e.r11),
            static_cast<unsigned long long>(e.r12),
            static_cast<unsigned long long>(e.r13),
            static_cast<unsigned long long>(e.r14),
            static_cast<unsigned long long>(e.r15),
            static_cast<unsigned long long>(e.eflags));
#endif

        if (e.is_noncontinuable || IsTrapFlagOrSingleStep(e))
        {
            PublishVehExceptionEventInternal(channel, e, moduleName);
        }
    }

    static void LowNoise(const ix::IX::Event &e, void *u) noexcept
    {
        UNREFERENCED_PARAMETER(e);
        UNREFERENCED_PARAMETER(u);
        LogVehExceptionEvent("target", e);
    }

    static void HighNoise(const ix::IX::Event &e, void *u) noexcept
    {
        UNREFERENCED_PARAMETER(e);
        UNREFERENCED_PARAMETER(u);
        LogVehExceptionEvent("foreign", e);
    }

    static bool MemFault(const ix::IX::Event &e, EXCEPTION_POINTERS *ep, void *) noexcept
    {
        if (e.exception_code == EXCEPTION_SINGLE_STEP)
        {
            return IX_RUNTIME_INTERNAL::HandleGuardedDetectionSingleStep(e, ep);
        }

        if (LaunchGateHandleFault(ep))
        {
            return true;
        }

        if (e.exception_code == STATUS_GUARD_PAGE_VIOLATION)
        {
            if (IX_RUNTIME_INTERNAL::HandleGuardedDetectionFault(e, ep))
            {
                return true;
            }
            return false;
        }

        if (ShouldDeferVehTelemetry())
        {
            return false;
        }

        LogVehExceptionEvent("memory-fault", e);
        if (e.exception_code != STATUS_GUARD_PAGE_VIOLATION)
        {
            char moduleName[96]{};
            if (e.module_basename_lower[0] != L'\0')
            {
                (void)WideCharToMultiByte(
                    CP_UTF8, 0, e.module_basename_lower, -1, moduleName, RTL_NUMBER_OF(moduleName), nullptr, nullptr);
            }
            else
            {
                (void)StringCchCopyA(moduleName, RTL_NUMBER_OF(moduleName), "unknown");
            }
            PublishVehExceptionEvent("memory-fault-unhandled", e, moduleName);
        }

        return e.exception_code == STATUS_GUARD_PAGE_VIOLATION;
    }

    static bool IxRuntimePrimeVectoredExceptionHandler() noexcept
    {
        auto blindName = DecodeIxDllName();
        g_RuntimeVehArgs.target_module_basename = blindName.c_str();
        g_RuntimeVehArgs.low_noise_telemetry = LowNoise;
        g_RuntimeVehArgs.high_noise_telemetry = HighNoise;
        g_RuntimeVehArgs.memory_fault_handler = MemFault;
        bool ok = IxRegisterVectoredExceptionHandler(&g_RuntimeVehArgs) != nullptr;
        g_RuntimeVehArgs.target_module_basename = nullptr;
        IxDbgLog("IxRuntimePrimeVectoredExceptionHandler: result=%u", ok ? 1u : 0u);
        return ok;
    }
} // namespace

void IxRuntimePrimeHooks() noexcept
{
    bool expected = false;
    if (!g_RuntimePrimed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    IC_STACKTRACE::InitCallerClassifier(reinterpret_cast<void *>(&IxRuntimePrimeHooks));
    InitializeAnalysisSubjectClassifier();
    SuppressWindowsFaultDialogs();
    EnsureProcessImageRange();
    (void)IxRuntimePrimeGuardedDetectionVeh();
    (void)IxRuntimePrimeVectoredExceptionHandler();

    ResetIntegrityWatchdogState();
    IxDbgLog("IxRuntimePrimeHooks: primed");
}

HANDLE IxRuntimeCreateBootstrapThread(LPTHREAD_START_ROUTINE startRoutine, LPVOID parameter) noexcept
{
    HANDLE threadHandle;

    if (startRoutine == nullptr)
    {
        IxDbgLog("IxRuntimeCreateBootstrapThread: invalid start routine");
        IxRuntimeReportFault(IxRuntimeFaultCode::BootstrapThreadCreateFailed, ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    threadHandle = CreateThread(nullptr, 0, startRoutine, parameter, 0, nullptr);
    if (threadHandle != nullptr)
    {
        IxDbgLog("IxRuntimeCreateBootstrapThread: CreateThread succeeded handle=%p", threadHandle);
        return threadHandle;
    }

    IxDbgLog("IxRuntimeCreateBootstrapThread: CreateThread failed gle=%lu, trying native fallback",
             (unsigned long)GetLastError());
    threadHandle = NativeCreateThread(reinterpret_cast<void *>(startRoutine), parameter);
    if (threadHandle != nullptr)
    {
        IxDbgLog("IxRuntimeCreateBootstrapThread: native fallback succeeded handle=%p", threadHandle);
    }
    else
    {
        IxDbgLog("IxRuntimeCreateBootstrapThread: native fallback failed");
        IxRuntimeReportFault(IxRuntimeFaultCode::BootstrapThreadCreateFailed, GetLastError());
    }

    return threadHandle;
}

void IxRuntimeCloseHandle(HANDLE handle) noexcept
{
    NativeCloseHandle(handle);
}

void IxRuntimeFailClosed(DWORD exitStatus) noexcept
{
    IxDbgLog("IxRuntimeFailClosed: exitStatus=%lu", (unsigned long)exitStatus);
    IxRuntimeReportFault(IxRuntimeFaultCode::FailClosedTriggered, exitStatus);
    NativeTerminateCurrentProcess(exitStatus);
}

bool IxInitializeSubsystems() noexcept
{
    IxRuntimePrimeHooks();

    if (!IxRuntimePrimeVectoredExceptionHandler())
    {
        IxDbgLog("IxInitializeSubsystems: VEH registration failed");
        IxRuntimeReportFault(IxRuntimeFaultCode::LaunchGatePrepareFailed);
        return false;
    }

    LaunchGateCallbacks callbacks{};
    callbacks.InitializeRuntime = &EnsureRuntimeInitializedForLaunch;
    callbacks.FailClosed = &IxRuntimeFailClosed;
    g_LaunchGateCallbacks = callbacks;
    bool ok = LaunchGatePrepare();
    IxDbgLog("IxInitializeSubsystems: result=%u", ok ? 1u : 0u);
    return ok;
}

void IxRuntimeSignalLaunchGateReady() noexcept
{
    LaunchGateRelease();
}

DWORD WINAPI IxRuntimeThreadProc(LPVOID)
{
    IxDbgLog("IxRuntimeThreadProc: start launchGatePrepared=%u", LaunchGateIsPrepared() ? 1u : 0u);

    if (!EnsureRuntimeInitializedForLaunch(!LaunchGateIsPrepared(), false))
    {
        IxDbgLog("IxRuntimeThreadProc: runtime initialization failed");
        return 0;
    }

    return IxRuntimeEventLoopThreadProc(nullptr);
}

void IxRuntimeShutdown()
{
    IxDbgLog("IxRuntimeShutdown: begin");
    IxRuntimeSignalLaunchGateReady();
    ClearGuardedDetections();

    g_KiHookController.Shutdown();
    g_ModuleHookController.Shutdown();
    g_NtHookController.Shutdown();
    g_WinsockController.Shutdown();
    g_ModuleInitialized = false;
    g_KiInitialized = false;
    g_NtInitialized = false;
    g_WinsockInitialized = false;

    IC_STACKTRACE::CleanupSymbols();

    IXIPC::Shutdown();
    IxRuntimeUnregisterGuardedDetectionVeh();
    IxUnregisterVectoredExceptionHandler();
    ResetControlFlowGuardPolicyCache();
    ResetProcessInstrumentationCallbackState();
    ResetCliHookPolicy();
    LaunchGateShutdown();
    g_RuntimeInitialized.store(false, std::memory_order_release);
    g_RuntimeWorkerStarted.store(false, std::memory_order_release);
    g_LastPublishedHookReadyMask.store(0, std::memory_order_release);
}
