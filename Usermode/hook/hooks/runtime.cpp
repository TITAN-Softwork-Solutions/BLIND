#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "runtime_private.h"

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

__declspec(thread) int g_IxCallDepth = 0;

namespace
{
    static constexpr DWORD kStatusSingleStep = 0x80000004u;
    static constexpr std::uint64_t kEFlagsTrapFlag = 0x100ull;
    static constexpr ULONGLONG kVehFrontChainPromotePeriodMs = 1000ull;

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
    HANDLE logFile = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (logFile != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        (void)WriteFile(logFile, line, static_cast<DWORD>(strnlen(line, RTL_NUMBER_OF(line))), &written, nullptr);
        CloseHandle(logFile);
    }
}

void IxRuntimeReportFault(IxRuntimeFaultCode code, std::uint64_t arg0, std::uint64_t arg1) noexcept
{
    IxDbgLog("Fault code=%lu arg0=0x%llX arg1=0x%llX", static_cast<unsigned long>(code),
             static_cast<unsigned long long>(arg0), static_cast<unsigned long long>(arg1));
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

        bool DecodeToken(IxIhrToken token, std::uint16_t &slot, std::uint32_t &type,
                         std::uint32_t &generation) noexcept
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

    IxIhrToken RegisterIndirectHandle(void *pointer, std::uint64_t size, IxIhrType type, std::uint32_t flags,
                                        const char *tag) noexcept
    {
        IxDbgLog("RegisterIndirectHandle: begin pointer=%p size=0x%llX type=%lu flags=0x%08lX tag=%s", pointer,
                 static_cast<unsigned long long>(size), static_cast<unsigned long>(type),
                 static_cast<unsigned long>(flags), tag != nullptr ? tag : "<null>");
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
                IxDbgLog("RegisterIndirectHandle: updated slot=%zu token=0x%llX", i + 1,
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
        IxDbgLog("RegisterIndirectHandle: created slot=%zu generation=0x%08lX token=0x%llX", freeIndex + 1,
                 static_cast<unsigned long>(generation), static_cast<unsigned long long>(token));
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

    static bool AddIxSelfMapEntry(IxSelfMapEntry *entries, std::size_t capacity, std::uint32_t &count,
                                    std::uint32_t &truncated, std::uint32_t kind, const char *owner,
                                    const char *name, std::uint64_t address, std::uint64_t size,
                                    std::uint32_t flags, std::uint64_t reference0 = 0,
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

    static std::uint64_t ComputeIxSelfMapSignature(const IxSelfMapEntry *entries,
                                                     std::uint32_t count) noexcept
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

    static void PublishIxSelfMapEntry(const IxSelfMapEntry &entry, std::uint32_t index, std::uint32_t total,
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
        record.Args[4] = (static_cast<std::uint64_t>(entry.Memory.Protect) << 32) |
                         static_cast<std::uint64_t>(entry.Memory.State);
        record.Args[5] = static_cast<std::uint64_t>(entry.Memory.Type);
        record.Args[6] = index;
        record.Args[7] = (static_cast<std::uint64_t>(total) << 32) | truncated;
        record.CallerFlags =
            ((IX_HOOK_COMPONENT_INTEGRITY << IX_HOOK_CALLER_COMPONENT_SHIFT) & IX_HOOK_CALLER_COMPONENT_MASK);
        (void)StringCchCopyA(record.ApiName, RTL_NUMBER_OF(record.ApiName), "IxSelfMap");
        (void)StringCchCopyA(record.ModuleName, RTL_NUMBER_OF(record.ModuleName),
                             entry.Owner[0] != '\0' ? entry.Owner : "Runtime");

        const std::size_t sampleChars = strnlen_s(entry.Name, RTL_NUMBER_OF(entry.Name));
        if (sampleChars != 0)
        {
            const std::size_t sampleBytes = std::min<std::size_t>(sampleChars, RTL_NUMBER_OF(record.DataSample));
            CopyMemory(record.DataSample, entry.Name, sampleBytes);
            record.DataSize = static_cast<std::uint32_t>(sampleBytes);
        }
        (void)IXIPC::PublishHookEvent(record);
    }

    static void CollectIxIndirectHandleSelfMap(IxSelfMapEntry *entries, std::size_t capacity,
                                                 std::uint32_t &count, std::uint32_t &truncated) noexcept
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
            (void)StringCchPrintfA(name, RTL_NUMBER_OF(name), "ihr.%s slot=%zu tag=0x%08lX gen=0x%08lX",
                                   IxSelfMapIhrTypeName(handle.Type), i + 1,
                                   static_cast<unsigned long>(handle.TagHash),
                                   static_cast<unsigned long>(handle.Generation));
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_INDIRECT_HANDLE,
                                      "IHR", name, reinterpret_cast<std::uint64_t>(pointer), handle.Size,
                                      handle.Flags | IX_SELF_MAP_FLAG_REFERENCE,
                                      static_cast<std::uint64_t>(i + 1),
                                      (static_cast<std::uint64_t>(handle.Type) << 32) | handle.TagHash);
        }
        ReleaseSRWLockShared(&g_IndirectHandleLock);
    }

    static void CollectIxHookPatchSelfMap(IxSelfMapEntry *entries, std::size_t capacity, std::uint32_t &count,
                                            std::uint32_t &truncated) noexcept
    {
        constexpr std::size_t kMaxNtPatches = 64;
        NtHookPatchInfo ntPatches[kMaxNtPatches]{};
        std::size_t ntPatchCount = IxCollectNtHookPatchInfos(ntPatches, kMaxNtPatches);
        for (std::size_t i = 0; i < ntPatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_HOOK_PATCH,
                                      "HookPatch", ntPatches[i].HookName ? ntPatches[i].HookName : "nt",
                                      reinterpret_cast<std::uint64_t>(ntPatches[i].PatchAddress),
                                      static_cast<std::uint64_t>(ntPatches[i].PatchSize),
                                      IX_HOOK_PATCH_FLAG_NT_INLINE | IX_SELF_MAP_FLAG_GUARDED, 0,
                                      IX_HOOK_PATCH_FLAG_NT_INLINE);
        }

        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockPatchCount = IxCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockPatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_HOOK_PATCH,
                                      "HookPatch", winsockPatches[i].HookName ? winsockPatches[i].HookName : "winsock",
                                      reinterpret_cast<std::uint64_t>(winsockPatches[i].PatchAddress),
                                      static_cast<std::uint64_t>(winsockPatches[i].PatchSize),
                                      winsockPatches[i].Flags | IX_SELF_MAP_FLAG_GUARDED, 0,
                                      winsockPatches[i].Flags);
        }

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiPatchCount = IxCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiPatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_HOOK_PATCH,
                                      "HookPatch", kiPatches[i].HookName ? kiPatches[i].HookName : "ki",
                                      reinterpret_cast<std::uint64_t>(kiPatches[i].PatchAddress),
                                      static_cast<std::uint64_t>(kiPatches[i].PatchSize),
                                      kiPatches[i].Flags | IX_SELF_MAP_FLAG_GUARDED, 0, kiPatches[i].Flags);
        }

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t modulePatchCount = IxCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < modulePatchCount; ++i)
        {
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_HOOK_PATCH,
                                      "HookPatch", modulePatches[i].HookName ? modulePatches[i].HookName : "module",
                                      reinterpret_cast<std::uint64_t>(modulePatches[i].PatchAddress),
                                      static_cast<std::uint64_t>(modulePatches[i].PatchSize),
                                      modulePatches[i].Flags | IX_SELF_MAP_FLAG_GUARDED, 0,
                                      modulePatches[i].Flags);
        }
    }

    static void CollectIxRuntimeSelfMap(IxSelfMapEntry *entries, std::size_t capacity, std::uint32_t &count,
                                          std::uint32_t &truncated) noexcept
    {
        auto addRuntime = [&](const char *name, const void *address, std::uint64_t size, std::uint32_t flags = 0,
                              std::uint64_t reference0 = 0, std::uint64_t reference1 = 0) noexcept {
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_RUNTIME_STATE,
                                      "Runtime", name, reinterpret_cast<std::uint64_t>(address), size,
                                      flags | IX_SELF_MAP_FLAG_OWNED, reference0, reference1);
        };

        addRuntime("runtime.primed", &g_RuntimePrimed, sizeof(g_RuntimePrimed));
        addRuntime("runtime.initialized", &g_RuntimeInitialized, sizeof(g_RuntimeInitialized));
        addRuntime("runtime.workerStarted", &g_RuntimeWorkerStarted, sizeof(g_RuntimeWorkerStarted));
        addRuntime("runtime.readyMask", &g_LastPublishedHookReadyMask, sizeof(g_LastPublishedHookReadyMask),
                   0, g_LastPublishedHookReadyMask.load(std::memory_order_acquire), IXIPC_HOOK_READY_REQUIRED_MASK);
        addRuntime("runtime.vehArgs", &g_RuntimeVehArgs, sizeof(g_RuntimeVehArgs));
        addRuntime("runtime.winsockController", &g_WinsockController, sizeof(g_WinsockController),
                   g_WinsockInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.ntController", &g_NtHookController, sizeof(g_NtHookController),
                   g_NtInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.kiController", &g_KiHookController, sizeof(g_KiHookController),
                   g_KiInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.moduleController", &g_ModuleHookController, sizeof(g_ModuleHookController),
                   g_ModuleInitialized ? IX_SELF_MAP_FLAG_REFERENCE : 0);
        addRuntime("runtime.indirectHandleTable", &g_IndirectHandles, sizeof(g_IndirectHandles),
                   IX_SELF_MAP_FLAG_GUARDED, kMaxIndirectHandles, g_IndirectHandleGeneration);
        addRuntime("runtime.launchGateCallbacks", &g_LaunchGateCallbacks, sizeof(g_LaunchGateCallbacks));
        addRuntime("runtime.launchGatePages", &g_LaunchGatePages, sizeof(g_LaunchGatePages),
                   IX_SELF_MAP_FLAG_GUARDED, g_LaunchGatePageCount, kLaunchGateMaxPages);
        addRuntime("runtime.launchGateParkContexts", &g_LaunchGateParkContexts, sizeof(g_LaunchGateParkContexts),
                   IX_SELF_MAP_FLAG_GUARDED, kLaunchGateMaxParkContexts, 0);
        addRuntime("runtime.launchGateReadyEvent", &g_LaunchGateReadyEvent, sizeof(g_LaunchGateReadyEvent), 0,
                   reinterpret_cast<std::uint64_t>(g_LaunchGateReadyEvent), 0);

        for (std::size_t i = 0; i < g_LaunchGatePageCount && i < kLaunchGateMaxPages; ++i)
        {
            const LaunchGatePage &page = g_LaunchGatePages[i];
            IxIhrResolved resolved{};
            if (!ResolveIndirectHandle(page.BaseToken, IxIhrType::LaunchGatePage, resolved))
            {
                continue;
            }

            char name[IXIPC_MAX_HOOK_API_NAME]{};
            (void)StringCchPrintfA(name, RTL_NUMBER_OF(name), "launchGate.page%zu trap=0x%p kind=%lu", i,
                                   page.TrapAddress, static_cast<unsigned long>(page.TrapKind));
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_LAUNCH_GATE_PAGE,
                                      "LaunchGate", name, reinterpret_cast<std::uint64_t>(resolved.Pointer),
                                      resolved.Size ? resolved.Size : kLaunchGatePageSize,
                                      resolved.Flags | IX_SELF_MAP_FLAG_GUARDED,
                                      reinterpret_cast<std::uint64_t>(page.TrapAddress), page.TrapIndex);
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
            (void)StringCchPrintfA(name, RTL_NUMBER_OF(name), "launchGate.park%zu tid=%lu state=%ld", i,
                                   static_cast<unsigned long>(park.ThreadId), static_cast<long>(state));
            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_LAUNCH_GATE_CONTEXT,
                                      "LaunchGate", name, reinterpret_cast<std::uint64_t>(&park), sizeof(park),
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

            (void)AddIxSelfMapEntry(entries, capacity, count, truncated, IX_SELF_MAP_KIND_SYSCALL_STUB,
                                      "NtStub", stubs[i].HookName ? stubs[i].HookName : "ntStub",
                                      reinterpret_cast<std::uint64_t>(stubs[i].StubBase),
                                      static_cast<std::uint64_t>(stubs[i].StubSize),
                                      IX_SELF_MAP_FLAG_EXECUTABLE | IX_SELF_MAP_FLAG_OWNED |
                                          IX_SELF_MAP_FLAG_GUARDED,
                                      i + 1, 0);
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
        (void)StringCchPrintfA(summaryName, RTL_NUMBER_OF(summaryName),
                               "summary entries=%lu truncated=%lu ready=0x%08lX signature=0x%llX",
                               static_cast<unsigned long>(count), static_cast<unsigned long>(truncated),
                               static_cast<unsigned long>(initMask), static_cast<unsigned long long>(signature));
        (void)AddIxSelfMapEntry(entries, RTL_NUMBER_OF(entries), count, truncated,
                                  IX_SELF_MAP_KIND_SNAPSHOT_SUMMARY, "Runtime", summaryName,
                                  reinterpret_cast<std::uint64_t>(&PublishIxSelfMapSnapshotBestEffort), count,
                                  (truncated != 0 ? IX_SELF_MAP_FLAG_TRUNCATED : 0u) |
                                      IX_SELF_MAP_FLAG_OWNED,
                                  signature, initMask);

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
                     name != nullptr ? name : L"<unnamed>", manualReset ? 1u : 0u, initialState ? 1u : 0u,
                     static_cast<unsigned long>(desiredAccess), static_cast<unsigned long>(err));
            SetLastError(err);
        }
        else
        {
            IxDbgLog("NativeCreateEvent: success name=%ls handle=%p access=0x%08lX gle=%lu",
                     name != nullptr ? name : L"<unnamed>", eventHandle, static_cast<unsigned long>(desiredAccess),
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
            if (!NtSucceeded(rtlCreateUserThread(CurrentProcessHandle(), nullptr, FALSE, 0, nullptr, nullptr,
                                                 startRoutine, parameter, &threadHandle, &clientId)))
            {
                return nullptr;
            }
            return threadHandle;
        }

        if (!NtSucceeded(fn(&threadHandle, THREAD_ALL_ACCESS, nullptr, CurrentProcessHandle(), startRoutine, parameter,
                            0, 0, 0, 0, nullptr)))
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

        IC_STACKTRACE::SetAnalysisSubjectMetadata(subjectKind, subjectKind == 1 ? subjectPath : nullptr,
                                                  subjectKind == 1 ? hostPath : nullptr);
        if (subjectKind == 1)
        {
            IxDbgLog("InitializeAnalysisSubjectClassifier: kind=DLL subject=%ls host=%ls",
                     subjectPath[0] != L'\0' ? subjectPath : L"<unset>", hostPath[0] != L'\0' ? hostPath : L"<unset>");
        }
    }

    static void FormatVehStackSummary(const ix::IX::Event &e, char *stackSummary,
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

            HRESULT hr = StringCchPrintfExA(stackSummary + offset, stackSummaryChars - offset, nullptr, nullptr,
                                            STRSAFE_IGNORE_NULLS, "%p", e.stack[i]);
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
            line, RTL_NUMBER_OF(line),
            "[VEH] crash-exception channel=%s code=0x%08lX flags=0x%08lX fault=%p pid=%lu tid=%lu module=%s info0=0x%llX info1=0x%llX rip=0x%llX rsp=0x%llX rbp=0x%llX rax=0x%llX rcx=0x%llX rdx=0x%llX r10=0x%llX eflags=0x%llX frames=%hu stack=%s\n",
            channel ? channel : "unknown", static_cast<unsigned long>(e.exception_code),
            static_cast<unsigned long>(e.exception_flags), e.exception_address, static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid), (moduleName && moduleName[0] != '\0') ? moduleName : "unknown",
            static_cast<unsigned long long>(e.exception_info_count > 0 ? e.exception_info[0] : 0),
            static_cast<unsigned long long>(e.exception_info_count > 1 ? e.exception_info[1] : 0),
#if defined(_M_X64)
            static_cast<unsigned long long>(e.rip), static_cast<unsigned long long>(e.rsp),
            static_cast<unsigned long long>(e.rbp), static_cast<unsigned long long>(e.rax),
            static_cast<unsigned long long>(e.rcx), static_cast<unsigned long long>(e.rdx),
            static_cast<unsigned long long>(e.r10), static_cast<unsigned long long>(e.eflags),
#else
            0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull,
#endif
            e.stack_frame_count, stackSummary[0] != '\0' ? stackSummary : "none");

        IxInternalScope scope;
        OutputDebugStringA(line);
    }

    static void PublishVehExceptionEvent(const char *channel, const ix::IX::Event &e, const char *moduleName) noexcept
    {
        if (e.exception_code == STATUS_GUARD_PAGE_VIOLATION || IsDebugPrintExceptionCode(e.exception_code))
        {
            return;
        }

        IXIPC_HOOK_EVENT record{};
        record.Kind =
            e.is_target_module ? IxIpcHookEventExceptionLowNoise : IxIpcHookEventExceptionHighPriv;
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
        (void)StringCchCopyA(record.ApiName, RTL_NUMBER_OF(record.ApiName),
                             e.is_memory_fault           ? "UsermodeMemoryFault"
                             : IsTrapFlagOrSingleStep(e) ? "UsermodeSingleStep"
                                                         : "UsermodeException");
        (void)StringCchCopyA(record.ModuleName, RTL_NUMBER_OF(record.ModuleName),
                             (moduleName && moduleName[0] != '\0') ? moduleName : "unknown");

        EmitVehCrashDebugLine(channel, e, moduleName);
        (void)IXIPC::PublishHookEventSynchronously(record);
    }

    static void LogVehExceptionEvent(const char *channel, const ix::IX::Event &e) noexcept
    {
        if (e.exception_code == STATUS_GUARD_PAGE_VIOLATION || IsDebugPrintExceptionCode(e.exception_code))
        {
            return;
        }

        char moduleName[96]{};
        if (e.module_basename_lower[0] != L'\0')
        {
            (void)WideCharToMultiByte(CP_UTF8, 0, e.module_basename_lower, -1, moduleName, RTL_NUMBER_OF(moduleName),
                                      nullptr, nullptr);
        }
        else
        {
            (void)StringCchCopyA(moduleName, RTL_NUMBER_OF(moduleName), "unknown");
        }

        char stackSummary[256]{};
        FormatVehStackSummary(e, stackSummary, RTL_NUMBER_OF(stackSummary));

        IxDbgLog(
            "[VEH] veh-exception channel=%s code=0x%08lX flags=0x%08lX addr=%p pid=%lu tid=%lu target=%u memory=%u noncontinuable=%u module=%s infoCount=%lu info0=0x%llX info1=0x%llX stack=%s",
            channel ? channel : "unknown", static_cast<unsigned long>(e.exception_code),
            static_cast<unsigned long>(e.exception_flags), e.exception_address, static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid), e.is_target_module ? 1u : 0u, e.is_memory_fault ? 1u : 0u,
            e.is_noncontinuable ? 1u : 0u, moduleName, static_cast<unsigned long>(e.exception_info_count),
            static_cast<unsigned long long>(e.exception_info_count > 0 ? e.exception_info[0] : 0),
            static_cast<unsigned long long>(e.exception_info_count > 1 ? e.exception_info[1] : 0),
            stackSummary[0] != '\0' ? stackSummary : "none");
#if defined(_M_X64)
        IxDbgLog(
            "[VEH] context rip=0x%llX rsp=0x%llX rbp=0x%llX rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rsi=0x%llX rdi=0x%llX r8=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX r12=0x%llX r13=0x%llX r14=0x%llX r15=0x%llX eflags=0x%llX",
            static_cast<unsigned long long>(e.rip), static_cast<unsigned long long>(e.rsp),
            static_cast<unsigned long long>(e.rbp), static_cast<unsigned long long>(e.rax),
            static_cast<unsigned long long>(e.rbx), static_cast<unsigned long long>(e.rcx),
            static_cast<unsigned long long>(e.rdx), static_cast<unsigned long long>(e.rsi),
            static_cast<unsigned long long>(e.rdi), static_cast<unsigned long long>(e.r8),
            static_cast<unsigned long long>(e.r9), static_cast<unsigned long long>(e.r10),
            static_cast<unsigned long long>(e.r11), static_cast<unsigned long long>(e.r12),
            static_cast<unsigned long long>(e.r13), static_cast<unsigned long long>(e.r14),
            static_cast<unsigned long long>(e.r15), static_cast<unsigned long long>(e.eflags));
#endif

        if (e.is_noncontinuable || IsTrapFlagOrSingleStep(e))
        {
            PublishVehExceptionEvent(channel, e, moduleName);
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
        LogVehExceptionEvent("memory-fault", e);
        if (LaunchGateHandleFault(ep))
        {
            return true;
        }

        if (e.exception_code != STATUS_GUARD_PAGE_VIOLATION)
        {
            char moduleName[96]{};
            if (e.module_basename_lower[0] != L'\0')
            {
                (void)WideCharToMultiByte(CP_UTF8, 0, e.module_basename_lower, -1, moduleName,
                                          RTL_NUMBER_OF(moduleName), nullptr, nullptr);
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
    IxUnregisterVectoredExceptionHandler();
    ResetControlFlowGuardPolicyCache();
    ResetProcessInstrumentationCallbackState();
    LaunchGateShutdown();
    g_RuntimeInitialized.store(false, std::memory_order_release);
    g_RuntimeWorkerStarted.store(false, std::memory_order_release);
    g_LastPublishedHookReadyMask.store(0, std::memory_order_release);
}
