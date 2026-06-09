#include "controller.h"
#include "stack_fabricate.h"

#include "../../ABI/blind_ipc.h"

#include <cstring>
#include <utility>

namespace IX_RUNTIME_INTERNAL
{
    void SignalHookEventsPending() noexcept;
    bool ShouldSanitizeModuleHookStackByPolicy(const char *name) noexcept;
} // namespace IX_RUNTIME_INTERNAL

namespace
{
    constexpr std::size_t kMaxQueuedHookEvents = 512;
    constexpr std::size_t kMaxQueueDedupeScan = 128;
    constexpr std::size_t kMaxCapturedPayloadBytes = IXIPC_MAX_HOOK_DATA_SAMPLE;
    constexpr std::uint32_t kMaxCapturedBufferCount = 16;
    constexpr std::uint32_t kRepeatCountLimit = 0xFFFFFFFFu;

#if defined(_MSC_VER)
#define IX_FORCEINLINE __forceinline
#else
#define IX_FORCEINLINE inline
#endif

    IX_FORCEINLINE std::size_t MinSize(std::size_t left, std::size_t right) noexcept
    {
        return left < right ? left : right;
    }

    IX_FORCEINLINE void IncrementRepeat(std::uint32_t &value) noexcept
    {
        if (value != kRepeatCountLimit)
        {
            ++value;
        }
    }

    IX_FORCEINLINE bool ArgsEqual(const std::uint64_t *left, const std::uint64_t *right, std::size_t count) noexcept
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }
        return true;
    }

    IX_FORCEINLINE bool BytesEqual(const std::uint8_t *left,
                                   std::size_t leftSize,
                                   const std::uint8_t *right,
                                   std::size_t rightSize) noexcept
    {
        if (leftSize != rightSize)
        {
            return false;
        }
        if (leftSize == 0)
        {
            return true;
        }
        return left != nullptr && right != nullptr && std::memcmp(left, right, leftSize) == 0;
    }

    bool SafeCopyBytes(void *destination, std::size_t destinationSize, const void *source, std::size_t bytes) noexcept
    {
        if (destination == nullptr || source == nullptr || bytes == 0 || bytes > destinationSize)
        {
            return false;
        }

        __try
        {
            std::memcpy(destination, source, bytes);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(destination, 0, destinationSize);
            return false;
        }
    }

    IX_FORCEINLINE bool CStringsEqual(const char *left, const char *right) noexcept
    {
        if (left == right)
        {
            return true;
        }
        if (left == nullptr || right == nullptr)
        {
            return false;
        }
        return std::strcmp(left, right) == 0;
    }

    IX_FORCEINLINE bool IsExecutableProtect(std::uint64_t protect) noexcept
    {
        switch (static_cast<DWORD>(protect) & 0xFFu)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    IX_FORCEINLINE bool IsRemoteTarget(std::uint64_t processHandle, std::uint64_t targetPid) noexcept
    {
        DWORD selfPid = GetCurrentProcessId();
        if (targetPid != 0 && targetPid <= MAXDWORD)
        {
            return static_cast<DWORD>(targetPid) != selfPid;
        }
        return processHandle != 0 && processHandle != 0xFFFFFFFFFFFFFFFFull;
    }

    bool NtEventIsInteresting(const NtCapturedEvent &event) noexcept
    {
        switch (event.Operation)
        {
        case NtOperation::NtCreateThread:
        case NtOperation::NtCreateThreadEx:
        case NtOperation::NtWriteVirtualMemory:
        case NtOperation::NtSetContextThread:
        case NtOperation::NtQueueApcThread:
        case NtOperation::NtQueueApcThreadEx:
        case NtOperation::NtQueueApcThreadEx2:
        case NtOperation::NtCreateSection:
        case NtOperation::NtTerminateProcess:
        case NtOperation::NtMapViewOfSection:
        case NtOperation::NtMapViewOfSectionEx:
        case NtOperation::NtUnmapViewOfSection:
        case NtOperation::NtUnmapViewOfSectionEx:
            return true;
        case NtOperation::NtAllocateVirtualMemory:
            return IsExecutableProtect(event.Args[5]) || IsRemoteTarget(event.Args[0], event.Args[6]);
        case NtOperation::NtAllocateVirtualMemoryEx:
            return IsExecutableProtect(event.Args[4]) || IsRemoteTarget(event.Args[0], event.Args[7]);
        case NtOperation::NtProtectVirtualMemory:
            return IsExecutableProtect(event.Args[3]) || IsRemoteTarget(event.Args[0], event.Args[7]);
        default:
            return false;
        }
    }

    bool NtEventKeyEquals(const NtCapturedEvent &left, const NtCapturedEvent &right) noexcept
    {
        if (left.Operation != right.Operation || left.Status != right.Status)
        {
            return false;
        }
        if (((left.PolicyFlags | right.PolicyFlags) & IXIPC_HOOK_RULE_FLAG_REGISTERS) != 0)
        {
            return false;
        }

        switch (left.Operation)
        {
        case NtOperation::NtAllocateVirtualMemory:
            return left.Args[1] == right.Args[1] && left.Args[3] == right.Args[3] && left.Args[4] == right.Args[4] &&
                   left.Args[5] == right.Args[5] && left.Args[6] == right.Args[6];
        case NtOperation::NtAllocateVirtualMemoryEx:
            return left.Args[1] == right.Args[1] && left.Args[2] == right.Args[2] && left.Args[3] == right.Args[3] &&
                   left.Args[4] == right.Args[4] && left.Args[7] == right.Args[7];
        case NtOperation::NtProtectVirtualMemory:
            return left.Args[1] == right.Args[1] && left.Args[2] == right.Args[2] && left.Args[3] == right.Args[3] &&
                   left.Args[4] == right.Args[4] && left.Args[7] == right.Args[7];
        case NtOperation::NtWriteVirtualMemory:
            return left.Args[1] == right.Args[1] && left.Args[3] == right.Args[3] && left.Args[5] == right.Args[5] &&
                   left.Args[6] == right.Args[6] &&
                   BytesEqual(left.DataSample, left.DataSize, right.DataSample, right.DataSize);
        case NtOperation::NtReadVirtualMemory:
            return left.Caller == right.Caller && left.Args[1] == right.Args[1] && left.Args[3] == right.Args[3] &&
                   left.Args[7] == right.Args[7];
        case NtOperation::NtQueryVirtualMemory:
            return left.Caller == right.Caller && left.Args[1] == right.Args[1] && left.Args[2] == right.Args[2] &&
                   left.Args[4] == right.Args[4];
        case NtOperation::NtQuerySystemInformation:
            return left.Caller == right.Caller && left.Args[0] == right.Args[0] && left.Args[2] == right.Args[2];
        case NtOperation::NtQuerySystemInformationEx:
            return left.Caller == right.Caller && left.Args[0] == right.Args[0] && left.Args[2] == right.Args[2] &&
                   left.Args[4] == right.Args[4];
        default:
            return left.Caller == right.Caller && CStringsEqual(left.FunctionName, right.FunctionName) &&
                   ArgsEqual(left.Args, right.Args, RTL_NUMBER_OF(left.Args));
        }
    }

    bool WinsockEventIsInteresting(const WinsockCapturedEvent &event) noexcept
    {
        return event.Operation == WinsockOperation::Connect || event.Operation == WinsockOperation::WsaConnect ||
               event.Operation == WinsockOperation::GetAddrInfoW;
    }

    bool WinsockEventKeyEquals(const WinsockCapturedEvent &left, const WinsockCapturedEvent &right) noexcept
    {
        return left.Operation == right.Operation && left.Socket == right.Socket && left.Caller == right.Caller &&
               ArgsEqual(left.Args, right.Args, RTL_NUMBER_OF(left.Args)) &&
               BytesEqual(left.DataSample, left.DataSize, right.DataSample, right.DataSize);
    }

    bool KiEventIsInteresting(const KiCapturedEvent &) noexcept
    {
        return true;
    }

    bool KiEventKeyEquals(const KiCapturedEvent &left, const KiCapturedEvent &right) noexcept
    {
        return left.Caller == right.Caller && left.StackPointer == right.StackPointer &&
               CStringsEqual(left.StubName, right.StubName);
    }

    bool ModuleEventIsInteresting(const ModuleCapturedEvent &) noexcept
    {
        return true;
    }

    bool ModuleEventKeyEquals(const ModuleCapturedEvent &left, const ModuleCapturedEvent &right) noexcept
    {
        return left.Operation == right.Operation && left.ModuleHandle == right.ModuleHandle &&
               left.Caller == right.Caller && CStringsEqual(left.FunctionName, right.FunctionName) &&
               CStringsEqual(left.SourceModule, right.SourceModule) &&
               ArgsEqual(left.Args, right.Args, RTL_NUMBER_OF(left.Args)) &&
               BytesEqual(left.NameSample, left.NameSampleSize, right.NameSample, right.NameSampleSize);
    }

    template <typename T, typename EqualFn, typename InterestingFn>
    bool TryQueueCoalescedEvent(
        std::mutex &mutex, std::vector<T> &queue, T &&event, EqualFn equals, InterestingFn isInteresting) noexcept
    {
        bool queued = false;
        try
        {
            std::lock_guard<std::mutex> lock(mutex);
            std::size_t checked = 0;
            for (auto it = queue.rbegin(); it != queue.rend() && checked < kMaxQueueDedupeScan; ++it, ++checked)
            {
                if (equals(*it, event))
                {
                    IncrementRepeat(it->RepeatCount);
                    return true;
                }
            }

            if (queue.size() < kMaxQueuedHookEvents)
            {
                queue.push_back(std::move(event));
                queued = true;
            }
            else
            {
                const bool incomingInteresting = isInteresting(event);
                if (incomingInteresting)
                {
                    for (auto it = queue.begin(); it != queue.end(); ++it)
                    {
                        if (!isInteresting(*it))
                        {
                            *it = std::move(event);
                            queued = true;
                            break;
                        }
                    }
                }

                if (!queued && !queue.empty())
                {
                    queue.erase(queue.begin());
                    queue.push_back(std::move(event));
                    queued = true;
                }
            }
        }
        catch (...)
        {
            return false;
        }

        if (queued)
        {
            IX_RUNTIME_INTERNAL::SignalHookEventsPending();
        }
        return queued;
    }

    template <typename T> void ReserveQueueStorage(std::vector<T> &queue)
    {
        if (queue.capacity() < kMaxQueuedHookEvents)
        {
            queue.reserve(kMaxQueuedHookEvents);
        }
    }

    template <typename T> std::vector<T> ConsumeQueuedEvents(std::mutex &mutex, std::vector<T> &queue)
    {
        std::vector<T> replacement;
        ReserveQueueStorage(replacement);

        std::vector<T> events;
        {
            std::lock_guard<std::mutex> lock(mutex);
            events.swap(queue);
            queue.swap(replacement);
        }
        return events;
    }

    template <typename T> void ConsumeQueuedEvents(std::mutex &mutex, std::vector<T> &queue, std::vector<T> &out)
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            out.clear();
            out.swap(queue);
            ReserveQueueStorage(queue);
        }
    }
} // namespace

bool WinsockHookController::s_Initialized = false;
std::mutex WinsockHookController::s_QueueMutex;
std::vector<WinsockCapturedEvent> WinsockHookController::s_Queue;

bool WinsockHookController::Initialize() noexcept
{
    try
    {
        if (s_Initialized)
        {
            return true;
        }

        {
            std::lock_guard<std::mutex> lock(s_QueueMutex);
            ReserveQueueStorage(s_Queue);
        }

        if (!IxSetWinsockHook(&WinsockHookController::IxWinsockHookCallback))
        {
            return false;
        }

        s_Initialized = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void WinsockHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    IxRemoveWinsockHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<WinsockCapturedEvent> WinsockHookController::ConsumeEvents()
{
    return ConsumeQueuedEvents(s_QueueMutex, s_Queue);
}

void WinsockHookController::ConsumeEvents(std::vector<WinsockCapturedEvent> &out)
{
    ConsumeQueuedEvents(s_QueueMutex, s_Queue, out);
}

void WinsockHookController::IxWinsockHookCallback(const WinsockHookContext &context) noexcept
{
    try
    {
        EnqueueEvent(context);
    }
    catch (...)
    {
    }
}

void WinsockHookController::EnqueueEvent(const WinsockHookContext &context)
{
    WinsockCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Socket = context.Socket;
    evt.Operation = context.Operation;
    evt.Caller = context.Caller;
    for (std::size_t i = 0; i < RTL_NUMBER_OF(evt.Args); ++i)
    {
        evt.Args[i] = context.Args[i];
    }

    if (context.Buffers && context.BufferCount > 0)
    {
        std::uint8_t scratch[kMaxCapturedPayloadBytes]{};
        std::size_t totalLen = 0;
        const std::uint32_t bufferCount =
            context.BufferCount < kMaxCapturedBufferCount ? context.BufferCount : kMaxCapturedBufferCount;
        for (std::uint32_t i = 0; i < bufferCount && totalLen < kMaxCapturedPayloadBytes; ++i)
        {
            WinsockHookBuffer bufferView{};
            if (!SafeCopyBytes(&bufferView, sizeof(bufferView), &context.Buffers[i], sizeof(bufferView)) ||
                bufferView.Data == nullptr || bufferView.Length == 0)
            {
                continue;
            }

            const std::size_t bytesToCopy =
                MinSize(static_cast<std::size_t>(bufferView.Length), kMaxCapturedPayloadBytes - totalLen);
            if (SafeCopyBytes(scratch + totalLen, sizeof(scratch) - totalLen, bufferView.Data, bytesToCopy))
            {
                totalLen += bytesToCopy;
            }
        }

        if (totalLen != 0)
        {
            evt.DataSize = static_cast<std::uint32_t>(totalLen);
            std::memcpy(evt.DataSample, scratch, totalLen);
        }
    }

    IC_STACKTRACE::Capture(evt.Stack, 2);

    (void)TryQueueCoalescedEvent(
        s_QueueMutex, s_Queue, std::move(evt), WinsockEventKeyEquals, WinsockEventIsInteresting);
}

bool NtHookController::s_Initialized = false;
std::mutex NtHookController::s_QueueMutex;
std::vector<NtCapturedEvent> NtHookController::s_Queue;

bool NtHookController::Initialize() noexcept
{
    try
    {
        if (s_Initialized)
        {
            return true;
        }

        {
            std::lock_guard<std::mutex> lock(s_QueueMutex);
            ReserveQueueStorage(s_Queue);
        }

        if (!IxSetNtHook(&NtHookController::IxNtHookCallback))
        {
            return false;
        }

        s_Initialized = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void NtHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    IxRemoveNtHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<NtCapturedEvent> NtHookController::ConsumeEvents()
{
    return ConsumeQueuedEvents(s_QueueMutex, s_Queue);
}

void NtHookController::ConsumeEvents(std::vector<NtCapturedEvent> &out)
{
    ConsumeQueuedEvents(s_QueueMutex, s_Queue, out);
}

void NtHookController::IxNtHookCallback(const NtHookContext &context) noexcept
{
    try
    {
        EnqueueEvent(context);
    }
    catch (...)
    {
    }
}

void NtHookController::EnqueueEvent(const NtHookContext &context)
{
    NtCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Operation = context.Operation;
    evt.FunctionName = context.FunctionName;
    evt.Caller = context.Caller;
    evt.Status = context.Status;
    evt.PolicyAction = context.PolicyAction;
    evt.PolicyFlags = context.PolicyFlags;
    for (std::size_t i = 0; i < 8; ++i)
    {
        evt.Args[i] = context.Args[i];
    }
    evt.DataSize = context.DataSize;
    if (evt.DataSize > sizeof(evt.DataSample))
    {
        evt.DataSize = sizeof(evt.DataSample);
    }
    if (evt.DataSize != 0)
    {
        std::memcpy(evt.DataSample, context.DataSample, evt.DataSize);
    }
    evt.HasRegisters = context.HasRegisters;
    evt.Registers = context.Registers;

    evt.Stack = context.Stack;
    if ((evt.PolicyFlags & IXIPC_HOOK_RULE_FLAG_STACK_FABRICATE) != 0)
    {
        IX_STACK_FABRICATE::SanitizeBlindFrames(evt.Stack);
    }

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), NtEventKeyEquals, NtEventIsInteresting);
}

bool KiHookController::s_Initialized = false;
std::mutex KiHookController::s_QueueMutex;
std::vector<KiCapturedEvent> KiHookController::s_Queue;

bool KiHookController::Initialize() noexcept
{
    try
    {
        if (s_Initialized)
        {
            return true;
        }

        {
            std::lock_guard<std::mutex> lock(s_QueueMutex);
            ReserveQueueStorage(s_Queue);
        }

        if (!IxSetKiHook(&KiHookController::IxKiHookCallback))
        {
            return false;
        }

        s_Initialized = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void KiHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    IxRemoveKiHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<KiCapturedEvent> KiHookController::ConsumeEvents()
{
    return ConsumeQueuedEvents(s_QueueMutex, s_Queue);
}

void KiHookController::ConsumeEvents(std::vector<KiCapturedEvent> &out)
{
    ConsumeQueuedEvents(s_QueueMutex, s_Queue, out);
}

void KiHookController::IxKiHookCallback(const KiHookContext &context) noexcept
{
    try
    {
        EnqueueEvent(context);
    }
    catch (...)
    {
    }
}

void KiHookController::EnqueueEvent(const KiHookContext &context)
{
    KiCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.StubName = context.StubName;
    evt.Caller = context.Caller;
    evt.StackPointer = context.StackPointer;
    IC_STACKTRACE::Capture(evt.Stack, 2);

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), KiEventKeyEquals, KiEventIsInteresting);
}

bool ModuleHookController::s_Initialized = false;
std::mutex ModuleHookController::s_QueueMutex;
std::vector<ModuleCapturedEvent> ModuleHookController::s_Queue;

bool ModuleHookController::Initialize() noexcept
{
    try
    {
        if (s_Initialized)
        {
            return true;
        }

        {
            std::lock_guard<std::mutex> lock(s_QueueMutex);
            ReserveQueueStorage(s_Queue);
        }

        if (!IxSetModuleHook(&ModuleHookController::IxModuleHookCallback))
        {
            return false;
        }

        s_Initialized = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void ModuleHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    IxRemoveModuleHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<ModuleCapturedEvent> ModuleHookController::ConsumeEvents()
{
    return ConsumeQueuedEvents(s_QueueMutex, s_Queue);
}

void ModuleHookController::ConsumeEvents(std::vector<ModuleCapturedEvent> &out)
{
    ConsumeQueuedEvents(s_QueueMutex, s_Queue, out);
}

void ModuleHookController::IxModuleHookCallback(const ModuleHookContext &context) noexcept
{
    try
    {
        EnqueueEvent(context);
    }
    catch (...)
    {
    }
}

void ModuleHookController::EnqueueEvent(const ModuleHookContext &context)
{
    ModuleCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Operation = context.Operation;
    evt.FunctionName = context.FunctionName;
    evt.SourceModule = context.SourceModule;
    evt.Caller = context.Caller;
    evt.ModuleHandle = context.ModuleHandle;
    for (std::size_t i = 0; i < RTL_NUMBER_OF(evt.Args); ++i)
    {
        evt.Args[i] = context.Args[i];
    }

    if (context.NameBuffer != nullptr && context.NameLength != 0)
    {
        std::uint8_t scratch[kMaxCapturedPayloadBytes]{};
        std::size_t bytesToCopy = MinSize(static_cast<std::size_t>(context.NameLength), kMaxCapturedPayloadBytes);
        if (SafeCopyBytes(scratch, sizeof(scratch), context.NameBuffer, bytesToCopy))
        {
            evt.NameSampleSize = static_cast<std::uint32_t>(bytesToCopy);
            std::memcpy(evt.NameSample, scratch, bytesToCopy);
        }
    }

    IC_STACKTRACE::Capture(evt.Stack, 2);
    if (IX_RUNTIME_INTERNAL::ShouldSanitizeModuleHookStackByPolicy(evt.FunctionName))
    {
        IX_STACK_FABRICATE::SanitizeBlindFrames(evt.Stack);
    }

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), ModuleEventKeyEquals, ModuleEventIsInteresting);
}
