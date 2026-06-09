#include "ws.h"
#include "runtime/runtime_internal.h"
#include "../../ABI/blind_ipc.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>

#include <cstring>
#include <limits>

#pragma intrinsic(_ReturnAddress)

namespace
{
    using WsasendFn =
        INT(WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

    using WsarecvFn =
        INT(WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

    using SendFn = int(WSAAPI *)(SOCKET, const char *, int, int);

    using RecvFn = int(WSAAPI *)(SOCKET, char *, int, int);

    using ConnectFn = int(WSAAPI *)(SOCKET, const sockaddr *, int);

    using WsaConnectFn = int(WSAAPI *)(SOCKET, const sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);

    using GetAddrInfoWFn = INT(WSAAPI *)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);
    using GetAddrInfoAFn = INT(WSAAPI *)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
    using DnsQueryWFn = LONG(WINAPI *)(PCWSTR, WORD, DWORD, PVOID, PVOID *, PVOID *);
    using DnsQueryAFn = LONG(WINAPI *)(PCSTR, WORD, DWORD, PVOID, PVOID *, PVOID *);

    struct HookEntry
    {
        const char *ModuleName;
        const char *FunctionName;
        void **OriginalFunction;
        void *HookFunction;
    };

    static WsasendFn g_OriginalWsasend = nullptr;
    static WsarecvFn g_OriginalWsarecv = nullptr;
    static SendFn g_OriginalSend = nullptr;
    static RecvFn g_OriginalRecv = nullptr;
    static ConnectFn g_OriginalConnect = nullptr;
    static WsaConnectFn g_OriginalWsaConnect = nullptr;
    static GetAddrInfoWFn g_OriginalGetAddrInfoW = nullptr;
    static GetAddrInfoAFn g_OriginalGetAddrInfoA = nullptr;
    static DnsQueryWFn g_OriginalDnsQueryW = nullptr;
    static DnsQueryAFn g_OriginalDnsQueryA = nullptr;
    static WinsockHookCallback g_ActiveCallback = nullptr;
    static bool g_HooksInstalled = false;
    static volatile LONG g_InHook = 0;

    struct SocketEndpointEntry
    {
        SOCKET socket;
        UINT16 family;
        UINT16 port;
        UINT32 addrNbo;
    };

    static constexpr std::size_t kEndpointCacheSlots = 64;
    static SocketEndpointEntry g_EndpointCache[kEndpointCacheSlots]{};
    static std::size_t g_EndpointCacheHead = 0;
    static SRWLOCK g_EndpointCacheLock = SRWLOCK_INIT;

    static void EndpointCacheStore(SOCKET s, const sockaddr *name, int nameLen) noexcept
    {
        if (s == INVALID_SOCKET || name == nullptr || nameLen < 4)
            return;

        SocketEndpointEntry entry{};
        entry.socket = s;
        entry.family = static_cast<UINT16>(name->sa_family);

        if (name->sa_family == AF_INET && nameLen >= static_cast<int>(sizeof(sockaddr_in)))
        {
            const auto *sin = reinterpret_cast<const sockaddr_in *>(name);
            /* Inline byte swap — avoids depending on ntohs from ws2_32.lib which is not linked
               directly in the hook DLL (Winsock is resolved through IAT patching, not the import lib). */
            const auto netPort = sin->sin_port;
            entry.port = static_cast<UINT16>(((netPort & 0x00FFu) << 8) | ((netPort & 0xFF00u) >> 8));
            entry.addrNbo = sin->sin_addr.s_addr;
        }

        AcquireSRWLockExclusive(&g_EndpointCacheLock);
        g_EndpointCache[g_EndpointCacheHead % kEndpointCacheSlots] = entry;
        g_EndpointCacheHead = (g_EndpointCacheHead + 1) % kEndpointCacheSlots;
        ReleaseSRWLockExclusive(&g_EndpointCacheLock);
    }

    static bool EndpointCacheLookup(SOCKET s, SocketEndpointEntry *out) noexcept
    {
        if (s == INVALID_SOCKET || out == nullptr)
            return false;
        bool found = false;
        AcquireSRWLockShared(&g_EndpointCacheLock);
        for (std::size_t i = 0; i < kEndpointCacheSlots; ++i)
        {
            if (g_EndpointCache[i].socket == s && g_EndpointCache[i].family != 0)
            {
                *out = g_EndpointCache[i];
                found = true;
                break;
            }
        }
        ReleaseSRWLockShared(&g_EndpointCacheLock);
        return found;
    }

    struct PatchedIatSlot
    {
        ULONG_PTR *Slot;
        ULONG_PTR OriginalValue;
        void *HookFunction;
        const char *FunctionName;
    };

    static PatchedIatSlot g_PatchedSlots[512]{};
    static std::size_t g_PatchedSlotCount = 0;

    struct WinsockInlinePatchSlot
    {
        void *Target;
        std::size_t PatchSize;
        std::uint8_t OriginalBytes[16];
        void *Trampoline;
        void *HookFunction;
        void **OriginalFunction;
        const char *FunctionName;
        bool Active;
    };

    static WinsockInlinePatchSlot g_InlinePatchSlots[16]{};
    static std::size_t g_InlinePatchSlotCount = 0;
    static SRWLOCK g_WinsockOriginalCallLock = SRWLOCK_INIT;

    static PatchedIatSlot *FindPatchedSlot(ULONG_PTR *slot) noexcept
    {
        if (slot == nullptr)
        {
            return nullptr;
        }

        for (std::size_t i = 0; i < g_PatchedSlotCount; ++i)
        {
            if (g_PatchedSlots[i].Slot == slot)
            {
                return &g_PatchedSlots[i];
            }
        }
        return nullptr;
    }

    static WinsockInlinePatchSlot *FindInlinePatchSlot(void *target) noexcept
    {
        if (target == nullptr)
        {
            return nullptr;
        }

        for (std::size_t i = 0; i < g_InlinePatchSlotCount; ++i)
        {
            if (g_InlinePatchSlots[i].Target == target)
            {
                return &g_InlinePatchSlots[i];
            }
        }
        return nullptr;
    }

    template <typename T> bool SafeReadValue(const void *address, T &out) noexcept
    {
        if (address == nullptr)
        {
            return false;
        }

        __try
        {
            out = *reinterpret_cast<const T *>(address);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    template <typename T> bool SafeWriteValue(void *address, const T &value) noexcept
    {
        if (address == nullptr)
        {
            return false;
        }

        __try
        {
            *reinterpret_cast<T *>(address) = value;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool SafeStringEquals(const char *left, const char *right, bool ignoreCase) noexcept
    {
        if (left == nullptr || right == nullptr)
        {
            return false;
        }

        __try
        {
            return ignoreCase ? (_stricmp(left, right) == 0) : (std::strcmp(left, right) == 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadModuleNtHeaders(HMODULE moduleHandle, std::uint8_t *&base, IMAGE_NT_HEADERS &ntHeaders) noexcept
    {
        if (moduleHandle == nullptr)
        {
            return false;
        }

        base = reinterpret_cast<std::uint8_t *>(moduleHandle);
        IMAGE_DOS_HEADER dosHeader{};
        if (!SafeReadValue(base, dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
            dosHeader.e_lfanew > 0x100000)
        {
            return false;
        }

        auto *ntHeaderAddress = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader.e_lfanew);
        if (!SafeReadValue(ntHeaderAddress, ntHeaders) || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        return true;
    }
    static bool ModuleImportsWinsock(HMODULE moduleHandle)
    {
        std::uint8_t *base = nullptr;
        IMAGE_NT_HEADERS ntHeaders{};
        if (!ReadModuleNtHeaders(moduleHandle, base, ntHeaders))
        {
            return false;
        }

        IMAGE_DATA_DIRECTORY &importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
        {
            return false;
        }

        auto *importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + importDirectory.VirtualAddress);
        const DWORD descriptorLimit = (importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 1;
        const DWORD maxDescriptors = descriptorLimit < 4096 ? descriptorLimit : 4096;

        for (DWORD i = 0; i < maxDescriptors; ++i, ++importDescriptor)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            if (!SafeReadValue(importDescriptor, descriptor) || descriptor.Name == 0)
            {
                break;
            }

            const char *importedModuleName = reinterpret_cast<const char *>(base + descriptor.Name);
            if (SafeStringEquals(importedModuleName, "WS2_32.dll", true) ||
                SafeStringEquals(importedModuleName, "WSOCK32.dll", true) ||
                SafeStringEquals(importedModuleName, "DNSAPI.dll", true))
            {
                return true;
            }
        }

        return false;
    }

    static void TrackPatchedSlot(ULONG_PTR *slot, ULONG_PTR originalValue, void *hookFunction, const char *functionName)
    {
        if (slot == nullptr || hookFunction == nullptr)
        {
            return;
        }

        for (std::size_t i = 0; i < g_PatchedSlotCount; ++i)
        {
            if (g_PatchedSlots[i].Slot == slot)
            {
                if (g_PatchedSlots[i].OriginalValue == 0)
                {
                    g_PatchedSlots[i].OriginalValue = originalValue;
                }
                g_PatchedSlots[i].HookFunction = hookFunction;
                g_PatchedSlots[i].FunctionName = functionName;
                return;
            }
        }

        if (g_PatchedSlotCount < RTL_NUMBER_OF(g_PatchedSlots))
        {
            g_PatchedSlots[g_PatchedSlotCount].Slot = slot;
            g_PatchedSlots[g_PatchedSlotCount].OriginalValue = originalValue;
            g_PatchedSlots[g_PatchedSlotCount].HookFunction = hookFunction;
            g_PatchedSlots[g_PatchedSlotCount].FunctionName = functionName;
            ++g_PatchedSlotCount;
        }
    }

    static void TrackInlinePatch(void *target,
                                 std::size_t patchSize,
                                 const std::uint8_t *originalBytes,
                                 void *trampoline,
                                 void *hookFunction,
                                 void **originalFunction,
                                 const char *functionName) noexcept
    {
        if (target == nullptr || patchSize == 0 || patchSize > 16 || originalBytes == nullptr ||
            trampoline == nullptr || hookFunction == nullptr || originalFunction == nullptr)
        {
            return;
        }

        for (std::size_t i = 0; i < g_InlinePatchSlotCount; ++i)
        {
            if (g_InlinePatchSlots[i].Target == target)
            {
                g_InlinePatchSlots[i].PatchSize = patchSize;
                std::memcpy(g_InlinePatchSlots[i].OriginalBytes, originalBytes, patchSize);
                g_InlinePatchSlots[i].Trampoline = trampoline;
                g_InlinePatchSlots[i].HookFunction = hookFunction;
                g_InlinePatchSlots[i].OriginalFunction = originalFunction;
                g_InlinePatchSlots[i].FunctionName = functionName;
                g_InlinePatchSlots[i].Active = true;
                return;
            }
        }

        if (g_InlinePatchSlotCount < RTL_NUMBER_OF(g_InlinePatchSlots))
        {
            g_InlinePatchSlots[g_InlinePatchSlotCount].Target = target;
            g_InlinePatchSlots[g_InlinePatchSlotCount].PatchSize = patchSize;
            std::memcpy(g_InlinePatchSlots[g_InlinePatchSlotCount].OriginalBytes, originalBytes, patchSize);
            g_InlinePatchSlots[g_InlinePatchSlotCount].Trampoline = trampoline;
            g_InlinePatchSlots[g_InlinePatchSlotCount].HookFunction = hookFunction;
            g_InlinePatchSlots[g_InlinePatchSlotCount].OriginalFunction = originalFunction;
            g_InlinePatchSlots[g_InlinePatchSlotCount].FunctionName = functionName;
            g_InlinePatchSlots[g_InlinePatchSlotCount].Active = true;
            ++g_InlinePatchSlotCount;
        }
    }

    static bool InstallInlineHook(void *target, void *hook, void **originalFunction, const char *functionName) noexcept
    {
        constexpr std::size_t kPatchSize = 16;
        constexpr std::size_t kTrampolineSize = 32;

        if (target == nullptr || hook == nullptr || originalFunction == nullptr)
        {
            return false;
        }

        if (auto *slot = FindInlinePatchSlot(target); slot != nullptr && slot->Active)
        {
            *originalFunction = slot->Trampoline;
            return true;
        }

        auto *dst = static_cast<std::uint8_t *>(target);
        __try
        {
            if (dst[0] == 0x48 && dst[1] == 0xB8 && dst[10] == 0xFF && dst[11] == 0xE0)
            {
                void *existingTarget = *reinterpret_cast<void **>(&dst[2]);
                if (existingTarget == hook)
                {
                    return true;
                }
                return false;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        void *trampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (trampoline == nullptr)
        {
            return false;
        }

        auto *gate = static_cast<std::uint8_t *>(trampoline);
        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        auto restoreTargetProtection = [&]() noexcept
        {
            DWORD temp = 0;
            (void)VirtualProtect(dst, kPatchSize, oldProtect, &temp);
        };

        std::uint8_t originalBytes[16]{};
        __try
        {
            std::memcpy(originalBytes, dst, kPatchSize);
            std::memcpy(gate, dst, kPatchSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            restoreTargetProtection();
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        gate[16] = 0x48;
        gate[17] = 0xB8;
        *reinterpret_cast<void **>(&gate[18]) = dst + kPatchSize;
        gate[26] = 0xFF;
        gate[27] = 0xE0;
        for (std::size_t i = 28; i < kTrampolineSize; ++i)
        {
            gate[i] = 0xCC;
        }

        DWORD trampolineProtect = 0;
        if (!VirtualProtect(trampoline, kTrampolineSize, PAGE_EXECUTE_READ, &trampolineProtect))
        {
            restoreTargetProtection();
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }
        FlushInstructionCache(GetCurrentProcess(), trampoline, kTrampolineSize);

        if (!IX_RUNTIME_INTERNAL::RegisterIxDynamicInstrumentationRange(
                trampoline, kTrampolineSize, IX_INSTRUMENTATION_FLAG_EXECUTABLE_HELPER, "rt.ws.trampoline"))
        {
            restoreTargetProtection();
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD temp = 0;
        (void)VirtualProtect(dst, kPatchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, kPatchSize);

        *originalFunction = trampoline;
        TrackInlinePatch(target, kPatchSize, originalBytes, trampoline, hook, originalFunction, functionName);
        return true;
    }

    static void RemoveInlineHooks() noexcept
    {
        for (std::size_t i = 0; i < g_InlinePatchSlotCount; ++i)
        {
            auto &slot = g_InlinePatchSlots[i];
            if (!slot.Active || slot.Target == nullptr || slot.PatchSize == 0 || slot.PatchSize > 16)
            {
                continue;
            }

            DWORD oldProtect = 0;
            if (VirtualProtect(slot.Target, slot.PatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::memcpy(slot.Target, slot.OriginalBytes, slot.PatchSize);
                DWORD temp = 0;
                (void)VirtualProtect(slot.Target, slot.PatchSize, oldProtect, &temp);
                FlushInstructionCache(GetCurrentProcess(), slot.Target, slot.PatchSize);
            }

            if (slot.Trampoline != nullptr)
            {
                VirtualFree(slot.Trampoline, 0, MEM_RELEASE);
            }
            if (slot.OriginalFunction != nullptr)
            {
                *slot.OriginalFunction = nullptr;
            }
            slot = WinsockInlinePatchSlot{};
        }
        g_InlinePatchSlotCount = 0;
    }

    static WinsockInlinePatchSlot *FindInlinePatchByOriginalFunction(void **originalFunction) noexcept
    {
        if (originalFunction == nullptr)
        {
            return nullptr;
        }

        for (std::size_t i = 0; i < g_InlinePatchSlotCount; ++i)
        {
            if (g_InlinePatchSlots[i].OriginalFunction == originalFunction)
            {
                return &g_InlinePatchSlots[i];
            }
        }
        return nullptr;
    }

    static bool RestoreInlinePatchOriginal(WinsockInlinePatchSlot &slot) noexcept
    {
        if (!slot.Active || slot.Target == nullptr || slot.PatchSize == 0 || slot.PatchSize > 16)
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(slot.Target, slot.PatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }
        std::memcpy(slot.Target, slot.OriginalBytes, slot.PatchSize);
        DWORD temp = 0;
        (void)VirtualProtect(slot.Target, slot.PatchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), slot.Target, slot.PatchSize);
        return true;
    }

    static bool ReinstallInlinePatch(WinsockInlinePatchSlot &slot) noexcept
    {
        if (!slot.Active || slot.Target == nullptr || slot.HookFunction == nullptr || slot.PatchSize < 16)
        {
            return false;
        }

        auto *dst = static_cast<std::uint8_t *>(slot.Target);
        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }

        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = slot.HookFunction;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD temp = 0;
        (void)VirtualProtect(dst, 16, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, 16);
        return true;
    }

    template <typename Fn, typename... Args>
    static auto CallOriginalWinsock(void **originalFunction, Fn fallback, Args... args) noexcept
        -> decltype(fallback(args...))
    {
        WinsockInlinePatchSlot *slot = FindInlinePatchByOriginalFunction(originalFunction);
        if (slot == nullptr || !slot->Active || slot->Target == nullptr)
        {
            return fallback(args...);
        }

        AcquireSRWLockExclusive(&g_WinsockOriginalCallLock);
        const bool restored = RestoreInlinePatchOriginal(*slot);
        void *targetAddress = slot->Target;
        ReleaseSRWLockExclusive(&g_WinsockOriginalCallLock);

        if (!restored || targetAddress == nullptr)
        {
            return fallback(args...);
        }

        auto target = reinterpret_cast<Fn>(targetAddress);
        auto result = target(args...);

        AcquireSRWLockExclusive(&g_WinsockOriginalCallLock);
        if (slot->Active && slot->Target == targetAddress)
        {
            (void)ReinstallInlinePatch(*slot);
        }
        ReleaseSRWLockExclusive(&g_WinsockOriginalCallLock);
        return result;
    }

    static void FillEndpointArgs(SOCKET s, WinsockHookContext &ctx) noexcept
    {
        SocketEndpointEntry ep{};
        if (EndpointCacheLookup(s, &ep))
        {
            ctx.Args[1] = (static_cast<std::uint64_t>(ep.family) << 16) | ep.port;
            ctx.Args[2] = static_cast<std::uint64_t>(ep.addrNbo);
        }
    }

    INT WSAAPI WsasendHook(SOCKET socketHandle,
                           LPWSABUF buffers,
                           DWORD bufferCount,
                           LPDWORD bytesSent,
                           DWORD flags,
                           LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && buffers != nullptr && bufferCount > 0)
        {
            g_InHook = true;
            void *caller = _ReturnAddress();

            for (DWORD i = 0; i < bufferCount; ++i)
            {
                if (buffers[i].buf == nullptr || buffers[i].len == 0)
                {
                    continue;
                }

                WinsockHookBuffer bufferView{};
                bufferView.Data = buffers[i].buf;
                bufferView.Length = buffers[i].len;

                WinsockHookContext context{};
                context.Operation = WinsockOperation::WsaSend;
                context.Socket = socketHandle;
                context.Buffers = &bufferView;
                context.BufferCount = 1U;
                context.Caller = caller;
                FillEndpointArgs(socketHandle, context);

                g_ActiveCallback(context);
            }

            g_InHook = false;
        }

        if (g_OriginalWsasend == nullptr)
        {
            return SOCKET_ERROR;
        }

        return CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalWsasend),
                                   g_OriginalWsasend,
                                   socketHandle,
                                   buffers,
                                   bufferCount,
                                   bytesSent,
                                   flags,
                                   overlapped,
                                   completionRoutine);
    }

    INT WSAAPI WsarecvHook(SOCKET socketHandle,
                           LPWSABUF buffers,
                           DWORD bufferCount,
                           LPDWORD bytesReceived,
                           LPDWORD flags,
                           LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
    {
        if (g_OriginalWsarecv == nullptr)
        {
            return SOCKET_ERROR;
        }

        const INT result = CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalWsarecv),
                                               g_OriginalWsarecv,
                                               socketHandle,
                                               buffers,
                                               bufferCount,
                                               bytesReceived,
                                               flags,
                                               overlapped,
                                               completionRoutine);

        if (result != 0)
        {
            return result;
        }

        if (!g_InHook && g_ActiveCallback != nullptr && buffers != nullptr && bufferCount > 0 &&
            bytesReceived != nullptr && *bytesReceived > 0)
        {
            g_InHook = true;
            void *caller = _ReturnAddress();

            std::size_t remaining = static_cast<std::size_t>(*bytesReceived);

            for (DWORD i = 0; i < bufferCount && remaining > 0; ++i)
            {
                if (buffers[i].buf == nullptr || buffers[i].len == 0)
                {
                    continue;
                }

                const std::size_t bufLen =
                    (remaining < buffers[i].len) ? remaining : static_cast<std::size_t>(buffers[i].len);

                WinsockHookBuffer bufferView{};
                bufferView.Data = buffers[i].buf;
                bufferView.Length = bufLen;

                WinsockHookContext context{};
                context.Operation = WinsockOperation::WsaRecv;
                context.Socket = socketHandle;
                context.Buffers = &bufferView;
                context.BufferCount = 1U;
                context.Caller = caller;
                FillEndpointArgs(socketHandle, context);

                g_ActiveCallback(context);

                remaining -= bufLen;
            }

            g_InHook = false;
        }

        return result;
    }

    int WSAAPI SendHook(SOCKET socketHandle, const char *buffer, int length, int flags)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && buffer != nullptr && length > 0)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = buffer;
            bufferView.Length = static_cast<std::size_t>(length);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::Send;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            FillEndpointArgs(socketHandle, context);

            g_ActiveCallback(context);

            g_InHook = false;
        }

        if (g_OriginalSend == nullptr)
        {
            return SOCKET_ERROR;
        }
        return CallOriginalWinsock(
            reinterpret_cast<void **>(&g_OriginalSend), g_OriginalSend, socketHandle, buffer, length, flags);
    }

    int WSAAPI RecvHook(SOCKET socketHandle, char *buffer, int length, int flags)
    {
        if (g_OriginalRecv == nullptr)
        {
            return SOCKET_ERROR;
        }

        const int result = CallOriginalWinsock(
            reinterpret_cast<void **>(&g_OriginalRecv), g_OriginalRecv, socketHandle, buffer, length, flags);

        if (result > 0 && !g_InHook && g_ActiveCallback != nullptr && buffer != nullptr)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = buffer;
            bufferView.Length = static_cast<std::size_t>(result);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::Recv;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            FillEndpointArgs(socketHandle, context);

            g_ActiveCallback(context);

            g_InHook = false;
        }

        return result;
    }

    int WSAAPI ConnectHook(SOCKET socketHandle, const sockaddr *name, int nameLength)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && name != nullptr && nameLength > 0)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = name;
            bufferView.Length = static_cast<std::size_t>(nameLength);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::Connect;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = static_cast<std::uint64_t>(name->sa_family);
            context.Args[1] = static_cast<std::uint64_t>(nameLength);

            g_ActiveCallback(context);

            EndpointCacheStore(socketHandle, name, nameLength);

            g_InHook = false;
        }

        if (g_OriginalConnect == nullptr)
        {
            return SOCKET_ERROR;
        }

        return CallOriginalWinsock(
            reinterpret_cast<void **>(&g_OriginalConnect), g_OriginalConnect, socketHandle, name, nameLength);
    }

    int WSAAPI WsaConnectHook(SOCKET socketHandle,
                              const sockaddr *name,
                              int nameLength,
                              LPWSABUF callerData,
                              LPWSABUF calleeData,
                              LPQOS sqos,
                              LPQOS gqos)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && name != nullptr && nameLength > 0)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = name;
            bufferView.Length = static_cast<std::size_t>(nameLength);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::WsaConnect;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = static_cast<std::uint64_t>(name->sa_family);
            context.Args[1] = static_cast<std::uint64_t>(nameLength);

            g_ActiveCallback(context);

            EndpointCacheStore(socketHandle, name, nameLength);

            g_InHook = false;
        }

        if (g_OriginalWsaConnect == nullptr)
        {
            return SOCKET_ERROR;
        }

        return CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalWsaConnect),
                                   g_OriginalWsaConnect,
                                   socketHandle,
                                   name,
                                   nameLength,
                                   callerData,
                                   calleeData,
                                   sqos,
                                   gqos);
    }

    INT WSAAPI GetAddrInfoWHook(PCWSTR nodeName, PCWSTR serviceName, const ADDRINFOW *hints, PADDRINFOW *result)
    {
#if defined(BLIND_STANDALONE)
        if (g_InHook)
        {
            return g_OriginalGetAddrInfoW != nullptr
                       ? CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalGetAddrInfoW),
                                             g_OriginalGetAddrInfoW,
                                             nodeName,
                                             serviceName,
                                             hints,
                                             result)
                       : EAI_FAIL;
        }
        g_InHook = true;
#endif
        if (
#if !defined(BLIND_STANDALONE)
            !g_InHook &&
#endif
            g_ActiveCallback != nullptr && nodeName != nullptr && nodeName[0] != L'\0')
        {
            g_InHook = true;

            std::size_t chars = 0;
            while (nodeName[chars] != L'\0' && chars + 1 < (IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(wchar_t)))
            {
                ++chars;
            }

            WinsockHookBuffer bufferView{};
            bufferView.Data = nodeName;
            bufferView.Length = chars * sizeof(wchar_t);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::GetAddrInfoW;
            context.Socket = INVALID_SOCKET;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = (hints != nullptr) ? static_cast<std::uint64_t>(hints->ai_family) : 0ull;
            context.Args[1] = (serviceName != nullptr && serviceName[0] != L'\0')
                                  ? reinterpret_cast<std::uint64_t>(serviceName)
                                  : 0ull;

            g_ActiveCallback(context);

#if !defined(BLIND_STANDALONE)
            g_InHook = false;
#endif
        }

        INT status = EAI_FAIL;
        if (g_OriginalGetAddrInfoW == nullptr)
        {
            status = EAI_FAIL;
        }
        else
        {
            status = CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalGetAddrInfoW),
                                         g_OriginalGetAddrInfoW,
                                         nodeName,
                                         serviceName,
                                         hints,
                                         result);
        }
#if defined(BLIND_STANDALONE)
        g_InHook = false;
#endif
        return status;
    }

    INT WSAAPI GetAddrInfoAHook(PCSTR nodeName, PCSTR serviceName, const ADDRINFOA *hints, PADDRINFOA *result)
    {
#if defined(BLIND_STANDALONE)
        if (g_InHook)
        {
            return g_OriginalGetAddrInfoA != nullptr
                       ? CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalGetAddrInfoA),
                                             g_OriginalGetAddrInfoA,
                                             nodeName,
                                             serviceName,
                                             hints,
                                             result)
                       : EAI_FAIL;
        }
        g_InHook = true;
#endif
        if (
#if !defined(BLIND_STANDALONE)
            !g_InHook &&
#endif
            g_ActiveCallback != nullptr && nodeName != nullptr && nodeName[0] != '\0')
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = nodeName;
            bufferView.Length = strnlen_s(nodeName, IXIPC_MAX_HOOK_DATA_SAMPLE - 1);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::GetAddrInfoA;
            context.Socket = INVALID_SOCKET;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = (hints != nullptr) ? static_cast<std::uint64_t>(hints->ai_family) : 0ull;
            context.Args[1] = (serviceName != nullptr && serviceName[0] != '\0')
                                  ? reinterpret_cast<std::uint64_t>(serviceName)
                                  : 0ull;

            g_ActiveCallback(context);

#if !defined(BLIND_STANDALONE)
            g_InHook = false;
#endif
        }

        INT status = EAI_FAIL;
        if (g_OriginalGetAddrInfoA == nullptr)
        {
            status = EAI_FAIL;
        }
        else
        {
            status = CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalGetAddrInfoA),
                                         g_OriginalGetAddrInfoA,
                                         nodeName,
                                         serviceName,
                                         hints,
                                         result);
        }
#if defined(BLIND_STANDALONE)
        g_InHook = false;
#endif
        return status;
    }

    LONG WINAPI DnsQueryWHook(PCWSTR name, WORD type, DWORD options, PVOID extra, PVOID *results, PVOID *reserved)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && name != nullptr && name[0] != L'\0')
        {
            g_InHook = true;

            std::size_t chars = 0;
            while (name[chars] != L'\0' && chars + 1 < (IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(wchar_t)))
            {
                ++chars;
            }

            WinsockHookBuffer bufferView{};
            bufferView.Data = name;
            bufferView.Length = chars * sizeof(wchar_t);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::DnsQueryW;
            context.Socket = INVALID_SOCKET;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = static_cast<std::uint64_t>(type);
            context.Args[1] = static_cast<std::uint64_t>(options);

            g_ActiveCallback(context);

            g_InHook = false;
        }

        if (g_OriginalDnsQueryW == nullptr)
        {
            return 9002L;
        }

        return CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalDnsQueryW),
                                   g_OriginalDnsQueryW,
                                   name,
                                   type,
                                   options,
                                   extra,
                                   results,
                                   reserved);
    }

    LONG WINAPI DnsQueryAHook(PCSTR name, WORD type, DWORD options, PVOID extra, PVOID *results, PVOID *reserved)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && name != nullptr && name[0] != '\0')
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = name;
            bufferView.Length = strnlen_s(name, IXIPC_MAX_HOOK_DATA_SAMPLE - 1);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::DnsQueryA;
            context.Socket = INVALID_SOCKET;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = static_cast<std::uint64_t>(type);
            context.Args[1] = static_cast<std::uint64_t>(options);

            g_ActiveCallback(context);

            g_InHook = false;
        }

        if (g_OriginalDnsQueryA == nullptr)
        {
            return 9002L;
        }

        return CallOriginalWinsock(reinterpret_cast<void **>(&g_OriginalDnsQueryA),
                                   g_OriginalDnsQueryA,
                                   name,
                                   type,
                                   options,
                                   extra,
                                   results,
                                   reserved);
    }

    static HookEntry g_HookEntries[] = {
        {"WS2_32.dll",
         "WSASend",
         reinterpret_cast<void **>(&g_OriginalWsasend),
         reinterpret_cast<void *>(&WsasendHook)},
        {"WS2_32.dll",
         "WSARecv",
         reinterpret_cast<void **>(&g_OriginalWsarecv),
         reinterpret_cast<void *>(&WsarecvHook)},
        {"WS2_32.dll", "send", reinterpret_cast<void **>(&g_OriginalSend), reinterpret_cast<void *>(&SendHook)},
        {"WS2_32.dll", "recv", reinterpret_cast<void **>(&g_OriginalRecv), reinterpret_cast<void *>(&RecvHook)},
        {"WS2_32.dll",
         "connect",
         reinterpret_cast<void **>(&g_OriginalConnect),
         reinterpret_cast<void *>(&ConnectHook)},
        {"WS2_32.dll",
         "WSAConnect",
         reinterpret_cast<void **>(&g_OriginalWsaConnect),
         reinterpret_cast<void *>(&WsaConnectHook)},
        {"WS2_32.dll",
         "GetAddrInfoW",
         reinterpret_cast<void **>(&g_OriginalGetAddrInfoW),
         reinterpret_cast<void *>(&GetAddrInfoWHook)},
        {"WS2_32.dll",
         "getaddrinfo",
         reinterpret_cast<void **>(&g_OriginalGetAddrInfoA),
         reinterpret_cast<void *>(&GetAddrInfoAHook)},
        {"DNSAPI.dll",
         "DnsQuery_W",
         reinterpret_cast<void **>(&g_OriginalDnsQueryW),
         reinterpret_cast<void *>(&DnsQueryWHook)},
        {"DNSAPI.dll",
         "DnsQuery_A",
         reinterpret_cast<void **>(&g_OriginalDnsQueryA),
         reinterpret_cast<void *>(&DnsQueryAHook)},
    };

    bool PatchImportAddressTableForModule(HMODULE moduleHandle, bool install)
    {
        std::uint8_t *base = nullptr;
        IMAGE_NT_HEADERS ntHeaders{};
        if (!ReadModuleNtHeaders(moduleHandle, base, ntHeaders))
        {
            return false;
        }

        IMAGE_DATA_DIRECTORY &importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
        {
            return false;
        }

        auto *importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + importDirectory.VirtualAddress);

        bool anyPatched = false;
        const DWORD descriptorLimit = (importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 1;
        const DWORD maxDescriptors = descriptorLimit < 4096 ? descriptorLimit : 4096;

        for (DWORD descriptorIndex = 0; descriptorIndex < maxDescriptors; ++descriptorIndex, ++importDescriptor)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            if (!SafeReadValue(importDescriptor, descriptor) || descriptor.Name == 0)
            {
                break;
            }

            const char *importedModuleName = reinterpret_cast<const char *>(base + descriptor.Name);

            bool moduleMatches = false;
            for (const auto &hookEntry : g_HookEntries)
            {
                if (!IX_RUNTIME_INTERNAL::ShouldInstallWinsockHookByPolicy(hookEntry.FunctionName))
                {
                    continue;
                }
                if (SafeStringEquals(importedModuleName, hookEntry.ModuleName, true))
                {
                    moduleMatches = true;
                    break;
                }
            }

            if (!moduleMatches)
            {
                continue;
            }

            auto *thunkIat = reinterpret_cast<PIMAGE_THUNK_DATA>(base + descriptor.FirstThunk);

            PIMAGE_THUNK_DATA thunkOriginal = nullptr;
            if (descriptor.OriginalFirstThunk != 0)
            {
                thunkOriginal = reinterpret_cast<PIMAGE_THUNK_DATA>(base + descriptor.OriginalFirstThunk);
            }

            for (DWORD thunkIndex = 0; thunkIndex < 16384; ++thunkIndex, ++thunkIat)
            {
                IMAGE_THUNK_DATA thunkIatValue{};
                if (!SafeReadValue(thunkIat, thunkIatValue) || thunkIatValue.u1.Function == 0)
                {
                    break;
                }

                const char *functionName = nullptr;

                if (thunkOriginal != nullptr)
                {
                    IMAGE_THUNK_DATA thunkOriginalValue{};
                    if (!SafeReadValue(thunkOriginal, thunkOriginalValue))
                    {
                        break;
                    }
                    if (IMAGE_SNAP_BY_ORDINAL(thunkOriginalValue.u1.Ordinal))
                    {
                        ++thunkOriginal;
                        continue;
                    }

                    auto *importByName =
                        reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + thunkOriginalValue.u1.AddressOfData);

                    functionName = reinterpret_cast<const char *>(importByName->Name);
                    ++thunkOriginal;
                }

                if (functionName == nullptr)
                {
                    continue;
                }

                for (auto &hookEntry : g_HookEntries)
                {
                    if (!IX_RUNTIME_INTERNAL::ShouldInstallWinsockHookByPolicy(hookEntry.FunctionName))
                    {
                        continue;
                    }

                    if (!SafeStringEquals(importedModuleName, hookEntry.ModuleName, true))
                    {
                        continue;
                    }

                    if (!SafeStringEquals(functionName, hookEntry.FunctionName, false))
                    {
                        continue;
                    }

                    if (install && !IX_RUNTIME_INTERNAL::RegisterControlFlowGuardCallTarget(
                                       hookEntry.HookFunction,
                                       IX_RUNTIME_INTERNAL::IxCfgCallTargetMode::CfgAndXfgWhenEnabled,
                                       hookEntry.FunctionName))
                    {
                        continue;
                    }

                    auto *functionSlot = reinterpret_cast<ULONG_PTR *>(&thunkIat->u1.Function);

                    DWORD oldProtection = 0;
                    if (!VirtualProtect(functionSlot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtection))
                    {
                        continue;
                    }

                    if (install)
                    {
                        ULONG_PTR currentValue = 0;
                        if (!SafeReadValue(functionSlot, currentValue))
                        {
                            VirtualProtect(functionSlot, sizeof(ULONG_PTR), oldProtection, &oldProtection);
                            continue;
                        }

                        if (currentValue == reinterpret_cast<ULONG_PTR>(hookEntry.HookFunction))
                        {
                            VirtualProtect(functionSlot, sizeof(ULONG_PTR), oldProtection, &oldProtection);
                            continue;
                        }

                        if (*hookEntry.OriginalFunction == nullptr)
                        {
                            *hookEntry.OriginalFunction = reinterpret_cast<void *>(currentValue);
                        }

                        ULONG_PTR originalValue = currentValue;
                        if (!SafeWriteValue(functionSlot, reinterpret_cast<ULONG_PTR>(hookEntry.HookFunction)))
                        {
                            VirtualProtect(functionSlot, sizeof(ULONG_PTR), oldProtection, &oldProtection);
                            continue;
                        }
                        TrackPatchedSlot(functionSlot, originalValue, hookEntry.HookFunction, hookEntry.FunctionName);
                        anyPatched = true;
                    }
                    else
                    {
                        ULONG_PTR restoreValue = reinterpret_cast<ULONG_PTR>(*hookEntry.OriginalFunction);
                        if (PatchedIatSlot *patchedSlot = FindPatchedSlot(functionSlot);
                            patchedSlot != nullptr && patchedSlot->OriginalValue != 0)
                        {
                            restoreValue = patchedSlot->OriginalValue;
                        }

                        if (restoreValue != 0)
                        {
                            if (SafeWriteValue(functionSlot, restoreValue))
                            {
                                anyPatched = true;
                            }
                        }
                    }

                    VirtualProtect(functionSlot, sizeof(ULONG_PTR), oldProtection, &oldProtection);
                }
            }
        }

        return anyPatched;
    }

    bool PatchLoadedModules(bool install, HMODULE specificModule = nullptr)
    {
        if (specificModule != nullptr)
        {
            return PatchImportAddressTableForModule(specificModule, install);
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        bool anyPatched = false;

        if (Module32FirstW(snapshot, &moduleEntry))
        {
            do
            {
                anyPatched |= PatchImportAddressTableForModule(moduleEntry.hModule, install);
            } while (Module32NextW(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
        return anyPatched;
    }

    bool AnyWinsockHookRequestedByPolicy() noexcept
    {
        for (const auto &hookEntry : g_HookEntries)
        {
            if (IX_RUNTIME_INTERNAL::ShouldInstallWinsockHookByPolicy(hookEntry.FunctionName))
            {
                return true;
            }
        }
        return false;
    }
} // namespace

bool IxSetWinsockHook(WinsockHookCallback callback) noexcept
{
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveCallback = callback;

    if (g_HooksInstalled)
    {
        return true;
    }

    g_PatchedSlotCount = 0;
    g_InlinePatchSlotCount = 0;

    const bool patched = PatchLoadedModules(true);
    const bool requested = AnyWinsockHookRequestedByPolicy();
    if (!patched && !requested)
    {
        g_ActiveCallback = nullptr;
        return false;
    }

    g_HooksInstalled = true;
    (void)IxInstallWinsockInlineHooks();
    return true;
}

bool IxIsWinsockHookRequired() noexcept
{
    const HMODULE moduleHandle = GetModuleHandleW(nullptr);
    if (moduleHandle == nullptr)
    {
        return true;
    }

    return ModuleImportsWinsock(moduleHandle);
}

bool IxRefreshWinsockHooks(HMODULE moduleHandle) noexcept
{
    if (!g_HooksInstalled)
    {
        return false;
    }

    bool patched = PatchLoadedModules(true, moduleHandle);
    patched = IxInstallWinsockInlineHooks() || patched;
    return patched;
}

void IxRemoveWinsockHook() noexcept
{
    if (!g_HooksInstalled)
    {
        g_ActiveCallback = nullptr;
        return;
    }

    (void)PatchLoadedModules(false);
    RemoveInlineHooks();

    g_ActiveCallback = nullptr;
    g_HooksInstalled = false;
    g_PatchedSlotCount = 0;
}

bool IxCheckWinsockHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
    std::uint32_t mismatches = 0;

    if (g_HooksInstalled)
    {
        for (std::size_t i = 0; i < g_PatchedSlotCount; ++i)
        {
            ULONG_PTR *slot = g_PatchedSlots[i].Slot;
            void *expectedHook = g_PatchedSlots[i].HookFunction;
            if (slot == nullptr || expectedHook == nullptr)
            {
                ++mismatches;
                continue;
            }

            if (*slot != reinterpret_cast<ULONG_PTR>(expectedHook))
            {
                ++mismatches;
            }
        }

        for (std::size_t i = 0; i < g_InlinePatchSlotCount; ++i)
        {
            const auto &slot = g_InlinePatchSlots[i];
            if (!slot.Active || slot.Target == nullptr || slot.PatchSize == 0 || slot.PatchSize > 16)
            {
                ++mismatches;
                continue;
            }

            auto *target = static_cast<const std::uint8_t *>(slot.Target);
            __try
            {
                if (!(target[0] == 0x48 && target[1] == 0xB8 && target[10] == 0xFF && target[11] == 0xE0))
                {
                    ++mismatches;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ++mismatches;
            }
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

bool IxInstallWinsockInlineHooks() noexcept
{
    if (!g_HooksInstalled || g_ActiveCallback == nullptr)
    {
        return false;
    }

    bool anyInstalled = false;
    bool anyFailed = false;

    for (const auto &entry : g_HookEntries)
    {
        if (!IX_RUNTIME_INTERNAL::ShouldInstallWinsockHookByPolicy(entry.FunctionName))
        {
            continue;
        }

        HMODULE module = GetModuleHandleA(entry.ModuleName);
        if (module == nullptr)
        {
            continue;
        }

        FARPROC exportAddress = GetProcAddress(module, entry.FunctionName);
        if (exportAddress == nullptr)
        {
            continue;
        }

        void *target = reinterpret_cast<void *>(exportAddress);
        if (target == entry.HookFunction)
        {
            continue;
        }

        if (!InstallInlineHook(target, entry.HookFunction, entry.OriginalFunction, entry.FunctionName))
        {
            anyFailed = true;
            continue;
        }
        anyInstalled = true;
    }

    return anyInstalled && !anyFailed;
}

std::size_t IxCollectWinsockHookPatchInfos(WinsockHookPatchInfo *out, std::size_t capacity) noexcept
{
    if (out == nullptr || capacity == 0)
    {
        return 0;
    }

    std::size_t count = 0;
    for (std::size_t i = 0; i < g_PatchedSlotCount && count < capacity; ++i)
    {
        if (g_PatchedSlots[i].Slot == nullptr || g_PatchedSlots[i].OriginalValue == 0)
        {
            continue;
        }
        out[count].PatchAddress = g_PatchedSlots[i].Slot;
        out[count].PatchSize = sizeof(g_PatchedSlots[i].OriginalValue);
        std::memset(out[count].OriginalBytes, 0, sizeof(out[count].OriginalBytes));
        std::memcpy(
            out[count].OriginalBytes, &g_PatchedSlots[i].OriginalValue, sizeof(g_PatchedSlots[i].OriginalValue));
        out[count].HookName = g_PatchedSlots[i].FunctionName;
        out[count].Flags = IX_HOOK_PATCH_FLAG_WINSOCK_IAT;
        ++count;
    }

    for (std::size_t i = 0; i < g_InlinePatchSlotCount && count < capacity; ++i)
    {
        if (!g_InlinePatchSlots[i].Active || g_InlinePatchSlots[i].Target == nullptr ||
            g_InlinePatchSlots[i].PatchSize == 0)
        {
            continue;
        }
        out[count].PatchAddress = g_InlinePatchSlots[i].Target;
        out[count].PatchSize = g_InlinePatchSlots[i].PatchSize;
        std::memset(out[count].OriginalBytes, 0, sizeof(out[count].OriginalBytes));
        std::memcpy(out[count].OriginalBytes, g_InlinePatchSlots[i].OriginalBytes, g_InlinePatchSlots[i].PatchSize);
        out[count].HookName = g_InlinePatchSlots[i].FunctionName;
        out[count].Flags = IX_HOOK_PATCH_FLAG_WINSOCK_INLINE;
        ++count;
    }

    return count;
}
