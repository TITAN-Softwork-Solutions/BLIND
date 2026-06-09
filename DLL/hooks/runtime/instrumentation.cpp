#include "runtime_internal.h"

namespace IX_RUNTIME_INTERNAL
{
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

    static bool PublishIxInstrumentationRange(void *base,
                                              std::uint64_t size,
                                              std::uint32_t instrumentationFlags,
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

        bool ok = IXIPC::RegisterInstrumentationRange(
            reinterpret_cast<UINT64>(resolved.Pointer), resolved.Size, instrumentationFlags, tag);
        if (!ok)
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::InstrumentationRangeRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(resolved.Pointer),
                                 resolved.Size);
        }
        return ok;
    }

    bool RegisterIxDynamicInstrumentationRange(void *base,
                                               std::uint64_t size,
                                               std::uint32_t instrumentationFlags,
                                               const char *tag) noexcept
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

    static void PublishIxHookPatch(void *patchAddress,
                                   std::size_t patchSize,
                                   const std::uint8_t originalBytes[16],
                                   std::uint32_t flags,
                                   const char *tagPrefix,
                                   const char *hookName) noexcept
    {
        if (patchAddress == nullptr || patchSize == 0 || patchSize > IX_MAX_HOOK_PATCH_BYTES ||
            originalBytes == nullptr)
        {
            return;
        }

        char tag[IX_HOOK_PATCH_TAG_CHARS]{};
        BuildHookPatchTag(tagPrefix, hookName, tag);
        if (!IXIPC::RegisterHookPatch(reinterpret_cast<UINT64>(patchAddress),
                                      static_cast<UINT32>(patchSize),
                                      originalBytes,
                                      IX_MAX_HOOK_PATCH_BYTES,
                                      flags,
                                      tag))
        {
            IxRuntimeReportFault(IxRuntimeFaultCode::HookPatchRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(patchAddress),
                                 static_cast<std::uint64_t>(patchSize));
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
            PublishIxHookPatch(ntPatches[i].PatchAddress,
                               ntPatches[i].PatchSize,
                               ntPatches[i].OriginalBytes,
                               ntPatches[i].Flags,
                               "rt.nt.",
                               ntPatches[i].HookName);
        }
        totalCount += ntPatchCount;

        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockPatchCount = IxCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockPatchCount; ++i)
        {
            const char *prefix =
                (winsockPatches[i].Flags == IX_HOOK_PATCH_FLAG_WINSOCK_INLINE) ? "rt.ws.inline." : "rt.ws.iat.";
            PublishIxHookPatch(winsockPatches[i].PatchAddress,
                               winsockPatches[i].PatchSize,
                               winsockPatches[i].OriginalBytes,
                               winsockPatches[i].Flags,
                               prefix,
                               winsockPatches[i].HookName);
        }
        totalCount += winsockPatchCount;

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiPatchCount = IxCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiPatchCount; ++i)
        {
            PublishIxHookPatch(kiPatches[i].PatchAddress,
                               kiPatches[i].PatchSize,
                               kiPatches[i].OriginalBytes,
                               kiPatches[i].Flags,
                               "rt.ki.",
                               kiPatches[i].HookName);
        }
        totalCount += kiPatchCount;

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t modulePatchCount = IxCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < modulePatchCount; ++i)
        {
            PublishIxHookPatch(modulePatches[i].PatchAddress,
                               modulePatches[i].PatchSize,
                               modulePatches[i].OriginalBytes,
                               modulePatches[i].Flags,
                               "rt.mod.",
                               modulePatches[i].HookName);
        }
        totalCount += modulePatchCount;

        IxDbgLog("RegisterIxHookPatchOverlays: registered nt=%zu winsock=%zu ki=%zu module=%zu total=%zu",
                 ntPatchCount,
                 winsockPatchCount,
                 kiPatchCount,
                 modulePatchCount,
                 totalCount);
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

            (void)PublishIxInstrumentationRange(
                stubs[i].StubBase, static_cast<UINT64>(stubs[i].StubSize), IX_INSTRUMENTATION_FLAG_SYSCALL_STUB, tag);
        }

        IxDbgLog("RegisterIxOwnedRanges: registered %zu NT-hook stubs", stubCount);

        RegisterIxHookPatchOverlays();

        for (std::size_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            const LaunchGatePage &page = g_LaunchGatePages[i];
            IxIhrResolved resolved{};
            if (!ResolveIndirectHandle(page.BaseToken, IxIhrType::LaunchGatePage, resolved))
                continue;
            if (!IXIPC::RegisterInstrumentationRange(reinterpret_cast<UINT64>(resolved.Pointer),
                                                     resolved.Size ? resolved.Size : 4096u,
                                                     IX_INSTRUMENTATION_FLAG_LAUNCH_GATE,
                                                     page.TrapKind == 2u ? "rt.tls" : "rt.entry"))
            {
                IxRuntimeReportFault(IxRuntimeFaultCode::InstrumentationRangeRegisterFailed,
                                     reinterpret_cast<std::uint64_t>(resolved.Pointer),
                                     resolved.Size ? resolved.Size : 4096u);
            }
        }
    }
} // namespace IX_RUNTIME_INTERNAL
