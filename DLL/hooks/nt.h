#pragma once

#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>

#include "../instrument/stacktrace.h"

enum class NtOperation : std::uint32_t
{
    NtCreateThread = 0,
    NtCreateThreadEx,
    NtWriteVirtualMemory,
    NtAllocateVirtualMemory,
    NtProtectVirtualMemory,
    NtReadVirtualMemory,
    NtQueryVirtualMemory,
    NtQuerySystemInformation,
    NtCreateSection,
    NtTerminateProcess,
    NtOpenProcessToken,
    NtOpenThreadToken,
    NtOpenFile,
    NtQueryInformationProcess,
    NtQueryInformationThread,
    NtSetContextThread,
    NtQuerySection,
    NtQueryBootOptions,
    NtOpenProcess,
    NtOpenThread,
    NtDuplicateObject,
    NtGetContextThread,
    NtSuspendThread,
    NtResumeThread,
    NtQueueApcThread,
    NtAllocateVirtualMemoryEx,
    NtMapViewOfSection,
    NtMapViewOfSectionEx,
    NtQueueApcThreadEx,
    NtOpenProcessTokenEx,
    NtOpenThreadTokenEx,
    NtQuerySystemInformationEx,
    NtGetNextThread,
    NtUnmapViewOfSection,
    NtUnmapViewOfSectionEx,
    NtQueueApcThreadEx2,
};

struct NtRegisterSnapshot
{
    std::uint32_t Valid = 0;
    std::uint32_t Reserved = 0;
    std::uint64_t Rip = 0;
    std::uint64_t Rsp = 0;
    std::uint64_t Rbp = 0;
    std::uint64_t Rax = 0;
    std::uint64_t Rbx = 0;
    std::uint64_t Rcx = 0;
    std::uint64_t Rdx = 0;
    std::uint64_t Rsi = 0;
    std::uint64_t Rdi = 0;
    std::uint64_t R8 = 0;
    std::uint64_t R9 = 0;
    std::uint64_t R10 = 0;
    std::uint64_t R11 = 0;
    std::uint64_t R12 = 0;
    std::uint64_t R13 = 0;
    std::uint64_t R14 = 0;
    std::uint64_t R15 = 0;
    std::uint64_t EFlags = 0;
};

struct NtHookContext
{
    NtOperation Operation;
    const char *FunctionName;
    void *Caller;
    NTSTATUS Status;
    std::uint32_t PolicyAction;
    std::uint32_t PolicyFlags;
    std::uint64_t Args[8];
    std::uint32_t DataSize;
    std::uint8_t DataSample[512];
    bool HasRegisters;
    NtRegisterSnapshot Registers;
    IC_STACKTRACE::Trace Stack;
};
using NtHookCallback = void (*)(const NtHookContext &context) noexcept;

inline constexpr std::uint64_t kNtHookTerminateBreakpointMarker = 0x535237315445524Dull;

enum class NtHookInitFaultCode : std::uint32_t
{
    None = 0,
    NtdllMissing,
    NtdllTextMissing,
    NtdllExportDirectoryMissing,
    ExportMissing,
    ExportOutsideImage,
    ExportOutsideText,
    ExportRedirectedOutsideImage,
    UnexpectedStubBytes,
    SyscallStubAllocFailed,
    HookEntryMissing,
    PatchInstallFailed,
};

struct NtHookInitFault
{
    NtHookInitFaultCode Code;
    const char *FunctionName;
    void *Address;
    void *RedirectTarget;
    std::uint32_t SyscallIndex;
    std::uint8_t Sample[16];
};

bool IxSetNtHook(NtHookCallback callback) noexcept;
void IxRemoveNtHook() noexcept;

bool IxCheckNtHookIntegrity(std::uint32_t *mismatchCount) noexcept;
bool IxGetLastNtHookInitFault(NtHookInitFault *faultOut) noexcept;

/* Returns the base address and 16-byte size of every allocated syscall stub so the
   IPC layer can register them with the controller as IX-owned pages.
   Each entry: {stubBase (16-byte alloc), hookName (null-terminated)}.
   Returns the number of entries written; outCount is the capacity on entry. */
struct NtHookStubInfo
{
    void *StubBase;
    std::size_t StubSize;
    const char *HookName;
};
std::size_t IxCollectNtHookStubInfos(_Out_writes_(capacity) NtHookStubInfo *out, _In_ std::size_t capacity) noexcept;

struct NtHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
    std::uint32_t Flags;
};
std::size_t IxCollectNtHookPatchInfos(_Out_writes_(capacity) NtHookPatchInfo *out, _In_ std::size_t capacity) noexcept;
