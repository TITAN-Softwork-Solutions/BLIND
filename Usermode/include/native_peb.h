#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

typedef struct _IX_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PVOID EntryPointActivationContext;
    PVOID Lock;
    PVOID DdagNode;
    LIST_ENTRY NodeModuleLink;
    PVOID LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
} IX_LDR_DATA_TABLE_ENTRY, *PIX_LDR_DATA_TABLE_ENTRY;

typedef struct _IX_PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} IX_PEB_LDR_DATA, *PIX_PEB_LDR_DATA;

typedef struct _IX_PEB
{
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PIX_PEB_LDR_DATA Ldr;
} IX_PEB, *PIX_PEB;

typedef struct _IX_CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} IX_CLIENT_ID, *PIX_CLIENT_ID;

typedef struct _IX_INITIAL_TEB
{
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocation;
} IX_INITIAL_TEB, *PIX_INITIAL_TEB;

#if defined(__cplusplus)
#if defined(_M_X64)
#pragma intrinsic(__readgsqword)
#elif defined(_M_IX86)
#pragma intrinsic(__readfsdword)
#endif

static __forceinline PIX_PEB IxCurrentPeb() noexcept
{
#if defined(_M_X64)
    return reinterpret_cast<PIX_PEB>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<PIX_PEB>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}
#endif
