#pragma once

#include <cstdint>
#include <vector>
#include <mutex>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include "../../ABI/blind_ipc.h"
#include "ws.h"
#include "nt.h"
#include "ki.h"
#include "module/module.h"

#include "../instrument/stacktrace.h"

struct WinsockCapturedEvent
{
    DWORD ThreadId;
    SOCKET Socket;
    WinsockOperation Operation;
    void *Caller;
    std::uint32_t RepeatCount = 1;
    std::uint64_t Args[4];
    std::uint32_t DataSize = 0;
    std::uint8_t DataSample[IXIPC_MAX_HOOK_DATA_SAMPLE]{};

    IC_STACKTRACE::Trace Stack;
};

struct NtCapturedEvent
{
    DWORD ThreadId;
    NtOperation Operation;
    const char *FunctionName;
    void *Caller;
    NTSTATUS Status;
    std::uint32_t PolicyAction = 0;
    std::uint32_t PolicyFlags = 0;
    std::uint32_t RepeatCount = 1;
    std::uint64_t Args[8];
    std::uint32_t DataSize;
    std::uint8_t DataSample[64];
    bool HasRegisters = false;
    NtRegisterSnapshot Registers{};

    IC_STACKTRACE::Trace Stack;
};

struct KiCapturedEvent
{
    DWORD ThreadId;
    const char *StubName;
    void *Caller;
    void *StackPointer;
    std::uint32_t RepeatCount = 1;

    IC_STACKTRACE::Trace Stack;
};

struct ModuleCapturedEvent
{
    DWORD ThreadId;
    ModuleHookOperation Operation;
    const char *FunctionName;
    const char *SourceModule;
    void *Caller;
    HMODULE ModuleHandle;
    std::uint32_t RepeatCount = 1;
    std::uint32_t NameSampleSize = 0;
    std::uint8_t NameSample[IXIPC_MAX_HOOK_DATA_SAMPLE]{};
    std::uint64_t Args[4];

    IC_STACKTRACE::Trace Stack;
};

class WinsockHookController
{
  public:
    WinsockHookController() = default;
    ~WinsockHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<WinsockCapturedEvent> ConsumeEvents();
    void ConsumeEvents(std::vector<WinsockCapturedEvent> &out);

  private:
    static void IxWinsockHookCallback(const WinsockHookContext &context) noexcept;
    static void EnqueueEvent(const WinsockHookContext &context);

    static bool s_Initialized;
    static std::mutex s_QueueMutex;
    static std::vector<WinsockCapturedEvent> s_Queue;
};

class NtHookController
{
  public:
    NtHookController() = default;
    ~NtHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<NtCapturedEvent> ConsumeEvents();
    void ConsumeEvents(std::vector<NtCapturedEvent> &out);

  private:
    static void IxNtHookCallback(const NtHookContext &context) noexcept;
    static void EnqueueEvent(const NtHookContext &context);

    static bool s_Initialized;
    static std::mutex s_QueueMutex;
    static std::vector<NtCapturedEvent> s_Queue;
};

class KiHookController
{
  public:
    KiHookController() = default;
    ~KiHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<KiCapturedEvent> ConsumeEvents();
    void ConsumeEvents(std::vector<KiCapturedEvent> &out);

  private:
    static void IxKiHookCallback(const KiHookContext &context) noexcept;
    static void EnqueueEvent(const KiHookContext &context);

    static bool s_Initialized;
    static std::mutex s_QueueMutex;
    static std::vector<KiCapturedEvent> s_Queue;
};

class ModuleHookController
{
  public:
    ModuleHookController() = default;
    ~ModuleHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<ModuleCapturedEvent> ConsumeEvents();
    void ConsumeEvents(std::vector<ModuleCapturedEvent> &out);

  private:
    static void IxModuleHookCallback(const ModuleHookContext &context) noexcept;
    static void EnqueueEvent(const ModuleHookContext &context);

    static bool s_Initialized;
    static std::mutex s_QueueMutex;
    static std::vector<ModuleCapturedEvent> s_Queue;
};
