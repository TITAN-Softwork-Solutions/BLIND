#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// clang-format off
#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <strsafe.h>
// clang-format on

#include "ABI/blind_ipc.h"
#include "DLL/support/win32_util.h"

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace blind::injector {
inline constexpr DWORD kPipeBufferBytes = 64 * 1024;
inline constexpr DWORD kReadyTimeoutMs = 15000;
inline constexpr DWORD kInjectTimeoutMs = 10000;
inline constexpr std::size_t kMaxCachedProcessHandles = 16;
inline constexpr std::size_t kMaxCachedVadEntries = 4096;

struct SelfMapEntry {
  UINT32 Index = 0;
  UINT32 Total = 0;
  UINT32 Truncated = 0;
  UINT32 Kind = 0;
  UINT32 Flags = 0;
  UINT32 Protect = 0;
  UINT32 State = 0;
  UINT32 Type = 0;
  UINT64 Address = 0;
  UINT64 Size = 0;
  UINT64 Reference0 = 0;
  UINT64 Reference1 = 0;
  UINT64 AllocationBase = 0;
  UINT64 RegionSize = 0;
  char Owner[IXIPC_MAX_HOOK_MODULE_NAME]{};
  char Name[IXIPC_MAX_HOOK_API_NAME]{};
};

struct ChildModuleEntry {
  UINT64 Base = 0;
  UINT64 Size = 0;
  char Name[MAX_PATH]{};
  wchar_t Path[MAX_PATH]{};
};

struct ProcessInfoEntry {
  DWORD ProcessId = 0;
  bool Queried = false;
  char ImageName[MAX_PATH]{};
};

struct ProcessHandleEntry {
  DWORD ProcessId = 0;
  HANDLE Handle = nullptr;
  DWORD LastUseTick = 0;
};

struct ThreadInfoEntry {
  DWORD ThreadId = 0;
  DWORD OwnerProcessId = 0;
  UINT64 Win32StartAddress = 0;
  bool HasOwnerProcess = false;
  bool HasWin32StartAddress = false;
  bool Queried = false;
};

enum SmartAreaFlags : UINT32 {
  kSmartAreaMemory = 0x00000001u,
  kSmartAreaProtect = 0x00000002u,
  kSmartAreaThreads = 0x00000004u,
  kSmartAreaWrites = 0x00000008u,
  kSmartAreaApc = 0x00000010u,
  kSmartAreaMaps = 0x00000020u,
  kSmartAreaReads = 0x00000040u,
  kSmartAreaQueries = 0x00000080u,
  kSmartAreaHandles = 0x00000100u,
  kSmartAreaRemote = kSmartAreaHandles | kSmartAreaQueries | kSmartAreaReads |
                     kSmartAreaWrites | kSmartAreaThreads | kSmartAreaApc,
  kSmartAreaDefault = kSmartAreaMemory | kSmartAreaProtect | kSmartAreaThreads |
                      kSmartAreaWrites | kSmartAreaApc | kSmartAreaMaps,
  kSmartAreaAll = kSmartAreaDefault | kSmartAreaReads | kSmartAreaQueries |
                  kSmartAreaHandles,
};

enum class ConsoleColorMode {
  Auto,
  Always,
  Never,
};

enum class LogColor {
  Default,
  Info,
  Smart,
  Alert,
  Suspicious,
  Remote,
  RemoteRisk,
  Success,
  Warning,
  Error,
  Muted,
  Stack,
  Lifecycle,
};

// clang-format off
#include "Telemetry/behavior_model.h"
#include "Core/server_context.h"
// clang-format on

struct RunnerOptions {
  bool CliMode = false;
  bool Verbose = false;
  bool ResolveSymbols = false;
  std::wstring SymbolSearchPath;
  bool SmartMode = false;
  bool SmartRawEvents = false;
  bool SmartStacks = false;
  bool SmartProtectStacks = false;
  bool SmartAutoProtect = false;
  bool SmartFoldedProtectStacks = false;
  UINT32 SmartAreas = kSmartAreaDefault;
  UINT32 SmartStackFrameLimit = IXIPC_MAX_HOOK_STACK_FRAMES;
  DWORD SmartSummaryIntervalMs = 0;
  SmartConditions Conditions{};
  bool DebugDiagnostics = true;
  bool LaunchGateMode = true;
  bool GuardedLaunchGate = false;
  bool ManualMap = false;
  DWORD ChildTimeoutMs = INFINITE;
  ConsoleColorMode ColorMode = ConsoleColorMode::Auto;
  bool HelpRequested = false;
  bool TargetSet = false;
  std::wstring TargetPath;
  std::vector<std::wstring> TargetArgs;
  IXIPC_QUERY_HOOK_POLICY_RESPONSE CliPolicy{};
  UINT32 LastRuleStart = 0;
  UINT32 LastRuleCount = 0;
};
} // namespace blind::injector
