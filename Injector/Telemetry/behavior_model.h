struct SmartConditions {
  bool Any = false;
  bool Rwx = false;
  bool Remote = false;
  bool StartPrivate = false;
  UINT32 ProtectFlipsAtLeast = 0;
  UINT32 ThreadCountAtLeast = 0;
  UINT64 AllocTotalGreater = 0;
};

struct SmartVadInfo {
  bool Valid = false;
  UINT64 BaseAddress = 0;
  UINT64 AllocationBase = 0;
  UINT64 RegionSize = 0;
  UINT32 Protect = 0;
  UINT32 AllocationProtect = 0;
  UINT32 State = 0;
  UINT32 Type = 0;
};

struct VadCacheEntry {
  DWORD TargetPid = 0;
  UINT64 Base = 0;
  UINT64 End = 0;
  DWORD LastUseTick = 0;
  SmartVadInfo Vad{};
};

struct SmartStackSample {
  DWORD ProcessId = 0;
  UINT32 Count = 0;
  UINT64 Frames[IXIPC_MAX_HOOK_STACK_FRAMES]{};
};

struct SmartMemoryRegion {
  DWORD TargetPid = 0;
  UINT64 Base = 0;
  UINT64 Size = 0;
  UINT32 Protect = 0;
  UINT32 AllocationProtect = 0;
  UINT32 AllocationType = 0;
  UINT32 State = 0;
  UINT32 Type = 0;
  UINT32 AllocCount = 0;
  UINT32 MapCount = 0;
  UINT32 ProtectCount = 0;
  UINT32 FlipCount = 0;
  UINT32 QueryCount = 0;
  UINT32 ReadCount = 0;
  UINT32 WriteCount = 0;
  UINT32 LastQueryClass = 0;
  UINT64 TotalRead = 0;
  UINT64 TotalWritten = 0;
  UINT64 Caller = 0;
  UINT64 StackHash = 0;
  SmartVadInfo CallerVad{};
  UINT64 PrivateFrame = 0;
  SmartVadInfo PrivateFrameVad{};
  UINT64 RwxFrame = 0;
  SmartVadInfo RwxFrameVad{};
  SmartStackSample Stack{};
  bool EvidenceCaptured = false;
  bool RwxSeen = false;
  bool AlertedRwx = false;
  bool AlertedFlips = false;
  char LastProtect[32]{};
  char ProtectSequence[160]{};
};

struct SmartProtectGroup {
  DWORD TargetPid = 0;
  UINT64 Caller = 0;
  UINT64 StackHash = 0;
  UINT64 FirstBase = 0;
  UINT64 LastBase = 0;
  UINT64 MinBase = 0;
  UINT64 MaxBase = 0;
  UINT64 Size = 0;
  UINT32 OldProtect = 0;
  UINT32 NewProtect = 0;
  UINT32 Count = 0;
  UINT64 Pages = 0;
  UINT32 RwxCount = 0;
  SmartVadInfo Vad{};
  SmartVadInfo CallerVad{};
  UINT64 PrivateFrame = 0;
  SmartVadInfo PrivateFrameVad{};
  UINT64 RwxFrame = 0;
  SmartVadInfo RwxFrameVad{};
  SmartStackSample Stack{};
  bool EvidenceCaptured = false;
};

struct SmartThreadGroup {
  DWORD TargetPid = 0;
  UINT64 Start = 0;
  UINT64 Caller = 0;
  UINT64 StackHash = 0;
  UINT32 Count = 0;
  UINT32 SuspendedCount = 0;
  bool PrivateStart = false;
  bool AlertedCount = false;
  bool AlertedPrivate = false;
  SmartVadInfo Vad{};
  SmartVadInfo CallerVad{};
  UINT64 PrivateFrame = 0;
  SmartVadInfo PrivateFrameVad{};
  UINT64 RwxFrame = 0;
  SmartVadInfo RwxFrameVad{};
  SmartStackSample Stack{};
  bool EvidenceCaptured = false;
};

enum class SmartHandleKind : UINT32 {
  Process = 1,
  Thread = 2,
};

struct SmartHandleGroup {
  DWORD TargetPid = 0;
  DWORD TargetTid = 0;
  SmartHandleKind Kind = SmartHandleKind::Process;
  UINT32 DesiredAccess = 0;
  UINT64 LastHandle = 0;
  UINT64 LastObject = 0;
  UINT64 ThreadStart = 0;
  UINT64 Caller = 0;
  UINT64 StackHash = 0;
  UINT32 Count = 0;
  UINT32 FailedCount = 0;
  UINT32 LastStatus = 0;
  SmartVadInfo ThreadVad{};
  SmartVadInfo CallerVad{};
  UINT64 PrivateFrame = 0;
  SmartVadInfo PrivateFrameVad{};
  UINT64 RwxFrame = 0;
  SmartVadInfo RwxFrameVad{};
  SmartStackSample Stack{};
  bool EvidenceCaptured = false;
};

struct SmartTargetSummary {
  DWORD TargetPid = 0;
  UINT32 AllocCount = 0;
  UINT32 MapCount = 0;
  UINT32 ProtectCount = 0;
  UINT32 QueryCount = 0;
  UINT32 ReadCount = 0;
  UINT32 WriteCount = 0;
  UINT32 ThreadCount = 0;
  UINT32 ApcCount = 0;
  UINT32 OpenProcessCount = 0;
  UINT32 OpenThreadCount = 0;
  UINT64 AllocBytes = 0;
  UINT64 MapBytes = 0;
  UINT64 QueryInfoBytes = 0;
  UINT64 ReadBytes = 0;
  UINT64 WriteBytes = 0;
  UINT64 RwxBytes = 0;
  bool AlertedRemote = false;
  bool AlertedAllocTotal = false;
};

struct AddressRangeKey {
  DWORD TargetPid = 0;
  UINT64 Base = 0;

  bool operator<(const AddressRangeKey &other) const noexcept {
    return TargetPid < other.TargetPid ||
           (TargetPid == other.TargetPid && Base < other.Base);
  }
};

inline void HashMix(std::size_t &seed, UINT64 value) noexcept {
  seed ^= static_cast<std::size_t>(value) + 0x9E3779B97F4A7C15ull +
          (seed << 6) + (seed >> 2);
}

struct SmartProtectKey {
  DWORD TargetPid = 0;
  UINT64 Caller = 0;
  UINT64 StackHash = 0;
  UINT64 Size = 0;
  UINT32 OldProtect = 0;
  UINT32 NewProtect = 0;

  bool operator==(const SmartProtectKey &other) const noexcept {
    return TargetPid == other.TargetPid && Caller == other.Caller &&
           StackHash == other.StackHash && Size == other.Size &&
           OldProtect == other.OldProtect && NewProtect == other.NewProtect;
  }
};

struct SmartProtectKeyHash {
  std::size_t operator()(const SmartProtectKey &key) const noexcept {
    std::size_t seed = 0;
    HashMix(seed, key.TargetPid);
    HashMix(seed, key.Caller);
    HashMix(seed, key.StackHash);
    HashMix(seed, key.Size);
    HashMix(seed, key.OldProtect);
    HashMix(seed, key.NewProtect);
    return seed;
  }
};

struct SmartThreadKey {
  DWORD TargetPid = 0;
  UINT64 Start = 0;
  UINT64 StackHash = 0;

  bool operator==(const SmartThreadKey &other) const noexcept {
    return TargetPid == other.TargetPid && Start == other.Start &&
           StackHash == other.StackHash;
  }
};

struct SmartThreadKeyHash {
  std::size_t operator()(const SmartThreadKey &key) const noexcept {
    std::size_t seed = 0;
    HashMix(seed, key.TargetPid);
    HashMix(seed, key.Start);
    HashMix(seed, key.StackHash);
    return seed;
  }
};

struct SmartHandleKey {
  DWORD TargetPid = 0;
  DWORD TargetTid = 0;
  SmartHandleKind Kind = SmartHandleKind::Process;
  UINT32 DesiredAccess = 0;
  UINT64 Caller = 0;
  UINT64 StackHash = 0;

  bool operator==(const SmartHandleKey &other) const noexcept {
    return TargetPid == other.TargetPid && TargetTid == other.TargetTid &&
           Kind == other.Kind && DesiredAccess == other.DesiredAccess &&
           Caller == other.Caller && StackHash == other.StackHash;
  }
};

struct SmartHandleKeyHash {
  std::size_t operator()(const SmartHandleKey &key) const noexcept {
    std::size_t seed = 0;
    HashMix(seed, key.TargetPid);
    HashMix(seed, key.TargetTid);
    HashMix(seed, static_cast<UINT32>(key.Kind));
    HashMix(seed, key.DesiredAccess);
    HashMix(seed, key.Caller);
    HashMix(seed, key.StackHash);
    return seed;
  }
};
