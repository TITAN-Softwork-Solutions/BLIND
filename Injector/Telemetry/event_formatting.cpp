#include "Telemetry/event_formatting.h"

namespace blind::injector {
void CopyEventSampleString(const IXIPC_HOOK_EVENT &eventRecord, char *out,
                           std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  UINT32 safe = eventRecord.DataSize < IXIPC_MAX_HOOK_DATA_SAMPLE
                    ? eventRecord.DataSize
                    : IXIPC_MAX_HOOK_DATA_SAMPLE;
  if (safe >= 4) {
    UINT32 pairs = safe / 2;
    UINT32 printableLow = 0;
    UINT32 zeroHigh = 0;
    for (UINT32 i = 0; i < pairs; ++i) {
      unsigned char low = eventRecord.DataSample[i * 2];
      unsigned char high = eventRecord.DataSample[i * 2 + 1];
      if ((low >= 0x20 && low < 0x7F) || low == 0) {
        ++printableLow;
      }
      if (high == 0) {
        ++zeroHigh;
      }
    }

    if (zeroHigh * 2 >= pairs && printableLow * 2 >= pairs) {
      std::size_t written = 0;
      for (UINT32 i = 0; i < pairs && written + 1 < outChars; ++i) {
        unsigned char low = eventRecord.DataSample[i * 2];
        unsigned char high = eventRecord.DataSample[i * 2 + 1];
        if (low == 0 && high == 0) {
          break;
        }
        out[written++] = (low >= 0x20 && low < 0x7F && high == 0)
                             ? static_cast<char>(low)
                             : '.';
      }
      out[written] = '\0';
      return;
    }
  }

  safe = safe < outChars - 1 ? safe : static_cast<UINT32>(outChars - 1);
  for (UINT32 i = 0; i < safe; ++i) {
    unsigned char ch = eventRecord.DataSample[i];
    out[i] = (ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '.';
  }
  out[safe] = '\0';
}

bool SampleLooksLikePath(const char *sample) noexcept {
  if (sample == nullptr || sample[0] == '\0') {
    return false;
  }

  return std::strchr(sample, '\\') != nullptr ||
         std::strchr(sample, '/') != nullptr ||
         (std::strlen(sample) > 2 && sample[1] == ':' &&
          (sample[2] == '\\' || sample[2] == '/'));
}

const char *SampleLabelForEvent(const IXIPC_HOOK_EVENT &eventRecord,
                                const char *sample) noexcept {
  if (eventRecord.ApiName[0] != '\0' &&
      (_stricmp(eventRecord.ApiName, "LdrLoadDll") == 0 ||
       _stricmp(eventRecord.ApiName, "LoadLibraryA") == 0 ||
       _stricmp(eventRecord.ApiName, "LoadLibraryW") == 0 ||
       _stricmp(eventRecord.ApiName, "LoadLibraryExA") == 0 ||
       _stricmp(eventRecord.ApiName, "LoadLibraryExW") == 0)) {
    return "path";
  }
  return SampleLooksLikePath(sample) ? "path" : "sample";
}

void CopyConsoleSampleDisplay(const char *sample, char *out,
                              std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';
  if (sample == nullptr || sample[0] == '\0') {
    return;
  }

  constexpr std::size_t kMaxConsoleSampleChars = 180;
  std::size_t limit = outChars > 1 ? outChars - 1 : 0;
  if (limit > kMaxConsoleSampleChars) {
    limit = kMaxConsoleSampleChars;
  }

  std::size_t written = 0;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(sample);
       *p != 0 && written < limit; ++p) {
    if (*p == '"' || *p < 0x20 || *p >= 0x7F) {
      out[written++] = '.';
    } else {
      out[written++] = static_cast<char>(*p);
    }
  }
  out[written] = '\0';

  if (sample[written] != '\0' && written >= 3) {
    out[written - 3] = '.';
    out[written - 2] = '.';
    out[written - 1] = '.';
  }
}

void FormatEventSampleSuffix(const IXIPC_HOOK_EVENT &eventRecord, char *out,
                             std::size_t outChars) noexcept {
  if (out == nullptr || outChars == 0) {
    return;
  }
  out[0] = '\0';

  char sample[IXIPC_MAX_HOOK_DATA_SAMPLE + 1]{};
  CopyEventSampleString(eventRecord, sample, RTL_NUMBER_OF(sample));
  if (sample[0] == '\0') {
    return;
  }

  char display[192]{};
  CopyConsoleSampleDisplay(sample, display, RTL_NUMBER_OF(display));
  (void)StringCchPrintfA(out, outChars, " %s=\"%s\"",
                         SampleLabelForEvent(eventRecord, sample), display);
}

UINT32 DecodeRepeatCount(UINT32 callerFlags) noexcept {
  UINT32 repeat =
      (callerFlags & IX_HOOK_CALLER_REPEAT_MASK) >> IX_HOOK_CALLER_REPEAT_SHIFT;
  return repeat != 0 ? repeat : 1u;
}

UINT32 EncodeRepeatCount(UINT32 callerFlags, UINT32 repeat) noexcept {
  callerFlags &= ~IX_HOOK_CALLER_REPEAT_MASK;
  if (repeat > 1) {
    if (repeat > 0xFFFu) {
      repeat = 0xFFFu;
    }
    callerFlags |=
        (repeat << IX_HOOK_CALLER_REPEAT_SHIFT) & IX_HOOK_CALLER_REPEAT_MASK;
  }
  return callerFlags;
}

} // namespace blind::injector
