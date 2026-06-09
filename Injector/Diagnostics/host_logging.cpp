#include "Diagnostics/diagnostics.h"

namespace blind::injector {
void HostDebugLog(ServerContext &ctx, const char *format, ...) {
  if (!ctx.DebugDiagnostics || ctx.HostLogFile == nullptr ||
      format == nullptr) {
    return;
  }

  char message[1024]{};
  va_list args;
  va_start(args, format);
  HRESULT hr = StringCchVPrintfA(message, RTL_NUMBER_OF(message), format, args);
  va_end(args);
  if (FAILED(hr)) {
    return;
  }

  std::fprintf(ctx.HostLogFile, "[%08lu] %s\n",
               static_cast<unsigned long>(GetTickCount()), message);
  std::fflush(ctx.HostLogFile);
}

std::wstring BuildRunDirectory(const std::wstring &baseDir) {
  SYSTEMTIME now{};
  GetLocalTime(&now);

  wchar_t name[96]{};
  (void)StringCchPrintfW(
      name, RTL_NUMBER_OF(name), L"run-%04u%02u%02u-%02u%02u%02u-%lu",
      static_cast<unsigned int>(now.wYear),
      static_cast<unsigned int>(now.wMonth),
      static_cast<unsigned int>(now.wDay), static_cast<unsigned int>(now.wHour),
      static_cast<unsigned int>(now.wMinute),
      static_cast<unsigned int>(now.wSecond),
      static_cast<unsigned long>(GetCurrentProcessId()));
  return JoinPath(JoinPath(baseDir, L"BlindDiagnostics"), name);
}
} // namespace blind::injector
