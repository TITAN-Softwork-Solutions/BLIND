#include "Core/runner_console.h"

namespace blind::injector {
bool g_ConsoleColorEnabled = false;

const char *AnsiForColor(LogColor color) noexcept {
  switch (color) {
  case LogColor::Info:
    return "\x1b[36m";
  case LogColor::Smart:
    return "\x1b[96m";
  case LogColor::Alert:
    return "\x1b[93m";
  case LogColor::Suspicious:
    return "\x1b[91m";
  case LogColor::Remote:
    return "\x1b[94m";
  case LogColor::RemoteRisk:
    return "\x1b[35m";
  case LogColor::Success:
    return "\x1b[92m";
  case LogColor::Warning:
    return "\x1b[33m";
  case LogColor::Error:
    return "\x1b[31m";
  case LogColor::Muted:
    return "\x1b[90m";
  case LogColor::Stack:
    return "\x1b[37m";
  case LogColor::Lifecycle:
    return "\x1b[95m";
  default:
    return "";
  }
}

bool StdoutIsConsole() noexcept {
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (output == nullptr || output == INVALID_HANDLE_VALUE) {
    return false;
  }

  DWORD mode = 0;
  if (!GetConsoleMode(output, &mode)) {
    return false;
  }

  DWORD desired = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (SetConsoleMode(output, desired)) {
    return true;
  }
  return GetConsoleMode(output, &mode) != FALSE;
}

void ConfigureConsoleColor(ConsoleColorMode mode) noexcept {
  if (mode == ConsoleColorMode::Never) {
    g_ConsoleColorEnabled = false;
    return;
  }
  if (mode == ConsoleColorMode::Always) {
    g_ConsoleColorEnabled = true;
    (void)StdoutIsConsole();
    return;
  }
  g_ConsoleColorEnabled = StdoutIsConsole();
}

void BeginColor(LogColor color) noexcept {
  if (!g_ConsoleColorEnabled || color == LogColor::Default) {
    return;
  }
  std::fputs(AnsiForColor(color), stdout);
}

void EndColor(LogColor color) noexcept {
  if (!g_ConsoleColorEnabled || color == LogColor::Default) {
    return;
  }
  std::fputs("\x1b[0m", stdout);
}

void ColorPrintf(LogColor color, const char *format, ...) {
  BeginColor(color);
  va_list args;
  va_start(args, format);
  std::vprintf(format, args);
  va_end(args);
  EndColor(color);
}

void ColorWprintf(LogColor color, const wchar_t *format, ...) {
  BeginColor(color);
  va_list args;
  va_start(args, format);
  std::vwprintf(format, args);
  va_end(args);
  EndColor(color);
}

} // namespace blind::injector
