#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
extern bool g_ConsoleColorEnabled;

const char *AnsiForColor(LogColor color) noexcept;
bool StdoutIsConsole() noexcept;
void ConfigureConsoleColor(ConsoleColorMode mode) noexcept;
void BeginColor(LogColor color) noexcept;
void EndColor(LogColor color) noexcept;
void ColorPrintf(LogColor color, const char *format, ...);
void ColorWprintf(LogColor color, const wchar_t *format, ...);
} // namespace blind::injector
