#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
bool IsHelpArgument(const wchar_t *arg) noexcept;
void PrintUsage();
void PrintHelpTopic(const wchar_t *topic);
bool CopyWideToAnsi(const wchar_t *input, char *out,
                    std::size_t outChars) noexcept;
const wchar_t *ComponentDisplayName(UINT32 component) noexcept;
} // namespace blind::injector
