#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
std::wstring WideBaseName(const std::wstring &path);
bool GetRemoteModuleBase(DWORD pid, const std::wstring &baseName, UINT64 &base);
bool InjectDllIntoChild(ServerContext &ctx, HANDLE process,
                        const std::wstring &dllPath);
} // namespace blind::injector
