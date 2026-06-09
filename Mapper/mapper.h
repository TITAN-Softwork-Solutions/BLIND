#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <string>

namespace blind::injector
{
    struct ServerContext;
}

namespace blind::mapper
{
    bool PauseDebuggedChildAtEntrypoint(blind::injector::ServerContext &ctx, PROCESS_INFORMATION &pi);
    bool MapDllIntoChild(blind::injector::ServerContext &ctx, HANDLE process, const std::wstring &dllPath);
} // namespace blind::mapper
