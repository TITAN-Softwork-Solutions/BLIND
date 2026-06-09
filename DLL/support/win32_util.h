#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <strsafe.h>

#include "../../ABI/blind_ipc.h"

#include <string>

namespace BLIND_SUPPORT
{
    inline bool FileExists(const std::wstring &path) noexcept
    {
        const DWORD attrs = GetFileAttributesW(path.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    inline std::wstring DirectoryOf(const wchar_t *path)
    {
        if (path == nullptr || path[0] == L'\0')
        {
            return L".";
        }

        wchar_t buffer[MAX_PATH]{};
        if (FAILED(StringCchCopyW(buffer, RTL_NUMBER_OF(buffer), path)))
        {
            return L".";
        }

        wchar_t *slash = wcsrchr(buffer, L'\\');
        if (slash != nullptr)
        {
            *slash = L'\0';
        }
        return buffer;
    }

    inline std::wstring ModuleDirectory()
    {
        wchar_t modulePath[MAX_PATH]{};
        const DWORD chars = GetModuleFileNameW(nullptr, modulePath, RTL_NUMBER_OF(modulePath));
        if (chars == 0 || chars >= RTL_NUMBER_OF(modulePath))
        {
            return L".";
        }
        return DirectoryOf(modulePath);
    }

    inline std::wstring JoinPath(const std::wstring &left, const wchar_t *right)
    {
        std::wstring joined = left;
        if (!joined.empty() && joined.back() != L'\\')
        {
            joined += L'\\';
        }
        if (right != nullptr)
        {
            joined += right;
        }
        return joined;
    }

    inline bool EnsureDirectory(const std::wstring &path) noexcept
    {
        if (path.empty())
        {
            return false;
        }

        if (CreateDirectoryW(path.c_str(), nullptr))
        {
            return true;
        }

        return GetLastError() == ERROR_ALREADY_EXISTS;
    }

    inline bool EnvironmentVariableEnabled(const wchar_t *name) noexcept
    {
        if (name == nullptr || name[0] == L'\0')
        {
            return false;
        }

        wchar_t value[16]{};
        const DWORD chars = GetEnvironmentVariableW(name, value, RTL_NUMBER_OF(value));
        if (chars == 0 || chars >= RTL_NUMBER_OF(value))
        {
            return false;
        }

        return lstrcmpiW(value, L"1") == 0 || lstrcmpiW(value, L"true") == 0 || lstrcmpiW(value, L"yes") == 0 ||
               lstrcmpiW(value, L"on") == 0;
    }

    inline std::wstring QuotePath(const std::wstring &path)
    {
        std::wstring quoted = L"\"";
        quoted += path;
        quoted += L"\"";
        return quoted;
    }

    inline std::wstring EffectivePipeName()
    {
        wchar_t pipeName[IXIPC_MAX_PIPE_NAME_CHARS]{};
        const DWORD chars = GetEnvironmentVariableW(IXIPC_PIPE_NAME_ENV, pipeName, RTL_NUMBER_OF(pipeName));
        if (chars > 0 && chars < RTL_NUMBER_OF(pipeName))
        {
            return pipeName;
        }
        return IXIPC_HOOK_PIPE_NAME;
    }

    inline bool WritePacket(HANDLE pipe, const IXIPC_PACKET &packet) noexcept
    {
        DWORD written = 0;
        return WriteFile(pipe, &packet, static_cast<DWORD>(sizeof(packet)), &written, nullptr) &&
               written == static_cast<DWORD>(sizeof(packet));
    }

    inline const char *KindName(UINT32 kind) noexcept
    {
        switch (kind)
        {
        case IxIpcHookEventNt:
            return "nt";
        case IxIpcHookEventWinsock:
            return "winsock";
        case IxIpcHookEventKi:
            return "ki";
        case IxIpcHookEventExceptionLowNoise:
        case IxIpcHookEventExceptionHighPriv:
            return "exception";
        case IxIpcHookEventIntegrity:
            return "integrity";
        case IxIpcHookEventModule:
            return "module";
        default:
            return "unknown";
        }
    }
} // namespace BLIND_SUPPORT
