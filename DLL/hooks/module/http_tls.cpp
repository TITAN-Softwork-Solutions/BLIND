#include "module_internal.h"

namespace IX_MODULE_INTERNAL
{
    struct HttpHandleEntry
    {
        PVOID Handle;
        PVOID Parent;
        INTERNET_PORT Port;
        bool Request;
        bool Secure;
        WCHAR Host[128];
        WCHAR Method[16];
        WCHAR Path[160];
    };

    static SRWLOCK g_HttpHandleLock = SRWLOCK_INIT;
    static HttpHandleEntry g_HttpHandles[128]{};
    static std::uint32_t g_HttpHandleHead = 0;

    static void CopyWideTruncated(WCHAR *dst, std::size_t dstCount, LPCWSTR src) noexcept
    {
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (src != nullptr && src[0] != L'\0')
        {
            (void)wcsncpy_s(dst, dstCount, src, _TRUNCATE);
        }
    }

    static void CopyAnsiToWideTruncated(WCHAR *dst, std::size_t dstCount, LPCSTR src) noexcept
    {
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (src == nullptr || src[0] == '\0')
        {
            return;
        }
        MultiByteToWideChar(CP_ACP, 0, src, -1, dst, static_cast<int>(dstCount));
        dst[dstCount - 1] = L'\0';
    }

    static void HttpCacheStoreConnect(PVOID handle, LPCWSTR host, INTERNET_PORT port) noexcept
    {
        if (handle == nullptr)
        {
            return;
        }
        AcquireSRWLockExclusive(&g_HttpHandleLock);
        HttpHandleEntry &entry = g_HttpHandles[g_HttpHandleHead++ % RTL_NUMBER_OF(g_HttpHandles)];
        std::memset(&entry, 0, sizeof(entry));
        entry.Handle = handle;
        entry.Port = port;
        entry.Request = false;
        entry.Secure = (port == 443);
        CopyWideTruncated(entry.Host, RTL_NUMBER_OF(entry.Host), host);
        ReleaseSRWLockExclusive(&g_HttpHandleLock);
    }

    static bool HttpCacheLookup(PVOID handle, HttpHandleEntry &out) noexcept
    {
        bool found = false;
        if (handle == nullptr)
        {
            return false;
        }
        AcquireSRWLockShared(&g_HttpHandleLock);
        for (const auto &entry : g_HttpHandles)
        {
            if (entry.Handle == handle)
            {
                out = entry;
                found = true;
                break;
            }
        }
        ReleaseSRWLockShared(&g_HttpHandleLock);
        return found;
    }

    static void HttpCacheStoreRequest(PVOID request, PVOID connect, LPCWSTR method, LPCWSTR path, bool secure) noexcept
    {
        if (request == nullptr)
        {
            return;
        }

        HttpHandleEntry parent{};
        (void)HttpCacheLookup(connect, parent);

        AcquireSRWLockExclusive(&g_HttpHandleLock);
        HttpHandleEntry &entry = g_HttpHandles[g_HttpHandleHead++ % RTL_NUMBER_OF(g_HttpHandles)];
        std::memset(&entry, 0, sizeof(entry));
        entry.Handle = request;
        entry.Parent = connect;
        entry.Port = parent.Port;
        entry.Request = true;
        entry.Secure = secure || parent.Secure;
        CopyWideTruncated(entry.Host, RTL_NUMBER_OF(entry.Host), parent.Host);
        CopyWideTruncated(
            entry.Method, RTL_NUMBER_OF(entry.Method), method != nullptr && method[0] != L'\0' ? method : L"GET");
        CopyWideTruncated(entry.Path, RTL_NUMBER_OF(entry.Path), path != nullptr && path[0] != L'\0' ? path : L"/");
        ReleaseSRWLockExclusive(&g_HttpHandleLock);
    }

    static void PublishHttpConnectEvent(ModuleHookOperation op,
                                        const char *apiName,
                                        const char *sourceModule,
                                        PVOID handle,
                                        LPCWSTR host,
                                        INTERNET_PORT port,
                                        bool secureHint) noexcept
    {
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)]{};
        (void)swprintf_s(reason,
                         RTL_NUMBER_OF(reason),
                         L"http.connect api=%S handle=0x%p url=%s://%s:%hu",
                         apiName,
                         handle,
                         (secureHint || port == 443) ? L"https" : L"http",
                         host != nullptr && host[0] != L'\0' ? host : L"<unknown>",
                         static_cast<unsigned short>(port));
        PublishModuleEvent(op,
                           apiName,
                           sourceModule,
                           nullptr,
                           reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR),
                           reinterpret_cast<std::uint64_t>(handle),
                           static_cast<std::uint64_t>(port),
                           secureHint ? 1u : 0u,
                           0);
    }

    static void PublishHttpOpenRequestEvent(ModuleHookOperation op,
                                            const char *apiName,
                                            const char *sourceModule,
                                            PVOID request,
                                            PVOID connect,
                                            LPCWSTR method,
                                            LPCWSTR path,
                                            bool secureHint) noexcept
    {
        HttpHandleEntry parent{};
        (void)HttpCacheLookup(connect, parent);

        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)]{};
        (void)swprintf_s(reason,
                         RTL_NUMBER_OF(reason),
                         L"http.open api=%S request=0x%p connect=0x%p method=%s url=%s://%s%s",
                         apiName,
                         request,
                         connect,
                         method != nullptr && method[0] != L'\0' ? method : L"GET",
                         (secureHint || parent.Secure) ? L"https" : L"http",
                         parent.Host[0] != L'\0' ? parent.Host : L"<unknown>",
                         path != nullptr && path[0] != L'\0' ? path : L"/");
        PublishModuleEvent(op,
                           apiName,
                           sourceModule,
                           nullptr,
                           reason,
                           wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR),
                           reinterpret_cast<std::uint64_t>(request),
                           reinterpret_cast<std::uint64_t>(connect),
                           secureHint ? 1u : 0u,
                           0);
    }

    void CopyPrintableBytesToWide(WCHAR *dst, std::size_t dstCount, const void *bytes, DWORD byteCount) noexcept
    {
        auto *src = static_cast<const unsigned char *>(bytes);
        std::size_t out = 0;
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (src == nullptr || byteCount == 0)
        {
            return;
        }
        for (DWORD i = 0; i < byteCount && out + 1 < dstCount; ++i)
        {
            unsigned char ch = src[i];
            if (ch == '\r')
            {
                continue;
            }
            dst[out++] = (ch == '\n') ? L'|' : (ch >= 0x20 && ch < 0x7F) ? static_cast<WCHAR>(ch) : L'.';
        }
        dst[out] = L'\0';
    }

    void CopyWidePrintableToWide(WCHAR *dst, std::size_t dstCount, LPCWSTR text, DWORD chars) noexcept
    {
        std::size_t out = 0;
        if (dst == nullptr || dstCount == 0)
        {
            return;
        }
        dst[0] = L'\0';
        if (text == nullptr)
        {
            return;
        }
        if (chars == 0xFFFFFFFFu)
        {
            chars = static_cast<DWORD>(wcsnlen_s(text, dstCount * 4));
        }
        for (DWORD i = 0; i < chars && text[i] != L'\0' && out + 1 < dstCount; ++i)
        {
            WCHAR ch = text[i];
            if (ch == L'\r')
            {
                continue;
            }
            dst[out++] = (ch == L'\n') ? L'|' : (ch >= 0x20 && ch < 0x7F) ? ch : L'.';
        }
        dst[out] = L'\0';
    }

    bool BufferLooksUtf16LeText(const void *buffer, ULONG byteCount) noexcept
    {
        auto *bytes = static_cast<const unsigned char *>(buffer);
        ULONG pairs = 0;
        ULONG wideAsciiPairs = 0;
        if (bytes == nullptr || byteCount < sizeof(WCHAR))
        {
            return false;
        }

        ULONG limit = byteCount < 128u ? byteCount : 128u;
        limit &= ~1u;
        for (ULONG i = 0; i + 1 < limit; i += 2)
        {
            unsigned char low = bytes[i];
            unsigned char high = bytes[i + 1];
            if (low == 0 && high == 0)
            {
                continue;
            }

            ++pairs;
            if (high == 0 && (low == '\r' || low == '\n' || low == '\t' || (low >= 0x20 && low < 0x7F)))
            {
                ++wideAsciiPairs;
            }
        }

        return pairs != 0 && (wideAsciiPairs * 2u) >= pairs;
    }

    static void PublishHttpLibraryRequest(ModuleHookOperation op,
                                          const char *apiName,
                                          const char *sourceModule,
                                          PVOID request,
                                          LPCWSTR headers,
                                          DWORD headerChars,
                                          PVOID optional,
                                          DWORD optionalBytes,
                                          bool secureHint) noexcept
    {
        HttpHandleEntry requestInfo{};
        WCHAR headerSample[96];
        WCHAR contentSample[64];
        WCHAR reason[IXIPC_MAX_HOOK_DATA_SAMPLE / sizeof(WCHAR)];

        std::memset(headerSample, 0, sizeof(headerSample));
        std::memset(contentSample, 0, sizeof(contentSample));
        std::memset(reason, 0, sizeof(reason));
        (void)HttpCacheLookup(request, requestInfo);
        if (requestInfo.Method[0] == L'\0')
        {
            CopyWideTruncated(requestInfo.Method, RTL_NUMBER_OF(requestInfo.Method), L"GET");
        }
        if (requestInfo.Path[0] == L'\0')
        {
            CopyWideTruncated(requestInfo.Path, RTL_NUMBER_OF(requestInfo.Path), L"/");
        }
        if (secureHint)
        {
            requestInfo.Secure = true;
        }

        CopyWidePrintableToWide(headerSample, RTL_NUMBER_OF(headerSample), headers, headerChars);
        CopyPrintableBytesToWide(contentSample, RTL_NUMBER_OF(contentSample), optional, optionalBytes);

        (void)swprintf_s(reason,
                         RTL_NUMBER_OF(reason),
                         L"http.request method=%s url=%s://%s%s cn=%s pid=%lu api=%S bytes=%lu ms=0 rep=unknown "
                         L"content=%s headers=\"%s\"",
                         requestInfo.Method,
                         requestInfo.Secure ? L"https" : L"http",
                         requestInfo.Host[0] != L'\0' ? requestInfo.Host : L"<unknown>",
                         requestInfo.Path,
                         requestInfo.Host[0] != L'\0' ? requestInfo.Host : L"<unknown>",
                         static_cast<unsigned long>(GetCurrentProcessId()),
                         apiName,
                         static_cast<unsigned long>(optionalBytes),
                         contentSample[0] != L'\0' ? contentSample : L"-",
                         headerSample[0] != L'\0' ? headerSample : L"-");

        PublishModuleEvent(
            op, apiName, sourceModule, nullptr, reason, wcsnlen_s(reason, RTL_NUMBER_OF(reason)) * sizeof(WCHAR));
    }

    static bool BufferLooksHttp(const unsigned char *data, DWORD size) noexcept
    {
        if (data == nullptr || size < 4)
        {
            return false;
        }
        const char *text = reinterpret_cast<const char *>(data);
        return (size >= 4 && _strnicmp(text, "GET ", 4) == 0) || (size >= 5 && _strnicmp(text, "POST ", 5) == 0) ||
               (size >= 4 && _strnicmp(text, "PUT ", 4) == 0) || (size >= 5 && _strnicmp(text, "HEAD ", 5) == 0) ||
               (size >= 7 && _strnicmp(text, "DELETE ", 7) == 0) || (size >= 6 && _strnicmp(text, "PATCH ", 6) == 0) ||
               (size >= 8 && _strnicmp(text, "OPTIONS ", 8) == 0) || (size >= 5 && _strnicmp(text, "HTTP/", 5) == 0);
    }

    static void PublishSchannelPlaintext(ModuleHookOperation op, const char *apiName, const void *message) noexcept
    {
        struct LocalSecBuffer
        {
            unsigned long cbBuffer;
            unsigned long BufferType;
            void *pvBuffer;
        };
        struct LocalSecBufferDesc
        {
            unsigned long ulVersion;
            unsigned long cBuffers;
            LocalSecBuffer *pBuffers;
        };

        auto *desc = static_cast<const LocalSecBufferDesc *>(message);
        if (desc == nullptr || desc->pBuffers == nullptr || desc->cBuffers > 16)
        {
            return;
        }

        for (unsigned long i = 0; i < desc->cBuffers; ++i)
        {
            const LocalSecBuffer &buffer = desc->pBuffers[i];
            if (buffer.BufferType != 1u || buffer.pvBuffer == nullptr || buffer.cbBuffer == 0)
            {
                continue;
            }
            auto *bytes = static_cast<const unsigned char *>(buffer.pvBuffer);
            if (!BufferLooksHttp(bytes, buffer.cbBuffer))
            {
                continue;
            }
            PublishModuleEvent(op, apiName, "secur32", nullptr, bytes, buffer.cbBuffer);
            break;
        }
    }

    PVOID WINAPI WinHttpConnectHook(PVOID session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved)
    {
        if (g_OriginalWinHttpConnect == nullptr)
        {
            return nullptr;
        }

        PVOID handle = CallOriginalSafely(g_OriginalWinHttpConnect, session, serverName, serverPort, reserved);
        HttpCacheStoreConnect(handle, serverName, serverPort);
        PublishHttpConnectEvent(
            ModuleHookOperation::WinHttpConnect, "WinHttpConnect", "winhttp", handle, serverName, serverPort, false);
        return handle;
    }

    PVOID WINAPI WinHttpOpenRequestHook(PVOID connect,
                                        LPCWSTR verb,
                                        LPCWSTR objectName,
                                        LPCWSTR version,
                                        LPCWSTR referrer,
                                        LPCWSTR *acceptTypes,
                                        DWORD flags)
    {
        if (g_OriginalWinHttpOpenRequest == nullptr)
        {
            return nullptr;
        }

        PVOID request = CallOriginalSafely(
            g_OriginalWinHttpOpenRequest, connect, verb, objectName, version, referrer, acceptTypes, flags);
        HttpCacheStoreRequest(request, connect, verb, objectName, (flags & WINHTTP_FLAG_SECURE) != 0);
        PublishHttpOpenRequestEvent(ModuleHookOperation::WinHttpOpenRequest,
                                    "WinHttpOpenRequest",
                                    "winhttp",
                                    request,
                                    connect,
                                    verb,
                                    objectName,
                                    (flags & WINHTTP_FLAG_SECURE) != 0);
        return request;
    }

    BOOL WINAPI WinHttpSendRequestHook(PVOID request,
                                       LPCWSTR headers,
                                       DWORD headersLength,
                                       PVOID optional,
                                       DWORD optionalLength,
                                       DWORD totalLength,
                                       DWORD_PTR context)
    {
        if (g_OriginalWinHttpSendRequest == nullptr)
        {
            return FALSE;
        }

        PublishHttpLibraryRequest(ModuleHookOperation::WinHttpSendRequest,
                                  "WinHttpSendRequest",
                                  "winhttp",
                                  request,
                                  headers,
                                  headersLength,
                                  optional,
                                  optionalLength,
                                  false);
        return CallOriginalSafely(g_OriginalWinHttpSendRequest,
                                  request,
                                  headers,
                                  headersLength,
                                  optional,
                                  optionalLength,
                                  totalLength,
                                  context);
    }

    PVOID WINAPI InternetConnectWHook(PVOID internet,
                                      LPCWSTR serverName,
                                      INTERNET_PORT serverPort,
                                      LPCWSTR userName,
                                      LPCWSTR password,
                                      DWORD service,
                                      DWORD flags,
                                      DWORD_PTR context)
    {
        if (g_OriginalInternetConnectW == nullptr)
        {
            return nullptr;
        }

        PVOID handle = CallOriginalSafely(
            g_OriginalInternetConnectW, internet, serverName, serverPort, userName, password, service, flags, context);
        if (service == INTERNET_SERVICE_HTTP)
        {
            HttpCacheStoreConnect(handle, serverName, serverPort);
            PublishHttpConnectEvent(ModuleHookOperation::InternetConnectW,
                                    "InternetConnectW",
                                    "wininet",
                                    handle,
                                    serverName,
                                    serverPort,
                                    (flags & INTERNET_FLAG_SECURE) != 0);
        }
        return handle;
    }

    PVOID WINAPI InternetConnectAHook(PVOID internet,
                                      LPCSTR serverName,
                                      INTERNET_PORT serverPort,
                                      LPCSTR userName,
                                      LPCSTR password,
                                      DWORD service,
                                      DWORD flags,
                                      DWORD_PTR context)
    {
        if (g_OriginalInternetConnectA == nullptr)
        {
            return nullptr;
        }

        PVOID handle = CallOriginalSafely(
            g_OriginalInternetConnectA, internet, serverName, serverPort, userName, password, service, flags, context);
        if (service == INTERNET_SERVICE_HTTP)
        {
            WCHAR host[128];
            CopyAnsiToWideTruncated(host, RTL_NUMBER_OF(host), serverName);
            HttpCacheStoreConnect(handle, host, serverPort);
            PublishHttpConnectEvent(ModuleHookOperation::InternetConnectA,
                                    "InternetConnectA",
                                    "wininet",
                                    handle,
                                    host,
                                    serverPort,
                                    (flags & INTERNET_FLAG_SECURE) != 0);
        }
        return handle;
    }

    PVOID WINAPI HttpOpenRequestWHook(PVOID connect,
                                      LPCWSTR verb,
                                      LPCWSTR objectName,
                                      LPCWSTR version,
                                      LPCWSTR referrer,
                                      LPCWSTR *acceptTypes,
                                      DWORD flags,
                                      DWORD_PTR context)
    {
        if (g_OriginalHttpOpenRequestW == nullptr)
        {
            return nullptr;
        }

        PVOID request = CallOriginalSafely(
            g_OriginalHttpOpenRequestW, connect, verb, objectName, version, referrer, acceptTypes, flags, context);
        HttpCacheStoreRequest(request, connect, verb, objectName, (flags & INTERNET_FLAG_SECURE) != 0);
        PublishHttpOpenRequestEvent(ModuleHookOperation::HttpOpenRequestW,
                                    "HttpOpenRequestW",
                                    "wininet",
                                    request,
                                    connect,
                                    verb,
                                    objectName,
                                    (flags & INTERNET_FLAG_SECURE) != 0);
        return request;
    }

    PVOID WINAPI HttpOpenRequestAHook(PVOID connect,
                                      LPCSTR verb,
                                      LPCSTR objectName,
                                      LPCSTR version,
                                      LPCSTR referrer,
                                      LPCSTR *acceptTypes,
                                      DWORD flags,
                                      DWORD_PTR context)
    {
        if (g_OriginalHttpOpenRequestA == nullptr)
        {
            return nullptr;
        }

        PVOID request = CallOriginalSafely(
            g_OriginalHttpOpenRequestA, connect, verb, objectName, version, referrer, acceptTypes, flags, context);
        WCHAR method[16];
        WCHAR path[160];
        CopyAnsiToWideTruncated(method, RTL_NUMBER_OF(method), verb);
        CopyAnsiToWideTruncated(path, RTL_NUMBER_OF(path), objectName);
        HttpCacheStoreRequest(request, connect, method, path, (flags & INTERNET_FLAG_SECURE) != 0);
        PublishHttpOpenRequestEvent(ModuleHookOperation::HttpOpenRequestA,
                                    "HttpOpenRequestA",
                                    "wininet",
                                    request,
                                    connect,
                                    method,
                                    path,
                                    (flags & INTERNET_FLAG_SECURE) != 0);
        return request;
    }

    BOOL WINAPI
    HttpSendRequestWHook(PVOID request, LPCWSTR headers, DWORD headersLength, PVOID optional, DWORD optionalLength)
    {
        if (g_OriginalHttpSendRequestW == nullptr)
        {
            return FALSE;
        }

        PublishHttpLibraryRequest(ModuleHookOperation::HttpSendRequestW,
                                  "HttpSendRequestW",
                                  "wininet",
                                  request,
                                  headers,
                                  headersLength,
                                  optional,
                                  optionalLength,
                                  false);
        return CallOriginalSafely(
            g_OriginalHttpSendRequestW, request, headers, headersLength, optional, optionalLength);
    }

    BOOL WINAPI
    HttpSendRequestAHook(PVOID request, LPCSTR headers, DWORD headersLength, PVOID optional, DWORD optionalLength)
    {
        if (g_OriginalHttpSendRequestA == nullptr)
        {
            return FALSE;
        }

        WCHAR wideHeaders[96];
        CopyAnsiToWideTruncated(wideHeaders, RTL_NUMBER_OF(wideHeaders), headers);
        PublishHttpLibraryRequest(ModuleHookOperation::HttpSendRequestA,
                                  "HttpSendRequestA",
                                  "wininet",
                                  request,
                                  wideHeaders,
                                  headersLength == 0xFFFFFFFFu
                                      ? static_cast<DWORD>(wcsnlen_s(wideHeaders, RTL_NUMBER_OF(wideHeaders)))
                                      : static_cast<DWORD>(wcsnlen_s(wideHeaders, RTL_NUMBER_OF(wideHeaders))),
                                  optional,
                                  optionalLength,
                                  false);
        return CallOriginalSafely(
            g_OriginalHttpSendRequestA, request, headers, headersLength, optional, optionalLength);
    }

    LONG WINAPI EncryptMessageHook(PVOID context, ULONG qualityOfProtection, PVOID message, ULONG sequenceNumber)
    {
        if (g_OriginalEncryptMessage == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        PublishSchannelPlaintext(ModuleHookOperation::SchannelEncryptMessage, "EncryptMessage", message);
        return CallOriginalSafely(g_OriginalEncryptMessage, context, qualityOfProtection, message, sequenceNumber);
    }

    LONG WINAPI DecryptMessageHook(PVOID context, PVOID message, ULONG sequenceNumber, PULONG qualityOfProtection)
    {
        if (g_OriginalDecryptMessage == nullptr)
        {
            return SEC_E_INTERNAL_ERROR;
        }

        LONG status =
            CallOriginalSafely(g_OriginalDecryptMessage, context, message, sequenceNumber, qualityOfProtection);
        if (status >= 0)
        {
            PublishSchannelPlaintext(ModuleHookOperation::SchannelDecryptMessage, "DecryptMessage", message);
        }
        return status;
    }
} // namespace IX_MODULE_INTERNAL
