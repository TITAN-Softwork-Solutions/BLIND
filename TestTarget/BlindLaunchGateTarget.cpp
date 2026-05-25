#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <WinSock2.h>
#include <Windows.h>

namespace
{
    using WsaStartupFn = int(WSAAPI *)(WORD, LPWSADATA);
    using WsaCleanupFn = int(WSAAPI *)();
    using SocketFn = SOCKET(WSAAPI *)(int, int, int);
    using CloseSocketFn = int(WSAAPI *)(SOCKET);

    void WriteConsoleLine(const char *message) noexcept
    {
        if (message == nullptr)
        {
            return;
        }

        DWORD length = 0;
        while (message[length] != '\0')
        {
            ++length;
        }

        DWORD written = 0;
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output != nullptr && output != INVALID_HANDLE_VALUE)
        {
            (void)WriteFile(output, message, length, &written, nullptr);
        }
    }

    void TouchWinsock() noexcept
    {
        HMODULE ws2 = LoadLibraryW(L"ws2_32.dll");
        if (ws2 == nullptr)
        {
            return;
        }

        auto wsaStartup = reinterpret_cast<WsaStartupFn>(GetProcAddress(ws2, "WSAStartup"));
        auto wsaCleanup = reinterpret_cast<WsaCleanupFn>(GetProcAddress(ws2, "WSACleanup"));
        auto socketFn = reinterpret_cast<SocketFn>(GetProcAddress(ws2, "socket"));
        auto closeSocket = reinterpret_cast<CloseSocketFn>(GetProcAddress(ws2, "closesocket"));

        WSADATA data;
        if (wsaStartup != nullptr && wsaCleanup != nullptr && socketFn != nullptr && closeSocket != nullptr &&
            wsaStartup(MAKEWORD(2, 2), &data) == 0)
        {
            SOCKET sock = socketFn(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock != INVALID_SOCKET)
            {
                (void)closeSocket(sock);
            }
            (void)wsaCleanup();
        }

        FreeLibrary(ws2);
    }
}

extern "C" void WINAPI LaunchGateTargetEntry()
{
    WriteConsoleLine("[launch-target] entry reached\r\n");
    TouchWinsock();
    Sleep(50);
    WriteConsoleLine("[launch-target] exit clean\r\n");
    ExitProcess(0);
}
