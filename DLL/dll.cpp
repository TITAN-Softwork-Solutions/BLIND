#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "ipc/pipe.h"
#include "hooks/runtime/runtime.h"
#include "hooks/encoded_literal.h"

template <std::size_t N>
static bool IsTruthyEnvironmentFlag(const IX_RUNTIME_INTERNAL::IxEncodedAnsiLiteral<N> &envName) noexcept
{
    char value[8]{};
    IX_RUNTIME_INTERNAL::IxScopedAnsiLiteral decoded(envName);
    DWORD read = GetEnvironmentVariableA(decoded.c_str(), value, (DWORD)RTL_NUMBER_OF(value));
    if (read == 0 || read >= RTL_NUMBER_OF(value))
    {
        return false;
    }

    return (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T');
}

static bool ShouldPrepareLaunchGate() noexcept
{
    static constexpr IX_RUNTIME_INTERNAL::IxEncodedAnsiLiteral kEnvName{"IX_HOOK_LAUNCH_GATE", 0x6Du};
    return IsTruthyEnvironmentFlag(kEnvName);
}

static DWORD WINAPI IxDispatchFlightThread(LPVOID)
{
    __try
    {
        IxDbgLog("IxDispatchFlightThread: entering runtime thread proc");
        return IxRuntimeThreadProc(nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IxDbgLog("IxDispatchFlightThread: runtime thread exception=0x%08lX", (unsigned long)GetExceptionCode());
        return 0;
    }
}

static BOOL IxProcessAttach(HMODULE hModule, LPVOID reserved)
{
    DisableThreadLibraryCalls(hModule);

    bool launchGate = ShouldPrepareLaunchGate();
    IxDbgLog("DllMain: PROCESS_ATTACH launchGate=%u reserved=%p", launchGate ? 1u : 0u, reserved);
    if (launchGate)
    {
        if (!IxInitializeSubsystems())
        {
            IxDbgLog("DllMain: launch gate preparation failed");
            IxRuntimeFailClosed(ERROR_DLL_INIT_FAILED);
            return FALSE;
        }

        IxDbgLog("DllMain: launch gate bootstrap deferred to trapped target thread");
        return TRUE;
    }

    HANDLE hThread = IxRuntimeCreateBootstrapThread(IxDispatchFlightThread, nullptr);

    if (hThread)
    {
        IxDbgLog("DllMain: bootstrap thread created handle=%p", hThread);
        IxRuntimeCloseHandle(hThread);
    }
    else if (launchGate)
    {
        IxDbgLog("DllMain: bootstrap thread creation failed");
        IxRuntimeFailClosed(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        return IxProcessAttach(hModule, reserved);
    }
    if (reason == DLL_PROCESS_DETACH)
    {
        IxDbgLog("DllMain: PROCESS_DETACH reserved=%p", reserved);
        IxRuntimeShutdown();
    }

    return TRUE;
}
