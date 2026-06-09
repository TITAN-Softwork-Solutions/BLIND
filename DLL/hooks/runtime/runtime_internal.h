#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "runtime.h"

#include "../controller.h"
#include "../encoded_literal.h"
#include "../module/module.h"
#include "../nt.h"
#include "../ws.h"

#include "../../ipc/pipe.h"
#include "../../instrument/ix.h"
#include "../../instrument/stacktrace.h"
#include "../../include/native_peb.h"

#include <Windows.h>
#include <winternl.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

/* Prevent BLIND housekeeping calls from recursively re-entering BLIND hooks.
 * Use Win32 TLS instead of __declspec(thread): BLIND is injected into already
 * running processes, and compiler TLS can fault on loader-created threads before
 * the DLL's dynamic TLS vector is populated. */
bool IxIsInternalCall() noexcept;
void IxEnterInternalCall() noexcept;
void IxLeaveInternalCall() noexcept;

struct IxInternalScope
{
    IxInternalScope() noexcept
    {
        IxEnterInternalCall();
    }
    ~IxInternalScope() noexcept
    {
        IxLeaveInternalCall();
    }
    IxInternalScope(const IxInternalScope &) = delete;
    IxInternalScope &operator=(const IxInternalScope &) = delete;
};

#define IX_INTERNAL_SCOPE() IxInternalScope _ix_internal_scope_

#include "private/types.h"
#include "private/api.h"
