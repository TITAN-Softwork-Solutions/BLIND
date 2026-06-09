#pragma once

#include "../instrument/stacktrace.h"

namespace IX_STACK_FABRICATE
{
    void SanitizeBlindFrames(IC_STACKTRACE::Trace &trace) noexcept;
}
