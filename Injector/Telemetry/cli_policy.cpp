#include "Telemetry/cli_events.h"

namespace blind::injector {
const IXIPC_HOOK_POLICY_RULE *
FindCliRule(const ServerContext &ctx,
            const IXIPC_HOOK_EVENT &eventRecord) noexcept {
  UINT32 component = 0;
  switch (eventRecord.Kind) {
  case IxIpcHookEventNt:
    component = IXIPC_HOOK_POLICY_COMPONENT_NT;
    break;
  case IxIpcHookEventModule:
    component = IXIPC_HOOK_POLICY_COMPONENT_MODULE;
    break;
  case IxIpcHookEventWinsock:
    component = IXIPC_HOOK_POLICY_COMPONENT_WINSOCK;
    break;
  default:
    return nullptr;
  }

  UINT32 count = ctx.CliPolicy.RuleCount < IXIPC_MAX_HOOK_POLICY_RULES
                     ? ctx.CliPolicy.RuleCount
                     : IXIPC_MAX_HOOK_POLICY_RULES;
  for (UINT32 i = 0; i < count; ++i) {
    const auto &rule = ctx.CliPolicy.Rules[i];
    if (rule.Component == component &&
        _stricmp(rule.ApiName, eventRecord.ApiName) == 0) {
      return &rule;
    }
  }
  return nullptr;
}
DWORD CliReadyMaskForPolicy(const ServerContext &ctx) noexcept {
  if (!ctx.CliMode) {
    return BLIND_SDK_READY_CORE_MASK;
  }
  DWORD mask = IXIPC_HOOK_READY_FLAG_IPC_CONNECTED;
  const DWORD flags = ctx.CliPolicy.Flags;
  if ((flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_NT) != 0) {
    mask |= IXIPC_HOOK_READY_FLAG_NT;
  }
  if ((flags & (IXIPC_HOOK_POLICY_FLAG_EXPLICIT_MODULE |
                IXIPC_HOOK_POLICY_FLAG_EXPLICIT_WINSOCK)) != 0) {
    mask |= IXIPC_HOOK_READY_FLAG_MODULE;
  }
  return mask;
}

bool RuleApiIs(const IXIPC_HOOK_POLICY_RULE &rule,
               const char *apiName) noexcept {
  return rule.Component == IXIPC_HOOK_POLICY_COMPONENT_NT &&
         rule.ApiName[0] != '\0' && _stricmp(rule.ApiName, apiName) == 0;
}
} // namespace blind::injector
