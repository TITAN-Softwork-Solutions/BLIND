#include "Policy/hook_catalog.h"
#include "Policy/option_parsing.h"
#include "Telemetry/cli_events.h"

namespace blind::injector {
bool AddDefaultSmartRules(RunnerOptions &options) {
  const wchar_t *memoryRules[] = {L"NtAllocateVirtualMemory",
                                  L"NtAllocateVirtualMemoryEx"};
  const wchar_t *protectRules[] = {L"NtProtectVirtualMemory"};
  const wchar_t *writeRules[] = {L"NtWriteVirtualMemory"};
  const wchar_t *readRules[] = {L"NtReadVirtualMemory"};
  const wchar_t *queryRules[] = {L"NtQueryVirtualMemory"};
  const wchar_t *handleRules[] = {L"NtOpenProcess", L"NtOpenThread"};
  const wchar_t *mapRules[] = {L"NtMapViewOfSection", L"NtMapViewOfSectionEx"};
  const wchar_t *threadRules[] = {L"NtCreateThreadEx"};

  auto addRules = [&](const wchar_t **rules, std::size_t count) -> bool {
    for (std::size_t i = 0; i < count; ++i) {
      if (!AddRuleIfMissing(options, IXIPC_HOOK_POLICY_COMPONENT_NT, rules[i],
                            true)) {
        return false;
      }
    }
    return true;
  };

  if ((options.SmartAreas & kSmartAreaMemory) != 0) {
    if (!addRules(memoryRules, RTL_NUMBER_OF(memoryRules))) {
      return false;
    }
  }
  if ((options.SmartAreas & kSmartAreaProtect) != 0 &&
      !addRules(protectRules, RTL_NUMBER_OF(protectRules))) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaWrites) != 0 &&
      !addRules(writeRules, RTL_NUMBER_OF(writeRules))) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaReads) != 0 &&
      !addRules(readRules, RTL_NUMBER_OF(readRules))) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaQueries) != 0 &&
      !addRules(queryRules, RTL_NUMBER_OF(queryRules))) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaHandles) != 0 &&
      !addRules(handleRules, RTL_NUMBER_OF(handleRules))) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaMaps) != 0 &&
      !addRules(mapRules, RTL_NUMBER_OF(mapRules))) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaThreads) != 0 &&
      !addRules(threadRules, RTL_NUMBER_OF(threadRules))) {
    return false;
  }
  return true;
}

void FinalizeSmartPolicy(RunnerOptions &options) {
  const UINT32 ruleCount =
      options.CliPolicy.RuleCount < IXIPC_MAX_HOOK_POLICY_RULES
          ? options.CliPolicy.RuleCount
          : IXIPC_MAX_HOOK_POLICY_RULES;

  for (UINT32 i = 0; i < ruleCount; ++i) {
    auto &rule = options.CliPolicy.Rules[i];
    if (options.SmartMode && rule.Component == IXIPC_HOOK_POLICY_COMPONENT_NT) {
      if (RuleApiIs(rule, "NtOpenProcess") || RuleApiIs(rule, "NtOpenThread")) {
        options.SmartAreas |= kSmartAreaHandles;
      } else if (RuleApiIs(rule, "NtQueryVirtualMemory")) {
        options.SmartAreas |= kSmartAreaQueries;
      } else if (RuleApiIs(rule, "NtReadVirtualMemory")) {
        options.SmartAreas |= kSmartAreaReads;
      } else if (RuleApiIs(rule, "NtWriteVirtualMemory")) {
        options.SmartAreas |= kSmartAreaWrites;
      }
    }
    if (!RuleApiIs(rule, "NtProtectVirtualMemory") ||
        (rule.Flags & IXIPC_HOOK_RULE_FLAG_LOG) == 0) {
      continue;
    }

    if (!options.SmartMode) {
      options.SmartMode = true;
      options.SmartAreas = kSmartAreaProtect;
      options.SmartAutoProtect = true;
    } else {
      options.SmartAreas |= kSmartAreaProtect;
    }
  }

  if (!options.SmartMode || options.SmartRawEvents) {
    return;
  }

  for (UINT32 i = 0; i < ruleCount; ++i) {
    auto &rule = options.CliPolicy.Rules[i];
    if (RuleApiIs(rule, "NtProtectVirtualMemory") &&
        (rule.Flags & IXIPC_HOOK_RULE_FLAG_STACK_TRACE) != 0) {
      options.SmartFoldedProtectStacks = true;
    }
  }
}

bool RuleMatchesSmartArea(const RunnerOptions &options,
                          const IXIPC_HOOK_POLICY_RULE &rule) noexcept {
  if (rule.Component != IXIPC_HOOK_POLICY_COMPONENT_NT) {
    return false;
  }
  if ((options.SmartAreas & kSmartAreaMemory) != 0 &&
      (_stricmp(rule.ApiName, "NtAllocateVirtualMemory") == 0 ||
       _stricmp(rule.ApiName, "NtAllocateVirtualMemoryEx") == 0)) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaProtect) != 0 &&
      _stricmp(rule.ApiName, "NtProtectVirtualMemory") == 0) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaWrites) != 0 &&
      _stricmp(rule.ApiName, "NtWriteVirtualMemory") == 0) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaReads) != 0 &&
      _stricmp(rule.ApiName, "NtReadVirtualMemory") == 0) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaQueries) != 0 &&
      _stricmp(rule.ApiName, "NtQueryVirtualMemory") == 0) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaHandles) != 0 &&
      (_stricmp(rule.ApiName, "NtOpenProcess") == 0 ||
       _stricmp(rule.ApiName, "NtOpenThread") == 0)) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaThreads) != 0 &&
      (_stricmp(rule.ApiName, "NtCreateThread") == 0 ||
       _stricmp(rule.ApiName, "NtCreateThreadEx") == 0)) {
    return true;
  }
  if ((options.SmartAreas & kSmartAreaApc) != 0 &&
      (_stricmp(rule.ApiName, "NtQueueApcThread") == 0 ||
       _stricmp(rule.ApiName, "NtQueueApcThreadEx") == 0 ||
       _stricmp(rule.ApiName, "NtQueueApcThreadEx2") == 0)) {
    return true;
  }
  return (options.SmartAreas & kSmartAreaMaps) != 0 &&
         (_stricmp(rule.ApiName, "NtMapViewOfSection") == 0 ||
          _stricmp(rule.ApiName, "NtMapViewOfSectionEx") == 0);
}

bool RuleIsSmartCallsiteCandidate(const RunnerOptions &options,
                                  const IXIPC_HOOK_POLICY_RULE &rule) noexcept {
  if (!RuleMatchesSmartArea(options, rule)) {
    return false;
  }
  if (_stricmp(rule.ApiName, "NtProtectVirtualMemory") == 0) {
    return options.SmartProtectStacks ||
           (rule.Flags & IXIPC_HOOK_RULE_FLAG_STACK_TRACE) != 0;
  }
  return true;
}

void EnableSmartCallsiteStackCollection(RunnerOptions &options) noexcept {
  if (!options.SmartMode) {
    return;
  }

  UINT32 ruleCount = options.CliPolicy.RuleCount < IXIPC_MAX_HOOK_POLICY_RULES
                         ? options.CliPolicy.RuleCount
                         : IXIPC_MAX_HOOK_POLICY_RULES;
  for (UINT32 i = 0; i < ruleCount; ++i) {
    auto &rule = options.CliPolicy.Rules[i];
    if (RuleMatchesSmartArea(options, rule) &&
        (rule.Flags & IXIPC_HOOK_RULE_FLAG_STACK_TRACE) != 0) {
      options.SmartStacks = true;
    }
    if (RuleIsSmartCallsiteCandidate(options, rule)) {
      rule.Flags |= IXIPC_HOOK_RULE_FLAG_STACK_TRACE;
    }
  }
}
} // namespace blind::injector
