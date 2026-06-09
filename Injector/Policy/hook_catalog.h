#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
void MarkRecentRules(RunnerOptions &options, UINT32 start,
                     UINT32 count) noexcept;
IXIPC_HOOK_POLICY_RULE *LastCliRule(RunnerOptions &options) noexcept;
bool ForEachRecentRule(RunnerOptions &options,
                       bool (*callback)(IXIPC_HOOK_POLICY_RULE &rule,
                                        void *context) noexcept,
                       void *context) noexcept;
bool AddCliRule(RunnerOptions &options, UINT32 component,
                const wchar_t *apiName, bool log, bool markRecent);
bool AddRuleIfMissing(RunnerOptions &options, UINT32 component,
                      const wchar_t *apiName, bool log);
bool AddIgnoreDll(RunnerOptions &options, const wchar_t *dllName);
std::wstring ToLowerWide(const wchar_t *input);
bool KnownHookComponent(const wchar_t *name, UINT32 &component) noexcept;
bool IsKnownHookGroupName(const wchar_t *groupName);
bool AddHookGroup(RunnerOptions &options, const wchar_t *groupName, bool log);
bool AddHookSpec(RunnerOptions &options, const wchar_t *spec, bool log);
std::wstring TrimHookListToken(std::wstring token);
bool AddHookList(RunnerOptions &options, const wchar_t *specs, bool log,
                 bool forceGroup);
} // namespace blind::injector
