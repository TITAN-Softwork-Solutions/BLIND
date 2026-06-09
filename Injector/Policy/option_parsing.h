#pragma once

#include "Core/runner_core.h"

namespace blind::injector {
bool ParseSizeValue(const std::wstring &value, UINT64 &out) noexcept;
bool ParseDurationMs(const wchar_t *arg, DWORD &out) noexcept;
bool ParseSmartAreas(RunnerOptions &options, const wchar_t *arg);
bool ParseSmartCondition(RunnerOptions &options, const wchar_t *condition);
bool IsSmartStackFrameValue(const wchar_t *arg);
bool ParseSmartStacks(RunnerOptions &options, const wchar_t *arg);
bool ParseColorMode(RunnerOptions &options, const wchar_t *arg);
bool AddDefaultSmartRules(RunnerOptions &options);
void FinalizeSmartPolicy(RunnerOptions &options);
bool RuleMatchesSmartArea(const RunnerOptions &options,
                          const IXIPC_HOOK_POLICY_RULE &rule) noexcept;
bool RuleIsSmartCallsiteCandidate(const RunnerOptions &options,
                                  const IXIPC_HOOK_POLICY_RULE &rule) noexcept;
void EnableSmartCallsiteStackCollection(RunnerOptions &options) noexcept;
std::wstring QuoteCommandLineArgument(const std::wstring &arg);
std::wstring
BuildTargetCommandLine(const std::wstring &targetPath,
                       const std::vector<std::wstring> &targetArgs);
std::wstring BuildUniqueCliPipeName();
bool ParseCliMode(int argc, wchar_t **argv, int startIndex,
                  RunnerOptions &options);
} // namespace blind::injector
