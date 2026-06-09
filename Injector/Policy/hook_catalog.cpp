#include "Policy/hook_catalog.h"
#include "Core/runner_help.h"

namespace blind::injector {
void MarkRecentRules(RunnerOptions &options, UINT32 start,
                     UINT32 count) noexcept {
  options.LastRuleStart = start;
  options.LastRuleCount = count;
}

IXIPC_HOOK_POLICY_RULE *LastCliRule(RunnerOptions &options) noexcept {
  if (options.CliPolicy.RuleCount == 0 ||
      options.CliPolicy.RuleCount > IXIPC_MAX_HOOK_POLICY_RULES) {
    return nullptr;
  }
  return &options.CliPolicy.Rules[options.CliPolicy.RuleCount - 1];
}

bool ForEachRecentRule(RunnerOptions &options,
                       bool (*callback)(IXIPC_HOOK_POLICY_RULE &rule,
                                        void *context) noexcept,
                       void *context) noexcept {
  if (options.LastRuleCount == 0 ||
      options.LastRuleStart >= options.CliPolicy.RuleCount ||
      callback == nullptr) {
    return false;
  }

  UINT32 end = options.LastRuleStart + options.LastRuleCount;
  if (end > options.CliPolicy.RuleCount) {
    end = options.CliPolicy.RuleCount;
  }
  for (UINT32 i = options.LastRuleStart; i < end; ++i) {
    if (!callback(options.CliPolicy.Rules[i], context)) {
      return false;
    }
  }
  return true;
}

bool AddCliRule(RunnerOptions &options, UINT32 component,
                const wchar_t *apiName, bool log, bool markRecent = true) {
  if (options.CliPolicy.RuleCount >= IXIPC_MAX_HOOK_POLICY_RULES) {
    std::wprintf(L"[blind] too many hook rules; max=%lu\n",
                 static_cast<unsigned long>(IXIPC_MAX_HOOK_POLICY_RULES));
    return false;
  }

  UINT32 start = options.CliPolicy.RuleCount;
  IXIPC_HOOK_POLICY_RULE &rule =
      options.CliPolicy.Rules[options.CliPolicy.RuleCount++];
  rule.Component = component;
  rule.Action = IXIPC_HOOK_ACTION_NONE;
  rule.Flags = log ? IXIPC_HOOK_RULE_FLAG_LOG : 0u;
  rule.DenyStatus = 0;
  rule.HookMethod = IXIPC_HOOK_METHOD_INLINE;
  rule.Reserved = 0;
  if (!CopyWideToAnsi(apiName, rule.ApiName, RTL_NUMBER_OF(rule.ApiName))) {
    std::wprintf(L"[blind] invalid hook name: %ls\n",
                 apiName != nullptr ? apiName : L"<null>");
    --options.CliPolicy.RuleCount;
    return false;
  }
  if (component == IXIPC_HOOK_POLICY_COMPONENT_NT) {
    options.CliPolicy.Flags |= IXIPC_HOOK_POLICY_FLAG_EXPLICIT_NT;
  } else if (component == IXIPC_HOOK_POLICY_COMPONENT_MODULE) {
    options.CliPolicy.Flags |= IXIPC_HOOK_POLICY_FLAG_EXPLICIT_MODULE;
  } else if (component == IXIPC_HOOK_POLICY_COMPONENT_WINSOCK) {
    options.CliPolicy.Flags |= IXIPC_HOOK_POLICY_FLAG_EXPLICIT_WINSOCK;
  }
  if (markRecent) {
    MarkRecentRules(options, start, 1);
  }
  return true;
}

bool AddRuleIfMissing(RunnerOptions &options, UINT32 component,
                      const wchar_t *apiName, bool log) {
  char api[IXIPC_MAX_HOOK_API_NAME]{};
  if (!CopyWideToAnsi(apiName, api, RTL_NUMBER_OF(api))) {
    std::wprintf(L"[blind] invalid hook name: %ls\n",
                 apiName != nullptr ? apiName : L"<null>");
    return false;
  }

  UINT32 count = options.CliPolicy.RuleCount < IXIPC_MAX_HOOK_POLICY_RULES
                     ? options.CliPolicy.RuleCount
                     : IXIPC_MAX_HOOK_POLICY_RULES;
  for (UINT32 i = 0; i < count; ++i) {
    auto &rule = options.CliPolicy.Rules[i];
    if (rule.Component == component && _stricmp(rule.ApiName, api) == 0) {
      if (log) {
        rule.Flags |= IXIPC_HOOK_RULE_FLAG_LOG;
      }
      return true;
    }
  }
  return AddCliRule(options, component, apiName, log, false);
}

bool AddIgnoreDll(RunnerOptions &options, const wchar_t *dllName) {
  if (options.CliPolicy.IgnoreDllCount >= IXIPC_MAX_HOOK_POLICY_IGNORE_DLLS) {
    std::wprintf(L"[blind] too many ignored DLL names; max=%lu\n",
                 static_cast<unsigned long>(IXIPC_MAX_HOOK_POLICY_IGNORE_DLLS));
    return false;
  }

  char *slot = options.CliPolicy.IgnoreDlls[options.CliPolicy.IgnoreDllCount++];
  if (!CopyWideToAnsi(dllName, slot, IXIPC_MAX_HOOK_MODULE_NAME)) {
    std::wprintf(L"[blind] invalid DLL name: %ls\n",
                 dllName != nullptr ? dllName : L"<null>");
    --options.CliPolicy.IgnoreDllCount;
    return false;
  }
  return true;
}

std::wstring ToLowerWide(const wchar_t *input) {
  std::wstring value = input != nullptr ? input : L"";
  for (auto &ch : value) {
    ch = static_cast<wchar_t>(std::towlower(ch));
  }
  return value;
}

bool AddHookSpec(RunnerOptions &options, const wchar_t *spec, bool log) {
  if (spec == nullptr || spec[0] == L'\0') {
    std::wprintf(L"[blind] empty hook name\n");
    return false;
  }

  const wchar_t *name = spec;
  UINT32 forcedComponent = 0;
  bool forced = false;
  const wchar_t *colon = wcschr(spec, L':');
  std::wstring prefix;
  if (colon != nullptr && colon != spec && colon[1] != L'\0') {
    prefix.assign(spec, colon - spec);
    std::wstring lowerPrefix = ToLowerWide(prefix.c_str());
    name = colon + 1;
    if (lowerPrefix == L"group" || lowerPrefix == L"g") {
      return AddHookGroup(options, name, log);
    }
    if (lowerPrefix == L"nt") {
      forcedComponent = IXIPC_HOOK_POLICY_COMPONENT_NT;
      forced = true;
    } else if (lowerPrefix == L"module" || lowerPrefix == L"mod" ||
               lowerPrefix == L"api") {
      forcedComponent = IXIPC_HOOK_POLICY_COMPONENT_MODULE;
      forced = true;
    } else if (lowerPrefix == L"winsock" || lowerPrefix == L"ws") {
      forcedComponent = IXIPC_HOOK_POLICY_COMPONENT_WINSOCK;
      forced = true;
    } else {
      std::wprintf(L"[blind] unknown hook component prefix: %ls\n",
                   prefix.c_str());
      return false;
    }
  }

  if (!forced) {
    if (IsKnownHookGroupName(name)) {
      return AddHookGroup(options, name, log);
    }
  }

  UINT32 component = forcedComponent;
  if (!forced && !KnownHookComponent(name, component)) {
    component = IXIPC_HOOK_POLICY_COMPONENT_NT;
  }

  return AddCliRule(options, component, name, log);
}
std::wstring TrimHookListToken(std::wstring token) {
  while (!token.empty() && std::iswspace(token.front())) {
    token.erase(token.begin());
  }
  while (!token.empty() && std::iswspace(token.back())) {
    token.pop_back();
  }
  if (token.size() >= 2) {
    wchar_t first = token.front();
    wchar_t last = token.back();
    if ((first == L'[' && last == L']') || (first == L'{' && last == L'}') ||
        (first == L'(' && last == L')') || (first == L'"' && last == L'"') ||
        (first == L'\'' && last == L'\'')) {
      token = token.substr(1, token.size() - 2);
    }
  }
  while (!token.empty() && std::iswspace(token.front())) {
    token.erase(token.begin());
  }
  while (!token.empty() && std::iswspace(token.back())) {
    token.pop_back();
  }
  return token;
}

bool AddHookList(RunnerOptions &options, const wchar_t *specs, bool log,
                 bool forceGroup) {
  if (specs == nullptr || specs[0] == L'\0') {
    std::wprintf(L"[blind] empty hook list\n");
    return false;
  }

  std::wstring list = TrimHookListToken(specs);
  UINT32 start = options.CliPolicy.RuleCount;
  bool ok = true;
  std::size_t tokenStart = 0;
  while (tokenStart <= list.size()) {
    std::size_t tokenEnd = list.find_first_of(L",;|", tokenStart);
    std::wstring token = TrimHookListToken(list.substr(
        tokenStart, tokenEnd == std::wstring::npos ? std::wstring::npos
                                                   : tokenEnd - tokenStart));
    if (!token.empty()) {
      ok = (forceGroup ? AddHookGroup(options, token.c_str(), log)
                       : AddHookSpec(options, token.c_str(), log)) &&
           ok;
    }
    if (tokenEnd == std::wstring::npos) {
      break;
    }
    tokenStart = tokenEnd + 1;
  }

  if (!ok) {
    return false;
  }
  if (options.CliPolicy.RuleCount == start) {
    std::wprintf(L"[blind] hook list did not add any rules: %ls\n", specs);
    return false;
  }
  MarkRecentRules(options, start, options.CliPolicy.RuleCount - start);
  return true;
}
} // namespace blind::injector
