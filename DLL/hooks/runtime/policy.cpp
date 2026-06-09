#include "runtime_internal.h"

#include <strsafe.h>
#include <cstring>

namespace IX_RUNTIME_INTERNAL
{
    static IXIPC_QUERY_HOOK_POLICY_RESPONSE g_CliHookPolicy{};
    static bool g_CliHookPolicyLoaded = false;
    static bool g_CliHookPolicyActive = false;

    static const char *BaseNameOfPath(const char *path) noexcept
    {
        if (path == nullptr)
        {
            return "";
        }

        const char *slash = std::strrchr(path, '\\');
        const char *altSlash = std::strrchr(path, '/');
        if (altSlash != nullptr && (slash == nullptr || altSlash > slash))
        {
            slash = altSlash;
        }
        return slash != nullptr ? slash + 1 : path;
    }

    static bool ModuleNameMatchesIgnore(const char *ignoreName, const char *moduleBaseName) noexcept
    {
        if (ignoreName == nullptr || ignoreName[0] == '\0' || moduleBaseName == nullptr || moduleBaseName[0] == '\0')
        {
            return false;
        }

        if (lstrcmpiA(ignoreName, moduleBaseName) == 0)
        {
            return true;
        }

        char moduleNoExt[IXIPC_MAX_HOOK_MODULE_NAME]{};
        (void)StringCchCopyA(moduleNoExt, RTL_NUMBER_OF(moduleNoExt), moduleBaseName);
        char *dot = std::strrchr(moduleNoExt, '.');
        if (dot != nullptr && lstrcmpiA(dot, ".dll") == 0)
        {
            *dot = '\0';
        }

        return lstrcmpiA(ignoreName, moduleNoExt) == 0;
    }

    static bool CallerModuleIgnored(void *caller) noexcept
    {
        if (caller == nullptr || g_CliHookPolicy.IgnoreDllCount == 0)
        {
            return false;
        }
        HMODULE module = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(caller),
                                &module) ||
            module == nullptr)
        {
            return false;
        }

        char modulePath[MAX_PATH]{};
        if (GetModuleFileNameA(module, modulePath, RTL_NUMBER_OF(modulePath)) == 0)
        {
            return false;
        }

        const char *baseName = BaseNameOfPath(modulePath);
        const UINT32 ignoreCount = g_CliHookPolicy.IgnoreDllCount < IXIPC_MAX_HOOK_POLICY_IGNORE_DLLS
                                       ? g_CliHookPolicy.IgnoreDllCount
                                       : IXIPC_MAX_HOOK_POLICY_IGNORE_DLLS;
        for (UINT32 i = 0; i < ignoreCount; ++i)
        {
            if (ModuleNameMatchesIgnore(g_CliHookPolicy.IgnoreDlls[i], baseName))
            {
                return true;
            }
        }
        return false;
    }

    static bool TraceMatchesIgnorePrivate(const IC_STACKTRACE::Trace &trace) noexcept
    {
        if ((g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_IGNORE_PRIVATE) == 0)
        {
            return false;
        }

        const auto cls = IC_STACKTRACE::ClassifyTrace(trace);
        if (cls.ImmediateCaller == IC_STACKTRACE::CallerKind::Unmapped ||
            cls.DeepestOrigin == IC_STACKTRACE::CallerKind::Unmapped)
        {
            return true;
        }

        constexpr std::uint32_t privateFlags = IC_STACKTRACE::kCallerFlagHasUnmapped |
                                               IC_STACKTRACE::kCallerFlagPrivateExecNoUnwind |
                                               IC_STACKTRACE::kCallerFlagPrivateExecDynamicUnwind;
        return (cls.Flags & privateFlags) != 0;
    }

    static const IXIPC_HOOK_POLICY_RULE *FindHookPolicyRule(UINT32 component, const char *name) noexcept
    {
        if (name == nullptr || name[0] == '\0')
        {
            return nullptr;
        }

        const UINT32 ruleCount = g_CliHookPolicy.RuleCount < IXIPC_MAX_HOOK_POLICY_RULES ? g_CliHookPolicy.RuleCount
                                                                                         : IXIPC_MAX_HOOK_POLICY_RULES;
        for (UINT32 i = 0; i < ruleCount; ++i)
        {
            const auto &rule = g_CliHookPolicy.Rules[i];
            if (rule.Component == component && lstrcmpiA(rule.ApiName, name) == 0)
            {
                return &rule;
            }
        }
        return nullptr;
    }

    static const IXIPC_HOOK_POLICY_RULE *FindNtHookPolicyRule(const char *name) noexcept
    {
        return FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_NT, name);
    }

    static std::uint32_t NormalizeHookMethod(UINT32 component, UINT32 method) noexcept
    {
        if (component == IXIPC_HOOK_POLICY_COMPONENT_NT)
        {
            return method == IXIPC_HOOK_METHOD_INT3 ? IXIPC_HOOK_METHOD_INT3 : IXIPC_HOOK_METHOD_INLINE;
        }
        if (component == IXIPC_HOOK_POLICY_COMPONENT_MODULE)
        {
            if (method == IXIPC_HOOK_METHOD_IAT || method == IXIPC_HOOK_METHOD_SHADOW_IAT)
            {
                return method;
            }
            return IXIPC_HOOK_METHOD_INLINE;
        }
        if (component == IXIPC_HOOK_POLICY_COMPONENT_WINSOCK)
        {
            return method == IXIPC_HOOK_METHOD_IAT ? IXIPC_HOOK_METHOD_IAT : IXIPC_HOOK_METHOD_INLINE;
        }
        return IXIPC_HOOK_METHOD_INLINE;
    }

    static bool HasPolicyRulesForComponent(UINT32 component) noexcept
    {
        const UINT32 ruleCount = g_CliHookPolicy.RuleCount < IXIPC_MAX_HOOK_POLICY_RULES ? g_CliHookPolicy.RuleCount
                                                                                         : IXIPC_MAX_HOOK_POLICY_RULES;
        for (UINT32 i = 0; i < ruleCount; ++i)
        {
            if (g_CliHookPolicy.Rules[i].Component == component)
            {
                return true;
            }
        }
        return false;
    }

    static bool HookNameIsAnyOf(const char *name, const char *const *values, std::size_t count) noexcept
    {
        if (name == nullptr || name[0] == '\0')
        {
            return false;
        }

        for (std::size_t i = 0; i < count; ++i)
        {
            if (lstrcmpiA(name, values[i]) == 0)
            {
                return true;
            }
        }
        return false;
    }

    static bool IsLoaderHookName(const char *name) noexcept
    {
        static const char *const kLoaderNames[] = {"LdrLoadDll"};
        return HookNameIsAnyOf(name, kLoaderNames, RTL_NUMBER_OF(kLoaderNames));
    }

    static bool IsHttpCacheHelperHookName(const char *name) noexcept
    {
        static const char *const kHttpCacheHelpers[] = {
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "InternetConnectW",
            "InternetConnectA",
            "HttpOpenRequestW",
            "HttpOpenRequestA",
        };
        return HookNameIsAnyOf(name, kHttpCacheHelpers, RTL_NUMBER_OF(kHttpCacheHelpers));
    }

    static bool HasHttpPublishRule() noexcept
    {
        return FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_MODULE, "WinHttpSendRequest") != nullptr ||
               FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_MODULE, "HttpSendRequestW") != nullptr ||
               FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_MODULE, "HttpSendRequestA") != nullptr;
    }

    static bool TraceIgnoredByPolicy(const IC_STACKTRACE::Trace *trace) noexcept
    {
        return trace != nullptr && TraceMatchesIgnorePrivate(*trace);
    }

    static bool ShouldPublishNonNtHookEvent(UINT32 component,
                                            const char *name,
                                            void *caller,
                                            const IC_STACKTRACE::Trace *trace) noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return true;
        }

        const IXIPC_HOOK_POLICY_RULE *rule = FindHookPolicyRule(component, name);
        if (rule == nullptr)
        {
            return false;
        }
        if (CallerModuleIgnored(caller) || TraceIgnoredByPolicy(trace))
        {
            return false;
        }
        return true;
    }

    void ResetCliHookPolicy() noexcept
    {
        std::memset(&g_CliHookPolicy, 0, sizeof(g_CliHookPolicy));
        g_CliHookPolicyLoaded = false;
        g_CliHookPolicyActive = false;
    }

    bool QueryCliHookPolicyFromHost() noexcept
    {
        IXIPC_QUERY_HOOK_POLICY_RESPONSE policy{};
        if (!IXIPC::QueryHookPolicy(policy) || policy.PolicyVersion != IXIPC_HOOK_POLICY_VERSION)
        {
            ResetCliHookPolicy();
            return false;
        }

        if (policy.RuleCount > IXIPC_MAX_HOOK_POLICY_RULES)
        {
            policy.RuleCount = IXIPC_MAX_HOOK_POLICY_RULES;
        }
        if (policy.IgnoreDllCount > IXIPC_MAX_HOOK_POLICY_IGNORE_DLLS)
        {
            policy.IgnoreDllCount = IXIPC_MAX_HOOK_POLICY_IGNORE_DLLS;
        }
        for (UINT32 i = 0; i < policy.RuleCount; ++i)
        {
            policy.Rules[i].ApiName[IXIPC_MAX_HOOK_API_NAME - 1] = '\0';
            policy.Rules[i].HookMethod = NormalizeHookMethod(policy.Rules[i].Component, policy.Rules[i].HookMethod);
        }
        for (UINT32 i = 0; i < policy.IgnoreDllCount; ++i)
        {
            policy.IgnoreDlls[i][IXIPC_MAX_HOOK_MODULE_NAME - 1] = '\0';
        }

        g_CliHookPolicy = policy;
        g_CliHookPolicyLoaded = true;
        g_CliHookPolicyActive = (policy.Flags & IXIPC_HOOK_POLICY_FLAG_CLI_MODE) != 0;
        IxDbgLog("QueryCliHookPolicyFromHost: active=%u rules=%lu ignoreDlls=%lu flags=0x%08lX",
                 g_CliHookPolicyActive ? 1u : 0u,
                 static_cast<unsigned long>(policy.RuleCount),
                 static_cast<unsigned long>(policy.IgnoreDllCount),
                 static_cast<unsigned long>(policy.Flags));
        return true;
    }

    bool IsCliHookPolicyActive() noexcept
    {
        return g_CliHookPolicyLoaded && g_CliHookPolicyActive;
    }

    bool ShouldInstallNtHookByPolicy(const char *name) noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return true;
        }

        if ((g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_NT) == 0)
        {
            return false;
        }

        return FindNtHookPolicyRule(name) != nullptr;
    }

    std::uint32_t HookMethodForNtHookByPolicy(const char *name) noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return IXIPC_HOOK_METHOD_INLINE;
        }

        const IXIPC_HOOK_POLICY_RULE *rule = FindNtHookPolicyRule(name);
        return rule != nullptr ? NormalizeHookMethod(rule->Component, rule->HookMethod) : IXIPC_HOOK_METHOD_INLINE;
    }

    bool ShouldEnableNtHookControllerByPolicy() noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return true;
        }

        return (g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_NT) != 0 &&
               HasPolicyRulesForComponent(IXIPC_HOOK_POLICY_COMPONENT_NT);
    }

    bool ShouldEnableModuleHookControllerByPolicy() noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return true;
        }

        return ((g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_MODULE) != 0 &&
                HasPolicyRulesForComponent(IXIPC_HOOK_POLICY_COMPONENT_MODULE)) ||
               ((g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_WINSOCK) != 0 &&
                HasPolicyRulesForComponent(IXIPC_HOOK_POLICY_COMPONENT_WINSOCK));
    }
    bool ShouldInstallModuleHookByPolicy(const char *moduleName, const char *name) noexcept
    {
        UNREFERENCED_PARAMETER(moduleName);

        if (!IsCliHookPolicyActive())
        {
            return true;
        }

        const bool wantsModule = (g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_MODULE) != 0;
        const bool wantsWinsock = (g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_WINSOCK) != 0;
        if (!wantsModule && !wantsWinsock)
        {
            return false;
        }

        if (wantsModule && FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_MODULE, name) != nullptr)
        {
            return true;
        }

        if (IsLoaderHookName(name) && (HasPolicyRulesForComponent(IXIPC_HOOK_POLICY_COMPONENT_MODULE) ||
                                       HasPolicyRulesForComponent(IXIPC_HOOK_POLICY_COMPONENT_WINSOCK)))
        {
            return true;
        }

        return IsHttpCacheHelperHookName(name) && HasHttpPublishRule();
    }

    std::uint32_t HookMethodForModuleHookByPolicy(const char *name) noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return IXIPC_HOOK_METHOD_INLINE;
        }

        const IXIPC_HOOK_POLICY_RULE *rule = FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_MODULE, name);
        return rule != nullptr ? NormalizeHookMethod(rule->Component, rule->HookMethod) : IXIPC_HOOK_METHOD_INLINE;
    }

    bool ShouldSanitizeModuleHookStackByPolicy(const char *name) noexcept
    {
        if (!IsCliHookPolicyActive())
        {
            return false;
        }

        const IXIPC_HOOK_POLICY_RULE *rule = FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_MODULE, name);
        return rule != nullptr && (rule->Flags & IXIPC_HOOK_RULE_FLAG_STACK_FABRICATE) != 0;
    }

    bool ShouldInstallWinsockHookByPolicy(const char *name) noexcept
    {
        if (!IsCliHookPolicyActive() || (g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_EXPLICIT_WINSOCK) == 0)
        {
            return !IsCliHookPolicyActive();
        }

        return FindHookPolicyRule(IXIPC_HOOK_POLICY_COMPONENT_WINSOCK, name) != nullptr;
    }

    bool ShouldPublishModuleHookEvent(const char *name, void *caller, const IC_STACKTRACE::Trace *trace) noexcept
    {
        return ShouldPublishNonNtHookEvent(IXIPC_HOOK_POLICY_COMPONENT_MODULE, name, caller, trace);
    }

    bool ShouldPublishWinsockHookEvent(const char *name, void *caller, const IC_STACKTRACE::Trace *trace) noexcept
    {
        return ShouldPublishNonNtHookEvent(IXIPC_HOOK_POLICY_COMPONENT_WINSOCK, name, caller, trace);
    }

    bool ShouldGuardDirectSyscallPagesByPolicy() noexcept
    {
        return IsCliHookPolicyActive() && ((g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_GUARD_DIRECT_SYSCALLS) != 0);
    }

    bool EvaluateNtHookPolicy(const char *name, void *caller, IxNtHookPolicyDecision &decision) noexcept
    {
        decision = IxNtHookPolicyDecision{};
        if (!IsCliHookPolicyActive())
        {
            return false;
        }

        const IXIPC_HOOK_POLICY_RULE *rule = FindNtHookPolicyRule(name);
        if (rule == nullptr)
        {
            return false;
        }

        decision.Matched = true;
        decision.Log = (rule->Flags & IXIPC_HOOK_RULE_FLAG_LOG) != 0;
        decision.StackTrace = (rule->Flags & IXIPC_HOOK_RULE_FLAG_STACK_TRACE) != 0;
        decision.Registers = (rule->Flags & IXIPC_HOOK_RULE_FLAG_REGISTERS) != 0;
        decision.StackFabricate = (rule->Flags & IXIPC_HOOK_RULE_FLAG_STACK_FABRICATE) != 0;
        decision.Action = rule->Action;
        decision.Status = static_cast<NTSTATUS>(rule->DenyStatus);

        const bool needsTrace = decision.StackTrace || decision.StackFabricate ||
                                ((g_CliHookPolicy.Flags & IXIPC_HOOK_POLICY_FLAG_IGNORE_PRIVATE) != 0);
        {
            if (needsTrace)
            {
                IX_INTERNAL_SCOPE();
                (void)IC_STACKTRACE::Capture(decision.Trace, 1);
            }
        }
        if (CallerModuleIgnored(caller) || (needsTrace && TraceMatchesIgnorePrivate(decision.Trace)))
        {
            decision.Ignored = true;
            return true;
        }

        if (decision.Action == IXIPC_HOOK_ACTION_DENY && decision.Status == 0)
        {
            decision.Status = static_cast<NTSTATUS>(0xC0000022L);
        }
        return true;
    }
} // namespace IX_RUNTIME_INTERNAL
