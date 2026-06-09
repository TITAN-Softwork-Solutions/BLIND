#include "Core/runner_core.h"

namespace blind::injector {
void ReserveServerContextStorage(ServerContext &ctx, bool remoteSmart) {
  ctx.ChildModules.reserve(128);
  ctx.ProcessInfoCache.reserve(remoteSmart ? 64 : 16);
  ctx.ProcessInfoByPid.reserve(remoteSmart ? 64 : 16);
  ctx.ProcessHandleCache.reserve(kMaxCachedProcessHandles);
  ctx.ThreadInfoCache.reserve(remoteSmart ? 256 : 64);
  ctx.ThreadInfoByTid.reserve(remoteSmart ? 256 : 64);
  ctx.SymbolAttemptedBases.reserve(256);
  ctx.SmartRegions.reserve(remoteSmart ? 8192 : 512);
  ctx.SmartProtectGroups.reserve(256);
  ctx.SmartProtectGroupByKey.reserve(256);
  ctx.SmartThreadGroups.reserve(remoteSmart ? 256 : 64);
  ctx.SmartThreadGroupByKey.reserve(remoteSmart ? 256 : 64);
  ctx.SmartHandleGroups.reserve(remoteSmart ? 256 : 64);
  ctx.SmartHandleGroupByKey.reserve(remoteSmart ? 256 : 64);
  ctx.SmartTargets.reserve(remoteSmart ? 32 : 8);
  ctx.SmartTargetByPid.reserve(remoteSmart ? 32 : 8);
}
} // namespace blind::injector
