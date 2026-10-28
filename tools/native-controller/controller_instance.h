#pragma once
#include "platform.h"

// All GUI modes and conflicting CLI operations share one per-user OS lock.
// Explicit, bounded CLI exceptions return an empty guard. Keep the returned
// guard alive until all windows, services and workers have stopped.
// waitMs is used only for the Windows elevated restart handoff.
platform::FileLock acquireControllerInstance(const std::vector<std::string> &args,
    const std::filesystem::path &directory = {}, unsigned waitMs = 0);
