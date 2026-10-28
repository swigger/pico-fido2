#include "controller_instance.h"
#include <chrono>
#include <stdexcept>

namespace {
bool parallelCommand(const std::vector<std::string> &args) {
    if (args.size() == 1) {
        for (const auto *command : {"--storage-new-id", "--self-test", "--list-devices", "--download-ports",
                                   "--status", "--relay-status", "--storage-status", "--relay-enrollments"})
            if (args[0] == command) return true;
#ifdef ENABLE_RELAY_DIAGNOSTICS
        if (args[0] == "--device-diagnostics") return true;
#endif
    }
    // Revoking a lost device must remain possible while the service is live.
    return args.size() == 2 && args[0] == "--relay-revoke";
}
}
platform::FileLock acquireControllerInstance(const std::vector<std::string> &args,
                                             const std::filesystem::path &directory, unsigned waitMs) {
    if (parallelCommand(args)) return {};
    auto dir = directory.empty() ? platform::dataDirectory() : directory;
    platform::createPrivateDirectories(dir);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMs);
    for (;;) {
        try {
            // Never delete this marker: unlinking an OS-locked file can allow
            // another process to lock a different inode at the same path.
            return platform::FileLock(dir / "controller-instance.lock", platform::FileLock::Mode::OpenAlways,
                "无法取得单实例锁：Controller 可能已在运行，请使用已有窗口或先退出它；若问题仍在，请检查本机数据目录权限。");
        } catch (const std::runtime_error &) {
            if (std::chrono::steady_clock::now() >= deadline) throw;
            sleepMs(50);
        }
    }
}
