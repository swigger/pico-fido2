#include "controller_instance.h"
#include "cli.h"
#include "core.h"
#include "test_process.h"
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>

namespace {
constexpr int blocked = 73;
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void write(const std::filesystem::path &path, const std::string &value) {
    std::ofstream out(path); out << value; out.close(); need(!out.fail(), "fixture write failed");
}
void waitFor(const std::filesystem::path &path) {
    auto start = tickMs();
    while (!std::filesystem::exists(path)) { need(tickMs() - start < 5000, "fixture timed out"); sleepMs(5); }
}
int probe(const std::filesystem::path &dir, const std::vector<std::string> &args, unsigned waitMs = 0) {
    std::vector<std::string> child{"probe", dir.u8string(), std::to_string(waitMs)};
    child.insert(child.end(), args.begin(), args.end());
    return test::run(platform::executablePath(), child, 5000);
}
void tests(const std::filesystem::path &dir) {
    const std::vector<std::vector<std::string>> exclusive{{}, {"--accounts"}, {"--safe-end"}, {"--serve"},
        {"--serve", "127.0.0.1", "8443"}, {"--pair"}, {"--approve", "--rp", "example.com"},
        {"--flash-esp32s3", "image.bin"}, {"--vault-init"}, {"--vault-import", "backup.pf2bak"},
        {"--storage-migrate-cloud"}, {"--generate"}, {"--unknown"}, {"--storage-new-id", "extra"}};
    const std::vector<std::vector<std::string>> parallel{{"--storage-new-id"}, {"--self-test"}, {"--list-devices"},
        {"--download-ports"}, {"--status"}, {"--relay-status"}, {"--storage-status"},
        {"--relay-enrollments"}, {"--relay-revoke", "0123456789abcdef"}};
    auto unused = dir / "unused";
    { auto guard = acquireControllerInstance({"--storage-new-id"}, unused);
      need(!guard.valid() && !std::filesystem::exists(unused), "short command touched the lock directory"); }
    {
        auto owner = acquireControllerInstance({}, dir);
        need(owner.valid(), "GUI did not acquire an OS lock");
        for (const auto &args : exclusive) need(probe(dir, args) == blocked, "second controller was allowed");
        for (const auto &args : parallel) need(probe(dir, args) == 0, "bounded CLI exception was blocked");
        need(probe(dir, {"--accounts"}, 100) == blocked, "handoff timeout bypassed a live owner");
    }
    need(std::filesystem::exists(dir / "controller-instance.lock"), "lock marker was deleted");
    need(probe(dir, {}) == 0, "normal exit did not release the lock");
    need(test::run(platform::executablePath(), {"crash", dir.u8string()}, 5000) == 0, "crash fixture failed");
    need(probe(dir, {"--serve"}) == 0, "abrupt exit left a stale lock");
    {
        auto owner = acquireControllerInstance({}, dir);
        auto release = std::async(std::launch::async, [guard = std::move(owner)]() mutable { sleepMs(200); guard = {}; });
        auto result = probe(dir, {"--accounts"}, 2000);
        release.get(); need(result == 0, "elevated handoff did not wait for release");
    }
    // Both processes reach the gate before racing the same OS lock. The winner
    // retains it until the parent has observed both outcomes.
    auto race = [&](const char *name) { return std::async(std::launch::async, [&, name] {
        return test::run(platform::executablePath(), {"race", dir.u8string(), name}, 8000);
    }); };
    auto first = race("first"), second = race("second");
    waitFor(dir / "first.ready"); waitFor(dir / "second.ready"); write(dir / "start", "start");
    waitFor(dir / "first.result"); waitFor(dir / "second.result"); write(dir / "release", "release");
    auto a = first.get(), b = second.get();
    need((a == 0 && b == blocked) || (a == blocked && b == 0), "simultaneous launches did not elect one owner");
    need(probe(dir, {}) == 0, "race winner did not release the lock");
}
}
int main(int argc, char **argv) {
    try {
        auto args = commandLine(argc, argv);
        if (args.size() >= 3 && args[0] == "probe") {
            try { auto guard = acquireControllerInstance({args.begin() + 3, args.end()}, std::filesystem::u8path(args[1]),
                                                        static_cast<unsigned>(std::stoul(args[2]))); }
            catch (...) { return blocked; }
            return 0;
        }
        if (args.size() == 2 && args[0] == "crash") {
            auto guard = acquireControllerInstance({}, std::filesystem::u8path(args[1]));
            std::_Exit(0); // No destructors: only OS cleanup releases ownership.
        }
        if (args.size() == 3 && args[0] == "race") {
            auto dir = std::filesystem::u8path(args[1]);
            write(dir / (args[2] + ".ready"), "ready"); waitFor(dir / "start");
            platform::FileLock guard;
            try { guard = acquireControllerInstance({}, dir); }
            catch (...) { write(dir / (args[2] + ".result"), "blocked"); return blocked; }
            write(dir / (args[2] + ".result"), "owner"); waitFor(dir / "release"); return 0;
        }
        need(args.empty(), "unknown fixture command");
        auto nonce = randomBytes(12);
        auto dir = std::filesystem::temp_directory_path() / ("pf2-instance-test-" + hex(nonce.data(), nonce.size()));
        platform::createPrivateDirectories(dir);
        struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(path, ec); } } cleanup{dir};
        tests(dir);
        std::cout << "PASS: single controller, CLI exceptions, simultaneous launch, handoff and crash recovery\n";
        return 0;
    } catch (const std::exception &error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
