#include "safe_end_session.h"
#include <cstdio>
#include <fstream>
#include <future>
#include <iterator>
#include <stdexcept>

using namespace relay;
namespace {
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void wait(const std::function<bool()> &predicate) {
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!predicate()) { need(std::chrono::steady_clock::now() < end, "session worker deadline"); sleepMs(5); }
}
bool hasQuestion(SafeEndSession &s, EnrollmentQuestion &q) { return s.pendingQuestion(q); }
Bytes contents(const std::filesystem::path &path) {
    std::ifstream file(path, std::ios::binary); return Bytes(std::istreambuf_iterator<char>(file), {});
}
void test(const std::filesystem::path &directory) {
    { Storage storage(directory); storage.initializeLocal(); }
    SafeEndSession s(directory, {});
    auto idle = [&] { wait([&] { return !s.busy(); }); };
    auto locked = [&] { wait([&] { return !s.busy() && !s.snapshot().unlocked; }); Storage successor(directory); (void)successor.open(); };
    idle();
    s.submit([&] { s.acquire(L""); s.publish("fixture open", true); }); idle();
    need(s.snapshot().unlocked, "session failed to open vault");
    bool excluded = false; try { Storage second(directory); } catch (...) { excluded = true; }
    need(excluded, "session did not retain exclusive ownership");
    s.requestLock(); locked();
    {
        std::promise<void> answered;
        s.submit([&] { EnrollmentQuestion q; q.kind = 3; q.name = "fixture-question";
            need(s.ask(q) == "fixture-answer", "session answer lost"); answered.set_value(); });
        EnrollmentQuestion q; wait([&] { return hasQuestion(s, q); });
        need(q.name == "fixture-question", "question content lost");
        s.answer(true, "fixture-answer");
        need(answered.get_future().wait_for(std::chrono::seconds(3)) == std::future_status::ready, "session answer blocked"); idle();
        std::atomic<bool> returned{false};
        s.submit([&] { EnrollmentQuestion q2; q2.kind = 1; (void)s.ask(q2); returned = true; });
        wait([&] { return hasQuestion(s, q); }); s.requestLock(); locked();
        need(!returned, "canceled question returned an answer");
        s.submit([&] { EnrollmentQuestion q3; q3.kind = 3; (void)s.ask(q3); returned = true; });
        wait([&] { return hasQuestion(s, q); }); s.answer(false, ""); idle();
        need(!returned, "declined question returned an answer");
    }
    // Cancellation while a job runs, including a request from the job's own tail,
    // must never be discarded by job completion.
    for (int attempt = 0; attempt < 12; ++attempt) {
        std::promise<void> entered, finish; auto finishSignal = finish.get_future();
        s.submit([&] { s.acquire(L""); s.publish("fixture active", true); entered.set_value();
            need(finishSignal.wait_for(std::chrono::seconds(3)) == std::future_status::ready, "session test gate timeout");
            if (attempt % 2) s.requestLock(); });
        need(entered.get_future().wait_for(std::chrono::seconds(3)) == std::future_status::ready, "session job did not start");
        if (!(attempt % 2)) s.requestLock(); finish.set_value(); locked();
    }
    s.submit([&] { s.acquire(L""); s.publish("fixture idle", true); }); idle();
    auto file = directory / ("backend-v1" + platform::protectedExtension()); auto original = contents(file);
    need(!original.empty(), "fixture missing selector");
    auto corrupted = original; corrupted.back() ^= 1;
    { std::ofstream out(file, std::ios::binary | std::ios::trunc); out.write(reinterpret_cast<const char *>(corrupted.data()), static_cast<std::streamsize>(corrupted.size())); need(out.good(), "fixture write"); }
    wait([&] { return !s.snapshot().unlocked && !s.busy(); }); // idle verification releases a faulted owner
    { std::ofstream out(file, std::ios::binary | std::ios::trunc); out.write(reinterpret_cast<const char *>(original.data()), static_cast<std::streamsize>(original.size())); need(out.good(), "fixture restore"); }
    locked();
    s.submit([&] { s.acquire(L""); s.publish("fixture closing", true); }); idle();
    s.close(); need(s.done(), "session did not finish");
    Storage successor(directory); (void)successor.open();
}
void backupAndClear(const std::filesystem::path &directory) {
    { Storage storage(directory); storage.initializeLocal(); }
    SafeEndSession s(directory, {});
    auto idle = [&] { wait([&] { return !s.busy(); }); };
    auto open = [&] { s.submit([&] { s.acquire(L""); s.publish("open", true); }); idle(); need(s.snapshot().unlocked, "open failed"); };
    const std::wstring password = L"session-backup-fixture-password";
    auto archive = directory / "saved.pf2bak";
    auto path = directory / ("credentials-v1" + platform::protectedExtension());
    auto original = contents(path);
    idle(); open();
    auto identity = s.snapshot().nameSpace;
    auto start = [&](const std::filesystem::path &file) {
        need(s.submit([&, file] { s.exportBackup(file, password); }), "backup job refused");
        EnrollmentQuestion q; wait([&] { return hasQuestion(s, q); });
        need(q.kind == SafeEndSession::ClearLocalAfterBackupQuestion && q.value == file.u8string() && std::filesystem::exists(file),
            "clear asked before backup success or for the wrong file");
        bool excluded = false; try { Storage second(directory); } catch (...) { excluded = true; }
        need(excluded, "ownership released while confirming clear");
    };
    start(archive); s.answer(true, "keep"); idle();
    need(contents(path) == original && s.snapshot().unlocked && s.snapshot().initialized, "keep removed or locked the vault");
    // A failed export must never ask to clear or delete an initialized vault.
    s.submit([&] { s.exportBackup(archive, password); }); idle();
    EnrollmentQuestion q; need(!hasQuestion(s, q) && contents(path) == original, "failed export offered clear");
    open(); start(directory / "canceled.pf2bak"); s.requestLock(); idle();
    s.answer(true, "clear"); // A late answer after locking must not revive the job.
    need(contents(path) == original && !s.snapshot().unlocked, "lock during confirmation removed the vault");
    open(); start(directory / "declined.pf2bak"); s.answer(false, ""); idle();
    need(contents(path) == original, "dismissed confirmation removed the vault");
    open(); auto changed = directory / "changed.pf2bak"; start(changed);
    { std::ofstream out(changed, std::ios::binary | std::ios::trunc); out << "damaged after prompt"; }
    s.answer(true, "clear"); idle();
    need(contents(path) == original && s.snapshot().initialized, "backup changed during confirmation authorized clear");
    open(); start(directory / "clear.pf2bak"); s.answer(true, "clear"); idle();
    auto cleared = s.snapshot();
    need(!cleared.initialized && !cleared.unlocked && cleared.nameSpace.empty() && cleared.rows.empty() &&
        !std::filesystem::exists(path) && !std::filesystem::exists(path.string() + ".lock"), "clear did not publish restorable state");
    s.submit([&] { s.storage().restoreLocal(archive, password); s.acquire(L""); s.publish("restored", true); }); idle();
    need(s.snapshot().initialized && s.snapshot().unlocked && s.snapshot().nameSpace == identity, "restore after clear failed");
    s.close();
}
}
int main() {
    auto directory = std::filesystem::temp_directory_path() / ("pf2-session-test-" + hex(randomBytes(8).data(), 8));
    int result = 0;
    try { test(directory); backupAndClear(directory / "backup-clear"); std::puts("PASS: safe-end session ownership, questions, cancellation and backup-confirmed clear/restore"); }
    catch (const std::exception &e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); result = 1; }
    std::error_code ignored; std::filesystem::remove_all(directory, ignored);
    return result;
}
