// Host-only synthetic helper and native vault tests. Never touches default paths.
// The same executable acts as the storage helper fixture (--pipe etc.).
#include "relay_authenticator.h"
#include "relay_backup.h"
#include "relay_storage.h"
#include "safe_end_session.h"
#include "relay_profile.h"
#include "relay_transport.h"
#include "cli.h"
#include "test_process.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#endif

using V = ctap::Value;
using test::withSuffix;
static const std::string ns = "0123456789abcdef0123456789abcdef";
static const std::wstring password = L"synthetic-cloud-password-中文";
static const std::string local = "credentials-v1" + platform::protectedExtension();
static const std::string selector = "backend-v1" + platform::protectedExtension();
static void need(bool ok, const char *why = "cloud test failed") { if (!ok) throw std::runtime_error(why); }
template<class F> static void rejects(F f) { bool failed = false; try { f(); } catch (...) { failed = true; } need(failed, "invalid cloud operation accepted"); }
static Bytes read(const std::filesystem::path &path) { std::ifstream f(path, std::ios::binary); return Bytes((std::istreambuf_iterator<char>(f)), {}); }
static void write(const std::filesystem::path &path, const Bytes &b) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char *>(b.data()), static_cast<std::streamsize>(b.size())); f.flush(); need(f.good());
}
static void mode(const std::filesystem::path &path, const std::string &value) { write(path, Bytes(value.begin(), value.end())); }
static uint64_t get(const Bytes &b, size_t at, unsigned width) { need(at + width <= b.size()); uint64_t n = 0; for (unsigned i = 0; i < width; ++i) n |= uint64_t(b[at + i]) << (i * 8); return n; }
static void put(Bytes &b, size_t at, uint64_t n, unsigned width) { need(at + width <= b.size()); for (unsigned i = 0; i < width; ++i) b[at + i] = static_cast<uint8_t>(n >> (i * 8)); }
static bool inTestDirectory(const std::filesystem::path &p, const char *prefix) { return p.parent_path().filename().u8string().rfind(prefix, 0) == 0; }
static int enrollmentFixture(const std::filesystem::path &profile, bool update = false) {
    need(inTestDirectory(profile, "pf2-cloud-test-"));
    auto raw = read(profile); std::string behavior(raw.begin(), raw.end()); unsigned step = 0;
    for (uint64_t sequence = 1;; ++sequence) {
        Bytes header(24); test::transfer(header, false);
        need(!memcmp(header.data(), "PF2STO01", 8) && get(header, 16, 8) == sequence && get(header, 8, 4) <= 256 * 1024);
        Bytes input(static_cast<size_t>(get(header, 8, 4))); test::transfer(input, false);
        auto op = header[12]; Bytes reply{0};
        auto string = [&](const std::string &value) { auto start = reply.size(); reply.resize(start + 4); put(reply, start, value.size(), 4); reply.insert(reply.end(), value.begin(), value.end()); };
        if (step == 0) {
            need(op == (update ? 10 : 7) && !input.empty()); reply.push_back(1);
            string(behavior == "bad-url" ? "https://accounts.google.com.evil.invalid/auth" : "https://accounts.google.com/o/oauth2/auth?state=synthetic"); ++step;
        } else if (step == 1) {
            need(op == 9 && input.empty());
            if (behavior == "waiting") reply.push_back(2);
            else {
                reply.push_back(behavior == "bad-kind" ? 99 : 3); string("config_driveid"); string("Synthetic drive selection"); string("choice1");
                reply.insert(reply.end(), {static_cast<uint8_t>(behavior == "bad-flags" ? 0xff : 3), 2, 0});
                string("choice1"); string("First fictional drive"); string("choice2"); string("Second fictional drive"); ++step;
            }
        } else if (step == 2) {
            need(op == 8 && std::string(input.begin(), input.end()) == "choice2"); reply.push_back(4);
            string("save_profile"); string("Save synthetic enrollment?"); string("cancel"); reply.insert(reply.end(), {3, 2, 0});
            string("cancel"); string("Cancel"); string("save"); string("Save"); ++step;
        } else { need(op == 8 && std::string(input.begin(), input.end()) == "save"); reply.push_back(0); }
        put(header, 8, reply.size(), 4); header[12] = op | 0x80;
        test::transfer(header, true); test::transfer(reply, true);
        if (reply.size() == 2 && reply[1] == 0) return 0;
    }
}
// Reports whether a descriptor/handle the parent deliberately left inheritable
// reached this helper. The launcher must pass only stdin/stdout/stderr.
static void probeInheritance(const std::filesystem::path &profile) {
    auto handle = read(withSuffix(profile, ".sentinel"));
    if (handle.size() != 8) return;
#ifdef _WIN32
    SetEvent(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(get(handle, 0, 8))));
#else
    char byte = 'x'; (void)!::write(static_cast<int>(get(handle, 0, 8)), &byte, 1);
#endif
}
static int fixture(const std::filesystem::path &profile) {
    need(inTestDirectory(profile, "pf2-cloud-test-"));
    std::unique_ptr<platform::FileLock> profileLock;
    if (std::filesystem::exists(withSuffix(profile, ".lock")))
        profileLock = std::make_unique<platform::FileLock>(withSuffix(profile, ".lock"), platform::FileLock::Mode::OpenExisting, "fixture profile busy");
    auto snapshot = withSuffix(profile, ".snapshot"), anchor = withSuffix(profile, ".anchor"), committed = withSuffix(profile, ".committed");
    std::unique_ptr<platform::FileLock> held;
    auto starts = read(withSuffix(profile, ".starts")); starts.push_back(1); write(withSuffix(profile, ".starts"), starts);
    probeInheritance(profile);
    uint64_t sequence = 0;
    for (;;) {
        Bytes header(24); test::transfer(header, false);
        auto flags = read(profile); std::string behavior(flags.begin(), flags.end());
        auto op = header[12]; need(!memcmp(header.data(), "PF2STO01", 8) && get(header, 16, 8) == ++sequence);
        if (op == 4 && behavior == "stall-write") { sleepMs(30000); return 1; }
        auto length = get(header, 8, 4); need(length <= relay::backup::maxPlaintext + 85);
        Bytes payload(static_cast<size_t>(length)); test::transfer(payload, false);
        if ((op == 5 || op == 12) && behavior == "slow-close") sleepMs(400);
        if (behavior == "stall") { sleepMs(30000); return 1; }
        Bytes response{0};
        if (op == 1 || op == 11) {
            need(!held); held = std::make_unique<platform::FileLock>(withSuffix(profile, ".held"), platform::FileLock::Mode::OpenAlways, "fixture lock");
        }
        if (op == 11) {
            if (behavior == "slow-open") sleepMs(2300);
            auto stored = read(snapshot); need(payload.size() == 40 && stored.size() > 8);
            auto cipherHash = hash(Bytes(stored.begin() + 8, stored.end()));
            if (get(payload, 0, 8) == get(stored, 0, 8) && std::equal(cipherHash.begin(), cipherHash.end(), payload.begin() + 8)) {
                response.insert(response.end(), stored.begin(), stored.begin() + 8);
                if (behavior == "cache-wrong-generation") put(response, 1, get(stored, 0, 8) + 1, 8);
            } else response.insert(response.end(), stored.begin(), stored.end());
        } else if (op == 1) {
            if (behavior == "slow-open") sleepMs(2300);
            need(payload.size() == 1 || payload.size() == 33); auto stored = read(snapshot);
            if (payload[0] == 1) {
                need(!std::filesystem::exists(anchor) && stored.empty()); write(anchor, payload.size() == 33 ? Bytes(payload.begin() + 1, payload.end()) : Bytes(32)); response.resize(9);
            } else if (payload[0] == 2) {
                need(payload.size() == 33); Bytes token(payload.begin() + 1, payload.end());
                if (!std::filesystem::exists(anchor)) write(anchor, token);
                need(read(anchor) == token);
                if (stored.empty()) { need(!std::filesystem::exists(committed)); response.resize(9); }
                else response.insert(response.end(), stored.begin(), stored.end());
            } else { need(stored.size() > 8); response.insert(response.end(), stored.begin(), stored.end()); }
        } else if (op == 4) {
            auto stored = read(snapshot); auto generation = stored.empty() ? 0 : get(stored, 0, 8);
            need(payload.size() >= 120 && get(payload, 0, 8) == generation);
            if (behavior == "reject") response = {1};
            else {
                put(payload, 0, generation + 1, 8); write(snapshot, payload);
                write(committed, {1});
                if (behavior == "ambiguous") return 1; // Durable commit, lost acknowledgement.
                response.resize(9); put(response, 1, generation + (behavior == "wrong-generation" ? 2 : 1), 8);
            }
        } else {
            need((op == 3 || op == 5 || op == 12 || op == 13) && payload.empty());
            if (op == 13) need(!held);
            if (op == 12 || op == 5) held.reset();
            if ((behavior == "lost" && op != 13) || (op == 3 && behavior == "final-check-lost")) response = {1};
        }
        header[12] |= 0x80; put(header, 8, response.size(), 4);
        if (behavior == "reserved") header[13] = 1;
        if (behavior == "sequence") put(header, 16, sequence + 1, 8);
        if (behavior == "operation") header[12] = 0x84;
        if (behavior == "oversize") put(header, 8, relay::backup::maxPlaintext + 86, 4);
        if (behavior == "bad-status") response[0] = 7;
        if (behavior == "short") { header.resize(13); test::transfer(header, true); return 1; }
        test::transfer(header, true); test::transfer(response, true);
        if (op == 5) return 0;
        if (op == 12 && behavior == "expire-idle") return 0;
        if (op == 12 && behavior == "audit-fail-idle") return 2;
    }
}
static relay::Operation operation() {
    relay::Operation op; op.deviceSerial = "0123456789abcdef"; op.requestId.fill(1); op.bootId.fill(2); op.enrollmentId.fill(3);
    op.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30); return op;
}
static Bytes request(bool create) {
    V data;
    if (create) {
        V algorithms; algorithms.type = V::Array; algorithms.items.push_back(V::map({V::string("type"), V::string("public-key"), V::string("alg"), V::integer(-7)}));
        V resident; resident.type = V::Boolean; resident.number = 1;
        data = V::map({V::integer(1), V::blob(Bytes(32, 0x55)), V::integer(2), V::map({V::string("id"), V::string("cloud.invalid")}),
            V::integer(3), V::map({V::string("id"), V::blob({1}), V::string("name"), V::string("fictional")}),
            V::integer(4), algorithms, V::integer(7), V::map({V::string("rk"), resident})});
    } else data = V::map({V::integer(1), V::string("cloud.invalid"), V::integer(2), V::blob(Bytes(32, 0x44))});
    Bytes wire{static_cast<uint8_t>(create ? 1 : 2)}; auto body = ctap::encode(data); wire.insert(wire.end(), body.begin(), body.end()); return wire;
}
static Bytes authorize(relay::Vault &vault, bool create, const std::function<void()> &approved = {}) {
    relay::Authenticator auth(vault, [&](const auto &approval, const auto &) {
        need(approval.rp == "cloud.invalid"); if (approved) approved();
        return relay::Decision{true, approval.accounts.empty() ? Bytes{} : approval.accounts.front().credentialId};
    });
    return auth.exchange(request(create), operation());
}
static void healthyReply(const Bytes &response) { need(response.size() > 1 && response[0] == 0, "CTAP cloud reply failed"); }
static Bytes appleCertificate(relay::Vault &vault) {
    auto body = request(true);
    auto params = ctap::decode(Bytes(body.begin() + 1, body.end()));
    for (size_t i = 0; i < params.items.size(); i += 2)
        if (params.items[i].number == 2) params.items[i + 1] = V::map({V::string("id"), V::string("apple.com")});
    body = ctap::encode(params); body.insert(body.begin(), 1);
    relay::Authenticator auth(vault, [](const auto &, const auto &) { return relay::Decision{true, {}}; });
    auto response = auth.exchange(body, operation()); healthyReply(response);
    return ctap::decode(Bytes(response.begin() + 1, response.end())).at(3).at("x5c").items.at(0).bytes;
}
static void attestationStorageTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "attestation";
    launch.timeout = std::chrono::seconds(5); mode(launch.profile, "normal");
    auto target = dir / "attestation-selected", archive = dir / "attestation.pf2bak";
    Bytes certificate; std::string identity;
    {
        relay::Storage storage(target, launch); storage.initializeLocal();
        auto &vault = storage.open(); certificate = appleCertificate(vault); identity = vault.namespaceId();
        vault.exportBackup(archive, password);
    }
    {
        relay::Storage storage(target, launch);
        storage.migrateCloud(password);
        need(appleCertificate(storage.open(password)) == certificate, "migration changed attestation identity");
    }
    auto first = relay::Vault::openCloud(identity, password, launch);
    auto second = relay::Vault::openCloud(identity, password, launch);
    need(appleCertificate(*first) == certificate && appleCertificate(*second) == certificate,
        "cloud refresh or another client lost attestation identity");
    auto restoredPath = dir / "attestation-restored";
    relay::Vault::restoreBackup(archive, password, restoredPath);
    { relay::Vault restored(restoredPath); need(appleCertificate(restored) == certificate, "backup lost attestation identity"); }
    auto plain = relay::backup::decrypt(read(archive), password);
    need(plain[7] == '3', "attestation did not upgrade storage format");
    // Authenticated storage containing a mismatched key/certificate must fail closed.
    auto otherKey = Key::generate()->blob();
    need(plain.size() > certificate.size() + 106);
    std::copy(otherKey.begin(), otherKey.end(), plain.end() - certificate.size() - 106);
    write(dir / "bad-attestation.pf2bak", relay::backup::encrypt(plain, password));
    rejects([&] { relay::Vault::restoreBackup(dir / "bad-attestation.pf2bak", password, dir / "bad-attestation"); });
    secureZero(plain.data(), plain.size()); secureZero(otherKey.data(), otherKey.size());
}
static void optimisticTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "optimistic";
    launch.timeout = std::chrono::seconds(5); mode(launch.profile, "normal");
    auto first = relay::Vault::createCloud(ns, password, launch);
    auto second = relay::Vault::openCloud(ns, password, launch);
    {
        relay::CloudStorage reuse(ns, launch); (void)reuse.open(false); reuse.release();
        auto starts = read(withSuffix(launch.profile, ".starts")).size();
        (void)reuse.open(false); reuse.release();
        need(read(withSuffix(launch.profile, ".starts")).size() == starts, "idle helper was not reused");
        (void)reuse.open(false); mode(launch.profile, "expire-idle"); reuse.release();
        sleepMs(30); mode(launch.profile, "normal"); (void)reuse.open(false); reuse.release();
        need(read(withSuffix(launch.profile, ".starts")).size() == starts + 1, "clean idle exit did not restart exactly once");
    }
    {
        auto audited = relay::Vault::openCloud(ns, password, launch);
        mode(launch.profile, "audit-fail-idle"); (void)audited->accounts();
        sleepMs(30); mode(launch.profile, "normal");
        rejects([&] { (void)audited->accounts(); });
        need(!audited->healthy(), "background corruption was silently reopened with cached data");
    }
    {
        relay::CloudStorage release(ns, launch); (void)release.open(false);
        mode(launch.profile, "slow-close"); unsigned polls = 0;
        release.cancellation([&] { ++polls; return false; }); release.close();
        need(polls >= 3, "slow lease release suppressed operation keepalives"); mode(launch.profile, "normal");
    }
    relay::Authenticator hints(*first, {});
    mode(launch.profile, "stall");
    auto start = std::chrono::steady_clock::now();
    need(first->displayAccounts().empty(), "management snapshot performed remote IO");
    for (int i = 0; i < 10; ++i) healthyReply(hints.exchange({4}, operation()));
    need(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(250), "discovery waited for cloud IO");
    auto cancelOp = operation();
    cancelOp.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(180);
    need(hints.exchange(request(true), cancelOp) == Bytes{0x7f} && first->healthy(), "canceled acquisition poisoned the vault or succeeded");
    mode(launch.profile, "normal");
    mode(launch.profile, "cache-wrong-generation");
    rejects([&] { (void)first->accounts(); });
    mode(launch.profile, "normal");
    mode(launch.profile, "slow-open"); start = std::chrono::steady_clock::now();
    healthyReply(authorize(*first, true));
    need(std::chrono::steady_clock::now() - start >= std::chrono::seconds(4), "slow cloud fixture did not exceed the Windows discovery deadline");
    mode(launch.profile, "normal");
    // Another open client can commit while this client's approval is visible.
    // The resumed assertion must increment the new counter, never overwrite it.
    healthyReply(authorize(*first, false, [&] { healthyReply(authorize(*second, false)); }));
    need(first->accounts().at(0).counter == 2 && second->accounts().at(0).counter == 2, "concurrent assertion lost a counter increment");
    auto oldId = first->accounts().at(0).credentialId;
    auto stale = authorize(*first, false, [&] { healthyReply(authorize(*second, true)); });
    need(stale == Bytes{0x2e}, "approval signed a credential replaced by another client");
    need(first->accounts().at(0).credentialId != oldId && first->accounts().at(0).counter == 0, "stale selection mutated the replacement");
    // A changed PIN on another client must override the optimistic clientPin
    // hint, even when this client's discovery cache still says unconfigured.
    relay::Authenticator writer(*second, [](const auto &, const auto &) { return relay::Decision{true, {}}; });
    auto agreementReply = writer.exchange({6,0xa2,1,1,2,2}, operation()); healthyReply(agreementReply);
    auto peer = ctap::decode(Bytes(agreementReply.begin() + 1, agreementReply.end())).at(1);
    ctap::Agreement agreement; auto key = relay::pin::shared(1, agreement, peer);
    Bytes pin(64); memcpy(pin.data(), "6789", 4); auto encrypted = relay::pin::encrypt(1, key, pin);
    auto body = ctap::encode(V::map({V::integer(1),V::integer(1), V::integer(2),V::integer(3),
        V::integer(3),agreement.publicKey(), V::integer(4),V::blob(relay::pin::authenticate(1,key,encrypted)), V::integer(5),V::blob(encrypted)}));
    body.insert(body.begin(), 6); need(writer.exchange(body, operation()) == Bytes{0}, "second client could not set PIN");
    auto oldInfo = hints.exchange({4}, operation()); healthyReply(oldInfo);
    need(!ctap::decode(Bytes(oldInfo.begin()+1,oldInfo.end())).at(4).at("clientPin").number, "fixture did not exercise a stale PIN hint");
    need(authorize(*first, true) == Bytes{0x36}, "stale PIN hint bypassed latest PIN requirement");
    auto refreshed = hints.exchange({4}, operation()); healthyReply(refreshed);
    need(ctap::decode(Bytes(refreshed.begin()+1,refreshed.end())).at(4).at("clientPin").number, "real operation did not refresh discovery cache");
    need(second->resetDevicePin(operation().deviceSerial), "could not prepare concurrent PIN reset");
    auto changedDuringApproval = authorize(*first, true, [&] {
        need(writer.exchange(body, operation()) == Bytes{0}, "another client could not change PIN during approval");
    });
    need(changedDuringApproval == Bytes{0x36}, "PIN set during approval was bypassed after reacquiring lease");
}
static void preflightCloudTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "preflight";
    launch.timeout = std::chrono::seconds(5); mode(launch.profile, "normal");
    auto vault = relay::Vault::createCloud(ns, password, launch);
    auto writer = relay::Vault::openCloud(ns, password, launch);
    healthyReply(authorize(*vault, true));
    unsigned approvals = 0; bool allow = true;
    relay::Authenticator auth(*vault, [&](const auto &a, const auto &) {
        ++approvals; return relay::Decision{allow, a.accounts.empty() ? Bytes{} : a.accounts.front().credentialId};
    });
    auto call = [&](uint8_t cmd, const V &params) {
        auto body = ctap::encode(params); body.insert(body.begin(), cmd);
        auto op = operation(); auto id = randomBytes(16); std::copy(id.begin(), id.end(), op.requestId.begin());
        return auth.exchange(body, op);
    };
    auto decode = [&](const Bytes &b) { healthyReply(b); return ctap::decode(Bytes(b.begin() + 1, b.end())); };
    auto peer = decode(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(2)}))).at(1);
    ctap::Agreement own; auto shared = relay::pin::shared(2, own, peer);
    Bytes padded(64); std::copy_n("test-pin", 8, padded.begin()); auto encrypted = relay::pin::encrypt(2, shared, padded);
    need(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(3), V::integer(3), own.publicKey(),
        V::integer(4), V::blob(relay::pin::authenticate(2, shared, encrypted)), V::integer(5), V::blob(encrypted)})) == Bytes{0});
    auto pinHash = hash(Bytes{'t','e','s','t','-','p','i','n'}); pinHash.resize(16);
    auto preflight = [&] {
        auto issued = decode(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(9), V::integer(3), own.publicKey(),
            V::integer(6), V::blob(relay::pin::encrypt(2, shared, pinHash)), V::integer(9), V::integer(2), V::integer(10), V::string("cloud.invalid")})));
        auto token = relay::pin::decrypt(2, shared, issued.at(2).bytes);
        V up; up.type = V::Boolean; up.number = 0;
        auto params = V::map({V::integer(1), V::string("cloud.invalid"), V::integer(2), V::blob(Bytes(32, 0x44)),
            V::integer(5), V::map({V::string("up"), up}), V::integer(6), V::blob(relay::pin::authenticate(2, token, Bytes(32, 0x44))),
            V::integer(7), V::integer(2)});
        healthyReply(call(2, params)); params.items[5].items[1].number = 1; return params;
    };
    // A real second client increments the counter between the two stages.
    auto formal = preflight(); auto before = approvals;
    healthyReply(authorize(*writer, false)); healthyReply(call(2, formal));
    need(approvals == before && vault->accounts().at(0).counter == 3, "preflight lost concurrent counter or requested extra consent");
    // Edit only the synthetic encrypted fixture to model another client's
    // identity/key update, including updates that retain the credential ID.
    for (auto field : {4, 6, 1}) {
        formal = preflight(); before = approvals;
        auto snapshot = withSuffix(launch.profile, ".snapshot"); auto stored = read(snapshot);
        auto plain = relay::backup::decrypt(Bytes(stored.begin() + 8, stored.end()), password);
        need(get(plain, 32, 4) == 1); auto length = static_cast<size_t>(get(plain, 36, 4));
        auto record = ctap::decode(Bytes(plain.begin() + 40, plain.begin() + 40 + length));
        for (size_t i = 0; i < record.items.size(); i += 2) if (record.items[i].number == field)
            record.items[i + 1] = field == 4 ? V::string("changed-account") : V::blob(field == 6 ? Key::generate()->blob() : randomBytes(32));
        auto encoded = ctap::encode(record); Bytes updated(plain.begin(), plain.begin() + 40);
        put(updated, 24, get(plain, 24, 8) + 1, 8); put(updated, 36, encoded.size(), 4);
        updated.insert(updated.end(), encoded.begin(), encoded.end());
        updated.insert(updated.end(), plain.begin() + 40 + length, plain.end());
        auto cipher = relay::backup::encrypt(updated, password); Bytes next(8); put(next, 0, get(stored, 0, 8) + 1, 8);
        next.insert(next.end(), cipher.begin(), cipher.end()); write(snapshot, next);
        allow = false;
        need(call(2, formal) == Bytes{0x27} && approvals == before + 1, "cloud account/key change reused preflight consent");
        need(call(2, formal) == Bytes{0x33}, "denied changed account retained token"); allow = true;
    }
    formal = preflight(); before = approvals;
    need(writer->resetDevicePin(operation().deviceSerial));
    need(call(2, formal) == Bytes{0x35} && approvals == before, "cloud PIN reset retained preflight UV");
}
static void profileMarker(const std::filesystem::path &profile, const std::string &nameSpace) {
    mode(withSuffix(profile, ".lock"), "PF2CLCK1" + nameSpace);
}
static void detachTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "detach-profile";
    launch.timeout = std::chrono::seconds(3); mode(launch.profile, "normal");
    auto target = dir / "detach-selected", archive = dir / "detach.pf2bak";
    std::string identity; Bytes localSource, retainedMarker, remote, pending;
    {
        relay::Storage storage(target, launch); storage.initializeLocal();
        identity = storage.localNamespace(); profileMarker(launch.profile, identity);
        storage.migrateCloud(password); auto &vault = storage.open(password);
        healthyReply(authorize(vault, true)); healthyReply(authorize(vault, false));
        localSource = read(target / local); retainedMarker = read(withSuffix(target / local, ".lock"));
        vault.exportBackup(archive, password);
        rejects([&] { storage.detachCloudAfterBackup(archive, L"incorrect-password"); });
        rejects([&] { storage.detachCloudAfterBackup(dir / "missing-backup", password); });
        auto damaged = read(archive); damaged.back() ^= 1; write(dir / "bad-detach.pf2bak", damaged);
        rejects([&] { storage.detachCloudAfterBackup(dir / "bad-detach.pf2bak", password); });
        rejects([&] { storage.detachCloudAfterBackup(archive, password, [] { return true; }); });
        need(storage.choice().kind == relay::StorageKind::Cloud && vault.healthy() && std::filesystem::exists(launch.profile), "rejected detach changed selection/profile");
        // A stale backup from this same vault must not authorize detaching a
        // newer snapshot that this process has already used.
        healthyReply(authorize(vault, false));
        rejects([&] { storage.detachCloudAfterBackup(archive, password); });
        archive = dir / "detach-current.pf2bak"; vault.exportBackup(archive, password);
        remote = read(withSuffix(launch.profile, ".snapshot"));
        {
            test::BlockReplace blocked(launch.profile);
            rejects([&] { storage.detachCloudAfterBackup(archive, password); });
        }
        need(storage.choice().kind == relay::StorageKind::DetachingCloud && std::filesystem::exists(launch.profile), "failed deletion did not leave resumable detach");
        pending = read(target / selector);
        rejects([&] { storage.open(password); });
    }
    auto guard = target / ("cloud-" + identity + ".generation"); auto highWater = read(guard);
    {
        // Restart completes previously confirmed cleanup, without the backup
        // password, cloud access or reactivating the migrated local source.
        relay::Storage storage(target, launch);
        need(storage.choice().kind == relay::StorageKind::Unbound && storage.choice().nameSpace.empty());
        need(!std::filesystem::exists(launch.profile) && std::filesystem::exists(withSuffix(launch.profile, ".lock")));
        need(read(withSuffix(launch.profile, ".snapshot")) == remote && read(guard) == highWater && !highWater.empty(), "detach changed cloud data or rollback guard");
        need(read(target / local) == localSource && read(withSuffix(target / local, ".lock")) == retainedMarker, "detach deleted or revived retired local data");
        rejects([&] { storage.open(); });
        rejects([&] { relay::Vault old(target / local); });
        // Simulate crash after profile removal but before saving Unbound.
    }
    write(target / selector, pending);
    { relay::Storage recovered(target, launch); need(recovered.choice().kind == relay::StorageKind::Unbound); }
    // Reconfigure and reconnect the same vault; retained non-secret marker and
    // generation guard remain usable. No existing remote data is initialized.
    mode(launch.profile, "normal");
    {
        relay::Storage storage(target, launch); storage.selectCloud(identity, password);
        need(storage.open(password).accounts().at(0).counter == 2);
        storage.open().exportBackup(dir / "detach-again.pf2bak", password);
        storage.detachCloudAfterBackup(dir / "detach-again.pf2bak", password);
    }
    // Switch to an independently initialized different cloud vault, even when
    // the former cloud's retired local source is still present.
    auto other = launch; other.profile = dir / "detach-other"; mode(other.profile, "normal"); profileMarker(other.profile, ns);
    { auto created = relay::Vault::createCloud(ns, password, other); }
    {
        relay::Storage storage(target, other); storage.selectCloud(ns, password);
        need(storage.open(password).namespaceId() == ns && storage.open().accounts().empty());
        need(read(withSuffix(launch.profile, ".snapshot")) == remote, "switch touched former cloud");
        storage.open().exportBackup(dir / "detach-other.pf2bak", password);
        storage.detachCloudAfterBackup(dir / "detach-other.pf2bak", password);
    }
    auto fresh = launch; fresh.profile = dir / "detach-new"; mode(fresh.profile, "reject"); profileMarker(fresh.profile, ns);
    {
        relay::Storage storage(target, fresh);
        rejects([&] { storage.initializeCloud(ns, password); });
        need(storage.choice().kind == relay::StorageKind::InitializingCloud);
    }
    mode(fresh.profile, "normal");
    {
        relay::Storage storage(target, fresh); storage.resume(password);
        need(storage.open(password).namespaceId() == ns && storage.open().accounts().empty(), "new cloud resume rejected retired local source");
        need(read(target / local) == localSource && read(withSuffix(target / local, ".lock")) == retainedMarker);
    }
}
static void rememberedCodeTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "remember-profile";
    mode(launch.profile, "normal"); profileMarker(launch.profile, ns);
    auto target = dir / "remember";
    auto codePath = target / ("cloud-code-" + ns + platform::protectedExtension());
    const std::wstring code = L"0123456789ABCDEFGHJKMNPQRS", wrong = L"ZZZZZZZZZZZZZZZZZZZZZZZZZZ";
    { relay::Storage storage(target, launch); storage.initializeCloud(ns, code); need(storage.rememberedCloudCode().empty()); }
    auto wait = [&](const std::function<bool()> &predicate) {
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        while (!predicate()) { need(std::chrono::steady_clock::now() < end, "remembered-code session deadline"); sleepMs(5); }
    };
    auto idle = [&](relay::SafeEndSession &s) { wait([&] { return !s.busy(); }); };
    auto unlock = [&](relay::SafeEndSession &s) {
        idle(s); need(s.submit([&s] { s.acquireRemembered(); s.publish("open", false); }));
    };
    auto question = [&](relay::SafeEndSession &s) {
        relay::EnrollmentQuestion q; wait([&] { return s.pendingQuestion(q); });
        need(q.kind == relay::SafeEndSession::CloudRecoveryCodeQuestion && q.value.empty(), "code missing or leaked into question"); return q;
    };
    auto answer = [&](relay::SafeEndSession &s, bool remember) { s.answer(true, std::string(remember ? "1" : "0") + utf8(code)); idle(s); need(s.snapshot().unlocked, "manual code did not unlock"); };
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); question(s); answer(s, false);
        need(!std::filesystem::exists(codePath), "code saved without consent");
    }
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); question(s);
        s.answer(true, "1" + utf8(wrong)); question(s);
        need(!std::filesystem::exists(codePath), "invalid manual code was saved");
        answer(s, true);
    }
    const auto sealed = read(codePath); const auto text = utf8(code);
    need(!sealed.empty() && std::search(sealed.begin(), sealed.end(), text.begin(), text.end()) == sealed.end(), "saved code is plaintext");
#ifndef _WIN32
    struct stat permissions{}; need(::stat(codePath.c_str(), &permissions) == 0 && (permissions.st_mode & 077) == 0, "remembered code is not private");
#endif
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); idle(s);
        relay::EnrollmentQuestion q; need(s.snapshot().unlocked && !s.pendingQuestion(q), "restart prompted for a remembered code");
        s.requestLock(); idle(s); need(!s.snapshot().unlocked && read(codePath) == sealed, "lock removed remembered code");
    }
    mode(launch.profile, "bad-status");
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); idle(s);
        relay::EnrollmentQuestion q; need(!s.snapshot().unlocked && !s.pendingQuestion(q) && read(codePath) == sealed, "network error erased code or asked for a new one");
    }
    mode(launch.profile, "normal");
    { relay::Storage storage(target, launch); storage.open(code); storage.rememberCloudCode(wrong); }
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); auto q = question(s);
        need(!q.message.empty() && !s.snapshot().unlocked && !std::filesystem::exists(codePath), "invalid saved code was not cleared before prompting");
        s.requestLock(); idle(s); s.answer(true, "1" + utf8(code));
        need(!s.snapshot().unlocked && !std::filesystem::exists(codePath), "late answer after locking persisted a code");
    }
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); question(s); answer(s, false);
        need(!std::filesystem::exists(codePath), "invalid saved code survived restart");
    }
    write(codePath, {1,2,3});
    {
        relay::SafeEndSession s(target, {}, launch); unlock(s); need(!question(s).message.empty(), "unreadable code did not explain manual fallback"); answer(s, true);
    }
    {
        // Copying another selection's ciphertext must never unlock this owner.
        auto other = dir / "other-owner";
        relay::Storage storage(other, launch); storage.selectCloud(ns, code);
        write(other / codePath.filename(), read(codePath)); rejects([&] { (void)storage.rememberedCloudCode(); });
    }
    {
        relay::Storage storage(target, launch); need(storage.rememberedCloudCode() == code);
        auto archive = dir / "remember-detach.pf2bak"; storage.open(code).exportBackup(archive, password);
        storage.detachCloudAfterBackup(archive, password);
        need(!std::filesystem::exists(codePath) && storage.choice().kind == relay::StorageKind::Unbound, "detach retained remembered code");
    }
}
static void detachSessionTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "session-detach-profile";
    mode(launch.profile, "normal"); profileMarker(launch.profile, ns);
    auto target = dir / "session-detach";
    { relay::Storage storage(target, launch); storage.initializeCloud(ns, password); }
    relay::SafeEndSession session(target, {}, launch);
    auto wait = [&](const std::function<bool()> &predicate) {
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        while (!predicate()) { need(std::chrono::steady_clock::now() < end, "cloud session deadline"); sleepMs(5); }
    };
    auto idle = [&] { wait([&] { return !session.busy(); }); };
    auto open = [&] { need(session.submit([&] { session.acquire(password); session.publish("open", true); })); idle(); need(session.snapshot().unlocked); };
    idle(); open();
    auto start = [&](const char *file) {
        auto path = dir / file;
        need(session.submit([&, path] { session.exportBackup(path, password); }));
        relay::EnrollmentQuestion q; wait([&] { return session.pendingQuestion(q); });
        need(q.kind == relay::SafeEndSession::DetachCloudAfterBackupQuestion && q.value == path.u8string() && std::filesystem::exists(path));
        rejects([&] { relay::Storage competing(target, launch); });
    };
    start("session-keep.pf2bak"); session.answer(true, "keep"); idle();
    need(session.snapshot().unlocked && std::filesystem::exists(launch.profile));
    // Failed export, cancellation and a corrupted backup cannot detach.
    need(session.submit([&] { session.exportBackup(dir / "session-keep.pf2bak", password); })); idle();
    relay::EnrollmentQuestion q; need(!session.pendingQuestion(q) && std::filesystem::exists(launch.profile));
    open(); start("session-cancel.pf2bak"); session.requestLock(); idle(); session.answer(true, "detach");
    need(session.snapshot().kind == relay::StorageKind::Cloud && std::filesystem::exists(launch.profile));
    open(); start("session-damaged.pf2bak"); write(dir / "session-damaged.pf2bak", {1,2,3});
    session.answer(true, "detach"); idle(); need(session.snapshot().kind == relay::StorageKind::Cloud && std::filesystem::exists(launch.profile));
    open(); start("session-detach.pf2bak");
    // Another client commits while the confirmation is visible. Detach must
    // preserve that newer remote snapshot and accept our verified export.
    auto remotePath = withSuffix(launch.profile, ".snapshot"); auto remote = read(remotePath);
    auto plain = relay::backup::decrypt(Bytes(remote.begin() + 8, remote.end()), password);
    put(plain, 24, get(plain, 24, 8) + 1, 8); auto cipher = relay::backup::encrypt(plain, password);
    auto revision = get(remote, 0, 8) + 1; remote.resize(8); put(remote, 0, revision, 8); remote.insert(remote.end(), cipher.begin(), cipher.end()); write(remotePath, remote);
    session.answer(true, "detach"); idle();
    auto state = session.snapshot();
    need(state.kind == relay::StorageKind::Unbound && !state.unlocked && !state.initialized && state.nameSpace.empty() && state.rows.empty(), "detach did not publish a switchable empty state");
    need(!std::filesystem::exists(launch.profile) && read(remotePath) == remote, "detach touched newer remote snapshot");
    need(session.submit([&] { session.storage().initializeLocal(); session.acquire({}); session.publish("local", true); })); idle();
    state = session.snapshot();
    need(state.kind == relay::StorageKind::Local && state.initialized && state.unlocked && state.nameSpace != ns && state.rows.empty(),
         "could not initialize local storage immediately after detach");
    need(read(remotePath) == remote, "local initialization changed the cloud snapshot");
    session.close();
    { relay::Storage reopened(target, launch); need(reopened.choice().kind == relay::StorageKind::Local && reopened.open().namespaceId() == state.nameSpace); }
}
static void detachedLocalTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    for (bool migrated : {false, true}) for (bool restore : {false, true}) {
        auto tag = std::string(migrated ? "migrated" : "direct") + (restore ? "-restore" : "-new");
        auto target = dir / tag, backup = dir / (tag + ".pf2bak");
        relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / (tag + "-profile");
        mode(launch.profile, "normal");
        std::string identity; Bytes source, marker;
        {
            relay::Storage storage(target, launch);
            if (migrated) {
                storage.initializeLocal(); identity = storage.localNamespace(); profileMarker(launch.profile, identity);
                storage.migrateCloud(password); source = read(target / local); marker = read(withSuffix(target / local, ".lock"));
            } else { identity = ns; profileMarker(launch.profile, identity); storage.initializeCloud(identity, password); }
            rejects([&] { storage.initializeLocal(); });
            auto &vault = storage.open(password); healthyReply(authorize(vault, true));
            vault.exportBackup(backup, password); storage.detachCloudAfterBackup(backup, password);
            need(storage.choice().kind == relay::StorageKind::Unbound);
        }
        auto remote = read(withSuffix(launch.profile, ".snapshot"));
        auto guard = target / ("cloud-" + identity + ".generation"); auto highWater = read(guard);
        auto archived = target / ("retired-local-" + identity) / local;
        if (!migrated && !restore) {
            // An unexpected live local vault must never be treated as a
            // retired migration source, even with an unbound selection.
            relay::Vault::create(target / local); auto unexpected = read(target / local);
            { relay::Storage storage(target, launch); rejects([&] { storage.initializeLocal(); });
              need(storage.choice().kind == relay::StorageKind::Unbound && read(target / local) == unexpected); }
            std::filesystem::remove(target / local); std::filesystem::remove(withSuffix(target / local, ".lock"));
        }
        if (migrated && !restore) {
            platform::createPrivateDirectories(archived.parent_path()); write(archived, {1,2,3});
            { relay::Storage storage(target, launch); rejects([&] { storage.initializeLocal(); });
              need(storage.choice().kind == relay::StorageKind::Unbound && read(archived) == Bytes({1,2,3}) && read(target / local) == source); }
            std::filesystem::remove(archived);
            {
                test::BlockReplace blocked(target / local);
                relay::Storage storage(target, launch); rejects([&] { storage.initializeLocal(); });
                need(storage.choice().kind == relay::StorageKind::Unbound && read(target / local) == source &&
                     read(withSuffix(target / local, ".lock")) == marker, "failed archival changed the selected vault");
            }
        }
        if (migrated && restore) {
            // Crash after the preserved retired copy was written and its old
            // data removed, but before removing the old retired marker.
            platform::createPrivateDirectories(archived.parent_path());
            write(archived, source); write(withSuffix(archived, ".lock"), marker);
            std::filesystem::remove(target / local);
        }
        {
            relay::Storage restarted(target, launch);
            rejects([&] { restarted.open(); }); // Never implicitly fall back.
            if (restore) restarted.restoreLocal(backup, password); else restarted.initializeLocal();
            need(restarted.choice().kind == relay::StorageKind::Local);
            auto &vault = restarted.open();
            need(restore ? vault.namespaceId() == identity && vault.accounts().size() == 1
                         : vault.namespaceId() != identity && vault.accounts().empty(), "wrong local vault after detach/restart");
            rejects([&] { restarted.initializeLocal(); }); rejects([&] { restarted.restoreLocal(backup, password); });
        }
        need(read(withSuffix(launch.profile, ".snapshot")) == remote && read(guard) == highWater, "local switch changed cloud state");
        if (migrated) {
            need(read(archived) == source && read(withSuffix(archived, ".lock")) == marker, "retired source was not preserved");
            rejects([&] { relay::Vault old(archived); });
        }
        { relay::Storage restarted(target, launch); need(restarted.choice().kind == relay::StorageKind::Local); (void)restarted.open(); }
    }
}
static void selectionTests(const std::filesystem::path &dir, const std::filesystem::path &executable) {
    optimisticTests(dir, executable);
    attestationStorageTests(dir, executable);
    preflightCloudTests(dir, executable);
    relay::CloudLaunch launch; launch.helper = executable; launch.profile = dir / "migration"; launch.timeout = std::chrono::seconds(3);
    mode(launch.profile, "normal"); auto seed = dir / ("seed" + platform::protectedExtension()); relay::Vault::create(seed);
    auto archive = dir / "seed.pf2bak";
    { relay::Vault vault(seed); healthyReply(authorize(vault, true)); healthyReply(authorize(vault, false)); vault.exportBackup(archive, password); }
    auto plain = relay::backup::decrypt(read(archive), password);
    need(plain.size() >= 38 && plain[plain.size() - 2] == 0 && plain.back() == 0);
    plain[plain.size() - 2] = 1; // One synthetic persisted PIN record, two retries left.
    const std::string serial = "0123456789abcdef"; plain.insert(plain.end(), serial.begin(), serial.end());
    plain.insert(plain.end(), 32, 0x31); plain.insert(plain.end(), 32, 0x52); plain.push_back(2);
    write(dir / "seed-with-pin.pf2bak", relay::backup::encrypt(plain, password));
    auto target = dir / "selected"; auto localFile = target / local;
    {
        relay::Storage storage(target, launch); need(storage.choice().kind == relay::StorageKind::Local);
        rejects([&] { relay::Storage other(target, launch); });
        storage.restoreLocal(dir / "seed-with-pin.pf2bak", password);
        need(storage.localNamespace() == hex(plain.data() + 8, 16));
        rejects([&] { storage.initializeCloud(ns, password); });
        rejects([&] { storage.selectCloud(ns, password); });
    }
    auto original = read(localFile);
    {
        relay::Storage storage(target, launch); storage.migrateCloud(password);
        need(storage.choice().kind == relay::StorageKind::Cloud);
        rejects([&] { relay::Vault old(localFile); });
    }
    need(read(localFile) == original, "migration destroyed retained source");
    {
        relay::Storage storage(target, launch); auto &vault = storage.open(password);
        vault.exportBackup(dir / "migrated.pf2bak", password);
        need(relay::backup::decrypt(read(dir / "migrated.pf2bak"), password) == plain, "migration changed credential/PIN/counter payload");
        rejects([&] { storage.clearLocalAfterBackup(dir / "migrated.pf2bak", password); });
        need(vault.healthy() && read(localFile) == original && storage.choice().kind == relay::StorageKind::Cloud,
             "local clear touched a cloud vault or its retained migration source");
        rejects([&] { storage.initializeLocal(); });
        auto selected = target / selector; auto bytes = read(selected); auto corrupt = bytes; corrupt.back() ^= 1; write(selected, corrupt);
        rejects([&] { (void)vault.accounts(); }); write(selected, bytes); rejects([&] { (void)vault.accounts(); });
    }
    // A chosen cloud never returns to a retained local file on helper/IO failure.
    mode(launch.profile, "lost");
    { relay::Storage storage(target, launch); rejects([&] { (void)storage.open(password); }); need(storage.choice().kind == relay::StorageKind::Cloud); }
    mode(launch.profile, "normal");
    for (const auto *failure : {"short", "reject", "ambiguous"}) {
        auto destination = dir / (std::string("resume-") + failure); auto profile = dir / (std::string("remote-") + failure);
        auto options = launch; options.profile = profile; mode(profile, failure);
        {
            relay::Storage storage(destination, options); storage.restoreLocal(dir / "seed-with-pin.pf2bak", password);
            rejects([&] { storage.migrateCloud(password); }); need(storage.choice().kind == relay::StorageKind::MovingToCloud);
            rejects([&] { (void)storage.open(); });
        }
        if (std::string(failure) == "short") { relay::Vault old(destination / local); need(old.accounts().size() == 1); }
        else rejects([&] { relay::Vault old(destination / local); });
        mode(profile, "normal");
        { relay::Storage storage(destination, options); storage.resume(password); need(storage.choice().kind == relay::StorageKind::Cloud); }
        { relay::Storage storage(destination, options); auto &vault = storage.open(password); vault.exportBackup(destination / "recovered.pf2bak", password);
          need(relay::backup::decrypt(read(destination / "recovered.pf2bak"), password) == plain); }
    }
    {
        auto destination = dir / "new-cloud"; auto options = launch; options.profile = dir / "remote-new"; mode(options.profile, "reject");
        { relay::Storage storage(destination, options); rejects([&] { storage.initializeCloud(ns, password); }); need(storage.choice().kind == relay::StorageKind::InitializingCloud); }
        mode(options.profile, "normal");
        { relay::Storage storage(destination, options); storage.resume(password); }
        { relay::Storage storage(destination, options); need(storage.open(password).accounts().empty()); }
        std::filesystem::remove(destination / selector); rejects([&] { relay::Storage missing(destination, options); });
    }
    {
        // A failed selection save leaves the old selection and faults the owner.
        auto destination = dir / "save-failed"; relay::Storage storage(destination, launch); auto file = destination / selector;
        auto before = read(file);
#ifdef _WIN32
        HANDLE denyReplace = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr); need(denyReplace != INVALID_HANDLE_VALUE);
        rejects([&] { storage.initializeCloud(ns, password); }); CloseHandle(denyReplace);
#else
        ::chmod(destination.c_str(), 0500); // no temporary file can be created
        rejects([&] { storage.initializeCloud(ns, password); }); ::chmod(destination.c_str(), 0700);
#endif
        need(read(file) == before); rejects([&] { (void)storage.choice(); });
    }
    secureZero(plain.data(), plain.size());
}
#ifdef _WIN32
static BOOL WINAPI consoleControl(DWORD event) { return event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT; }
// check_relay_console.py: run the CLI's --vault-import inside a pseudoconsole and
// verify that the console mode is restored after cancellation or errors.
static int consoleHost(const std::string &cli, const std::string &missingArg) {
    auto missing = std::filesystem::absolute(std::filesystem::u8path(missingArg));
    need(inTestDirectory(missing, "pf2-console-test-") && !std::filesystem::exists(missing));
    need(SetConsoleCtrlHandler(consoleControl, TRUE));
    HANDLE consoleInput = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD originalMode = 0; if (consoleInput == INVALID_HANDLE_VALUE || !GetConsoleMode(consoleInput, &originalMode)) return 98;
    auto program = std::filesystem::u8path(cli);
    auto command = L"\"" + program.wstring() + L"\" --vault-import \"" + missing.wstring() + L"\"";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION child{};
    need(CreateProcessW(program.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &child));
    CloseHandle(child.hThread); auto result = WaitForSingleObject(child.hProcess, 15000); DWORD code = 99;
    if (result == WAIT_TIMEOUT) { TerminateProcess(child.hProcess, 99); WaitForSingleObject(child.hProcess, 3000); }
    GetExitCodeProcess(child.hProcess, &code); CloseHandle(child.hProcess);
    DWORD restoredMode = 0; bool restored = GetConsoleMode(consoleInput, &restoredMode) && restoredMode == originalMode;
    CloseHandle(consoleInput); if (!restored) return 98;
    return static_cast<int>(code);
}
#endif
static void crashParent(const std::filesystem::path &profile) {
    need(inTestDirectory(profile, "pf2-cloud-test-"));
    relay::CloudLaunch launch; launch.helper = platform::executablePath(); launch.profile = profile;
    relay::CloudStorage storage(ns, launch); (void)storage.open(false);
    // Skip all C++ destructors: the OS (job object / pipe EOF) must stop the child.
#ifdef _WIN32
    ExitProcess(0);
#else
    _exit(0);
#endif
}
static int realHelper(const std::vector<std::string> &args);
int main(int argc, char **argv) {
    auto args = commandLine(argc, argv);
    try {
#ifdef _WIN32
        if (args.size() == 3 && args[0] == "--console-host") return consoleHost(args[1], args[2]);
#endif
        if (args.size() == 3 && args[0] == "--pipe") return fixture(std::filesystem::u8path(args[2]));
        if (args.size() == 3 && args[0] == "--enroll-pipe") return enrollmentFixture(std::filesystem::u8path(args[2]));
        if (args.size() == 3 && args[0] == "--maintain-pipe") return enrollmentFixture(std::filesystem::u8path(args[2]), true);
        if (args.size() == 2 && args[0] == "--crash-parent") { crashParent(std::filesystem::absolute(std::filesystem::u8path(args[1]))); return 1; }
        if (args.size() == 5 && args[0].rfind("--real-", 0) == 0) return realHelper(args);
        bool codesOnly = args.size() == 1 && args[0] == "--remembered-code-tests";
        bool detachedLocalOnly = args.size() == 1 && args[0] == "--detached-local-tests";
        need(args.empty() || codesOnly || detachedLocalOnly); auto executable = platform::executablePath();
        auto random = randomBytes(12); auto dir = std::filesystem::temp_directory_path() / ("pf2-cloud-test-" + hex(random.data(), random.size()));
        std::filesystem::create_directories(dir);
        struct Cleanup { std::filesystem::path p; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(p, ec); } } cleanup{dir};
        if (codesOnly) { rememberedCodeTests(dir, executable); std::cout << "PASS: remembered cloud recovery codes\n"; return 0; }
        if (detachedLocalOnly) { detachedLocalTests(dir, executable); detachSessionTests(dir, executable); std::cout << "PASS: local initialization and restore after cloud detach/restart\n"; return 0; }
        selectionTests(dir, executable);
        detachTests(dir, executable);
        detachSessionTests(dir, executable);
        auto profile = dir / std::filesystem::u8path("fictional profile 中文");
        relay::CloudLaunch launch; launch.helper = executable; launch.profile = profile; launch.timeout = std::chrono::seconds(3);
        {
            auto missing = launch; missing.helper = dir / "missing-storage-helper";
            bool explained = false;
            try { relay::CloudStorage storage(ns, missing); }
            catch (const std::exception &e) { explained = std::string(e.what()).find("安装包不完整") != std::string::npos; }
            need(explained, "missing helper was reported as an unavailable cloud vault");
        }
        {
            auto enrollment = launch; enrollment.profile = dir / "enrollment"; mode(enrollment.profile, "normal"); unsigned questions = 0;
            auto ask = [&](const relay::EnrollmentQuestion &q) { ++questions;
                if (q.kind == 1) return std::string("opened");
                need(q.exclusive && q.required && q.choices.size() == 2);
                return std::string(q.kind == 4 ? "save" : "choice2"); };
            relay::CloudStorage::enrollProfile(ns, Bytes{'{','}'}, ask, enrollment); need(questions == 3, "enrollment skipped review");
            questions = 0; relay::CloudStorage::updateProfile(ns, Bytes{'{','}'}, ask, enrollment); need(questions == 3, "maintenance skipped review");
            for (const auto *invalid : {"bad-url", "bad-kind", "bad-flags"}) {
                mode(enrollment.profile, invalid); rejects([&] { relay::CloudStorage::enrollProfile(ns, Bytes{'{','}'}, ask, enrollment); });
            }
            mode(enrollment.profile, "waiting"); unsigned polls = 0; enrollment.canceled = [&] { return ++polls > 20; };
            auto start = std::chrono::steady_clock::now(); rejects([&] { relay::CloudStorage::enrollProfile(ns, Bytes{'{','}'}, ask, enrollment); });
            need(std::chrono::steady_clock::now() - start < std::chrono::seconds(3), "enrollment cancellation blocked");
        }
        mode(profile, "normal");
        rejects([&] { (void)relay::Vault::openCloud(ns, password, launch); });
        rejects([&] { (void)relay::Vault::createCloud(ns, L"short", launch); });
        need(!std::filesystem::exists(withSuffix(profile, ".snapshot")));
        {
            // Deliberately inheritable handle/descriptor: the launcher must not pass it on.
#ifdef _WIN32
            SECURITY_ATTRIBUTES attr{sizeof(attr), nullptr, TRUE}; HANDLE sentinel = CreateEventW(&attr, TRUE, FALSE, nullptr); need(sentinel != nullptr);
            Bytes handle(8); put(handle, 0, reinterpret_cast<uintptr_t>(sentinel), 8);
#else
            int fds[2]; need(::pipe(fds) == 0); ::fcntl(fds[0], F_SETFL, O_NONBLOCK);
            Bytes handle(8); put(handle, 0, static_cast<uint64_t>(fds[1]), 8);
#endif
            write(withSuffix(profile, ".sentinel"), handle);
            {
                auto vault = relay::Vault::createCloud(ns, password, launch);
#ifdef _WIN32
                need(WaitForSingleObject(sentinel, 0) == WAIT_TIMEOUT, "unrelated handle inherited");
#else
                char byte = 0; need(::read(fds[0], &byte, 1) < 0, "unrelated descriptor inherited");
#endif
                { auto other = relay::Vault::openCloud(ns, password, launch); need(other->accounts().empty(), "idle vault retained its lease"); }
                healthyReply(authorize(*vault, true)); need(vault->revision() == 2 && vault->accounts().size() == 1);
                healthyReply(authorize(*vault, false)); need(vault->accounts()[0].counter == 1);
                vault->exportBackup(dir / "export.pf2bak", password);
            }
#ifdef _WIN32
            CloseHandle(sentinel);
#else
            ::close(fds[0]); ::close(fds[1]);
#endif
            std::filesystem::remove(withSuffix(profile, ".sentinel"));
        }
        rejects([&] { (void)relay::Vault::openCloud(ns, L"wrong-cloud-password", launch); });
        rejects([&] { (void)relay::Vault::openCloud("1123456789abcdef0123456789abcdef", password, launch); });
        {
            auto vault = relay::Vault::openCloud(ns, password, launch); need(vault->accounts()[0].counter == 1);
            auto reply = authorize(*vault, false, [&] { mode(profile, "lost"); });
            need(reply == Bytes{0x7f} && !vault->healthy(), "lost ownership allowed signature");
            mode(profile, "normal"); rejects([&] { (void)vault->accounts(); }); // Fault never self-heals.
        }
        {
            auto vault = relay::Vault::openCloud(ns, password, launch); need(vault->accounts()[0].counter == 1);
            auto reply = authorize(*vault, false, [&] { mode(profile, "ambiguous"); });
            need(reply == Bytes{0x7f} && !vault->healthy(), "ambiguous commit allowed response");
        }
        mode(profile, "normal");
        { auto vault = relay::Vault::openCloud(ns, password, launch); need(vault->accounts()[0].counter == 2, "ack loss lost durable counter"); }
        {
            // A coordinator/storage rollback to an older head is refused once this host saw a newer one.
            auto guarded = launch; guarded.highWater = dir / "rollback.generation";
            auto older = read(withSuffix(profile, ".snapshot"));
            { auto vault = relay::Vault::openCloud(ns, password, guarded); healthyReply(authorize(*vault, false)); }
            auto newer = read(withSuffix(profile, ".snapshot"));
            write(withSuffix(profile, ".snapshot"), older);
            rejects([&] { (void)relay::Vault::openCloud(ns, password, guarded); });
            (void)relay::Vault::openCloud(ns, password, launch); // unguarded callers are unaffected
            write(withSuffix(profile, ".snapshot"), newer);
            { auto vault = relay::Vault::openCloud(ns, password, guarded); need(vault->accounts()[0].counter == 3, "rollback guard lost counter"); }
        }
        for (const auto *bad : {"reject", "wrong-generation"}) {
            auto vault = relay::Vault::openCloud(ns, password, launch);
            need(authorize(*vault, false, [&] { mode(profile, bad); }) == Bytes{0x7f} && !vault->healthy());
            mode(profile, "normal");
        }
        {
            auto vault = relay::Vault::openCloud(ns, password, launch);
            relay::Authenticator auth(*vault, [&](const auto &, const auto &) {
                mode(profile, "final-check-lost"); return relay::Decision{true, {}};
            });
            Bytes wire{RELAY_CTAP_EXACT_QUERY}; auto query = ctap::encode(V::map({V::integer(1), V::string("cloud.invalid"), V::integer(2), V::string("fictional")}));
            wire.insert(wire.end(), query.begin(), query.end());
            need(auth.exchange(wire, operation()) == Bytes{0x7f} && !vault->healthy(), "read-only response escaped final ownership check");
            mode(profile, "normal");
        }
        {
            need(test::run(executable, {"--crash-parent", profile.u8string()}, 10000) == 0, "crash fixture failed");
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3); bool released = false;
            do {
                try { platform::FileLock probe(withSuffix(profile, ".held"), platform::FileLock::Mode::OpenExisting, "held"); released = true; break; }
                catch (...) { sleepMs(10); }
            } while (std::chrono::steady_clock::now() < deadline);
            need(released, "parent crash orphaned storage child");
        }
        for (const auto *bad : {"reserved", "sequence", "operation", "oversize", "bad-status", "short", "lost"}) {
            relay::CloudStorage storage(ns, launch); (void)storage.open(false); mode(profile, bad);
            rejects([&] { storage.check(); }); mode(profile, "normal"); rejects([&] { storage.check(); });
        }
        for (bool writing : {false, true}) {
            relay::CloudStorage storage(ns, launch); auto snapshot = storage.open(false);
            mode(profile, writing ? "stall-write" : "stall"); unsigned polls = 0;
            storage.cancellation([&] { return ++polls > 10; }); auto start = std::chrono::steady_clock::now();
            rejects([&] { if (writing) { Bytes big(2 * 1024 * 1024); memcpy(big.data(), "PF2BAK01", 8); storage.commit(snapshot.generation, big); } else storage.check(); });
            need(std::chrono::steady_clock::now() - start < std::chrono::seconds(2), "pipe cancellation blocked"); mode(profile, "normal");
        }
        {
            bool canceled = false; auto options = launch; options.canceled = [&] { return canceled; };
            relay::CloudStorage storage(ns, options); (void)storage.open(false); canceled = true;
            storage.cancellation([] { return false; }); // Per-request callback must never override manager cancellation.
            rejects([&] { storage.check(); }); canceled = false; rejects([&] { storage.check(); });
        }
        {
            launch.timeout = std::chrono::milliseconds(150); relay::CloudStorage storage(ns, launch); (void)storage.open(false); mode(profile, "stall");
            auto start = std::chrono::steady_clock::now(); rejects([&] { storage.check(); });
            need(std::chrono::steady_clock::now() - start < std::chrono::seconds(2), "pipe timeout blocked");
        }
        std::cout << "cloud pipe, encryption, ownership, acknowledgement loss and cancellation tests passed\n"; return 0;
    } catch (const std::exception &e) { if (args.empty() || args[0] != "--pipe") std::cerr << e.what() << '\n'; return 1; }
}
// Actual helper integration entry point: called only by the Go TLS/RBAC fixture
// (tools/relay-storage native test) with --real-ACTION NAMESPACE PROFILE HELPER OUTPUT.
static int realHelper(const std::vector<std::string> &args) {
    auto profile = std::filesystem::absolute(std::filesystem::u8path(args[2]));
    need(inTestDirectory(profile, "pf2-cloud-interop-"));
    relay::CloudLaunch launch; launch.profile = profile; launch.helper = std::filesystem::absolute(std::filesystem::u8path(args[3]));
    const std::string &action = args[0]; auto selected = withSuffix(profile, ".selection");
    auto destination = std::filesystem::absolute(std::filesystem::u8path(args[4])); need(destination.parent_path() == profile.parent_path());
    if (action.rfind("--real-maintain-", 0) == 0) {
        relay::ProfileMaintenance patch; auto before = read(profile); need(!before.empty());
        bool cancel = action == "--real-maintain-cancel";
        if (cancel) patch.action = "oauth";
        else if (action == "--real-maintain-webdav") { patch.action = "webdav"; patch.secret = L"fictional-webdav-\"\\中文-password"; }
        else {
            need(action == "--real-maintain-coordinator"); patch.action = "coordinator";
            std::ifstream input(destination); std::string ignored; need(bool(std::getline(input, ignored)) && bool(std::getline(input, patch.coordinator.coordinator)));
            patch.coordinator.ca = profile.parent_path() / "ca.pem"; patch.coordinator.certificate = profile.parent_path() / "client.pem";
            patch.coordinator.privateKey = profile.parent_path() / "client.key";
        }
        auto json = relay::profileMaintenancePatch(patch); bool asked = false;
        auto perform = [&] { relay::CloudStorage::updateProfile(args[1], json, [&](const relay::EnrollmentQuestion &q) -> std::string {
            asked = true;
            if (cancel) { need(q.kind == 1); throw std::runtime_error("Synthetic reauthorization canceled before browser"); }
            need(q.kind == 4 && q.name == "save_profile" && q.value == "cancel"); return "save";
        }, launch); };
        if (cancel) rejects(perform); else perform();
        secureZero(json.data(), json.size()); need(asked);
        need(cancel ? read(profile) == before : read(profile) != before); return 0;
    }
    if (action == "--real-enroll-cancel") {
        relay::OAuthProfile config; config.nameSpace = args[1]; config.provider = "drive";
        std::ifstream input(destination); std::string ignored; need(bool(std::getline(input, ignored)) && bool(std::getline(input, config.coordinator)));
        config.root = "pico-fido2"; config.clientId = "fictional-desktop-client"; config.clientSecret = L"fictional-desktop-secret"; config.scopeOrRegion = "drive.file";
        config.ca = profile.parent_path() / "ca.pem"; config.certificate = profile.parent_path() / "client.pem"; config.privateKey = profile.parent_path() / "client.key";
        auto json = relay::oauthProfileSetup(config); bool browser = false;
        rejects([&] { relay::CloudStorage::enrollProfile(config.nameSpace, json, [&](const relay::EnrollmentQuestion &question) -> std::string {
            need(question.kind == 1 && question.value.rfind("https://accounts.google.com/", 0) == 0); browser = true;
            throw std::runtime_error("Synthetic operator canceled before opening a browser");
        }, launch); });
        secureZero(json.data(), json.size()); need(browser && !std::filesystem::exists(profile)); return 0;
    }
    if (action == "--real-setup") {
        relay::WebDavProfile config; config.nameSpace = args[1];
        std::ifstream input(destination); need(bool(std::getline(input, config.url)) && bool(std::getline(input, config.coordinator)));
        config.root = "pico-fido2"; config.user = "fixture"; config.password = L"fictional-webdav-\"\\中文-password";
        config.ca = profile.parent_path() / "ca.pem"; config.certificate = profile.parent_path() / "client.pem";
        config.privateKey = profile.parent_path() / "client.key"; config.providerCa = profile.parent_path() / "dav-ca.pem";
        auto json = relay::webDavProfileSetup(config); relay::CloudStorage::saveProfile(config.nameSpace, json, launch);
        secureZero(json.data(), json.size()); return 0;
    }
    relay::Storage storage(selected, launch);
    if (action == "--real-local") {
        storage.initializeLocal(); auto &vault = storage.open(); healthyReply(authorize(vault, true)); healthyReply(authorize(vault, false));
        vault.exportBackup(destination, password); std::cout << vault.namespaceId() << '\n'; return 0;
    }
    if (action == "--real-migrate-failure") {
        rejects([&] { storage.migrateCloud(password); }); need(storage.choice().kind == relay::StorageKind::MovingToCloud);
        rejects([&] { relay::Vault old(selected / local); }); std::cout << "migration pending\n"; return 0;
    }
    if (action == "--real-resume") {
        storage.resume(password); need(storage.choice().kind == relay::StorageKind::Cloud);
        auto &recovered = storage.open(password); need(recovered.accounts().size() == 1 && recovered.accounts()[0].counter == 1);
        recovered.exportBackup(destination, password); rejects([&] { relay::Vault old(selected / local); });
        std::cout << "migration recovered\n"; return 0;
    }
    need(action == "--real-init" || action == "--real-open" || action == "--real-failure" || action == "--real-wait");
    bool create = action == "--real-init";
    if (create) storage.initializeCloud(args[1], password);
    need(storage.choice().kind == relay::StorageKind::Cloud && storage.choice().nameSpace == args[1]);
    auto vault = &storage.open(password);
    need(vault->accounts().size() == (create ? 0 : 1));
    auto previousCounter = create ? 0u : vault->accounts().at(0).counter;
    auto response = authorize(*vault, create, [&] {
        if (action == "--real-wait") { std::cout << "APPROVAL\n" << std::flush; std::string answer; need(bool(std::getline(std::cin, answer)) && answer == "continue"); }
    });
    if (action == "--real-failure") {
        need(response == Bytes{0x7f} && !vault->healthy()); rejects([&] { (void)vault->accounts(); });
        std::cout << "native cloud failure closed\n"; return 0;
    }
    healthyReply(response);
    need(vault->accounts().size() == 1 && vault->accounts()[0].counter == (create ? 0u : previousCounter + 1));
    vault->exportBackup(destination, password); std::cout << "native cloud vault ok\n"; return 0;
}
