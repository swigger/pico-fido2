#include "relay_authenticator.h"
#include "test_process.h"
#include "cli.h"
#include "credentials.h"
#include "relay_transport.h"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <thread>

using V = ctap::Value;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> static void rejects(F f) { bool failed = false; try { f(); } catch (...) { failed = true; } check(failed, "accepted invalid state"); }
static V flag(bool b) { V v; v.type = V::Boolean; v.number = b; return v; }
static V array(std::initializer_list<V> items) { V v; v.type = V::Array; v.items = items; return v; }
static Bytes wire(uint8_t cmd, const V &v) { Bytes b{cmd}; auto encoded = ctap::encode(v); b.insert(b.end(), encoded.begin(), encoded.end()); return b; }
static V decode(const Bytes &b) { check(b.size() > 1 && b[0] == 0, "CTAP operation failed"); return ctap::decode(Bytes(b.begin() + 1, b.end())); }
static Bytes file(const std::filesystem::path &p) { std::ifstream f(p, std::ios::binary); return Bytes((std::istreambuf_iterator<char>(f)), {}); }
static void overwrite(const std::filesystem::path &p, const Bytes &b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char *>(b.data()), b.size()); check(f.good(), "test file write");
}
static relay::Operation operation() {
    relay::Operation op; op.deviceSerial = "0123456789abcdef"; auto r = randomBytes(16);
    std::copy(r.begin(), r.end(), op.requestId.begin()); op.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30); return op;
}
static V make(const std::string &rp, uint8_t user = 1, bool resident = true) {
    return V::map({V::integer(1), V::blob(Bytes(32, 0x5a)), V::integer(2), V::map({V::string("id"), V::string(rp)}),
        V::integer(3), V::map({V::string("id"), V::blob({user}), V::string("name"), V::string("alice@example.com"),
            V::string("displayName"), V::string("Alice" + std::to_string(user))}),
        V::integer(4), array({V::map({V::string("type"), V::string("public-key"), V::string("alg"), V::integer(-7)})}),
        V::integer(7), V::map({V::string("rk"), flag(resident)})});
}
static V descriptor(const Bytes &id, const std::string &type = "public-key") { return V::map({V::string("type"), V::string(type), V::string("id"), V::blob(id)}); }
static V assertion(const std::string &rp, const Bytes &id = {}) {
    auto v = V::map({V::integer(1), V::string(rp), V::integer(2), V::blob(Bytes(32, 0x27))});
    if (!id.empty()) { v.items.push_back(V::integer(3)); v.items.push_back(array({descriptor(id)})); } return v;
}
static Bytes publicBlob(const V &cose) {
    check(cose.at(1).number == 2 && cose.at(3).number == -7 && cose.at(-1).number == 1, "COSE algorithm");
    auto x = cose.at(-2).bytes, y = cose.at(-3).bytes; check(x.size() == 32 && y.size() == 32, "COSE coordinate length");
    Bytes b(65); b[0] = 4; memcpy(b.data() + 1, x.data(), 32); memcpy(b.data() + 33, y.data(), 32); return b;
}
static bool verify(const Bytes &pub, Bytes message, const Bytes &der) {
    check(der.size() >= 8 && der[0] == 0x30 && der[1] == der.size() - 2, "DER signature sequence");
    Bytes raw(64); size_t pos = 2;
    for (size_t offset : {size_t(0), size_t(32)}) {
        check(pos + 2 < der.size() && der[pos++] == 0x02, "DER integer tag"); size_t length = der[pos++];
        check(length && length <= 33 && pos + length <= der.size() && !(der[pos] & 0x80), "DER integer bounds");
        if (length > 1 && der[pos] == 0) { check(der[pos + 1] & 0x80, "DER redundant sign padding"); ++pos; --length; }
        check(length <= 32, "DER integer too big");
        memcpy(raw.data() + offset + 32 - length, der.data() + pos, length); pos += length;
    }
    check(pos == der.size(), "DER trailing bytes");
    return crypto::verifyP256(pub, hash(message), raw);
}
static void crossProcessLock(const std::filesystem::path &path) {
    check(test::run(platform::executablePath(), {"--probe-lock", path.u8string()}, 10000) == 0, "another process opened locked vault");
}
int main(int argc, char **argv) {
    auto args = commandLine(argc, argv);
    if (args.size() == 2 && args[0] == "--probe-lock") {
        try { relay::Vault v(std::filesystem::u8path(args[1])); return 1; } catch (...) { return 0; }
    }
    auto n = randomBytes(12); auto dir = std::filesystem::temp_directory_path() / ("pf2-auth-test-" + hex(n.data(), n.size()));
    auto path = dir / "vault.dpapi";
    try {
        rejects([&] { relay::Vault missing(path); }); relay::Vault::create(path); rejects([&] { relay::Vault::create(path); });
        Bytes credential, pub, initialCipher;
        {
            relay::Vault vault(path); check(vault.accounts().empty() && vault.revision() == 1, "empty initialized vault");
            {
                // Selection probes must not invoke any approval callback, even
                // one that would deny them. They cannot change the vault.
                unsigned probes = 0;
                relay::Authenticator probe(vault, [&](const auto &, const auto &) { ++probes; return relay::Decision{}; });
                auto before = vault.revision();
                for (uint8_t command : {uint8_t(1), uint8_t(2)}) {
                    auto request = command == 1 ? make("webauthn.io") : assertion("webauthn.io");
                    request.items.push_back(V::integer(command == 1 ? 8 : 6)); request.items.push_back(V::blob({}));
                    check(probe.exchange(wire(command, request), operation()) == Bytes{0x35}, "phone presence probe rejected");
                }
                check(probes == 0 && vault.revision() == before && vault.accounts().empty(), "presence probe requested consent or modified vault");
            }
            rejects([&] { relay::Vault second(path); }); crossProcessLock(path);
            int approved = 0; relay::Approval observed;
            relay::Authenticator auth(vault, [&](const auto &a, const auto &) {
                ++approved; observed = a; return relay::Decision{true, a.accounts.empty() ? Bytes{} : a.accounts.front().credentialId};
            });
            auto op = operation(); auto req = wire(1, make("example.com"));
            auto created = decode(auth.exchange(req, op));
            check(approved == 1 && observed.rp == "example.com" && observed.requestId == op.requestId && observed.requestHash == hash(req), "approval binding");
            check(created.at(1).text == "packed", "self attestation format");
            auto data = created.at(2).bytes;
            check(data.size() > 87 && data[32] == 0x41 && data[33] == 0 && data[36] == 0 && data[53] == 0 && data[54] == 32, "registration authenticator data");
            auto expectedHash = hash(Bytes{'e','x','a','m','p','l','e','.','c','o','m'});
            check(std::equal(expectedHash.begin(), expectedHash.end(), data.begin()), "RP hash");
            check(std::all_of(data.begin() + 37, data.begin() + 53, [](auto b) { return !b; }), "anonymous AAGUID");
            credential.assign(data.begin() + 55, data.begin() + 87);
            pub = publicBlob(ctap::decode(Bytes(data.begin() + 87, data.end())));
            auto signedData = data; signedData.insert(signedData.end(), 32, 0x5a);
            check(verify(pub, signedData, created.at(3).at("sig").bytes), "registration signature invalid");
            signedData.back() ^= 1; check(!verify(pub, signedData, created.at(3).at("sig").bytes), "signature accepted altered client hash");
            check(vault.accounts().size() == 1 && vault.contains("example.com", "alice@example.com") &&
                !vault.contains("example.com.evil", "alice@example.com") && !vault.contains("example.com", "alice"), "exact account query");
            rejects([&] { vault.contains("example.com", ""); });
            {
                int queries = 0; relay::Approval scope;
                relay::Authenticator query(vault, [&](const auto &a, const auto &) { ++queries; scope = a; return relay::Decision{true, {}}; });
                auto queryRequest = [](const std::string &rp, const std::string &user) {
                    return wire(RELAY_CTAP_EXACT_QUERY, V::map({V::integer(1), V::string(rp), V::integer(2), V::string(user)}));
                };
                auto before = vault.revision(); auto context = operation(); auto bytes = queryRequest("example.com", "alice@example.com");
                check(query.exchange(bytes, context) == Bytes({0, 0xa1, 1, 0xf5}), "exact query must return only boolean true");
                check(scope.operation == RELAY_CTAP_EXACT_QUERY && scope.rp == "example.com" && scope.queryUserName == "alice@example.com" &&
                    scope.accounts.empty() && scope.requestHash == hash(bytes) && scope.requestId == context.requestId, "query consent scope leaked or mismatched");
                for (const auto &missing : {queryRequest("example.com", "alice"), queryRequest("example.com.evil", "alice@example.com"), queryRequest("example.com", "ALICE@example.com")})
                    check(query.exchange(missing, operation()) == Bytes({0, 0xa1, 1, 0xf4}), "query suffix/prefix/case match accepted");
                check(queries == 4 && vault.revision() == before, "query reused approval or modified storage");
                check(query.exchange(queryRequest("example.com", ""), operation()) == Bytes{2} && queries == 4, "empty account query accepted");
                check(query.exchange(wire(RELAY_CTAP_EXACT_QUERY, V::map({V::integer(1), V::string("example.com")})), operation()) == Bytes{2}, "partial query accepted");
                relay::Authenticator refusal(vault, [](const auto &, const auto &) { return relay::Decision{}; });
                check(refusal.exchange(bytes, operation()) == Bytes{0x27}, "query denial leaked a result");
                bool canceled = false; auto cancelContext = operation(); cancelContext.canceled = [&] { return canceled; };
                relay::Authenticator canceledQuery(vault, [&](const auto &, const auto &) { canceled = true; return relay::Decision{true, {}}; });
                check(canceledQuery.exchange(bytes, cancelContext) == Bytes{0x2d}, "canceled query leaked a result");
            }
            auto signedIn = decode(auth.exchange(wire(2, assertion("example.com", credential)), operation()));
            auto authBytes = signedIn.at(2).bytes; check(authBytes.size() == 37 && authBytes[32] == 1 && authBytes.back() == 1, "assertion flags/counter");
            authBytes.insert(authBytes.end(), 32, 0x27);
            check(verify(pub, authBytes, signedIn.at(3).bytes), "assertion signature invalid");
            check(!signedIn.find(4) && approved == 2 && vault.accounts()[0].counter == 1, "allowList privacy/commit");
            auto info = decode(auth.exchange({4}, operation()));
            check(info.at(1).items[0].text == "FIDO_2_0" && !info.at(4).find("uv") && !info.at(4).at("clientPin").number && info.at(6).items[0].number == 2, "PIN capabilities or built-in verification incorrect");
            auto generation = vault.revision();
            check(auth.exchange(wire(2, assertion("wrong.example", credential)), operation()) == Bytes{0x2e}, "RP isolation");
            for (auto cmd : {0x0a, 0x41}) check(auth.exchange({static_cast<uint8_t>(cmd)}, operation()) == Bytes{0x2e}, "enumeration leaked");
            check(auth.exchange({8}, operation()) == Bytes{0x30}, "unexpected next-assertion state");
            check(info.at(5).number == 1976 && auth.exchange(Bytes(1977, 0), operation()) == Bytes{3}, "advertised beyond firmware USB capacity");
            for (auto cmd : {0x07, 0x0d, 0x40}) check(auth.exchange({static_cast<uint8_t>(cmd)}, operation()) == Bytes{0x01}, "unsupported command executed");
            check(auth.exchange({6}, operation()) == Bytes{0x12}, "missing ClientPIN parameters accepted");
            relay::Authenticator denied(vault, [](const auto &, const auto &) { return relay::Decision{}; });
            check(denied.exchange(wire(1, make("denied.example")), operation()) == Bytes{0x27}, "registration denial ignored");
            check(denied.exchange(wire(2, assertion("example.com")), operation()) == Bytes{0x27}, "assertion denial ignored");
            relay::Authenticator wrongSelection(vault, [](const auto &, const auto &) { return relay::Decision{true, Bytes(32, 0xff)}; });
            check(wrongSelection.exchange(wire(2, assertion("example.com")), operation()) == Bytes{0x27}, "arbitrary selected credential");
            auto expired = operation(); expired.deadline = std::chrono::steady_clock::now();
            check(auth.exchange(req, expired) == Bytes{0x2f}, "expired request");
            auto canceled = operation(); bool cancel = false; canceled.canceled = [&] { return cancel; };
            relay::Authenticator cancelAtApproval(vault, [&](const auto &, const auto &) { cancel = true; return relay::Decision{true, credential}; });
            check(cancelAtApproval.exchange(req, canceled) == Bytes{0x2d}, "cancellation after approval");
            check(vault.revision() == generation && approved == 3, "rejected operations modified vault or reused approval");
            std::promise<void> pending, resume; auto ready = resume.get_future();
            relay::Authenticator waiting(vault, [&](const auto &, const auto &) { pending.set_value(); ready.wait(); return relay::Decision{}; });
            auto worker = std::async(std::launch::async, [&] { return waiting.exchange(req, operation()); });
            pending.get_future().wait(); auto busy = auth.exchange(req, operation()); resume.set_value();
            check(busy == Bytes{6} && worker.get() == Bytes{0x27}, "concurrent operation inherited approval");
            auto excluded = make("example.com"); excluded.items.push_back(V::integer(5)); excluded.items.push_back(array({descriptor(credential)}));
            check(auth.exchange(wire(1, excluded), operation()) == Bytes{0x19} && approved == 4 && vault.revision() == generation, "excludeList consent or scope");
            auto requiredUv = make("uv.example"); for (size_t i = 0; i < requiredUv.items.size(); i += 2)
                if (requiredUv.items[i].number == 7) requiredUv.items[i + 1] = V::map({V::string("uv"), flag(true)});
            check(auth.exchange(wire(1, requiredUv), operation()) == Bytes{0x2b}, "UV fabricated from consent");
            check(auth.exchange({1, 0xa2, 1, 0, 1, 0}, operation()) == Bytes{0x12}, "duplicate CBOR keys");
            check(auth.exchange({1, 0xa0}, operation()) == Bytes{0x14}, "missing required field");
            auto other = decode(auth.exchange(wire(1, make("elsewhere.example")), operation()));
            (void)other; decode(auth.exchange(wire(1, make("example.com", 2)), operation()));
            auto resident = decode(auth.exchange(wire(2, assertion("example.com")), operation()));
            check(resident.at(4).items.size() == 2 && resident.at(4).at("id").bytes == Bytes{1} &&
                observed.accounts.size() == 2 && !resident.find(5), "discoverable selection leaked names/count");
            auto unsupported = assertion("example.com"); unsupported.items.push_back(V::integer(3));
            unsupported.items.push_back(array({descriptor(credential, "unknown-type")}));
            check(auth.exchange(wire(2, unsupported), operation()) == Bytes{0x2e}, "unknown descriptor broadened allowList");
            decode(auth.exchange(wire(1, make("example.com", 1)), operation()));
            check(vault.accounts().size() == 3 && auth.exchange(wire(2, assertion("example.com", credential)), operation()) == Bytes{0x2e}, "resident replacement");
            auto nonresident = decode(auth.exchange(wire(1, make("nonresident.example", 1, false)), operation()));
            auto nonData = nonresident.at(2).bytes; Bytes nonId(nonData.begin() + 55, nonData.begin() + 87);
            check(auth.exchange(wire(2, assertion("nonresident.example")), operation()) == Bytes{0x2e}, "nonresident appeared in discovery");
            decode(auth.exchange(wire(2, assertion("nonresident.example", nonId)), operation()));
            initialCipher = file(path); const std::string name = "alice@example.com";
            check(std::search(initialCipher.begin(), initialCipher.end(), name.begin(), name.end()) == initialCipher.end(), "plaintext account on disk");
        }
        {
            relay::Vault restored(path); check(restored.accounts().size() == 4 && restored.accounts().back().counter == 1, "persistent credentials/counter");
            relay::Authenticator auth(restored, [](const auto &a, const auto &) { return relay::Decision{true, a.accounts.front().credentialId}; });
            Bytes failed;
            { test::BlockReplace blocker(path); failed = auth.exchange(wire(1, make("apple.com")), operation()); }
            check(failed == Bytes{0x7f} && !restored.healthy() && file(path) == initialCipher, "failed save released signature or modified snapshot");
            check(auth.exchange({4}, operation()) == Bytes{0x7f}, "continued after ambiguous commit");
        }
        { relay::Vault restored(path); check(restored.accounts().size() == 4, "old vault not preserved by write failure"); }
        {
            relay::Vault restored(path);
            relay::Authenticator auth(restored, [](const auto &a, const auto &) { return relay::Decision{true, a.accounts.front().credentialId}; });
            Bytes failed;
            { test::BlockReplace blocker(path); failed = auth.exchange(wire(2, assertion("example.com")), operation()); }
            check(failed == Bytes{0x7f} && !restored.healthy() && file(path) == initialCipher, "signature released before durable counter");
        }
        auto otherPath = dir / "other.dpapi"; relay::Vault::create(otherPath);
        overwrite(path, file(otherPath)); rejects([&] { relay::Vault swapped(path); });
        auto corrupt = initialCipher; corrupt.back() ^= 1; overwrite(path, corrupt); rejects([&] { relay::Vault tampered(path); });
        overwrite(path, initialCipher);
        {
            relay::Vault restored(path);
            relay::Authenticator auth(restored, [](const auto &a, const auto &) { return relay::Decision{true, a.accounts.front().credentialId}; });
            overwrite(path, corrupt);
            check(auth.exchange(wire(1, make("stale.example")), operation()) == Bytes{0x7f} && file(path) == corrupt, "overwrote unexpected disk state");
        }
        std::filesystem::remove(path); rejects([&] { relay::Vault missing(path); }); rejects([&] { relay::Vault::create(path); });
        for (const auto &entry : std::filesystem::directory_iterator(dir)) std::filesystem::remove(entry.path());
        std::filesystem::remove(dir);
        puts("PASS: real ES256 CTAP signatures, request approval/cancel, RP isolation, OS data protection, exclusive process lock and fail-closed durable commits"); return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s (test directory %s)\n", e.what(), dir.u8string().c_str()); return 1; }
}
