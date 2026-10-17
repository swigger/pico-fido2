#include "relay_server.h"
#include "relay_transport.h"
#include "credentials.h"
#include "relay_settings.h"
#include <cstring>
#include <atomic>
#include <future>
#include <thread>
#include <fstream>
#include <cstdio>

using V = ctap::Value;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> static void rejects(F f) { bool rejected = false; try { f(); } catch (...) { rejected = true; } check(rejected, "invalid network operation accepted"); }
static relay::Deadline deadline() { return std::chrono::steady_clock::now() + std::chrono::seconds(5); }
static Bytes wire(uint8_t cmd, const V &value) { Bytes b{cmd}; auto payload = ctap::encode(value); b.insert(b.end(), payload.begin(), payload.end()); return b; }
static V array(std::initializer_list<V> values) { V v; v.type = V::Array; v.items = values; return v; }
static Bytes registration() {
    return wire(1, V::map({V::integer(1), V::blob(Bytes(32, 0x51)), V::integer(2), V::map({V::string("id"), V::string("relay-test.invalid")}),
        V::integer(3), V::map({V::string("id"), V::blob({1}), V::string("name"), V::string("relay-test")}),
        V::integer(4), array({V::map({V::string("type"), V::string("public-key"), V::string("alg"), V::integer(-7)})})}));
}
struct Client {
    relay::Socket socket;
    std::unique_ptr<relay::Tls> tls;
    relay_frame_header_t binding{};
    static constexpr char serial[] = "0123456789ABCDEF";
    // The client is the device's view: it trusts only servers issued by `controller`.
    Client(uint16_t port, const Key &controller) : Client(relay::Socket::connect("127.0.0.1", port, deadline(), {}), controller) {}
    Client(relay::Socket connection, const Key &controller) : socket(std::move(connection)) {
        tls = std::make_unique<relay::Tls>(socket, controller.pub()); tls->handshake(deadline(), {});
    }
    void request(const Bytes &body, const Key &device, bool mismatchedSerial = false) {
        uint8_t challenge[RELAY_REQUEST_CHALLENGE_SIZE], nonce[32], context[RELAY_REQUEST_CONTEXT_SIZE];
        tls->read(challenge, sizeof(challenge), deadline(), {});
        check(relay_request_challenge_parse(challenge, sizeof(challenge), nonce), "request challenge");
        relay_request_header_t h{}; memcpy(h.serial, serial, 16); if (mismatchedSerial) h.serial[0] = 'f';
        memset(h.boot_id, 0x42, sizeof(h.boot_id));
        auto id = randomBytes(16); memcpy(h.request_id, id.data(), 16); h.length = static_cast<uint16_t>(body.size());
        memcpy(binding.request_id, id.data(), 16); auto digest = hash(body); memcpy(binding.request_hash, digest.data(), 32);
        check(relay_request_context(&h, nonce, binding.request_hash, context), "request context");
        auto signature = device.sign(Bytes(context, context + sizeof(context))); memcpy(h.signature, signature.data(), 64);
        uint8_t header[RELAY_REQUEST_HEADER_SIZE]; check(relay_request_encode(&h, header), "request header");
        // Deliberately fragment both headers and application data across records.
        for (size_t pos = 0; pos < sizeof(header); pos += 7) tls->write(header + pos, std::min<size_t>(7, sizeof(header) - pos), deadline(), {});
        for (size_t pos = 0; pos < body.size(); pos += 11) tls->write(body.data() + pos, std::min<size_t>(11, body.size() - pos), deadline(), {});
    }
    void cancel(bool wrongHash = false) {
        auto h = binding; h.type = RELAY_FRAME_CANCEL; h.length = 0; if (wrongHash) h.request_hash[0] ^= 1;
        uint8_t header[RELAY_FRAME_HEADER_SIZE]; check(relay_frame_encode(&h, header), "cancel frame"); tls->write(header, sizeof(header), deadline(), {});
    }
    Bytes response(const std::function<void()> &keepalive = {}) {
        for (unsigned count = 0; count < 40; ++count) {
            uint8_t header[RELAY_FRAME_HEADER_SIZE]; tls->read(header, sizeof(header), deadline(), {});
            relay_frame_header_t h{}; check(relay_frame_decode(header, sizeof(header), &h) &&
                relay_frame_matches(&h, binding.request_id, binding.request_hash), "response request binding");
            Bytes body(h.length); tls->read(body.data(), body.size(), deadline(), {}); check(relay_frame_payload(&h, body.data(), body.size()), "frame payload");
            if (h.type == RELAY_FRAME_RESPONSE) return body;
            check(h.type == RELAY_FRAME_KEEPALIVE, "wrong server frame direction"); if (keepalive) keepalive();
        }
        throw std::runtime_error("too many keepalive frames");
    }
};
static void discoveryScheduling(relay::Vault &vault, const Key &controller) {
    auto device = Key::generate(); std::atomic_bool stop{false};
    relay::Server server(vault, controller, [&](const std::string &serial) {
        return serial == Client::serial ? device->pub() : Bytes{};
    }, {});
    std::promise<std::unique_ptr<relay::Socket>> connected;
    auto running = std::async(std::launch::async, [&] {
        server.run("127.0.0.1", 0, [&] { return stop.load(); }, [&](auto port) {
            // Queue the connection before the accept loop starts, like a USB
            // discovery arriving while the UI/idle cloud refresh is due.
            connected.set_value(std::make_unique<relay::Socket>(relay::Socket::connect("127.0.0.1", port, deadline(), {})));
        }, {}, [] { sleepMs(2500); }); // Slow coordinator/UI maintenance.
    });
    struct Stop { std::atomic_bool &stop; std::future<void> &running;
        ~Stop() { stop = true; if (running.valid()) running.wait(); } } shutdown{stop, running};
    auto connection = connected.get_future().get();
    auto start = std::chrono::steady_clock::now();
    { Client client(std::move(*connection), controller); client.request({4}, *device);
      auto response = client.response(); check(response.size() > 1 && response[0] == 0, "queued discovery GetInfo failed"); }
    auto elapsed = std::chrono::steady_clock::now() - start;
    check(elapsed < std::chrono::seconds(2), "GetInfo blocked behind idle cloud maintenance (Windows discovery timeout)");
    stop = true; running.get();
}
int main() {
    auto random = randomBytes(12); auto dir = std::filesystem::temp_directory_path() / ("pf2-network-test-" + hex(random.data(), random.size()));
    try {
        auto controller = Key::generate(), otherController = Key::generate();
        std::filesystem::create_directories(dir);
        relay::Vault::create(dir / "vault.dpapi");
        {
            relay::Vault vault(dir / "vault.dpapi");
            discoveryScheduling(vault, *controller);
            std::atomic_bool stop{false}, allowed{true}, waiting{false}; std::atomic_int mode{0}, approvals{0};
            auto device = Key::generate();
            trustRelayDevice(Client::serial, device->pub(), dir);
            relay::Server server(vault, *controller,
                [&](const std::string &serial) { return allowed.load() && serial == Client::serial ? relayDeviceKey(serial, dir) : Bytes{}; },
                [&](const auto &a, const auto &op) {
                    ++approvals;
                    if (mode == 2) { waiting = true; while (mode == 2 && !op.canceled()) std::this_thread::sleep_for(std::chrono::milliseconds(5)); waiting = false; }
                    return relay::Decision{mode == 0, a.accounts.empty() ? Bytes{} : a.accounts.front().credentialId};
                });
            std::promise<uint16_t> ready;
            auto running = std::async(std::launch::async, [&] { server.run("127.0.0.1", 0, [&] { return stop.load(); }, [&](auto p) { ready.set_value(p); }); });
            struct Stop { std::atomic_bool &stop; std::future<void> &running; ~Stop() { stop = true; if (running.valid()) running.wait(); } } shutdown{stop, running};
            auto port = ready.get_future().get();
            { Client client(port, *controller); client.request({4}, *device); auto response = client.response(); check(response.size() > 1 && response[0] == 0 && approvals == 0, "TLS GetInfo"); }
            Bytes credential;
            { Client client(port, *controller); client.request(registration(), *device); auto response = client.response();
                check(response.size() > 1 && response[0] == 0, "TLS registration"); auto decoded = ctap::decode(Bytes(response.begin() + 1, response.end()));
                auto data = decoded.at(2).bytes; credential.assign(data.begin() + 55, data.begin() + 87); }
            check(approvals == 1 && vault.accounts().size() == 1, "registration committed without one approval");
            auto request = wire(2, V::map({V::integer(1), V::string("relay-test.invalid"), V::integer(2), V::blob(Bytes(32, 0x62)),
                V::integer(3), array({V::map({V::string("type"), V::string("public-key"), V::string("id"), V::blob(credential)})})}));
            { Client client(port, *controller); client.request(request, *device); auto response = client.response(); check(response.size() > 1 && !response[0], "TLS assertion"); }
            auto query = [&](const std::string &rp, const std::string &user) {
                return ctap::queryRelay([&](const Bytes &body) { Client client(port, *controller); client.request(body, *device); return client.response(); }, rp, user);
            };
            check(query("relay-test.invalid", "relay-test") && !query("relay-test.invalid", "relay") &&
                !query("other.invalid", "relay-test"), "TLS exact query scope");
            check(approvals == 5, "query reused or skipped per-request consent");
            rejects([&] { query("relay-test.invalid", ""); });
            rejects([&] { ctap::queryRelay([](const Bytes &) { return Bytes{0, 0xa1, 1, 1}; }, "relay-test.invalid", "relay-test"); });
            rejects([&] { ctap::queryRelay([](const Bytes &) { return Bytes{0, 0xa2, 1, 0xf5, 2, 0xf5}; }, "relay-test.invalid", "relay-test"); });
            // ClientPIN state must survive separate TLS connections from this
            // device boot. Core protocol crypto is also tested by python-fido2.
            auto call = [&](uint8_t command, const V &params) {
                Client client(port, *controller); client.request(wire(command, params), *device); return client.response();
            };
            auto decode = [&](const Bytes &b) { check(b.size() > 1 && b[0] == 0, "TLS PIN operation failed"); return ctap::decode(Bytes(b.begin() + 1, b.end())); };
            auto peer = decode(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(2)}))).at(1);
            ctap::Agreement own; auto shared = relay::pin::shared(2, own, peer); Bytes padded(64); std::copy_n("test-pin", 8, padded.begin());
            auto encrypted = relay::pin::encrypt(2, shared, padded);
            check(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(3), V::integer(3), own.publicKey(),
                V::integer(4), V::blob(relay::pin::authenticate(2, shared, encrypted)), V::integer(5), V::blob(encrypted)})) == Bytes{0}, "TLS PIN setup");
            auto pinHash = hash(Bytes{'t','e','s','t','-','p','i','n'}); pinHash.resize(16);
            auto beforeLoginApprovals = approvals.load();
            auto issued = decode(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(9), V::integer(3), own.publicKey(),
                V::integer(6), V::blob(relay::pin::encrypt(2, shared, pinHash)), V::integer(9), V::integer(2), V::integer(10), V::string("relay-test.invalid")})));
            auto pinToken = relay::pin::decrypt(2, shared, issued.at(2).bytes);
            auto uvRequest = ctap::decode(Bytes(request.begin() + 1, request.end()));
            uvRequest.items.push_back(V::integer(6)); uvRequest.items.push_back(V::blob(relay::pin::authenticate(2, pinToken, Bytes(32, 0x62))));
            uvRequest.items.push_back(V::integer(7)); uvRequest.items.push_back(V::integer(2));
            check(approvals == beforeLoginApprovals, "TLS PIN token requested approval");
            auto uv = decode(call(2, uvRequest)); check((uv.at(2).bytes[32] & 5) == 5, "TLS PIN did not establish UV plus fresh presence");
            check(approvals == beforeLoginApprovals + 1, "TLS PIN login did not require exactly one approval");
            check(call(2, uvRequest) == Bytes{0x33}, "TLS reused a consumed PIN token");
            // Windows probes with up=false, closes TLS, then sends the same
            // assertion with up=true. Only this exact continuation shares consent.
            auto probeToken = decode(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(9), V::integer(3), own.publicKey(),
                V::integer(6), V::blob(relay::pin::encrypt(2, shared, pinHash)), V::integer(9), V::integer(2), V::integer(10), V::string("relay-test.invalid")})));
            auto probeProof = relay::pin::decrypt(2, shared, probeToken.at(2).bytes);
            auto probeRequest = ctap::decode(Bytes(request.begin() + 1, request.end()));
            V up; up.type = V::Boolean; up.number = 0;
            probeRequest.items.insert(probeRequest.items.end(), {V::integer(5), V::map({V::string("up"), up}),
                V::integer(6), V::blob(relay::pin::authenticate(2, probeProof, Bytes(32, 0x62))), V::integer(7), V::integer(2)});
            auto probeApprovals = approvals.load();
            auto probe = decode(call(2, probeRequest)); check((probe.at(2).bytes[32] & 5) == 4, "TLS preflight presence/UV flags");
            { Client client(port, *controller); client.request({4}, *device); decode(client.response()); }
            probeRequest.items[7].items[1].number = 1;
            auto formal = decode(call(2, probeRequest));
            check((formal.at(2).bytes[32] & 5) == 5 && approvals == probeApprovals + 1, "TLS preflight continuation did not share exactly one approval");
            check(call(2, probeRequest) == Bytes{0x33}, "TLS preflight approval could be replayed");
            auto beforeRegistration = approvals.load();
            auto registerToken = decode(call(6, V::map({V::integer(1), V::integer(2), V::integer(2), V::integer(9), V::integer(3), own.publicKey(),
                V::integer(6), V::blob(relay::pin::encrypt(2, shared, pinHash)), V::integer(9), V::integer(1), V::integer(10), V::string("relay-test.invalid")})));
            auto registerProof = relay::pin::decrypt(2, shared, registerToken.at(2).bytes);
            auto registerBody = registration(); auto registerParams = ctap::decode(Bytes(registerBody.begin() + 1, registerBody.end()));
            registerParams.items.push_back(V::integer(8)); registerParams.items.push_back(V::blob(relay::pin::authenticate(2, registerProof, Bytes(32, 0x51))));
            registerParams.items.push_back(V::integer(9)); registerParams.items.push_back(V::integer(2));
            auto registered = decode(call(1, registerParams));
            check((registered.at(2).bytes[32] & 5) == 5 && approvals == beforeRegistration + 1, "PIN registration did not require exactly one approval");
            auto revision = vault.revision(); auto count = approvals.load();
            rejects([&] { Client c(port, *otherController); }); // server not issued by a paired controller
            rejects([&] { Client c(port, *controller); c.request({4}, *Key::generate()); (void)c.response(); });
            rejects([&] { Client c(port, *controller); c.request({4}, *device, true); (void)c.response(); });
            check(approvals == count && vault.revision() == revision, "unauthorized traffic reached approval/store");
            mode = 1;
            { Client c(port, *controller); c.request(request, *device); check(c.response() == Bytes{0x27}, "operator denial ignored"); }
            mode = 2;
            { Client c(port, *controller); c.request(request, *device); bool sent = false;
                auto response = c.response([&] { if (waiting && !sent) { c.cancel(); sent = true; } }); check(sent && response == Bytes{0x2d}, "CTAP cancel ignored"); }
            { Client c(port, *controller); c.request(request, *device); bool sent = false;
                auto response = c.response([&] { if (waiting && !sent) { c.cancel(true); sent = true; } }); check(sent && response == Bytes{0x2d}, "foreign cancel did not fail closed"); }
            { Client c(port, *controller); c.request(request, *device);
                auto response = c.response([&] { if (waiting) allowed = false; }); check(response == Bytes{0x2d}, "revocation while pending ignored"); }
            allowed = true;
            { Client c(port, *controller); c.request(request, *device);
                auto limit = deadline(); while (!waiting && std::chrono::steady_clock::now() < limit) std::this_thread::sleep_for(std::chrono::milliseconds(5));
                check(waiting, "approval did not become pending"); } // Disconnect during consent.
            auto limit = deadline(); while (waiting && std::chrono::steady_clock::now() < limit) std::this_thread::sleep_for(std::chrono::milliseconds(5));
            check(!waiting && vault.revision() == revision, "canceled/disconnected operation committed");
            mode = 0;
            { Client c(port, *controller); c.request({4}, *device); check(c.response()[0] == 0, "server did not recover after disconnected client"); }
            mode = 2;
            { Client c(port, *controller); c.request(request, *device); bool revoked = false;
                auto response = c.response([&] { if (waiting && !revoked) { forgetRelayDevice(Client::serial, dir); revoked = true; } });
                check(revoked && response == Bytes{0x2d}, "persisted device revocation did not cancel pending approval"); }
            check(vault.revision() == revision, "revocation committed an operation");
            count = approvals.load();
            rejects([&] { Client c(port, *controller); c.request({4}, *device); (void)c.response(); });
            check(approvals == count && vault.revision() == revision, "revoked device reached approval/store");
            stop = true; running.get();
            bool checked = false;
            rejects([&] { server.run("127.0.0.1", 0, [] { return false; }, {}, {}, [&] {
                checked = true; throw std::runtime_error("synthetic lost storage ownership"); }); });
            check(checked, "service did not verify idle storage ownership");
        }
        std::filesystem::remove_all(dir);
        puts("PASS: real TLS loopback registration/assertion, controller-issued server pinning, device-signature rejection, consent/cancel/revocation/disconnect"); return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s (test directory %s)\n", e.what(), dir.u8string().c_str()); return 1; }
}
