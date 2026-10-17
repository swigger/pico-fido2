#include "core.h"
#include "../../shared/relay_setup.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Setup {
    relay_setup_t state{};
    std::unique_ptr<Key> key = Key::generate();
    Bytes persisted{0x42};
    Bytes wire;
    bool authorized = true, failStorage = false, failRandom = false;
    unsigned commits = 0;
    Id tx{};
    Setup() {
        relay_config_t local{};
        wire.resize(RELAY_CONFIG_MAX_SIZE); size_t n = 0;
        check(relay_config_encode(&local, wire.data(), wire.size(), &n) == RELAY_CONFIG_OK, "encode");
        wire.resize(n);
        memcpy(tx.data(), randomBytes(16).data(), 16);
        relay_setup_callbacks_t callbacks{};
        callbacks.user = this;
        callbacks.random = [](void *user, uint8_t *nonce) {
            auto &self = *static_cast<Setup *>(user);
            if (self.failRandom) return false;
            auto b = randomBytes(32); memcpy(nonce, b.data(), b.size()); return true;
        };
        callbacks.verify = [](void *user, const uint8_t *id, const uint8_t *context, size_t length,
                               const uint8_t *wire, size_t size, const uint8_t *sig, const relay_config_t *) {
            auto &self = *static_cast<Setup *>(user);
            if (!self.authorized || memcmp(id, self.key->id().data(), 16)) return false;
            Bytes message(context, context + length); message.insert(message.end(), wire, wire + size);
            auto digest = hash(message);
            return crypto::verifyP256(self.key->pub(), digest, Bytes(sig, sig + 64));
        };
        callbacks.persist = [](void *user, const uint8_t *wire, size_t length) {
            auto &self = *static_cast<Setup *>(user);
            if (self.failStorage) return false;
            self.persisted.assign(wire, wire + length); ++self.commits; return true;
        };
        const uint8_t serial[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
        relay_setup_init(&state, serial, callbacks);
    }
    void begin(uint32_t now = 100) {
        check(relay_setup_begin(&state, tx.data(), wire.size(), now, false), "begin");
        check(relay_setup_chunk(&state, tx.data(), 0, wire.data(), wire.size(), now), "chunk");
    }
    Bytes signature() {
        // Independent construction of the protocol signing input; includes the
        // NUL domain terminator, ASCII serial and little-endian wire length.
        const char domain[] = "pico-fido2 relay setup v1";
        Bytes message(domain, domain + sizeof(domain));
        message.insert(message.end(), state.serial, state.serial + 16);
        message.insert(message.end(), tx.begin(), tx.end());
        auto id = key->id(); message.insert(message.end(), id.begin(), id.end());
        message.insert(message.end(), state.nonce, state.nonce + 32);
        for (unsigned i = 0; i < 4; ++i) message.push_back(static_cast<uint8_t>(wire.size() >> (8 * i)));
        message.insert(message.end(), wire.begin(), wire.end());
        return key->sign(message);
    }
    void seal(const Bytes &sig, uint32_t now = 100) {
        check(relay_setup_seal(&state, tx.data(), key->id().data(), sig.data(), now), "seal");
        relay_setup_poll(&state, false, false, now);
    }
    void physical(uint32_t now = 200) {
        relay_setup_poll(&state, false, false, now);
        relay_setup_poll(&state, false, true, now + 1);
        relay_setup_poll(&state, false, true, now + 1001);
        relay_setup_poll(&state, false, false, now + 1002);
    }
    void wiped() {
        for (auto b : state.wire) check(b == 0, "wire not wiped");
        for (auto b : state.signature) check(b == 0, "signature not wiped");
        for (auto b : state.nonce) check(b == 0, "challenge not wiped");
        const auto *decoded = reinterpret_cast<const uint8_t *>(&state.decoded);
        for (size_t i = 0; i < sizeof(state.decoded); ++i) check(decoded[i] == 0, "decoded secrets not wiped");
    }
};
int main() {
    try {
        {
            Setup s; s.begin(); s.seal(s.signature());
            check(s.state.phase == RELAY_SETUP_RELEASE && !s.commits, "saved before physical confirmation");
            relay_setup_poll(&s.state, false, true, 200);
            relay_setup_poll(&s.state, false, true, 5000);
            check(s.state.phase == RELAY_SETUP_RELEASE, "pre-held button authorized setup");
            relay_setup_poll(&s.state, false, false, 5001);
            relay_setup_poll(&s.state, false, true, 5002);
            relay_setup_poll(&s.state, false, false, 5003);
            check(s.state.phase == RELAY_SETUP_PRESS && !s.commits, "short press saved configuration");
            s.physical(5010);
            check(s.state.phase == RELAY_SETUP_DONE && s.commits == 1 && s.persisted == s.wire, "save after press/hold/release");
            s.physical(7000); check(s.commits == 1, "repeated save"); s.wiped();
        }
        {
            Setup s; s.begin(); auto replay = s.signature();
            check(relay_setup_cancel(&s.state, s.tx.data()), "cancel"); s.wiped();
            s.begin(); s.seal(replay);
            check(s.state.result == RELAY_SETUP_UNAUTHORIZED && !s.commits, "replay accepted"); s.wiped();
        }
        for (unsigned field = 0; field < 6; ++field) {
            Setup s; s.begin(); auto sig = s.signature();
            if (field == 0) s.state.serial[0] ^= 1;
            if (field == 1) { s.state.transaction[0] ^= 1; s.tx[0] ^= 1; }
            if (field == 2) s.state.nonce[0] ^= 1;
            if (field == 3) sig[0] ^= 1;
            if (field == 4) s.authorized = false;
            if (field == 5) s.key = Key::generate();
            s.seal(sig);
            check(s.state.result == RELAY_SETUP_UNAUTHORIZED && !s.commits, "unbound/unauthorized signature"); s.wiped();
        }
        {
            Setup s;
            // Both modes are structurally valid with retained profiles: an
            // attacker changing only the mode must fail signature verification.
            relay_config_t config{};
            config.network_count = 1;
            config.networks[0].ssid_length = config.networks[0].host_length = 1;
            config.networks[0].ssid[0] = 's'; config.networks[0].host[0] = 'h'; config.networks[0].port = 443;
            s.wire.resize(RELAY_CONFIG_MAX_SIZE); size_t n = 0;
            check(relay_config_encode(&config, s.wire.data(), s.wire.size(), &n) == RELAY_CONFIG_OK, "profile encoding");
            s.wire.resize(n); s.begin(); auto sig = s.signature();
            s.state.wire[8] = RELAY_MODE_RELAY;
            s.seal(sig);
            check(s.state.result == RELAY_SETUP_UNAUTHORIZED && !s.commits, "modified mode accepted"); s.wiped();
        }
        {
            Setup s; s.begin(); s.seal(s.signature()); s.authorized = false; s.physical();
            check(s.state.result == RELAY_SETUP_UNAUTHORIZED && !s.commits, "revoked controller saved configuration"); s.wiped();
        }
        {
            Setup s; s.begin(); s.seal(s.signature()); s.failStorage = true; s.physical();
            check(s.state.result == RELAY_SETUP_STORAGE && s.persisted == Bytes{0x42}, "failed write lost old config"); s.wiped();
        }
        {
            Setup s; s.failRandom = true;
            check(!relay_setup_begin(&s.state, s.tx.data(), s.wire.size(), 0, false) &&
                  s.state.result == RELAY_SETUP_RANDOM, "RNG failure accepted"); s.wiped();
        }
        {
            Setup s; s.begin();
            auto other = s.tx; other[0] ^= 1;
            check(!relay_setup_cancel(&s.state, other.data()), "unrelated transaction canceled setup");
            check(!relay_setup_begin(&s.state, other.data(), s.wire.size(), 100, false), "overlapping setup");
            check(relay_setup_active(&s.state), "failed competing begin erased setup");
            relay_setup_poll(&s.state, true, false, 100);
            check(s.state.result == RELAY_SETUP_BUSY && !s.commits, "busy authenticator allowed setup"); s.wiped();
        }
        {
            Setup s;
            check(relay_setup_begin(&s.state, s.tx.data(), s.wire.size(), 0, false), "begin");
            check(!relay_setup_chunk(&s.state, s.tx.data(), 1, s.wire.data(), 1, 0), "out of order chunk"); s.wiped();
            check(relay_setup_begin(&s.state, s.tx.data(), s.wire.size(), 0, false), "begin");
            auto sig = Bytes(64);
            check(!relay_setup_seal(&s.state, s.tx.data(), s.key->id().data(), sig.data(), 0), "truncated upload sealed"); s.wiped();
        }
        {
            Setup s; const uint32_t start = 0xfffff000u; s.begin(start); s.seal(s.signature(), start);
            relay_setup_poll(&s.state, false, false, start + RELAY_SETUP_TIMEOUT_MS);
            check(s.state.phase == RELAY_SETUP_EXPIRED && !s.commits, "wraparound timeout"); s.wiped();
        }
        puts("PASS: signed setup challenge, replay/context binding, physical gate, revocation, busy/cancel/timeout and storage failure");
        return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
