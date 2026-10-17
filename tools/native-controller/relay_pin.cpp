#include "relay_pin.h"
#include "relay_authenticator.h"
#include "device_names.h"
#include <algorithm>
#include <array>
#include <map>

namespace relay {
namespace {
using V = ctap::Value;
void need(bool ok, uint8_t code = 0x02) { if (!ok) throw ctap::Error(code); }
struct Secret { Bytes b; ~Secret() { if (!b.empty()) secureZero(b.data(), b.size()); } };
std::string canonical(std::string serial) {
    need(validDeviceSerial(serial)); for (auto &c : serial) if (c >= 'A' && c <= 'F') c += 'a' - 'A'; return serial;
}
const V &field(const V &v, int key) { auto p = v.find(key); need(p != nullptr, 0x14); return *p; }
unsigned number(const V &v, unsigned maximum) { need(v.type == V::Integer, 0x11); need(v.number >= 0 && v.number <= maximum); return static_cast<unsigned>(v.number); }
const Bytes &blob(const V &v) { need(v.type == V::ByteString, 0x11); return v.bytes; }
V flag(bool b) { V v; v.type = V::Boolean; v.number = b; return v; }
Bytes result(const V &v) { Bytes b{0}; auto out = ctap::encode(v); b.insert(b.end(), out.begin(), out.end()); return b; }
void live(const Operation &op) {
    need(!op.canceled || !op.canceled(), 0x2d); need(std::chrono::steady_clock::now() < op.deadline, 0x2f);
}
std::string rpId(const V &v) {
    need(v.type == V::Text, 0x11); need(!v.text.empty() && v.text.size() <= 253);
    size_t label = 0;
    for (size_t i = 0; i < v.text.size(); ++i) {
        auto c = v.text[i];
        if (c == '.') { need(label && label <= 63 && v.text[i - 1] != '-'); label = 0; }
        else { need((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && label)); ++label; }
    }
    need(label && label <= 63 && v.text.back() != '-'); return v.text;
}
Bytes verifier(const Bytes &hash16, const Bytes &salt) {
    need(hash16.size() == 16 && salt.size() == 32);
    try { return crypto::pbkdf2Sha256(hash16.data(), 16, salt.data(), 32, 600000, 32); }
    catch (...) { throw ctap::Error(0x7f); }
}
Bytes newPinHash(unsigned protocol, const Bytes &key, const Bytes &cipher) {
    Secret padded{pin::decrypt(protocol, key, cipher)}; need(padded.b.size() == 64);
    auto end = std::find(padded.b.begin(), padded.b.end(), 0);
    need(end != padded.b.end() && std::all_of(end, padded.b.end(), [](uint8_t b) { return b == 0; }), 0x37);
    Secret text{Bytes(padded.b.begin(), end)};
    try {
        std::string s(text.b.begin(), text.b.end()); struct Clear { std::string &s; ~Clear() { wipe(s); } } clear{s};
        if (!validUtf8(s)) throw ctap::Error(0x37);
    }
    catch (...) { throw ctap::Error(0x37); }
    auto points = std::count_if(text.b.begin(), text.b.end(), [](uint8_t b) { return (b & 0xc0) != 0x80; });
    need(points >= 4 && text.b.size() <= 63, 0x37);
    Secret digest{hash(text.b)}; return Bytes(digest.b.begin(), digest.b.begin() + 16);
}
}
namespace pin {
bool equal(const Bytes &a, const Bytes &b) {
    if (a.size() != b.size()) return false;
    uint8_t difference = 0; for (size_t i = 0; i < a.size(); ++i) difference |= a[i] ^ b[i]; return difference == 0;
}
Bytes shared(unsigned protocol, const ctap::Agreement &own, const V &peer) {
    need(protocol == 1 || protocol == 2);
    Secret raw;
    try { raw.b = own.rawSecret(peer); } catch (...) { throw ctap::Error(0x02); }
    if (protocol == 1) return hash(raw.b);
    Secret extract{ctap::hmac(Bytes(32), raw.b)};
    auto expand = [&](const std::string &info) { Bytes context(info.begin(), info.end()); context.push_back(1); return ctap::hmac(extract.b, context); };
    Secret out{expand("CTAP2 HMAC key")}, aes{expand("CTAP2 AES key")};
    out.b.insert(out.b.end(), aes.b.begin(), aes.b.end()); return std::move(out.b);
}
Bytes encrypt(unsigned protocol, const Bytes &key, const Bytes &plain) {
    need(protocol == 1 || protocol == 2); need(key.size() == (protocol == 1 ? 32u : 64u));
    if (protocol == 1) return ctap::aesCbc(key, plain, true);
    Secret aes{Bytes(key.begin() + 32, key.end())}; auto iv = randomBytes(16);
    auto out = ctap::aesCbcIv(aes.b, plain, true, iv); iv.insert(iv.end(), out.begin(), out.end()); return iv;
}
Bytes decrypt(unsigned protocol, const Bytes &key, const Bytes &cipher) {
    need(protocol == 1 || protocol == 2); need(key.size() == (protocol == 1 ? 32u : 64u));
    need(!cipher.empty() && cipher.size() % 16 == 0);
    if (protocol == 1) return ctap::aesCbc(key, cipher, false);
    need(cipher.size() >= 32);
    Secret aes{Bytes(key.begin() + 32, key.end())};
    return ctap::aesCbcIv(aes.b, Bytes(cipher.begin() + 16, cipher.end()), false, Bytes(cipher.begin(), cipher.begin() + 16));
}
Bytes authenticate(unsigned protocol, const Bytes &key, const Bytes &message) {
    need(protocol == 1 || protocol == 2); need(key.size() == 32 || (protocol == 2 && key.size() == 64));
    Secret macKey{Bytes(key.begin(), key.begin() + 32)}; auto mac = ctap::hmac(macKey.b, message); if (protocol == 1) mac.resize(16); return mac;
}
}
struct PinManager::State {
    struct Session {
        Id boot{}, enrollment{};
        std::array<std::unique_ptr<ctap::Agreement>, 2> keys;
        Bytes token, pinSalt;
        unsigned wrong = 0, permissions = 0, protocol = 0;
        std::string rp;
        std::chrono::steady_clock::time_point expires{};
        ~Session() { wipe(token); }
        void revoke() { wipe(token); pinSalt.clear(); permissions = protocol = 0; rp.clear(); }
    };
    std::map<std::string, std::unique_ptr<Session>> sessions;
    Clock clock;
    explicit State(Clock now) : clock(now ? std::move(now) : Clock([] { return std::chrono::steady_clock::now(); })) {}
    Session &session(const Operation &op) {
        need(op.bootId != Id{} && op.enrollmentId != Id{}, 0x7f);
        auto serial = canonical(op.deviceSerial); auto it = sessions.find(serial);
        if (it == sessions.end()) { need(sessions.size() < 256, 0x28); it = sessions.emplace(serial, nullptr).first; }
        if (!it->second || it->second->boot != op.bootId || it->second->enrollment != op.enrollmentId) {
            it->second = std::make_unique<Session>(); it->second->boot = op.bootId; it->second->enrollment = op.enrollmentId;
        }
        return *it->second;
    }
};
PinManager::PinManager(Vault &v, Clock clock) : vault(v), state(std::make_unique<State>(std::move(clock))) {}
PinManager::~PinManager() = default;
bool PinManager::configured(const std::string &serial) const { return vault.pins.count(canonical(serial)) != 0; }
Bytes PinManager::exchange(const V &params, const Operation &op, const Consent &consent) {
    auto serial = canonical(op.deviceSerial); auto &session = state->session(op);
    unsigned sub = number(field(params, 2), 255);
    auto stored = vault.pins.find(serial); bool configured = stored != vault.pins.end();
    if (sub == 1) return result(V::map({V::integer(3), V::integer(configured ? stored->second.retries : 8), V::integer(4), flag(session.wrong >= 3)}));
    need(sub == 2 || sub == 3 || sub == 4 || sub == 5 || sub == 9, 0x2b);
    // Legacy getPinToken always grants the default scope. Reject scoped-token
    // fields instead of silently issuing a broader token than the caller asked for.
    if (sub == 5) need(!params.find(9) && !params.find(10));
    unsigned protocol = number(field(params, 1), 2); need(protocol >= 1);
    auto &agreement = session.keys[protocol - 1]; if (!agreement) agreement = std::make_unique<ctap::Agreement>();
    if (sub == 2) return result(V::map({V::integer(1), agreement->publicKey()}));
    if (sub == 3) need(!configured, 0x33);
    else { need(configured, 0x35); need(stored->second.retries > 0, 0x32); need(session.wrong < 3, 0x34); }
    const auto &peer = field(params, 3);
    const Bytes *newPin = nullptr, *pinHash = nullptr, *auth = nullptr;
    if (sub == 3 || sub == 4) { newPin = &blob(field(params, 5)); auth = &blob(field(params, 4)); need(newPin->size() == (protocol == 1 ? 64u : 80u)); }
    if (sub != 3) { pinHash = &blob(field(params, 6)); need(pinHash->size() == (protocol == 1 ? 16u : 32u)); }
    unsigned permissions = 3; std::string rp;
    if (sub == 9) {
        permissions = number(field(params, 9), 255); need(permissions != 0);
        need((permissions & 0x7c) == 0, 0x40); permissions &= 3; // No management (including persistent), biometrics, large blobs or configuration.
        if (permissions) rp = rpId(field(params, 10)); else if (auto value = params.find(10)) rp = rpId(*value);
    }
    Secret key{pin::shared(protocol, *agreement, peer)};
    if (auth) {
        Bytes message = *newPin; if (pinHash) message.insert(message.end(), pinHash->begin(), pinHash->end());
        need(pin::equal(pin::authenticate(protocol, key.b, message), *auth), 0x33);
    }
    live(op);
    // Normal PIN verification establishes UV only. The subsequent account-bound
    // operation still needs its own approval; setting/changing a PIN needs consent.
    if (sub == 3 || sub == 4) consent(static_cast<uint8_t>(sub), 0, rp);
    live(op);
    // Consent releases/reacquires the cloud lease. Never use the pre-dialog
    // iterator or assume another client has left the PIN/retries unchanged.
    stored = vault.pins.find(serial); configured = stored != vault.pins.end();
    if (sub == 3) need(!configured, 0x33);
    else { need(configured, 0x35); need(stored->second.retries > 0, 0x32); need(session.wrong < 3, 0x34); }
    if (sub != 3) {
        // Persist the decrement BEFORE comparing a guess. IO failures latch the
        // vault fault; process/power loss can never restore an uncounted attempt.
        auto next = vault.pins; --next.at(serial).retries; vault.commitPins(std::move(next));
        bool match = false;
        try { Secret supplied{pin::decrypt(protocol, key.b, *pinHash)}; Secret actual{verifier(supplied.b, vault.pins.at(serial).salt)}; match = pin::equal(actual.b, vault.pins.at(serial).verifier); }
        catch (const ctap::Error &) { match = false; }
        if (!match) {
            session.revoke(); agreement = std::make_unique<ctap::Agreement>(); ++session.wrong;
            need(vault.pins.at(serial).retries != 0, 0x32); need(session.wrong < 3, 0x34); throw ctap::Error(0x31);
        }
        next = vault.pins; next.at(serial).retries = 8; vault.commitPins(std::move(next)); session.wrong = 0;
    }
    if (sub == 3 || sub == 4) {
        Secret hash16{newPinHash(protocol, key.b, *newPin)}; PinRecord pin;
        pin.salt = randomBytes(32); pin.verifier = verifier(hash16.b, pin.salt);
        auto next = vault.pins; need(next.count(serial) || next.size() < 256, 0x28); next[serial] = pin;
        live(op); vault.commitPins(std::move(next)); session.revoke(); live(op); return {0};
    }
    live(op); session.revoke(); session.token = randomBytes(32); session.protocol = protocol;
    session.pinSalt = vault.pins.at(serial).salt;
    session.permissions = permissions; session.rp = rp; session.expires = state->clock() + std::chrono::seconds(30);
    auto response = result(V::map({V::integer(2), V::blob(pin::encrypt(protocol, key.b, session.token))}));
    live(op); return response;
}
Bytes PinManager::verify(const Operation &op, unsigned protocol, const Bytes &auth, const Bytes &clientHash,
                         const std::string &rp, unsigned permission, bool consume) {
    need(configured(op.deviceSerial), 0x35); need(protocol == 1 || protocol == 2);
    const auto &stored = vault.pins.at(canonical(op.deviceSerial)); need(stored.retries > 0, 0x32);
    auto &session = state->session(op);
    need(session.token.size() == 32 && session.protocol == protocol, 0x33);
    if (session.pinSalt != stored.salt) { session.revoke(); throw ctap::Error(0x33); }
    if (state->clock() >= session.expires) { session.revoke(); throw ctap::Error(0x38); }
    need((session.permissions & permission) && (session.rp.empty() || session.rp == rp), 0x33);
    need(pin::equal(pin::authenticate(protocol, session.token, clientHash), auth), 0x33);
    auto binding = hash(session.token);
    // Formal requests remain single-use, including denied ones. Preflight
    // failures are invalidated by Authenticator::exchange instead.
    if (consume) session.revoke();
    return binding;
}
void PinManager::invalidate(const Operation &op) {
    if (!validDeviceSerial(op.deviceSerial)) return;
    auto it = state->sessions.find(canonical(op.deviceSerial));
    if (it != state->sessions.end() && it->second && it->second->boot == op.bootId &&
        it->second->enrollment == op.enrollmentId) it->second->revoke();
}
}
