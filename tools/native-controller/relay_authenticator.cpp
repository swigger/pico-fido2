#include "relay_authenticator.h"
#include "credentials.h"
#include "device_names.h"
#include "relay_transport.h"
#include <algorithm>
#include <stdexcept>

namespace relay {
namespace {
using V = ctap::Value;
void need(bool ok, uint8_t code = 0x02) { if (!ok) throw ctap::Error(code); }
void live(const Operation &op) {
    need(!op.canceled || !op.canceled(), 0x2d);
    need(std::chrono::steady_clock::now() < op.deadline, 0x2f);
}
void append(Bytes &to, const Bytes &from) { to.insert(to.end(), from.begin(), from.end()); }
void put32(Bytes &b, uint32_t n) {
    for (unsigned i = 4; i; --i) b.push_back(static_cast<uint8_t>(n >> ((i - 1) * 8)));
}
V flag(bool b) { V v; v.type = V::Boolean; v.number = b; return v; }
V array(std::initializer_list<V> values) { V v; v.type = V::Array; v.items = values; return v; }
const V &field(const V &v, int key) { auto p = v.find(key); need(p != nullptr, 0x14); return *p; }
const V &field(const V &v, const char *key) { auto p = v.find(key); need(p != nullptr, 0x14); return *p; }
std::string text(const V &v, size_t min, size_t max) {
    need(v.type == V::Text, 0x11); need(v.text.size() >= min && v.text.size() <= max); return v.text;
}
Bytes blob(const V &v, size_t min, size_t max) {
    need(v.type == V::ByteString, 0x11); need(v.bytes.size() >= min && v.bytes.size() <= max); return v.bytes;
}
bool option(const V *v, const char *name, bool def) {
    if (!v) return def;
    need(v->type == V::Map, 0x11);
    for (size_t i = 0; i < v->items.size(); i += 2) {
        need(v->items[i].type == V::Text && v->items[i + 1].type == V::Boolean, 0x11);
    }
    auto p = v->find(name); return p ? p->number != 0 : def;
}
// RP IDs are lower-case ASCII DNS names (IDNs are punycode); never a URL, path,
// user-supplied display name, or a suffix match. IPv4 and localhost are allowed.
std::string rpId(const V &v) {
    auto rp = text(v, 1, 253); size_t label = 0;
    for (size_t i = 0; i < rp.size(); ++i) {
        auto c = rp[i];
        if (c == '.') { need(label && label <= 63 && rp[i - 1] != '-'); label = 0; }
        else { need((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && label)); ++label; }
    }
    need(label && label <= 63 && rp.back() != '-'); return rp;
}
std::vector<Bytes> descriptors(const V *v) {
    std::vector<Bytes> out;
    if (!v) return out;
    need(v->type == V::Array, 0x11); need(v->items.size() <= 64, 0x15);
    for (const auto &entry : v->items) {
        need(entry.type == V::Map, 0x11);
        auto type = text(field(entry, "type"), 1, 32); auto id = blob(field(entry, "id"), 1, 1024);
        if (type == "public-key") out.push_back(std::move(id));
    }
    return out;
}
bool includes(const std::vector<Bytes> &ids, const Bytes &id) {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}
Bytes derSignature(const Bytes &raw) {
    need(raw.size() == 64, 0x7f); Bytes body;
    for (size_t offset : {size_t(0), size_t(32)}) {
        size_t first = offset;
        while (first < offset + 31 && !raw[first]) ++first;
        bool prefix = (raw[first] & 0x80) != 0;
        body.push_back(0x02); body.push_back(static_cast<uint8_t>(offset + 32 - first + (prefix ? 1 : 0)));
        if (prefix) body.push_back(0);
        body.insert(body.end(), raw.begin() + first, raw.begin() + offset + 32);
    }
    Bytes der{0x30, static_cast<uint8_t>(body.size())}; append(der, body); return der;
}
Bytes authData(const Credential &r, bool attested, bool verified, const Bytes &pub = {}, bool present = true) {
    Bytes b = hash(Bytes(r.rp.begin(), r.rp.end()));
    b.push_back(static_cast<uint8_t>((attested ? 0x40 : 0) | (present ? 1 : 0) | (verified ? 4 : 0)));
    put32(b, r.counter);
    if (attested) {
        b.insert(b.end(), 16, 0); // Unassigned model AAGUID, also returned by GetInfo.
        b.push_back(0); b.push_back(static_cast<uint8_t>(r.credentialId.size())); append(b, r.credentialId);
        need(pub.size() == 65, 0x7f);
        append(b, ctap::encode(V::map({V::integer(1), V::integer(2), V::integer(3), V::integer(-7),
            V::integer(-1), V::integer(1), V::integer(-2), V::blob(Bytes(pub.begin() + 1, pub.begin() + 33)),
            V::integer(-3), V::blob(Bytes(pub.begin() + 33, pub.end()))})));
    }
    return b;
}
Bytes result(const V &v) { Bytes out{0}; append(out, ctap::encode(v)); return out; }
void extensions(const V *v) {
    if (!v) return;
    need(v->type == V::Map, 0x11);
    for (size_t i = 0; i < v->items.size(); i += 2) need(v->items[i].type == V::Text, 0x11);
    // No extensions are advertised. Unknown extensions are ignored per CTAP.
}
std::string serialOf(const Operation &op) {
    auto serial = op.deviceSerial;
    for (auto &c : serial) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
    return serial;
}
Bytes assertionScope(V params) {
    // Normalize ONLY the presence bit (absent means true). Every other field,
    // including PIN proof, extensions and the complete allowList, must match.
    for (size_t i = 0; i < params.items.size(); i += 2) if (params.items[i].number == 5) {
        auto &options = params.items[i + 1].items;
        for (size_t j = 0; j < options.size(); j += 2) if (options[j].text == "up") {
            options.erase(options.begin() + j, options.begin() + j + 2); break;
        }
        if (options.empty()) params.items.erase(params.items.begin() + i, params.items.begin() + i + 2);
        break;
    }
    Bytes wire{2}; append(wire, ctap::encode(params)); return hash(wire);
}
bool sameAccount(const Account &a, const Account &b) {
    // A concurrent counter increment is harmless; identity changes are not.
    return a.credentialId == b.credentialId && a.rp == b.rp && a.userId == b.userId &&
        a.userName == b.userName && a.displayName == b.displayName && a.discoverable == b.discoverable;
}
}
void Authenticator::cancel(const Operation &op) {
    std::lock_guard<std::mutex> guard(vault.transactionMutex);
    auto it = assertionGrants.find(serialOf(op));
    if (it != assertionGrants.end() && it->second.boot == op.bootId && it->second.enrollment == op.enrollmentId &&
        it->second.requestId == op.requestId) {
        assertionGrants.erase(it); pins.invalidate(op);
    }
}
Bytes Authenticator::discovery(const std::string &serial) {
    std::lock_guard<std::mutex> guard(vault.transactionMutex);
    if (vault.faulted || !validDeviceSerial(serial)) return {};
    Bytes out(vault.identity.begin(), vault.identity.end());
    for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(vault.generation >> (8 * i)));
    out.push_back(pins.configured(serial) ? 1 : 0); return out;
}
Bytes Authenticator::exchange(const Bytes &request, const Operation &operation) {
    std::unique_lock<std::mutex> guard(vault.transactionMutex, std::try_to_lock);
    if (!guard.owns_lock()) return {0x06};
    auto clear = [&](Vault *v) { v->endTransaction(); v->cancellation({}); };
    std::unique_ptr<Vault, decltype(clear)> scope(&vault, clear);
    try {
        live(operation); need(validDeviceSerial(operation.deviceSerial) && operation.requestId != Id{}, 0x02);
        // Public discovery runs between transactions. Any other intervening
        // command invalidates the one permitted assertion continuation.
        if (request != Bytes{4} && (request.empty() || request[0] != 2)) assertionGrants.erase(serialOf(operation));
        vault.cancellation([&] { return std::chrono::steady_clock::now() >= operation.deadline || (operation.canceled && operation.canceled()); });
        vault.check();
        bool discovery = request == Bytes{4};
        if (!request.empty() && request[0] == 6) {
            // These are negotiation hints/volatile ECDH only. A later PIN
            // attempt always acquires authoritative retry and verifier state.
            try { auto p = ctap::decode(Bytes(request.begin() + 1, request.end())); auto sub = p.find(2);
                discovery = sub && sub->type == V::Integer && (sub->number == 1 || sub->number == 2);
            } catch (...) {}
        }
        if (!discovery) vault.beginTransaction();
        auto response = perform(request, operation); vault.check(); live(operation); return response;
    } catch (const ctap::Error &e) {
        assertionGrants.erase(serialOf(operation));
        if (!request.empty() && request[0] == 2) pins.invalidate(operation);
        return {e.code};
    } catch (...) {
        assertionGrants.erase(serialOf(operation));
        if (!request.empty() && request[0] == 2) pins.invalidate(operation);
        return {0x7f}; // No keys, account strings or IO errors enter the wire response.
    }
}
Bytes Authenticator::perform(const Bytes &request, const Operation &op) {
    need(!request.empty() && request.size() <= RELAY_CTAP_MAX, 0x03); uint8_t cmd = request[0];
    if (cmd == 0x04) {
        need(request.size() == 1, 0x03);
        return result(V::map({V::integer(1), array({V::string("FIDO_2_0")}), V::integer(3), V::blob(Bytes(16)),
            V::integer(4), V::map({V::string("rk"), flag(true), V::string("up"), flag(true), V::string("plat"), flag(false),
                V::string("clientPin"), flag(pins.configured(op.deviceSerial)), V::string("pinUvAuthToken"), flag(true)}),
            V::integer(5), V::integer(RELAY_CTAP_MAX), V::integer(6), array({V::integer(2), V::integer(1)})}));
    }
    if (cmd == 0x0a || cmd == 0x41) return {0x2e};
    if (cmd == 0x08) return {0x30}; // No pending getNextAssertion pagination.
    // Only this narrowly scoped vendor query is exposed; no remote management.
    need(cmd == 0x01 || cmd == 0x02 || cmd == 0x06 || cmd == RELAY_CTAP_EXACT_QUERY, 0x01);
    V params;
    try { params = ctap::decode(Bytes(request.begin() + 1, request.end())); }
    catch (...) { throw ctap::Error(0x12); }
    need(params.type == V::Map, 0x11);
    for (size_t i = 0; i < params.items.size(); i += 2) need(params.items[i].type == V::Integer, 0x11);
    if (cmd == 6) return pins.exchange(params, op, [&](uint8_t sub, unsigned permissions, const std::string &rp) {
        Approval a; a.operation = 6; a.pinSubcommand = sub; a.pinPermissions = permissions; a.rp = rp;
        a.deviceSerial = op.deviceSerial; a.requestId = op.requestId; a.requestHash = hash(request);
        live(op); vault.check(); need(static_cast<bool>(approve), 0x27);
        vault.endTransaction(); const auto decision = approve(a, op);
        live(op); need(decision.allow, 0x27); vault.beginTransaction();
    });
    if (cmd == RELAY_CTAP_EXACT_QUERY) {
        need(params.items.size() == 4, 0x02);
        Approval query; query.operation = cmd; query.deviceSerial = op.deviceSerial;
        query.requestId = op.requestId; query.requestHash = hash(request);
        query.rp = rpId(field(params, 1)); query.queryUserName = text(field(params, 2), 1, 64);
        live(op); vault.check(); need(static_cast<bool>(approve), 0x27);
        vault.endTransaction(); const auto decision = approve(query, op);
        live(op); need(decision.allow, 0x27); vault.beginTransaction();
        bool found = std::any_of(vault.records.begin(), vault.records.end(), [&](const Credential &c) {
            return c.rp == query.rp && c.userName == query.queryUserName;
        });
        return result(V::map({V::integer(1), flag(found)}));
    }
    auto options = params.find(cmd == 1 ? 7 : 5);
    bool wantsUv = option(options, "uv", false);
    bool wantsUp = cmd == 1 || option(options, "up", true);
    if (options) need(!options->find(cmd == 1 ? "up" : "rk"), 0x2c);
    extensions(params.find(cmd == 1 ? 6 : 4));
    auto clientHash = blob(field(params, cmd == 1 ? 1 : 2), 32, 32);
    Approval approval; approval.operation = cmd; approval.deviceSerial = op.deviceSerial;
    approval.requestId = op.requestId; approval.requestHash = hash(request);
    auto consent = [&]() {
        live(op); vault.check(); need(static_cast<bool>(approve), 0x27);
        vault.endTransaction(); const Decision decision = approve(approval, op);
        live(op); need(decision.allow, 0x27); vault.beginTransaction(); return decision;
    };
    Bytes verifiedPinSalt, tokenBinding;
    auto verifyPin = [&](const std::string &rp) {
        auto auth = params.find(cmd == 1 ? 8 : 6); auto protocol = params.find(cmd == 1 ? 9 : 7);
        if (auth) {
            need(auth->type == V::ByteString, 0x11);
            // A selection probe only reports PIN configuration. Hardware handles
            // it automatically; retain the same no-dialog behavior for older
            // relay firmware. It grants neither a PIN token nor user presence.
            if (auth->bytes.empty()) throw ctap::Error(pins.configured(op.deviceSerial) ? 0x31 : 0x35);
            need(protocol != nullptr, 0x14); need(protocol->type == V::Integer, 0x11); need(protocol->number == 1 || protocol->number == 2);
            tokenBinding = pins.verify(op, static_cast<unsigned>(protocol->number), auth->bytes, clientHash, rp, cmd == 1 ? 1 : 2, wantsUp);
            verifiedPinSalt = vault.pins.at(serialOf(op)).salt; return true;
        }
        need(!protocol, 0x14); need(!wantsUv, 0x2b); // No built-in biometric/UV modality.
        need(cmd != 1 || !pins.configured(op.deviceSerial), 0x36); return false;
    };
    auto revalidatePin = [&](bool verified) {
        if (!verified) { need(cmd != 1 || !pins.configured(op.deviceSerial), 0x36); return; }
        auto current = vault.pins.find(serialOf(op));
        need(current != vault.pins.end() && current->second.salt == verifiedPinSalt, 0x33);
        need(current->second.retries > 0, 0x32);
    };
    if (cmd == 1) {
        const auto &rp = field(params, 2); const auto &user = field(params, 3);
        need(rp.type == V::Map && user.type == V::Map, 0x11);
        Credential credential; credential.rp = rpId(field(rp, "id")); approval.rp = credential.rp;
        bool verified = verifyPin(credential.rp);
        credential.userId = blob(field(user, "id"), 1, 64);
        if (auto v = user.find("name")) credential.userName = text(*v, 0, 64);
        if (auto v = user.find("displayName")) credential.displayName = text(*v, 0, 64);
        const auto &algorithms = field(params, 4);
        need(algorithms.type == V::Array, 0x11); need(!algorithms.items.empty() && algorithms.items.size() <= 64, 0x15);
        bool supported = false;
        for (const auto &a : algorithms.items) {
            need(a.type == V::Map, 0x11);
            auto type = text(field(a, "type"), 1, 32); const auto &alg = field(a, "alg");
            need(alg.type == V::Integer, 0x11); supported |= type == "public-key" && alg.number == -7;
        }
        need(supported, 0x26);
        auto excluded = descriptors(params.find(5));
        credential.discoverable = option(options, "rk", false);
        approval.accounts.push_back(credential); (void)consent();
        revalidatePin(verified);
        bool exists = std::any_of(vault.records.begin(), vault.records.end(), [&](const auto &r) {
            return r.rp == credential.rp && includes(excluded, r.credentialId);
        });
        need(!exists, 0x19); // Exclusion is revealed only after explicit presence.
        auto next = vault.records;
        if (credential.discoverable) {
            // CTAP replaces the discoverable credential for the same RP/user ID.
            next.erase(std::remove_if(next.begin(), next.end(), [&](const auto &r) {
                return r.discoverable && r.rp == credential.rp && r.userId == credential.userId;
            }), next.end());
        }
        need(next.size() < Vault::capacity, 0x28);
        do { credential.credentialId = randomBytes(32); }
        while (std::any_of(vault.records.begin(), vault.records.end(), [&](const auto &r) { return r.credentialId == credential.credentialId; }));
        auto key = Key::generate(); credential.privateKey = key->blob();
        auto auth = authData(credential, true, verified, key->pub()); auto message = auth; append(message, clientHash);
        auto attestation = vault.attestation;
        V statement;
        if (credential.rp == "apple.com") {
            if (attestation.privateKey.empty()) attestation = Attestation::generate();
            auto signingKey = Key::fromBlob(attestation.privateKey);
            statement = V::map({V::string("alg"), V::integer(-7),
                V::string("sig"), V::blob(derSignature(signingKey->sign(message))),
                V::string("x5c"), array({V::blob(attestation.certificate)})});
        } else {
            statement = V::map({V::string("alg"), V::integer(-7), V::string("sig"), V::blob(derSignature(key->sign(message)))});
        }
        auto response = result(V::map({V::integer(1), V::string("packed"), V::integer(2), V::blob(auth),
            V::integer(3), std::move(statement)}));
        need(response.size() <= RELAY_CTAP_MAX, 0x39);
        live(op); next.push_back(std::move(credential)); vault.commit(std::move(next), std::move(attestation)); live(op); return response;
    }
    approval.rp = rpId(field(params, 1));
    bool verified = verifyPin(approval.rp);
    auto allow = params.find(3); auto ids = descriptors(allow);
    // An explicitly empty list is equivalent to no list; a nonempty list of
    // unsupported descriptor types must NOT broaden into discoverable lookup.
    bool restricted = allow && !allow->items.empty();
    for (const auto &r : vault.records)
        if (r.rp == approval.rp && (restricted ? includes(ids, r.credentialId) : r.discoverable)) approval.accounts.push_back(r);
    auto scope = assertionScope(params);
    Decision decision;
    auto pending = assertionGrants.find(serialOf(op));
    if (pending != assertionGrants.end()) {
        auto grant = std::move(pending->second); assertionGrants.erase(pending);
        if (wantsUp && verified && grant.boot == op.bootId && grant.enrollment == op.enrollmentId &&
            grant.requestId != op.requestId && grant.token == tokenBinding && grant.scope == scope) {
            auto current = std::find_if(vault.records.begin(), vault.records.end(), [&](const auto &r) {
                return sameAccount(grant.account, r) && grant.keyHash == hash(r.privateKey);
            });
            if (current != vault.records.end()) decision = {true, grant.account.credentialId};
        }
    }
    // The approved preflight covers only its exact, single formal assertion.
    // A mismatch, unverified request or repeated preflight needs new consent.
    if (!decision.allow) decision = consent();
    revalidatePin(verified);
    need(!approval.accounts.empty(), 0x2e); // Even a negative RP lookup requires presence.
    need(std::any_of(approval.accounts.begin(), approval.accounts.end(), [&](const auto &a) { return a.credentialId == decision.credentialId; }), 0x27);
    auto next = vault.records;
    auto match = std::find_if(next.begin(), next.end(), [&](const auto &r) { return r.credentialId == decision.credentialId; });
    need(match != next.end() && match->rp == approval.rp && (restricted ? includes(ids, match->credentialId) : match->discoverable), 0x2e);
    // Approval describes a specific account. A changed identity requires a new
    // approval; a counter increment by another client is safe to incorporate.
    auto selected = std::find_if(approval.accounts.begin(), approval.accounts.end(), [&](const auto &a) { return a.credentialId == decision.credentialId; });
    need(selected != approval.accounts.end() && selected->userId == match->userId && selected->userName == match->userName && selected->displayName == match->displayName, 0x27);
    need(match->counter != UINT32_MAX, 0x7f); ++match->counter;
    auto key = Key::fromBlob(match->privateKey); auto auth = authData(*match, false, verified, {}, wantsUp); auto message = auth; append(message, clientHash);
    auto response = V::map({V::integer(1), V::map({V::string("type"), V::string("public-key"), V::string("id"), V::blob(match->credentialId)}),
        V::integer(2), V::blob(auth), V::integer(3), V::blob(derSignature(key->sign(message)))});
    if (!restricted) {
        response.items.push_back(V::integer(4)); response.items.push_back(V::map({V::string("id"), V::blob(match->userId)}));
    }
    // Account names and other candidates never leave the safe-end selection UI.
    // Persist the counter before any signature can be delivered to the client.
    AssertionGrant grant;
    if (!wantsUp && verified) {
        grant.boot = op.bootId; grant.enrollment = op.enrollmentId; grant.requestId = op.requestId;
        grant.token = tokenBinding; grant.scope = std::move(scope); grant.account = *match; grant.keyHash = hash(match->privateKey);
    }
    auto wire = result(response); live(op); vault.commit(std::move(next)); live(op);
    if (!wantsUp && verified) assertionGrants[serialOf(op)] = std::move(grant);
    return wire;
}
}
