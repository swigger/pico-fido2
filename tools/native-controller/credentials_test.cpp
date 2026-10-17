#include "credentials.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

using V = ctap::Value;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static Bytes unhex(const char *s) {
    Bytes b;
    while (*s) {
        auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        b.push_back(static_cast<unsigned char>(digit(s[0]) * 16 + digit(s[1]))); s += 2;
    }
    return b;
}
static V boolean(bool b) { V v; v.type = V::Boolean; v.number = b; return v; }
static V array(std::initializer_list<V> a) { V v; v.type = V::Array; v.items = a; return v; }
static Bytes reply(const V &v) { auto b = ctap::encode(v); b.insert(b.begin(), 0); return b; }
template<typename Fn> static void fails(Fn fn, const char *why) {
    bool failed = false;
    try { fn(); } catch (const std::exception &) { failed = true; }
    check(failed, why);
}
static void agreement() {
    // Independently computed with Python cryptography/OpenSSL, d=1 and peer=2G.
    const auto gx = unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    const auto gy = unhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    Bytes blob(104); const unsigned char hdr[8] = {'E', 'C', 'S', '2', 32, 0, 0, 0};
    memcpy(blob.data(), hdr, 8); memcpy(blob.data() + 8, gx.data(), 32); memcpy(blob.data() + 40, gy.data(), 32);
    blob.back() = 1;
    ctap::Agreement a;
    a.key = crypto::P256::fromBlob(blob);
    auto peer = V::map({V::integer(1), V::integer(2), V::integer(3), V::integer(-25),
        V::integer(-1), V::integer(1),
        V::integer(-2), V::blob(unhex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")),
        V::integer(-3), V::blob(unhex("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"))});
    check(a.sharedSecret(peer) == unhex("23775201799b2234a18e8071e409cec80d42632fe77534180afdc533c9b76f81"), "ECDH byte order/KDF");
    ctap::Agreement c;
    check(a.sharedSecret(c.publicKey()) == c.sharedSecret(a.publicKey()), "ECDH symmetry");
    Bytes key(32); for (unsigned char n = 0; n < 32; ++n) key[n] = n;
    auto encrypted = unhex("5a6e045708fb7196f02e553d02c3a692c77147ebd5121de8d0fae7762423b6bf");
    check(ctap::aesCbc(key, key, true) == encrypted, "AES zero-IV vector");
    check(ctap::aesCbc(key, encrypted, false) == key, "AES decrypt vector");
    const std::string message = "Hi There";
    check(ctap::hmac(Bytes(20, 0x0b), Bytes(message.begin(), message.end())) ==
        unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), "RFC 4231 HMAC vector");
    puts("PASS: independent ECDH byte-order/KDF, AES-CBC, HMAC vectors");
}
static void cbor() {
    auto v = V::map({V::integer(3), V::integer(-25), V::integer(1), V::integer(2),
        V::integer(-1), V::integer(1)});
    check(ctap::encode(v) == unhex("a301020338182001"), "canonical map ordering");
    check(ctap::encode(ctap::decode(ctap::encode(v))) == ctap::encode(v), "CBOR roundtrip");
    for (const char *s : {"", "a101", "a201010102", "a202010101", "1817", "7f", "61ff", "0100", "9a7fffffff", "a1f601"})
        fails([&] { ctap::decode(unhex(s)); }, "malformed CBOR accepted");
    auto label = V::string("site\n\xe2\x80\xae").label();
    check(label == L"site\ufffd\ufffd", "label control characters");
    puts("PASS: canonical CBOR, malformed/duplicate/truncated input, safe labels");
}
struct Mock {
    ctap::Agreement agreement;
    Bytes shared, token = Bytes(32, 0x7b);
    bool wrong = false, empty = false, configured = true, supported = true, badCount = false, badHash = false;
    int attempts = 0, retryReads = 0, metadata = 0, rpIndex = 0, siteIndex = 0, userIndex = 0;
    std::atomic_bool *cancel = nullptr;
    const std::wstring pin = L"测试1234";
    const std::vector<std::string> sites{"z.example", "a.example"};
    static Bytes siteHash(const std::string &s) { return hash(Bytes(s.begin(), s.end())); }
    Bytes exchange(const Bytes &request) {
        check(!request.empty(), "empty request");
        if (request[0] == 4) {
            check(request.size() == 1, "getInfo request");
            return reply(V::map({V::integer(4), V::map({V::string("credMgmt"), boolean(supported),
                V::string("clientPin"), boolean(configured)}), V::integer(6), array({V::integer(1), V::integer(2)})}));
        }
        auto p = ctap::decode(Bytes(request.begin() + 1, request.end()));
        if (request[0] == 6) {
            check(p.at(1).number == 1, "PIN protocol");
            switch (p.at(2).number) {
            case 1: ++retryReads; return reply(V::map({V::integer(3), V::integer(8 - attempts)}));
            case 2: return reply(V::map({V::integer(1), agreement.publicKey()}));
            case 9: {
                ++attempts;
                check(p.at(9).number == 4 && !p.find(10), "CM permission, unbound token");
                shared = agreement.sharedSecret(p.at(3));
                auto raw = utf8(pin); auto digest = hash(Bytes(raw.begin(), raw.end())); digest.resize(16);
                check(ctap::aesCbc(shared, p.at(6).bytes, false) == digest, "encrypted PIN hash");
                if (wrong) return Bytes{0x31};
                return reply(V::map({V::integer(2), V::blob(ctap::aesCbc(shared, token, true))}));
            }
            default: throw std::runtime_error("unexpected PIN command / mutation");
            }
        }
        check(request[0] == 0x0a && attempts == 1, "only authenticated credential management allowed");
        int sub = static_cast<int>(p.at(1).number);
        check(sub >= 1 && sub <= 5, "write command forbidden");
        if (sub != 3 && sub != 5) {
            Bytes message{static_cast<uint8_t>(sub)};
            if (auto params = p.find(2)) { auto body = ctap::encode(*params); message.insert(message.end(), body.begin(), body.end()); }
            auto mac = ctap::hmac(token, message); mac.resize(16);
            check(p.at(3).number == 1 && p.at(4).bytes == mac, "CM HMAC");
        } else check(!p.find(3) && !p.find(4), "next command without HMAC");
        if (sub == 1) {
            ++metadata;
            if (cancel) *cancel = true;
            return reply(V::map({V::integer(1), V::integer(empty ? 0 : badCount ? 4097 : 3), V::integer(2), V::integer(50)}));
        }
        if (sub == 2 || sub == 3) {
            if (sub == 2) rpIndex = 0; else ++rpIndex;
            check(rpIndex < 2, "RP pagination");
            auto value = V::map({V::integer(3), V::map({V::string("id"), V::string(sites[rpIndex])}),
                V::integer(4), V::blob(badHash ? Bytes(32) : siteHash(sites[rpIndex]))});
            if (sub == 2) { value.items.push_back(V::integer(5)); value.items.push_back(V::integer(2)); }
            return reply(value);
        }
        check(rpIndex == 1, "all RPs must be read before credentials");
        if (sub == 4) {
            auto h = p.at(2).at(1).bytes;
            siteIndex = h == siteHash(sites[0]) ? 0 : 1;
            check(h == siteHash(sites[siteIndex]), "credential RP hash");
            userIndex = 0;
        } else ++userIndex;
        check(userIndex < (siteIndex == 0 ? 2 : 1), "credential pagination");
        auto user = V::map({V::string("id"), V::blob(Bytes{static_cast<uint8_t>(siteIndex), static_cast<uint8_t>(userIndex)})});
        if (!siteIndex) {
            user.items.push_back(V::string("name")); user.items.push_back(V::string(userIndex ? "alice@example.test" : "bob@example.test"));
            user.items.push_back(V::string("displayName")); user.items.push_back(V::string("测试账号"));
        }
        auto value = V::map({V::integer(6), user, V::integer(7),
            V::map({V::string("id"), V::blob(Bytes{0x90, static_cast<uint8_t>(siteIndex), static_cast<uint8_t>(userIndex)}),
                    V::string("type"), V::string("public-key")}),
            V::integer(8), V::map({}), V::integer(11), V::blob(Bytes(32, 0xee))});
        if (sub == 4) { value.items.push_back(V::integer(9)); value.items.push_back(V::integer(siteIndex ? 1 : 2)); }
        return reply(value);
    }
    AccountSnapshot run(std::atomic_bool &stop) {
        return ctap::enumerate([&](auto &q) { return exchange(q); }, "test-serial", pin, stop);
    }
};
static void enumeration() {
    std::atomic_bool stop{false};
    Mock m; auto r = m.run(stop);
    check(r.serial == "test-serial" && r.websites == 2 && r.accounts.size() == 3, "account counts");
    check(r.accounts[0].website == L"a.example" && r.accounts[0].account.empty() && r.accounts[0].userId == L"0100", "missing name / ID fallback");
    check(r.accounts[1].account == L"alice@example.test" && r.accounts[1].displayName == L"测试账号", "sort / Unicode names");
    check(m.attempts == 1 && m.metadata == 1, "one PIN attempt");
    Mock empty; empty.empty = true; check(empty.run(stop).accounts.empty() && empty.attempts == 1, "empty still authenticates");
    Mock wrong; wrong.wrong = true;
    std::string message;
    try { wrong.run(stop); } catch (const std::exception &e) { message = e.what(); }
    check(message.find("7") != std::string::npos && wrong.attempts == 1 && wrong.retryReads == 2 && wrong.metadata == 0, "wrong PIN no retry/no listing");
    Mock unset; unset.configured = false; fails([&] { unset.run(stop); }, "unset PIN accepted"); check(unset.attempts == 0, "unset PIN sent");
    Mock unsupported; unsupported.supported = false; fails([&] { unsupported.run(stop); }, "unsupported accepted");
    Mock badCount; badCount.badCount = true; fails([&] { badCount.run(stop); }, "unbounded count accepted");
    Mock badHash; badHash.badHash = true; fails([&] { badHash.run(stop); }, "mismatched RP hash accepted");
    Mock cancel; cancel.cancel = &stop; fails([&] { cancel.run(stop); }, "cancellation ignored");
    Mock before; fails([&] { before.run(stop); }, "early cancellation ignored"); check(before.attempts == 0, "PIN sent after cancellation");
    puts("PASS: read-only multi-RP/multi-account protocol, Unicode, missing names, empty key, wrong PIN single attempt, no PIN, unsupported, counts/hash validation, cancellation");
}
int main() {
    try { agreement(); cbor(); enumeration(); return 0; }
    catch (const std::exception &e) { fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
