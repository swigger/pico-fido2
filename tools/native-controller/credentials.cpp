#include "credentials.h"
#include "../../shared/relay_transport.h"
#include "hid.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

namespace {
void require(bool ok, const char *message = "安全密钥返回了无效的数据") {
    if (!ok) throw std::runtime_error(message);
}
struct Secret {
    Bytes data;
    explicit Secret(Bytes b) : data(std::move(b)) {}
    ~Secret() { if (!data.empty()) secureZero(data.data(), data.size()); }
    Secret(const Secret &) = delete;
    Secret &operator=(const Secret &) = delete;
};
void cancelled(const std::atomic_bool &cancel) {
    require(!cancel.load(), "读取已取消，请重新输入 PIN 解锁");
}
std::string errorText(uint8_t code) {
    switch (code) {
    case 0x06: return "安全密钥正忙，请完成网页登录后重试";
    case 0x2e: return "安全密钥中没有可列出的通行密钥";
    case 0x2f: return "读取已取消";
    case 0x31: return "FIDO PIN 不正确；请确认 PIN 后再试，避免用尽重试次数";
    case 0x32: return "FIDO PIN 已被锁定；程序不会重置或清空安全密钥";
    case 0x33: return "PIN 授权已失效，请重新解锁";
    case 0x34: return "PIN 暂时锁定，请拔插安全密钥后再试";
#ifdef _WIN32
    case 0x35: return "尚未设置 FIDO PIN，请先在 Windows 设置的“账户 → 登录选项 → 安全密钥”中设置 PIN";
#else
    // macOS and Linux have no system setting for this; Chrome manages the key directly.
    case 0x35: return "尚未设置 FIDO PIN。网站登录不受影响；如需查询列表，请在 Chrome 的“设置 → 隐私和安全 → 安全 → 管理安全密钥”中设置 PIN";
#endif
    case 0x36: return "需要先输入 FIDO PIN";
    case 0x38: return "PIN 授权已过期，请重新输入 PIN";
    default: return "安全密钥返回错误 0x" + hex(&code, 1);
    }
}
}

namespace ctap {
Value &Value::operator=(Value other) noexcept {
    std::swap(type, other.type); std::swap(number, other.number);
    bytes.swap(other.bytes); text.swap(other.text); items.swap(other.items);
    return *this; // the replaced buffers are wiped by other's destructor
}
Value::~Value() {
    if (!bytes.empty()) secureZero(bytes.data(), bytes.size());
    if (!text.empty()) secureZero(text.data(), text.size());
}
Value Value::integer(int64_t n) { Value v; v.type = Integer; v.number = n; return v; }
Value Value::blob(Bytes b) { Value v; v.type = ByteString; v.bytes = std::move(b); return v; }
Value Value::string(std::string s) { Value v; v.type = Text; v.text = std::move(s); return v; }
Value Value::map(std::initializer_list<Value> pairs) {
    Value v; v.type = Map; v.items = pairs; require(v.items.size() % 2 == 0); return v;
}
const Value *Value::find(int64_t k) const {
    require(type == Map);
    for (size_t i = 0; i < items.size(); i += 2)
        if (items[i].type == Integer && items[i].number == k) return &items[i + 1];
    return nullptr;
}
const Value *Value::find(const char *k) const {
    require(type == Map);
    for (size_t i = 0; i < items.size(); i += 2)
        if (items[i].type == Text && items[i].text == k) return &items[i + 1];
    return nullptr;
}
const Value &Value::at(int64_t k) const { auto v = find(k); require(v != nullptr); return *v; }
const Value &Value::at(const char *k) const { auto v = find(k); require(v != nullptr); return *v; }
size_t Value::count(size_t max) const {
    require(type == Integer && number >= 0 && static_cast<uint64_t>(number) <= max);
    return static_cast<size_t>(number);
}
std::wstring Value::label() const {
    require(type == Text && text.size() <= 2048);
    auto result = widen(text);
    for (auto &c : result) // avoid control characters/bidi overrides masquerading as another RP
        if (c < 32 || c == 127 || (c >= 0x202a && c <= 0x202e) ||
            (c >= 0x2066 && c <= 0x2069)) c = L'\ufffd';
    return result;
}
static void head(Bytes &b, uint8_t major, uint64_t n) {
    if (n < 24) { b.push_back(static_cast<uint8_t>((major << 5) | n)); return; }
    unsigned size = n <= 0xff ? 1 : n <= 0xffff ? 2 : n <= 0xffffffff ? 4 : 8;
    b.push_back(static_cast<uint8_t>((major << 5) | (size == 1 ? 24 : size == 2 ? 25 : size == 4 ? 26 : 27)));
    for (unsigned i = size; i; --i) b.push_back(static_cast<uint8_t>(n >> ((i - 1) * 8)));
}
static void append(Bytes &to, const Bytes &from) { to.insert(to.end(), from.begin(), from.end()); }
Bytes encode(const Value &v) {
    Bytes b;
    switch (v.type) {
    case Value::Integer:
        head(b, v.number < 0 ? 1 : 0, v.number < 0 ? static_cast<uint64_t>(-(v.number + 1)) : v.number); break;
    case Value::ByteString: head(b, 2, v.bytes.size()); append(b, v.bytes); break;
    case Value::Text: head(b, 3, v.text.size()); b.insert(b.end(), v.text.begin(), v.text.end()); break;
    case Value::Array:
        head(b, 4, v.items.size()); for (const auto &item : v.items) append(b, encode(item)); break;
    case Value::Map: {
        require(v.items.size() % 2 == 0);
        std::vector<std::pair<Bytes, size_t>> keys;
        for (size_t i = 0; i < v.items.size(); i += 2) keys.emplace_back(encode(v.items[i]), i + 1);
        std::sort(keys.begin(), keys.end(), [](const auto &a, const auto &c) {
            return a.first.size() != c.first.size() ? a.first.size() < c.first.size() : a.first < c.first;
        });
        head(b, 5, keys.size());
        Bytes last;
        for (auto &entry : keys) {
            require(last != entry.first); last = entry.first;
            append(b, entry.first); append(b, encode(v.items[entry.second]));
        }
        break;
    }
    case Value::Boolean: b.push_back(v.number ? 0xf5 : 0xf4); break;
    case Value::Null: b.push_back(0xf6); break;
    }
    return b;
}
Value decode(const Bytes &bytes) {
    require(bytes.size() <= 7609);
    size_t offset = 0, nodes = 0;
    std::function<Value(unsigned)> parse = [&](unsigned depth) -> Value {
        require(depth <= 12 && ++nodes <= 2048 && offset < bytes.size());
        uint8_t first = bytes[offset++], major = first >> 5, low = first & 31;
        Value v;
        if (major == 7) {
            require(low == 20 || low == 21 || low == 22);
            v.type = low == 22 ? Value::Null : Value::Boolean; v.number = low == 21; return v;
        }
        uint64_t n = low;
        if (low >= 24) {
            require(low <= 27); unsigned count = 1u << (low - 24);
            require(count <= bytes.size() - offset); n = 0;
            for (unsigned i = 0; i < count; ++i) n = (n << 8) | bytes[offset++];
            require(n >= (count == 1 ? 24ull : 1ull << ((count / 2) * 8)));
        }
        if (major <= 1) {
            require(n <= static_cast<uint64_t>(INT64_MAX));
            return Value::integer(major ? -static_cast<int64_t>(n) - 1 : static_cast<int64_t>(n));
        }
        if (major == 2 || major == 3) {
            require(n <= bytes.size() - offset);
            if (major == 2) v = Value::blob(Bytes(bytes.begin() + offset, bytes.begin() + offset + static_cast<size_t>(n)));
            else {
                v = Value::string(std::string(bytes.begin() + offset, bytes.begin() + offset + static_cast<size_t>(n)));
                (void)widen(v.text); // validate UTF-8, including unused fields
            }
            offset += static_cast<size_t>(n); return v;
        }
        require(major == 4 || major == 5);
        require(n <= 1024 && n * (major == 5 ? 2 : 1) <= bytes.size() - offset);
        v.type = major == 4 ? Value::Array : Value::Map;
        Bytes last;
        for (size_t i = 0; i < n; ++i) {
            auto item = parse(depth + 1);
            if (major == 5) {
                require(item.type == Value::Integer || item.type == Value::Text);
                auto key = encode(item);
                require(last.empty() || (last.size() != key.size() ? last.size() < key.size() : last < key));
                last = std::move(key); v.items.push_back(std::move(item));
                v.items.push_back(parse(depth + 1));
            } else v.items.push_back(std::move(item));
        }
        return v;
    };
    auto v = parse(0); require(offset == bytes.size()); return v;
}
Error::Error(uint8_t c) : std::runtime_error(errorText(c)), code(c) {}
Bytes hmac(const Bytes &key, const Bytes &message) { return crypto::hmacSha256(key, message); }
Bytes aesCbc(const Bytes &key, const Bytes &input, bool encrypt) {
    return aesCbcIv(key, input, encrypt, Bytes(16));
}
Bytes aesCbcIv(const Bytes &key, const Bytes &input, bool encrypt, const Bytes &initialIv) {
    require(key.size() == 32 && !input.empty() && input.size() % 16 == 0);
    require(initialIv.size() == 16);
    return crypto::aesCbc(key, initialIv, input, encrypt);
}
Agreement::Agreement() : key(crypto::P256::generate()) {}
Agreement::~Agreement() = default;
Value Agreement::publicKey() const {
    auto b = key->publicKey();
    return Value::map({Value::integer(1), Value::integer(2), Value::integer(3), Value::integer(-25),
        Value::integer(-1), Value::integer(1), Value::integer(-2), Value::blob(Bytes(b.begin() + 1, b.begin() + 33)),
        Value::integer(-3), Value::blob(Bytes(b.begin() + 33, b.end()))});
}
Bytes Agreement::rawSecret(const Value &peer) const {
    require(peer.type == Value::Map && peer.items.size() == 10);
    require(peer.at(1).type == Value::Integer && peer.at(1).number == 2 &&
            peer.at(3).type == Value::Integer && peer.at(3).number == -25 &&
            peer.at(-1).type == Value::Integer && peer.at(-1).number == 1);
    auto &x = peer.at(-2); auto &y = peer.at(-3);
    require(x.type == Value::ByteString && x.bytes.size() == 32 && y.type == Value::ByteString && y.bytes.size() == 32);
    return key->agree(x.bytes, y.bytes); // big-endian ECDH x coordinate, as CTAP hashes it
}
Bytes Agreement::sharedSecret(const Value &peer) const {
    Secret raw(rawSecret(peer)); return hash(raw.data);
}
AccountSnapshot enumerate(const Exchange &exchange, const std::string &serial,
                          const std::wstring &pin, const std::atomic_bool &cancel) {
    auto call = [&](uint8_t cmd, const Value &params = Value()) {
        cancelled(cancel);
        Bytes request{cmd};
        if (params.type != Value::Null) append(request, encode(params));
        Secret response(exchange(request));
        require(!response.data.empty());
        if (response.data[0]) throw Error(response.data[0]);
        require(response.data.size() > 1);
        Secret body(Bytes(response.data.begin() + 1, response.data.end()));
        return decode(body.data);
    };
    auto info = call(0x04);
    auto *supported = info.at(4).find("credMgmt");
    require(supported && supported->type == Value::Boolean && supported->number,
            "固件未提供凭据管理接口，请先升级固件");
    auto *configured = info.at(4).find("clientPin");
    if (!configured || configured->type != Value::Boolean || !configured->number) throw Error(0x35);
    auto &protocols = info.at(6); require(protocols.type == Value::Array);
    require(std::any_of(protocols.items.begin(), protocols.items.end(), [](auto &v) {
        return v.type == Value::Integer && v.number == 1;
    }), "固件不支持此程序使用的 PIN 协议");
    // One explicit PIN attempt only. Never retry a wrong PIN automatically.
    auto retries = call(0x06, Value::map({Value::integer(1), Value::integer(1), Value::integer(2), Value::integer(1)}));
    if (!retries.at(3).count(255)) throw Error(0x32);
    auto pinText = utf8(pin);
    Secret pinBytes(Bytes(pinText.begin(), pinText.end()));
    secureZero(pinText.data(), pinText.size());
    require(pinBytes.data.size() >= 4 && pinBytes.data.size() <= 63, "请输入有效的 FIDO PIN（UTF-8 长度为 4～63 字节）");
    auto peer = call(0x06, Value::map({Value::integer(1), Value::integer(1), Value::integer(2), Value::integer(2)}));
    Agreement own;
    Secret shared(own.sharedSecret(peer.at(1))), digest(hash(pinBytes.data));
    Secret pinHash(Bytes(digest.data.begin(), digest.data.begin() + 16));
    auto params = Value::map({Value::integer(1), Value::integer(1), Value::integer(2), Value::integer(9),
        Value::integer(3), own.publicKey(), Value::integer(6), Value::blob(aesCbc(shared.data, pinHash.data, true)),
        Value::integer(9), Value::integer(4)}); // credentialManagement permission; no RP binding
    Value auth;
    try { auth = call(0x06, params); }
    catch (const Error &e) {
        if (e.code != 0x31) throw;
        std::string message = e.what();
        try {
            auto left = call(0x06, Value::map({Value::integer(1), Value::integer(1), Value::integer(2), Value::integer(1)}));
            message += "（剩余 " + std::to_string(left.at(3).count(255)) + " 次）";
        } catch (...) {}
        throw std::runtime_error(message);
    }
    require(auth.at(2).type == Value::ByteString && auth.at(2).bytes.size() == 32);
    Secret token(aesCbc(shared.data, auth.at(2).bytes, false));
    auto manage = [&](int sub, const Value &subParams = Value()) {
        auto request = Value::map({Value::integer(1), Value::integer(sub)});
        if (sub != 3 && sub != 5) {
            Bytes message{static_cast<uint8_t>(sub)};
            if (subParams.type != Value::Null) {
                append(message, encode(subParams));
                request.items.push_back(Value::integer(2)); request.items.push_back(subParams);
            }
            Secret signature(hmac(token.data, message));
            request.items.push_back(Value::integer(3)); request.items.push_back(Value::integer(1));
            request.items.push_back(Value::integer(4));
            request.items.push_back(Value::blob(Bytes(signature.data.begin(), signature.data.begin() + 16)));
        }
        return call(0x0a, request);
    };
    AccountSnapshot result; result.serial = serial;
    size_t total = manage(1).at(1).count(4096);
    if (!total) return result; // PIN was still verified on empty keys
    auto rp = manage(2);
    size_t rpCount = rp.at(5).count(total); require(rpCount > 0);
    std::vector<std::pair<std::wstring, Bytes>> rps;
    std::set<Bytes> seenRps;
    // Finish RP enumeration before credential enumeration (authenticators are stateful).
    for (size_t i = 0; i < rpCount; ++i) {
        if (i) rp = manage(3);
        auto name = rp.at(3).at("id").label();
        auto &rpHash = rp.at(4); require(rpHash.type == Value::ByteString && rpHash.bytes.size() == 32 && !name.empty());
        auto rawId = rp.at(3).at("id").text;
        require(hash(Bytes(rawId.begin(), rawId.end())) == rpHash.bytes);
        require(seenRps.insert(rpHash.bytes).second);
        rps.emplace_back(std::move(name), rpHash.bytes);
    }
    std::set<Bytes> seenCredentials;
    for (const auto &site : rps) {
        auto item = manage(4, Value::map({Value::integer(1), Value::blob(site.second)}));
        size_t count = item.at(9).count(total - result.accounts.size()); require(count > 0);
        for (size_t i = 0; i < count; ++i) {
            if (i) item = manage(5);
            const auto &credential = item.at(7).at("id");
            require(credential.type == Value::ByteString && !credential.bytes.empty());
            require(seenCredentials.insert(credential.bytes).second);
            const auto &user = item.at(6), &id = user.at("id");
            require(id.type == Value::ByteString && id.bytes.size() <= 64);
            StoredAccount row; row.website = site.first;
            if (auto value = user.find("name")) row.account = value->label();
            if (auto value = user.find("displayName")) row.displayName = value->label();
            row.userId = widen(hex(id.bytes.data(), id.bytes.size()));
            result.accounts.push_back(std::move(row));
            // Other response fields (public key, credential ID, largeBlobKey) are not exposed.
        }
    }
    require(result.accounts.size() == total, "读取期间凭据发生变化，请重新验证并刷新");
    result.websites = rps.size();
    cancelled(cancel);
    std::stable_sort(result.accounts.begin(), result.accounts.end(), [](auto &a, auto &b) {
        return a.website != b.website ? a.website < b.website : a.account < b.account;
    });
    return result;
}
}

namespace {
struct HidChannel {
    hid::Device device;
    uint32_t channel = 0xffffffff;
    const std::atomic_bool &cancel;
    explicit HidChannel(const std::string &serial, const std::atomic_bool &c)
        : device(hid::Collection::Fido, serial, "未找到对应的 FIDO 接口，请重新连接安全密钥"), cancel(c) {
        auto nonce = randomBytes(8);
        auto init = transact(0x86, nonce);
        require(init.size() == 17 && std::equal(nonce.begin(), nonce.end(), init.begin()));
        channel = u32(init.data() + 8); require(channel && channel != 0xffffffff);
        require((init[16] & 4) != 0, "设备不支持 FIDO2 CBOR");
    }
    static uint32_t u32(const uint8_t *p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
    }
    // Interrupt IO in short slices so cancellation and the deadline stay responsive.
    void send(const std::array<uint8_t, 64> &packet) { cancelled(cancel); device.write(packet); }
    void receive(std::array<uint8_t, 64> &packet, uint64_t deadline) {
        for (;;) {
            cancelled(cancel);
            if (tickMs() >= deadline) throw std::runtime_error("安全密钥响应超时，请重新连接后再试");
            if (device.read(packet, 50)) return;
        }
    }
    Bytes transact(uint8_t cmd, const Bytes &message, unsigned timeout = 15000) {
        require(message.size() <= 7609); cancelled(cancel);
        auto deadline = tickMs() + timeout;
        auto packet = [&] {
            std::array<uint8_t, 64> b{};
            b[0] = uint8_t(channel >> 24); b[1] = uint8_t(channel >> 16);
            b[2] = uint8_t(channel >> 8); b[3] = uint8_t(channel); return b;
        };
        auto initial = packet(); initial[4] = cmd; initial[5] = uint8_t(message.size() >> 8); initial[6] = uint8_t(message.size());
        size_t offset = std::min<size_t>(57, message.size());
        std::copy_n(message.begin(), offset, initial.begin() + 7); send(initial);
        uint8_t sequence = 0;
        while (offset < message.size()) {
            auto b = packet(); b[4] = sequence++;
            auto size = std::min<size_t>(59, message.size() - offset);
            std::copy_n(message.begin() + offset, size, b.begin() + 5); send(b); offset += size;
        }
        Secret responseBuffer(Bytes{});
        auto &response = responseBuffer.data;
        size_t expected = 0; bool started = false; sequence = 0;
        while (true) {
            std::array<uint8_t, 64> b{}; receive(b, deadline);
            if (u32(b.data()) != channel) continue;
            if (b[4] & 0x80) {
                auto length = (size_t(b[5]) << 8) | b[6];
                if (b[4] == 0xbb) { require(length == 1 && (b[7] == 1 || b[7] == 2)); continue; }
                if (b[4] == 0xbf) { require(length == 1); throw ctap::Error(b[7]); }
                require(!started && b[4] == cmd && length <= 7609);
                expected = length; started = true;
                response.insert(response.end(), b.begin() + 7, b.begin() + 7 + std::min<size_t>(57, expected));
            } else {
                require(started && b[4] == sequence++);
                auto length = std::min<size_t>(59, expected - response.size());
                response.insert(response.end(), b.begin() + 5, b.begin() + 5 + length);
            }
            if (started && response.size() == expected) return std::move(response);
        }
    }
};
}
AccountSnapshot readAccounts(const std::string &serial, const std::wstring &pin,
                             const std::atomic_bool &cancel) {
    HidChannel device(serial, cancel);
    return ctap::enumerate([&](const Bytes &request) { return device.transact(0x90, request); }, serial, pin, cancel);
}

bool ctap::queryRelay(const Exchange &exchange, const std::string &rp, const std::string &userName) {
    require(!rp.empty() && rp.size() <= 253 && !userName.empty() && userName.size() <= 64,
            "查询需要完整网站和账号名；账号名最多 64 个 UTF-8 字节");
    auto body = encode(Value::map({Value::integer(1), Value::string(rp), Value::integer(2), Value::string(userName)}));
    body.insert(body.begin(), RELAY_CTAP_EXACT_QUERY);
    auto response = exchange(body); require(!response.empty(), "查询响应为空");
    if (response[0]) throw Error(response[0]);
    auto result = decode(Bytes(response.begin() + 1, response.end()));
    require(result.type == Value::Map && result.items.size() == 2 && result.at(1).type == Value::Boolean,
            "查询响应必须只有一个是／否结果");
    return result.at(1).number != 0;
}
bool queryRelayAccount(const std::string &serial, const std::string &rp, const std::string &userName,
                       const std::atomic_bool &cancel) {
    HidChannel device(serial, cancel);
    return ctap::queryRelay([&](const Bytes &request) { return device.transact(0x90, request, RELAY_OPERATION_TIMEOUT_MS + 5000); }, rp, userName);
}
