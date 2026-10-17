#include "core.h"
#include "device_names.h"
#include "hid.h"
#include <stdexcept>
#include <algorithm>
#include <cstring>

static void check(bool ok, const char *message) {
    if (!ok)
        throw std::runtime_error(message);
}
namespace {
struct Secret {
    Bytes b;
    explicit Secret(Bytes v = {}) : b(std::move(v)) {}
    ~Secret() { wipe(b); }
};
constexpr const char *keyPurpose = "ESP32 controller v2";
}
std::string hex(const unsigned char *p, size_t n) {
    const char *h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s += h[p[i] >> 4];
        s += h[p[i] & 15];
    }
    return s;
}
std::filesystem::path keyPath() {
    return platform::dataDirectory() / ("controller-v2" + platform::protectedExtension());
}
std::unique_ptr<Key> Key::generate() { return std::make_unique<Key>(crypto::P256::generate()); }
std::unique_ptr<Key> Key::fromBlob(const Bytes &b) { return std::make_unique<Key>(crypto::P256::fromBlob(b)); }
Bytes Key::blob() const { return pair->blob(); }
Bytes Key::pub() const { return pair->publicKey(); }
Id Key::id() const {
    auto h = hash(pub());
    Id id{};
    memcpy(id.data(), h.data(), 16);
    return id;
}
Bytes Key::sign(const Bytes &message) const { return pair->sign(message); }
Bytes Key::signDigest(const Bytes &digest) const { return pair->signDigest(digest); }
void Key::save() const {
    auto p = keyPath();
    platform::createPrivateDirectories(p.parent_path());
    Secret raw(blob());
    auto encrypted = platform::protect(raw.b, keyPurpose);
    if (std::filesystem::exists(p)) {
        auto t = std::time(nullptr); auto tm = std::localtime(&t);
        char stamp[64];
        std::strftime(stamp, sizeof(stamp), ".previous-%Y%m%d-%H%M%S", tm);
        auto backup = p;
        backup += stamp + std::string("-") + hex(randomBytes(2).data(), 2);
        std::error_code error;
        check(std::filesystem::copy_file(p, backup, std::filesystem::copy_options::none, error) && !error,
              "无法保存旧密钥备份");
    }
    platform::publishFile(p, encrypted, true, "无法保存本机密钥");
}
std::unique_ptr<Key> Key::load() {
    auto p = keyPath();
    if (!std::filesystem::exists(p))
        return {};
    Secret b(platform::unprotect(platform::readFile(p, 4096, "读取本机密钥失败"), keyPurpose));
    return fromBlob(b.b);
}
static uint32_t u32(const unsigned char *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
static void append(Bytes &b, const unsigned char *p, size_t n) {
    b.insert(b.end(), p, p + n);
}
static void append32(Bytes &b, uint32_t n) {
    for (unsigned i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>(n >> (8 * i)));
}
std::vector<std::string> Device::enumerate() {
    std::vector<std::string> result;
    for (const auto &entry : hid::enumerate(hid::Collection::Control)) result.push_back(entry.serial);
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}
Device::Device(const std::string &selectedSerial)
    : handle(std::make_unique<hid::Device>(hid::Collection::Control, selectedSerial, "所选 ESP32 安全密钥未连接")) {
    serial = handle->serial();
}
Device::~Device() = default;
Report Device::get(uint8_t r) { return handle->getFeature(r); }
void Device::set(uint8_t r, const Bytes &data) { handle->setFeature(r, data.data(), data.size()); }
Request Device::status() {
    auto b = get(1);
    check(!memcmp(b.data(), "PRP2", 4), "设备需要更新为配对版固件 v2");
    Request r;
    r.pending = b[4] != 0;
    r.operation = b[5];
    r.result = b[6];
    r.generation = u32(b.data() + 7);
    r.remaining = u32(b.data() + 11);
    r.nonce.assign(b.begin() + 15, b.begin() + 47);
    return r;
}
Request Device::snapshot() {
    auto r = status();
    if (!r.pending)
        return r;
    auto h = get(2), c = get(9);
    r.rpHash.assign(h.begin(), h.begin() + 32);
    r.clientHash.assign(c.begin(), c.begin() + 32);
    Bytes raw;
    for (uint8_t i : std::array<uint8_t, 5>{5, 6, 7, 8, 10}) {
        auto part = get(i);
        append(raw, part.data(), i == 10 ? 4 : 63);
    }
    auto end = std::find(raw.begin(), raw.end(), 0);
    raw.erase(end, raw.end());
    check(!raw.empty() && raw.size() <= 253 && hash(raw) == r.rpHash, "网站信息与请求不一致");
    for (auto ch : raw)
        check(ch >= 33 && ch <= 126, "网站名称包含无效字符");
    r.rp.assign(raw.begin(), raw.end());
    auto current = status();
    if (!current.same(r))
        return {};
    return r;
}
bool PairStatus::contains(const Id &id) const {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}
PairStatus Device::pairStatus() {
    auto b = get(12);
    check(!memcmp(b.data(), "PRP2", 4), "设备需要更新为配对版固件 v2");
    PairStatus s;
    s.phase = b[4];
    s.result = b[5];
    s.count = b[6];
    s.storage = b[7] != 0;
    memcpy(s.tx.data(), b.data() + 8, 16);
    memcpy(s.pendingId.data(), b.data() + 24, 16);
    s.remaining = u32(b.data() + 40);
    s.capacity = b[44];
    auto a = get(13), d = get(14);
    memcpy(s.ids.data(), a.data(), 48);
    memcpy(s.ids[3].data(), d.data(), 16);
    return s;
}
Bytes Device::publicKey() {
    auto x = get(20), y = get(21);
    Bytes pub{4};
    append(pub, x.data(), 32);
    append(pub, y.data(), 32);
    check(crypto::validP256(pub), "设备没有可用的设备密钥，请更新固件后重新配对");
    return pub;
}
Id Device::pair(const Key &key) {
    auto ps = pairStatus();
    check(ps.storage, "设备授权存储不可用");
    check(!ps.active(), "已有配对请求，请先完成或取消");
    check(!status().pending, "请先结束网页的安全密钥请求");
    auto p = key.pub(), random = randomBytes(16);
    Id tx{};
    memcpy(tx.data(), random.data(), 16);
    Bytes a = random, b = random, c = random;
    append(a, p.data(), 32);
    append(b, p.data() + 32, 33);
    c.push_back(1);
    set(12, a);
    set(13, b);
    set(14, c);
    return tx;
}
Id Device::revoke(const Id &id) {
    auto ps = pairStatus();
    check(!ps.active() && !status().pending, "请先结束当前请求");
    check(ps.contains(id), "找不到此授权");
    auto random = randomBytes(16);
    Id tx{};
    memcpy(tx.data(), random.data(), 16);
    Bytes a = random;
    a.resize(48);
    set(12, a);
    Bytes commit = random;
    commit.push_back(2);
    append(commit, id.data(), 16);
    set(14, commit);
    return tx;
}
void Device::cancel(const Id &tx) {
    Bytes b(tx.begin(), tx.end());
    b.push_back(0);
    set(14, b);
}
void Device::approve(const Request &r, const Key &key) {
    check(status().same(r), "请求已改变，请重新检查网站后确认");
    auto id = key.id();
    check(pairStatus().contains(id), "本机尚未获得该设备授权，请先按 BOOT 配对");
    static const char domain[] = "pico-fido2 remote presence v2";
    Bytes message;
    append(message, (const unsigned char *)domain, sizeof(domain));
    append(message, id.data(), 16);
    append(message, (const unsigned char *)serial.data(), 16);
    message.push_back(r.operation);
    append32(message, r.generation);
    append(message, r.nonce.data(), 32);
    append(message, r.rpHash.data(), 32);
    append(message, r.clientHash.data(), 32);
    auto sig = key.sign(message);
    Bytes selector;
    append32(selector, r.generation);
    append(selector, id.data(), 16);
    set(11, selector);
    Bytes a, b;
    append32(a, r.generation);
    append32(b, r.generation);
    append(a, sig.data(), 32);
    append(b, sig.data() + 32, 32);
    set(3, a);
    set(4, b);
    for (int i = 0; i < 50; i++) {
        auto now = status();
        check(now.generation == r.generation, "请求已改变");
        if (now.result == 1)
            return;
        sleepMs(50);
    }
    throw std::runtime_error("设备未接受确认，请重新发起网页操作");
}
void selfTest() {
    auto k = Key::generate();
    Secret blob(k->blob());
    auto restored = Key::fromBlob(blob.b);
    check(k->id() == restored->id(), "key roundtrip failed");
    auto challenge = randomBytes(32);
    check(crypto::verifyP256(k->pub(), hash(challenge), restored->sign(challenge)), "restored key signing failed");
    check(crypto::validP256(k->pub()) && !crypto::validP256(Bytes(65, 4)), "public key validation failed");
    Secret protectedBlob(platform::protect(blob.b, "self-test"));
    Secret unprotected(platform::unprotect(protectedBlob.b, "self-test"));
    check(blob.b == unprotected.b, "OS data protection roundtrip failed");
    bool wrongPurpose = false;
    try { Secret other(platform::unprotect(protectedBlob.b, "other purpose")); } catch (...) { wrongPurpose = true; }
#ifndef _WIN32
    check(wrongPurpose, "data protection purpose not bound");
#else
    (void)wrongPurpose; // DPAPI descriptions are metadata only.
#endif
    auto digest = hash(Bytes{'a', 'b', 'c'});
    check(hex(digest.data(), digest.size()) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256 vector failed");
}
