#pragma once
#include "platform.h"
#include "crypto.h"
#include <array>
#include <vector>
#include <string>
#include <filesystem>
#include <memory>
using Id = std::array<unsigned char, 16>;
using Report = std::array<unsigned char, 63>;
namespace hid { class Device; }
std::string hex(const unsigned char *p, size_t n);
inline Bytes hash(const Bytes &b) { return crypto::sha256(b); }
inline Bytes randomBytes(size_t n) { return crypto::randomBytes(n); }
std::filesystem::path keyPath();
struct Key {
    Key() = default;
    explicit Key(std::unique_ptr<crypto::P256> pair) : pair(std::move(pair)) {}
    Key(const Key &) = delete;
    Key &operator=(const Key &) = delete;
    static std::unique_ptr<Key> generate();
    static std::unique_ptr<Key> fromBlob(const Bytes &b);
    static std::unique_ptr<Key> load();
    Bytes blob() const;
    Bytes pub() const;
    Id id() const;
    Bytes sign(const Bytes &message) const;
    Bytes signDigest(const Bytes &digest) const;
    void save() const;
private:
    std::unique_ptr<crypto::P256> pair;
};
struct Request {
    bool pending = false;
    uint8_t operation = 0, result = 0;
    uint32_t generation = 0, remaining = 0;
    Bytes nonce, rpHash, clientHash;
    std::string rp;
    bool same(const Request &b) const {
        return pending && b.pending && generation == b.generation && nonce == b.nonce;
    }
};
struct PairStatus {
    uint8_t phase = 0, result = 0, count = 0, capacity = 0;
    bool storage = false;
    Id tx{}, pendingId{};
    uint32_t remaining = 0;
    std::array<Id, 4> ids{};
    bool contains(const Id &id) const;
    bool active() const {
        return phase >= 1 && phase <= 6;
    }
};
struct Device {
    std::string serial;
    static std::vector<std::string> enumerate();
    explicit Device(const std::string &selectedSerial = {});
    ~Device();
    Device(const Device &) = delete;
    Report get(uint8_t report);
    void set(uint8_t report, const Bytes &data);
    Request status();
    Request snapshot();
    PairStatus pairStatus();
    Bytes publicKey(); // this device's own key, 0x04 || X || Y
    Id pair(const Key &key);
    Id revoke(const Id &id);
    void cancel(const Id &tx);
    void approve(const Request &request, const Key &key);
private:
    std::unique_ptr<hid::Device> handle;
};
void selfTest();
