#pragma once
#include "core.h"
#include <atomic>
#include <functional>
#include <stdexcept>

struct StoredAccount {
    std::wstring website, account, displayName, userId;
};
struct AccountSnapshot {
    std::string serial;
    std::vector<StoredAccount> accounts;
    size_t websites = 0;
};
// The caller owns and wipes the PIN. No PIN, token, or credential data is saved.
AccountSnapshot readAccounts(const std::string &serial, const std::wstring &pin,
                             const std::atomic_bool &cancel);
bool queryRelayAccount(const std::string &serial, const std::string &rp, const std::string &userName,
                       const std::atomic_bool &cancel);

namespace ctap {
struct Value {
    enum Type { Integer, ByteString, Text, Array, Map, Boolean, Null } type = Null;
    int64_t number = 0;
    Bytes bytes;
    std::string text;
    std::vector<Value> items; // maps contain alternating keys and values
    Value() = default;
    Value(const Value &) = default;
    Value(Value &&) noexcept = default;
    Value &operator=(Value other) noexcept;
    ~Value();
    static Value integer(int64_t n);
    static Value blob(Bytes b);
    static Value string(std::string s);
    static Value map(std::initializer_list<Value> pairs);
    const Value &at(int64_t key) const;
    const Value &at(const char *key) const;
    const Value *find(int64_t key) const;
    const Value *find(const char *key) const;
    size_t count(size_t max) const;
    std::wstring label() const;
};
Bytes encode(const Value &v);
Value decode(const Bytes &b);
struct Error : std::runtime_error {
    uint8_t code;
    explicit Error(uint8_t code);
};
using Exchange = std::function<Bytes(const Bytes &)>;
// Exact vendor query; successful response contains only one boolean field.
bool queryRelay(const Exchange &exchange, const std::string &rp, const std::string &userName);
// Transport injection supports protocol tests without touching a real key.
AccountSnapshot enumerate(const Exchange &exchange, const std::string &serial,
                          const std::wstring &pin, const std::atomic_bool &cancel);
Bytes hmac(const Bytes &key, const Bytes &message);
Bytes aesCbc(const Bytes &key, const Bytes &input, bool encrypt);
Bytes aesCbcIv(const Bytes &key, const Bytes &input, bool encrypt, const Bytes &iv);
struct Agreement {
    std::unique_ptr<crypto::P256> key;
    Agreement();
    ~Agreement();
    Agreement(const Agreement &) = delete;
    Agreement &operator=(const Agreement &) = delete;
    Value publicKey() const;
    Bytes rawSecret(const Value &peer) const;
    Bytes sharedSecret(const Value &peer) const;
};
}
