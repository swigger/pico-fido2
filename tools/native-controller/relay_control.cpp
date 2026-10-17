#include "relay_control.h"
#include "device_names.h"
#include "../../shared/device_restart.h"
#ifdef ENABLE_RELAY_DIAGNOSTICS
#include "../../shared/relay_diagnostics.h"
#include <sstream>
#endif
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
uint16_t read16(const unsigned char *p) { return static_cast<uint16_t>(p[0] | (unsigned(p[1]) << 8)); }
uint32_t read32(const unsigned char *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
void write32(unsigned char *p, uint32_t n) { for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<unsigned char>(n >> (8 * i)); }
struct Secret {
    Bytes bytes;
    explicit Secret(size_t n = 0) : bytes(n) {}
    ~Secret() { if (!bytes.empty()) secureZero(bytes.data(), bytes.size()); }
};
Bytes packet(uint8_t opcode, uint32_t seq, const Id &tx) {
    Bytes b(63); b[0] = opcode; write32(b.data() + 1, seq); memcpy(b.data() + 5, tx.data(), 16); return b;
}
void supported(const Report &b) {
    require(!memcmp(b.data(), "PRL1", 4), "设备固件尚不支持中转设置，请先更新固件");
}
void setupError(const RelayStatus &s) {
    if (s.phase < RELAY_SETUP_ERROR) return;
    switch (s.result) {
    case RELAY_SETUP_UNAUTHORIZED: throw std::runtime_error("配置校验失败：请检查本机配对、安全端 CA 证书或 Wi-Fi 密码加密串是否有效");
    case RELAY_SETUP_BUSY: throw std::runtime_error("设备正在处理其他请求，中转设置已取消");
    case RELAY_SETUP_STORAGE: throw std::runtime_error("配置保存未完成；设备已停止凭证操作，请重新设置并检查设备状态");
    case RELAY_SETUP_TIMEOUT: throw std::runtime_error("配置确认已超时，原有账号不会被删除");
    case RELAY_SETUP_ABORTED: throw std::runtime_error("配置已取消");
    default: throw std::runtime_error("设备拒绝了配置，请重新设置");
    }
}
}
RelayControl::RelayControl(Device &d) : RelayControl(d.serial, [&d](uint8_t r) { return d.get(r); },
    [&d](uint8_t r, const Bytes &b) { d.set(r, b); }) {}
RelayControl::RelayControl(std::string id, std::function<Report(uint8_t)> read,
                           std::function<void(uint8_t, const Bytes &)> write)
    : serial(std::move(id)), get(std::move(read)), set(std::move(write)) {
    require(validDeviceSerial(serial), "设备序列号不正确");
}
RelayStatus RelayControl::status() const {
    Report b{};
    try { b = get(RELAY_HID_STATUS); }
    catch (const std::exception &) {
        throw std::runtime_error("无法读取中转设置，请确认设备固件支持此功能且 USB 连接正常");
    }
    supported(b);
    require(b[11] == RELAY_CONFIG_VERSION && b[4] <= RELAY_SETUP_EXPIRED && b[5] <= RELAY_SETUP_ABORTED &&
        b[6] <= 1 && b[7] <= 1 && b[8] <= 10 && b[9] <= 10 && !(b[10] & ~7) && b[40] <= RELAY_HID_BAD_STATE &&
        b[41] <= 2, "设备返回了不兼容的中转配置状态");
    RelayStatus s;
    s.phase = b[4]; s.result = b[5]; s.runningMode = b[6]; s.storedMode = b[7];
    s.runningNetworks = b[8]; s.storedNetworks = b[9]; s.flags = b[10];
    s.sequence = read32(b.data() + 12); memcpy(s.transaction.data(), b.data() + 16, 16);
    s.received = read16(b.data() + 32); s.expected = read16(b.data() + 34);
    s.remaining = read32(b.data() + 36); s.commandResult = b[40]; s.signatureParts = b[41];
    if (!memcmp(b.data() + 42, "NET1", 4)) {
        s.network = true; s.networkPhase = b[46]; s.wifiReason = b[47]; s.networkFlags = b[48]; s.networkProfile = b[49];
    }
    if (!memcmp(b.data() + 50, "MGT1", 4)) { s.canRestart = (b[54] & 1) != 0; }
    require(s.received <= s.expected && s.expected <= RELAY_CONFIG_MAX_SIZE && s.remaining <= RELAY_SETUP_TIMEOUT_MS,
        "设备返回了无效的中转传输进度");
    return s;
}
RelayStatus RelayControl::send(uint8_t report, const Bytes &data, const Id &tx, uint32_t seq) {
    set(report, data);
    for (unsigned i = 0; i < 200; ++i) {
        auto s = status();
        if (s.transaction == tx && s.sequence == seq) {
            setupError(s);
            require(s.commandResult == RELAY_HID_OK, "设备拒绝了配置数据包，设置已中止");
            return s;
        }
        wait();
    }
    throw std::runtime_error("设备未确认配置数据包，设置已中止");
}
RelayTicket RelayControl::stage(const relay_config_t &config, const Key &key) {
    Secret wire(RELAY_CONFIG_MAX_SIZE); size_t length = 0;
    require(relay_config_encode(&config, wire.bytes.data(), wire.bytes.size(), &length) == RELAY_CONFIG_OK,
            "模式、Wi-Fi、安全端地址、端口或证书配置不完整");
    wire.bytes.resize(length);
    auto initial = status();
    require((initial.flags & RELAY_HID_STORAGE_READY) && !initial.active(), "设备配置存储不可用或正在设置中");
    RelayTicket ticket;
    auto tx = randomBytes(16); memcpy(ticket.transaction.data(), tx.data(), 16);
    ticket.digest = hash(wire.bytes);
    uint32_t seq = 1;
    auto begin = packet(RELAY_HID_BEGIN, seq, ticket.transaction);
    begin[21] = static_cast<unsigned char>(length); begin[22] = static_cast<unsigned char>(length >> 8);
    try {
        send(16, begin, ticket.transaction, seq);
        auto challenge = get(17); supported(challenge);
        require(!memcmp(challenge.data() + 4, ticket.transaction.data(), 16) &&
                read16(challenge.data() + 52) == length && read32(challenge.data() + 54) > 0,
                "设备的配置挑战已改变");
        const char domain[] = "pico-fido2 relay setup v1";
        Secret message;
        message.bytes.insert(message.bytes.end(), domain, domain + sizeof(domain));
        message.bytes.insert(message.bytes.end(), serial.begin(), serial.end());
        message.bytes.insert(message.bytes.end(), tx.begin(), tx.end());
        auto id = key.id(); message.bytes.insert(message.bytes.end(), id.begin(), id.end());
        message.bytes.insert(message.bytes.end(), challenge.begin() + 20, challenge.begin() + 52);
        for (unsigned i = 0; i < 4; ++i) message.bytes.push_back(static_cast<unsigned char>(length >> (8 * i)));
        message.bytes.insert(message.bytes.end(), wire.bytes.begin(), wire.bytes.end());
        auto signature = key.sign(message.bytes);
        require(signature.size() == 64, "配置签名长度不正确");
        for (size_t offset = 0; offset < length;) {
            size_t n = std::min<size_t>(RELAY_HID_CHUNK_SIZE, length - offset);
            Secret part; part.bytes = packet(RELAY_HID_DATA, ++seq, ticket.transaction);
            part.bytes[21] = static_cast<unsigned char>(offset); part.bytes[22] = static_cast<unsigned char>(offset >> 8);
            part.bytes[23] = static_cast<unsigned char>(n);
            memcpy(part.bytes.data() + 24, wire.bytes.data() + offset, n);
            auto s = send(17, part.bytes, ticket.transaction, seq);
            require(s.received == offset + n, "设备未保存完整配置数据包");
            offset += n;
        }
        for (unsigned i = 0; i < 2; ++i) {
            auto part = packet(RELAY_HID_SIGNATURE, ++seq, ticket.transaction);
            part[21] = static_cast<unsigned char>(i); memcpy(part.data() + 22, signature.data() + i * 32, 32);
            auto s = send(18, part, ticket.transaction, seq);
            require(s.signatureParts == i + 1, "设备未接收完整配置签名");
        }
        auto seal = packet(RELAY_HID_FINISH, ++seq, ticket.transaction);
        memcpy(seal.data() + 21, id.data(), 16);
        auto current = send(19, seal, ticket.transaction, seq);
        for (unsigned i = 0; current.phase == RELAY_SETUP_VERIFY && i < 300; ++i) { wait(); current = status(); }
        require(current.transaction == ticket.transaction, "配置事务已改变");
        setupError(current);
        require(current.phase >= RELAY_SETUP_RELEASE && current.phase <= RELAY_SETUP_DONE,
            "设备未完成配置签名校验");
        return ticket;
    } catch (...) {
        try { cancel(ticket.transaction); } catch (...) {}
        throw;
    }
}
bool RelayControl::completed(const RelayTicket &ticket) const {
    auto current = status();
    require(current.transaction == ticket.transaction, "配置事务已改变");
    setupError(current);
    if (current.phase != RELAY_SETUP_DONE) return false;
    auto digest = get(RELAY_HID_DIGEST); supported(digest);
    require(ticket.digest.size() == 32 && !memcmp(digest.data() + 4, ticket.digest.data(), 32) &&
            (digest[36] & RELAY_HID_REBOOT_REQUIRED), "设备保存的配置与本次设置不一致");
    return true;
}
void RelayControl::cancel(const Id &tx) {
    auto current = status();
    if (current.transaction != tx || !current.active()) return;
    require(current.sequence != UINT32_MAX, "配置数据包序号已耗尽");
    auto b = packet(RELAY_HID_CANCEL, current.sequence + 1, tx);
    set(16, b);
    for (unsigned i = 0; i < 200; ++i) {
        current = status();
        require(current.transaction == tx, "配置事务已改变");
        if (!current.active()) return;
        wait();
    }
    throw std::runtime_error("取消设置未获确认，请等待设备的配置超时");
}
relay_config_t RelayControl::readConfig() const {
    auto initial = status();
    require((initial.flags & RELAY_HID_STORAGE_READY) && !initial.active(),
            "设备配置存储不可用或正在设置中");
    Id tx{};
    auto random = randomBytes(16);
    memcpy(tx.data(), random.data(), 16);
    secureZero(random.data(), random.size());
    Bytes wire;
    uint16_t total = 0;
    for (uint16_t offset = 0;;) {
        auto request = packet(RELAY_HID_READ_REQUEST, 1, tx);
        request[21] = static_cast<unsigned char>(offset);
        request[22] = static_cast<unsigned char>(offset >> 8);
        set(16, request);
        Report page{};
        bool received = false;
        for (unsigned i = 0; i < 200; ++i) {
            try { page = get(RELAY_HID_READ); }
            catch (const std::exception &) {
                // A read request is queued before its first page exists; give the
                // device a short window before deciding the firmware is old.
                if (i < 50) { wait(); continue; }
                throw std::runtime_error("设备固件尚不支持读取设置，请先更新固件");
            }
            if (!memcmp(page.data(), RELAY_HID_READ_MAGIC, 4) &&
                !memcmp(page.data() + 4, tx.data(), 16) && read16(page.data() + 22) == offset) {
                received = true;
                break;
            }
            wait();
        }
        require(received, "设备未响应读取设置请求");
        uint16_t reported = read16(page.data() + 20);
        if (!total) {
            require(reported >= RELAY_CONFIG_HEADER_SIZE && reported <= RELAY_CONFIG_MAX_SIZE,
                    "设备返回的配置长度不正确");
            total = reported;
            wire.reserve(total);
        } else {
            require(reported == total, "设备配置在读取过程中改变");
        }
        uint8_t length = page[24];
        require(length <= RELAY_HID_READ_CHUNK_SIZE && offset + length <= total,
                "设备返回了无效的配置分片");
        require(length || offset == total, "设备返回了空配置分片");
        wire.insert(wire.end(), page.begin() + 25, page.begin() + 25 + length);
        offset = static_cast<uint16_t>(offset + length);
        if (offset == total) break;
    }
    relay_config_t config{};
    require(relay_config_decode(wire.data(), wire.size(), &config) == RELAY_CONFIG_OK,
            "设备返回的配置不完整");
    return config;
}
void RelayControl::reboot(const Key &key) {
    auto s = status();
    require(s.canRestart, "设备固件尚不支持重启指令，请先更新固件或手动拔插");
    require(!s.active(), "设备正在写入配置，请完成后再重启");
    auto tx = randomBytes(16);
    auto send = [&](uint8_t report, const Bytes &b, uint8_t phase, uint8_t parts) {
        set(report, b);
        for (unsigned i = 0; i < 200; ++i) {
            auto r = get(DEVICE_RESTART_REPORT);
            require(!memcmp(r.data(), "PRS1", 4), "设备返回了不兼容的重启状态");
            if (!memcmp(r.data() + 8, tx.data(), 16)) {
                require(r[4] != DEVICE_RESTART_FAILED, r[5] == DEVICE_RESTART_BUSY ? "设备正忙，未执行重启" : "重启请求被拒绝，请检查本机配对或重新尝试");
                if (r[4] == phase && r[6] == parts) return r;
            }
            wait();
        }
        throw std::runtime_error("设备未确认重启请求，请检查连接状态");
    };
    Bytes b(63); b[0] = 1; memcpy(b.data() + 1, tx.data(), 16);
    auto challenge = send(DEVICE_RESTART_REPORT, b, DEVICE_RESTART_CHALLENGE, 0);
    device_restart_t context{}; memcpy(context.serial, serial.data(), 16); memcpy(context.transaction, tx.data(), 16);
    memcpy(context.nonce, challenge.data() + 24, 32);
    uint8_t message[128]; auto id = key.id(); size_t length = device_restart_message(&context, id.data(), message);
    auto signature = key.sign(Bytes(message, message + length)); require(signature.size() == 64, "重启签名长度错误");
    for (uint8_t i = 0; i < 2; ++i) {
        b.assign(63, 0); b[0] = i; memcpy(b.data() + 1, tx.data(), 16); memcpy(b.data() + 17, signature.data() + 32 * i, 32);
        send(DEVICE_RESTART_SIGNATURE_REPORT, b, DEVICE_RESTART_CHALLENGE, i + 1);
    }
    b.assign(63, 0); b[0] = 2; memcpy(b.data() + 1, tx.data(), 16); memcpy(b.data() + 17, id.data(), 16);
    send(DEVICE_RESTART_REPORT, b, DEVICE_RESTART_ACCEPTED, 0);
}
#ifdef ENABLE_RELAY_DIAGNOSTICS
std::string RelayControl::diagnostics() const {
    auto capabilities = get(RELAY_HID_STATUS);
    require(!memcmp(capabilities.data() + 50, "MGT1", 4) && (capabilities[54] & 2), "当前固件未启用诊断");
    static_assert(sizeof(relay_diag_record_t) == 280, "diagnostic layout");
    auto tx = randomBytes(16); Bytes bytes;
    constexpr unsigned pages = (sizeof(relay_diag_record_t) + RELAY_DIAGNOSTIC_CHUNK - 1) / RELAY_DIAGNOSTIC_CHUNK;
    for (uint8_t page = 0; page < pages; ++page) {
        Bytes request(63); request[1] = page; memcpy(request.data() + 2, tx.data(), 16);
        set(RELAY_DIAGNOSTIC_REPORT, request);
        Report r{}; bool found = false;
        for (unsigned i = 0; i < 200; ++i) {
            try { r = get(RELAY_DIAGNOSTIC_REPORT); } catch (...) { wait(); continue; }
            if (!memcmp(r.data(), "PDG2", 4) && !memcmp(r.data() + 4, tx.data(), 16) && !r[20] && r[21] == page) { found = true; break; }
            wait();
        }
        size_t n = std::min<size_t>(RELAY_DIAGNOSTIC_CHUNK, sizeof(relay_diag_record_t) - bytes.size());
        require(found && r[22] == pages && r[24] == n, "诊断读取失败或版本不兼容");
        bytes.insert(bytes.end(), r.begin() + 25, r.begin() + 25 + n);
    }
    relay_diag_record_t record{}; memcpy(&record, bytes.data(), sizeof(record));
    require(record.count <= RELAY_DIAGNOSTIC_EVENTS, "诊断事件数量无效");
    std::ostringstream out;
    out << "reset=" << record.reset_reason << " uptime_ms=" << record.uptime_ms << " usb=" << unsigned(record.usb)
        << " network_phase=" << unsigned(record.network[0]) << " wifi_reason=" << unsigned(record.network[1])
        << " network_flags=" << unsigned(record.network[2]) << " profile=" << unsigned(record.network[3]) << "\n";
    std::stable_sort(record.events, record.events + record.count, [](const auto &a, const auto &b) { return a.ms < b.ms; });
    static const char *names[] = {"?", "USB", "HID", "CTAP", "RESULT", "NETWORK", "RESTART"};
    for (unsigned i = 0; i < record.count; ++i) {
        const auto &e = record.events[i]; out << e.ms << "ms " << (e.kind < 7 ? names[e.kind] : "?")
            << " code=0x" << std::hex << unsigned(e.code) << std::dec << " value=" << e.value << "\n";
    }
    return out.str();
}
#endif
