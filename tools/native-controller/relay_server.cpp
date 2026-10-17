#include "relay_server.h"
#include "relay_transport.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace relay {
namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Secret { Bytes bytes; ~Secret() { if (!bytes.empty()) secureZero(bytes.data(), bytes.size()); } };
Deadline after(unsigned ms) { return std::chrono::steady_clock::now() + std::chrono::milliseconds(ms); }
}
Server::Server(Vault &vault, const Key &controller, Authorize authorize, Authenticator::Approve approve)
    : identity(Identity::issue(controller)), authorize(std::move(authorize)),
      authenticator(vault, [this, approve = std::move(approve)](const Approval &a, const Operation &op) {
          struct Waiting {
              bool &value;
              explicit Waiting(bool &value) : value(value) { value = true; }
              ~Waiting() { value = false; }
          } waiting(waitingForApproval);
          if (op.canceled && op.canceled()) return Decision{};
          return approve ? approve(a, op) : Decision{};
      }) {}
void Server::session(Socket socket, const Canceled &stop) {
    Tls tls(socket, identity); tls.handshake(after(10000), stop);
    auto nonce = randomBytes(32); uint8_t challengeWire[RELAY_REQUEST_CHALLENGE_SIZE];
    require(relay_request_challenge(nonce.data(), challengeWire), "请求挑战生成失败");
    tls.write(challengeWire, sizeof(challengeWire), after(5000), stop);
    uint8_t header[RELAY_REQUEST_HEADER_SIZE]; tls.read(header, sizeof(header), after(5000), stop);
    relay_request_header_t request{};
    require(relay_request_decode(header, sizeof(header), &request), "请求头格式不正确");
    std::string serial(reinterpret_cast<char *>(request.serial), 16);
    auto device = authorize ? authorize(serial) : Bytes{};
    require(device.size() == 65, "设备没有中转授权");
    // The signature covers the complete request, so read it before verifying;
    // nothing is parsed or acted on until the device key has been checked.
    Secret body{Bytes(request.length)}; tls.read(body.bytes.data(), body.bytes.size(), after(5000), stop);
    auto digest = hash(body.bytes); uint8_t signedContext[RELAY_REQUEST_CONTEXT_SIZE];
    require(relay_request_context(&request, nonce.data(), digest.data(), signedContext) &&
        crypto::verifyP256(device, hash(Bytes(signedContext, signedContext + sizeof(signedContext))), Bytes(request.signature, request.signature + 64)),
        "设备签名无效");
    relay_frame_header_t frame{};
    memcpy(frame.request_id, request.request_id, 16); memcpy(frame.request_hash, digest.data(), 32);
    Operation op; op.deviceSerial = serial; std::copy(request.request_id, request.request_id + 16, op.requestId.begin()); op.deadline = after(RELAY_OPERATION_TIMEOUT_MS);
    std::copy(request.boot_id, request.boot_id + 16, op.bootId.begin());
    auto enrollment = hash(device); std::copy_n(enrollment.begin(), 16, op.enrollmentId.begin());
    auto sendFrame = [&](relay_frame_type_t type, const Bytes &payload) {
        auto f = frame; f.type = type; f.length = static_cast<uint16_t>(payload.size()); uint8_t wire[RELAY_FRAME_HEADER_SIZE];
        require(relay_frame_payload(&f, payload.data(), payload.size()) && relay_frame_encode(&f, wire), "响应帧格式不正确");
        auto deadline = std::min(op.deadline, after(1000));
        tls.write(wire, sizeof(wire), deadline, stop); if (!payload.empty()) tls.write(payload.data(), payload.size(), deadline, stop);
    };
    bool canceled = false; uint8_t incoming[RELAY_FRAME_HEADER_SIZE]; size_t received = 0;
    auto nextKeepalive = std::chrono::steady_clock::now();
    uint8_t lastKeepalive = 0;
    op.canceled = [&] {
        if (canceled || (stop && stop()) || std::chrono::steady_clock::now() >= op.deadline) return true;
        try {
            require(authorize(serial) == device, "设备的中转授权已失效");
            received += tls.poll(incoming + received, sizeof(incoming) - received);
            if (received == sizeof(incoming)) {
                relay_frame_header_t cancel{};
                require(relay_frame_decode(incoming, sizeof(incoming), &cancel) && cancel.type == RELAY_FRAME_CANCEL &&
                    relay_frame_matches(&cancel, frame.request_id, frame.request_hash), "非法取消帧");
                canceled = true; return true;
            }
            uint8_t status = waitingForApproval ? 2 : 1;
            if (status != lastKeepalive || std::chrono::steady_clock::now() >= nextKeepalive) {
                sendFrame(RELAY_FRAME_KEEPALIVE, {status});
                lastKeepalive = status;
                nextKeepalive = after(200);
            }
            return false;
        } catch (...) { canceled = true; return true; }
    };
    auto hints = [&] {
        if (request.version != 4) return; // Existing firmware remains compatible.
        auto metadata = authenticator.discovery(serial);
        if (!metadata.empty()) sendFrame(RELAY_FRAME_DISCOVERY, metadata);
    };
    hints();
    try {
        auto response = authenticator.exchange(body.bytes, op);
        hints();
        // Check cancellation/revocation again before delivering an assertion
        // preflight. Normal per-command TLS teardown after delivery is expected.
        if (op.canceled()) { authenticator.cancel(op); response = {0x2d}; }
        sendFrame(RELAY_FRAME_RESPONSE, response);
    } catch (...) { authenticator.cancel(op); throw; }
}
void Server::run(const std::string &bindAddress, uint16_t port, const Canceled &stop,
                 const std::function<void(uint16_t)> &ready, const std::function<void(const std::string &)> &error,
                 const std::function<void()> &betweenSessions) {
    auto listener = Socket::listen(bindAddress, port); if (ready) ready(listener.port());
    auto nextMaintenance = after(1000);
    while (!stop || !stop()) {
        try {
            if (listener.wait(false, after(1000), stop, 100))
                session(listener.accept(after(1000), stop), stop);
        } catch (const std::exception &e) { if (stop && stop()) break; if (error) error(e.what()); }
        if (stop && stop()) break;
        // Accept first: Windows gives GetInfo only a short discovery window.
        // Credential operations acquire/revalidate their own short transaction;
        // discovery uses public hints from the last validated snapshot.
        // Polling the UI/idle health on every 100 ms accept poll used to add
        // several cloud round trips before even starting the TLS handshake.
        if (betweenSessions && std::chrono::steady_clock::now() >= nextMaintenance) {
            // Ownership failures must escape the connection-error handler so
            // the manager releases the vault, including during steady traffic.
            betweenSessions();
            nextMaintenance = after(1000);
        }
    }
}
}
