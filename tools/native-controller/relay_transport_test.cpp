#include "core.h"
#include "relay_transport.h"
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class T> static bool zero(const T &object) {
    auto p = reinterpret_cast<const uint8_t *>(&object);
    return std::all_of(p, p + sizeof(object), [](auto b) { return !b; });
}
int main() {
    try {
        const uint8_t serial[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

        uint8_t reqNonce[32], challengeWire[RELAY_REQUEST_CHALLENGE_SIZE], parsedNonce[32];
        memset(reqNonce, 0x66, 32);
        check(relay_request_challenge(reqNonce, challengeWire) && !memcmp(challengeWire, "PF2CHL01", 8) &&
            relay_request_challenge_parse(challengeWire, sizeof(challengeWire), parsedNonce) && !memcmp(parsedNonce, reqNonce, 32), "request challenge roundtrip");
        for (size_t n = 0; n < sizeof(challengeWire); ++n) check(!relay_request_challenge_parse(challengeWire, n, parsedNonce), "truncated challenge");
        memset(parsedNonce, 0, 32); check(!relay_request_challenge(parsedNonce, challengeWire), "zero challenge accepted");
        relay_request_header_t request{}; memcpy(request.serial, serial, 16);
        memset(request.request_id, 0x33, 16); request.length = RELAY_CTAP_MAX;
        memset(request.boot_id, 0x55, 16); memset(request.signature, 0x22, 64);
        uint8_t requestWire[RELAY_REQUEST_HEADER_SIZE];
        check(relay_request_encode(&request, requestWire), "request encode");
        check(!memcmp(requestWire, "PF2REQ030123456789ABCDEF", 24) && requestWire[24] == 0x33 && requestWire[40] == 0x55 &&
            requestWire[56] == 0xb8 && requestWire[57] == 7 && requestWire[58] == 0x22 && requestWire[121] == 0x22, "request golden header bytes");
        relay_request_header_t parsed;
        check(relay_request_decode(requestWire, sizeof(requestWire), &parsed) && parsed.length == RELAY_CTAP_MAX &&
            !memcmp(parsed.signature, request.signature, 64), "request roundtrip");
        for (size_t n = 0; n < sizeof(requestWire); ++n)
            check(!relay_request_decode(requestWire, n, &parsed) && zero(parsed), "truncated request kept fields");
        for (unsigned n : {0u, RELAY_CTAP_MAX + 1, 65535u}) {
            requestWire[56] = static_cast<uint8_t>(n); requestWire[57] = static_cast<uint8_t>(n >> 8);
            check(!relay_request_decode(requestWire, sizeof(requestWire), &parsed) && zero(parsed), "invalid CTAP length");
        }
        request.length = 1; check(relay_request_encode(&request, requestWire), "single byte CTAP");
        memset(requestWire + 40, 0, 16); check(!relay_request_decode(requestWire, sizeof(requestWire), &parsed), "missing boot scope accepted");
        check(relay_request_encode(&request, requestWire), "restore header");
        memset(requestWire + 58, 0, 64); check(!relay_request_decode(requestWire, sizeof(requestWire), &parsed), "unsigned request accepted");
        check(relay_request_encode(&request, requestWire), "restore header"); requestWire[7] = '2';
        check(!relay_request_decode(requestWire, sizeof(requestWire), &parsed), "old token request version accepted");
        check(relay_request_encode(&request, requestWire), "restore header");
        requestWire[8] = '/'; check(!relay_request_decode(requestWire, sizeof(requestWire), &parsed) && zero(parsed), "invalid device serial");
        // The signed context binds the challenge, device, boot, request ID, length and body hash.
        uint8_t hashBytes[32], signedContext[RELAY_REQUEST_CONTEXT_SIZE], other[RELAY_REQUEST_CONTEXT_SIZE];
        memset(hashBytes, 0x77, 32); memset(request.signature, 0, 64); // the context does not cover the signature itself
        check(relay_request_context(&request, reqNonce, hashBytes, signedContext) && !memcmp(signedContext, "pico-fido2 relay request v1", 28), "request context");
        auto differs = [&](auto change) { auto copy = request; uint8_t n2[32], h2[32]; memcpy(n2, reqNonce, 32); memcpy(h2, hashBytes, 32);
            change(copy, n2, h2); return relay_request_context(&copy, n2, h2, other) && memcmp(signedContext, other, sizeof(signedContext)); };
        check(differs([](auto &r, auto *, auto *) { r.serial[15] = '0'; }) && differs([](auto &r, auto *, auto *) { r.request_id[0] ^= 1; }) &&
            differs([](auto &r, auto *, auto *) { r.boot_id[0] ^= 1; }) && differs([](auto &r, auto *, auto *) { r.length = 2; }) &&
            differs([](auto &, auto *n, auto *) { n[0] ^= 1; }) && differs([](auto &, auto *, auto *h) { h[0] ^= 1; }), "request context binding");
        memset(parsedNonce, 0, 32); check(!relay_request_context(&request, parsedNonce, hashBytes, other), "zero nonce context");
        relay_frame_header_t frame{}; frame.type = RELAY_FRAME_RESPONSE; frame.length = 2;
        memcpy(frame.request_id, request.request_id, 16); memset(frame.request_hash, 0x44, 32);
        uint8_t frameWire[RELAY_FRAME_HEADER_SIZE]; relay_frame_header_t readFrame;
        check(relay_frame_encode(&frame, frameWire), "frame encode");
        check(!memcmp(frameWire, "PF2F\x01\x00\x02\x00", 8) && frameWire[8] == 0x33 && frameWire[24] == 0x44, "frame golden bytes");
        check(relay_frame_decode(frameWire, sizeof(frameWire), &readFrame) &&
            relay_frame_matches(&readFrame, frame.request_id, frame.request_hash), "frame roundtrip and binding");
        uint8_t body[2]{0, 0xa0}; check(relay_frame_payload(&frame, body, sizeof(body)), "successful response");
        body[0] = 0x27; check(!relay_frame_payload(&frame, body, sizeof(body)), "error response smuggled data");
        frame.request_id[0] ^= 1; check(!relay_frame_matches(&readFrame, frame.request_id, frame.request_hash), "wrong request id"); frame.request_id[0] ^= 1;
        frame.request_hash[0] ^= 1; check(!relay_frame_matches(&readFrame, frame.request_id, frame.request_hash), "wrong request body hash"); frame.request_hash[0] ^= 1;
        for (size_t n = 0; n < sizeof(frameWire); ++n) check(!relay_frame_decode(frameWire, n, &readFrame) && zero(readFrame), "truncated frame");
        frameWire[5] = 1; check(!relay_frame_decode(frameWire, sizeof(frameWire), &readFrame) && zero(readFrame), "reserved frame byte");
        frame.type = RELAY_FRAME_KEEPALIVE; frame.length = 1;
        for (uint8_t status : {uint8_t(1), uint8_t(2)}) check(relay_frame_payload(&frame, &status, 1), "keepalive valid status");
        uint8_t badStatus = 3; check(!relay_frame_payload(&frame, &badStatus, 1), "invalid keepalive status");
        frame.type = RELAY_FRAME_CANCEL; frame.length = 0;
        check(relay_frame_payload(&frame, nullptr, 0) && !relay_frame_payload(&frame, body, 1), "cancel length");
        frame.type = static_cast<relay_frame_type_t>(4); check(!relay_frame_encode(&frame, frameWire) && zero(frameWire), "unknown frame type");
        frame.type = RELAY_FRAME_DISCOVERY; frame.length = RELAY_DISCOVERY_SIZE;
        uint8_t hints[RELAY_DISCOVERY_SIZE]{}; hints[0] = 1; hints[16] = 1; hints[24] = 1;
        check(relay_frame_payload(&frame, hints, sizeof(hints)) && relay_frame_encode(&frame, frameWire), "discovery framing");
        hints[24] = 2; check(!relay_frame_payload(&frame, hints, sizeof(hints)), "invalid PIN hint accepted");
        request.version = 4; memset(request.signature, 1, sizeof(request.signature));
        check(relay_request_context(&request, reqNonce, hashBytes, other) && memcmp(signedContext, other, sizeof(other)), "request version not signed");
        check(relay_request_encode(&request, requestWire) && requestWire[7] == '4' && relay_request_decode(requestWire, sizeof(requestWire), &parsed) && parsed.version == 4, "discovery request version roundtrip");
        relay_transport_clear(&request, sizeof(request)); check(zero(request), "request clearing");
        puts("PASS: signed bounded TLS request, keepalive/cancel framing and secret clearing"); return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
