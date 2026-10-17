#pragma once
#include "core.h"

namespace relay::backup {
// Only an authentication-tag mismatch, not an IO, format or KDF failure.
struct PasswordError : std::runtime_error { using std::runtime_error::runtime_error; };
// Portable authenticated snapshot envelope, separate from controller-key exports.
// Plaintext contains the complete versioned vault, including PIN retry state.
constexpr size_t maxPlaintext = 8 * 1024 * 1024;
constexpr size_t overhead = 76; // 60-byte authenticated header + 16-byte GCM tag.
Bytes encrypt(const Bytes &plain, const std::wstring &password);
Bytes decrypt(const Bytes &encrypted, const std::wstring &password);
// Cloud vault secret: 128 random bits as 26 Crockford base32 characters. It is
// generated, never chosen, so a leaked cloud ciphertext cannot be brute-forced.
std::wstring newRecoveryCode();
// Accepts any case, spaces and dashes; I/L read as 1, O as 0. Throws on malformed input.
std::wstring recoveryCode(const std::wstring &typed);
std::wstring displayRecoveryCode(const std::wstring &code); // groups: XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX
}
