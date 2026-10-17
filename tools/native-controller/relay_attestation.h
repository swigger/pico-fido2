#pragma once
#include "core.h"

namespace relay {
// Separate from credential and TLS keys; stored inside the encrypted vault.
struct Attestation {
    Bytes privateKey, certificate;
    Attestation() = default;
    Attestation(const Attestation &) = default;
    Attestation(Attestation &&) noexcept = default;
    Attestation &operator=(Attestation other) noexcept;
    ~Attestation();
    static Attestation generate();
    void validate() const;
};
}
