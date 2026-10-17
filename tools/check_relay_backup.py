"""Independent portable-vault crypto and recovery checks; disposable fixtures only."""
from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fido2 import cbor
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from check_relay_pin import Bridge, error


PASSWORD = "portable-fixture-password-中文".encode()


def decrypt(blob):
    assert blob[:8] == b"PF2BAK01"
    assert struct.unpack_from("<I", blob, 8)[0] == 600_000
    size = struct.unpack_from("<I", blob, 56)[0]
    assert size + 76 == len(blob)
    key = hashlib.pbkdf2_hmac("sha256", PASSWORD, blob[12:44], 600_000, 32)
    return AESGCM(key).decrypt(blob[44:56], blob[60:], blob[:60])


def encrypt(plain):
    salt, nonce = os.urandom(32), os.urandom(12)
    header = b"PF2BAK01" + struct.pack("<I", 600_000) + salt + nonce + struct.pack("<I", len(plain))
    key = hashlib.pbkdf2_hmac("sha256", PASSWORD, salt, 600_000, 32)
    return header + AESGCM(key).encrypt(nonce, plain, header)


def schema(plain):
    assert plain[:8] == b"PF2VLT02"
    revision, count = struct.unpack_from("<QI", plain, 24)
    pos, records = 36, []
    for _ in range(count):
        size = struct.unpack_from("<I", plain, pos)[0]
        pos += 4
        records.append(cbor.decode(plain[pos:pos + size]))
        pos += size
    pin_count = struct.unpack_from("<H", plain, pos)[0]
    assert pos + 2 + pin_count * 81 == len(plain)
    return revision, records, pos, pin_count


def rejected(executable, blob):
    with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as directory:
        root = Path(directory)
        (root / "backup.pf2bak").write_bytes(blob)
        result = subprocess.run([str(executable), str(root / "pin-test.dpapi"), "--restore"],
            input="", capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == 1, result.stdout
        assert not (root / "pin-test.dpapi").exists()
        assert not (root / "pin-test.dpapi.lock").exists()


def run(executable):
    with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as source:
        root = Path(source)
        with Bridge(executable, root / "pin-test.dpapi") as device:
            ctap, pin = Ctap2(device), "1234-fixture"
            client = ClientPin(ctap)
            client.set_pin(pin)
            rp, digest = "backup-test.invalid", hashlib.sha256(b"backup test client data").digest()
            token = client.get_pin_token(pin, 1, rp)
            created = ctap.make_credential(digest, {"id": rp}, {"id": b"portable-user", "name": "portable-alice"},
                [{"type": "public-key", "alg": -7}], options={"rk": True}, pin_uv_protocol=2,
                pin_uv_param=client.protocol.authenticate(token, digest))
            credential = created.auth_data.credential_data
            credential.public_key.verify(bytes(created.auth_data) + digest, created.att_stmt["sig"])
            allow = [{"type": "public-key", "id": credential.credential_id}]
            signed = ctap.get_assertion(rp, digest, allow)
            assert signed.auth_data.counter == 1
            for _ in range(2):
                error(0x31, lambda: client.get_pin_token("wrong-fixture", 2, rp))
            assert client.get_pin_retries() == (6, False)
            revision = device.revision
            device.control("BACKUP")
            assert device.revision == revision
        archive = (root / "backup.pf2bak").read_bytes()
        assert b"portable-alice" not in archive and pin.encode() not in archive
        plain = decrypt(archive)
        generation, records, pos, pin_count = schema(plain)
        assert generation == revision and len(records) == 1 and pin_count == 1
        assert records[0][1] == credential.credential_id and records[0][2] == rp
        assert records[0][7] == 1 and records[0][8] is True
        assert plain[pos + 2:pos + 18] == b"0123456789abcdef"
        assert plain[-1] == 6
        # Independent AES-GCM encryption, then native import and actual signing.
        with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as destination:
            target = Path(destination)
            (target / "backup.pf2bak").write_bytes(encrypt(plain))
            with Bridge(executable, target / "pin-test.dpapi", restore=True) as restored:
                ctap = Ctap2(restored)
                client = ClientPin(ctap)
                assert restored.revision == revision and client.get_pin_retries() == (6, False)
                signed = ctap.get_assertion(rp, digest, allow)
                assert signed.auth_data.counter == 2 and not signed.auth_data.is_user_verified()
                credential.public_key.verify(bytes(signed.auth_data) + digest, signed.signature)
                token = client.get_pin_token(pin, 2, rp)
                signed = ctap.get_assertion(rp, digest, allow, pin_uv_protocol=2,
                    pin_uv_param=client.protocol.authenticate(token, digest))
                assert signed.auth_data.counter == 3 and signed.auth_data.is_user_verified()
                credential.public_key.verify(bytes(signed.auth_data) + digest, signed.signature)
        # Reject both authenticated schema errors and unauthenticated corruption.
        for index in (0, 8, 12, 44, 56, 60, len(archive) - 1):
            changed = bytearray(archive)
            changed[index] ^= 1
            rejected(executable, bytes(changed))
        for changed in (archive[:-1], archive + b"\0"):
            rejected(executable, changed)
        changes = [plain + b"\0", plain[:24] + bytes(8) + plain[32:], plain[:-1] + b"\x09"]
        # Malformed P-256 private/public halves must fail even with a valid AEAD tag.
        record = dict(records[0])
        key = bytearray(record[6]); key[-1] ^= 1; record[6] = bytes(key)
        encoded = cbor.encode(record)
        changes.append(plain[:36] + struct.pack("<I", len(encoded)) + encoded + plain[pos:])
        changes.append(plain[:pos] + struct.pack("<H", 2) + plain[pos + 2:] * 2)  # duplicate serial
        for changed in changes:
            rejected(executable, encrypt(changed))
        # Offline recovery preserves permanent PIN lockout instead of restoring guesses.
        with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as destination:
            target = Path(destination)
            (target / "backup.pf2bak").write_bytes(encrypt(plain[:-1] + b"\0"))
            with Bridge(executable, target / "pin-test.dpapi", restore=True) as restored:
                client = ClientPin(Ctap2(restored))
                assert client.get_pin_retries()[0] == 0
                error(0x32, lambda: client.get_pin_token(pin, 2, rp))
    print("PASS: independent AES-GCM/PBKDF2 portable backup, credential signatures/counters/PIN recovery and authenticated-schema rejection")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(strict=True))
