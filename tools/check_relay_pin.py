"""Independent ClientPIN interoperability checks. Temporary vaults only; no hardware.

Uses the pinned python-fido2 dependency from requirements-test.txt to generate all
key agreement, HKDF, AES-CBC and HMAC messages independently of native code.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

from fido2 import cbor
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2


class Bridge(CtapDevice):
    capabilities = 4

    def __init__(self, executable: Path, path: Path, legacy=False, restore=False):
        self.process = subprocess.Popen(
            [str(executable), str(path)] + (["--legacy"] if legacy else []) + (["--restore"] if restore else []), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.serial = "0123456789ABCDEF"
        self.boot, self.enrollment = "11" * 16, "22" * 16
        self.mode = self.seconds = self.decisions = self.revision = 0
        self.closed = False

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == 0x10
        return self.control(f"{self.serial} {self.boot} {self.enrollment} {self.mode} {self.seconds} {data.hex()}")

    def control(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("native adapter exited: " + self.process.stderr.read())
        response, decisions, revision = line.split()
        self.decisions, self.revision = int(decisions), int(revision)
        return bytes.fromhex(response)

    @classmethod
    def list_devices(cls):
        return iter(())

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()  # Only the test adapter created above.
                self.process.wait(timeout=5)
        error = self.process.stderr.read()
        self.process.stdout.close()
        self.process.stderr.close()
        assert self.process.returncode == 0, error


def error(code, operation):
    try:
        operation()
    except CtapError as exc:
        assert exc.code == code, (hex(code), exc)
    else:
        raise AssertionError(f"expected CTAP error {code:02x}")


def run_protocol(executable, protocol_type):
    with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as directory:
        path = Path(directory) / "pin-test.dpapi"
        device = Bridge(executable, path)
        try:
            ctap = Ctap2(device)
            client = ClientPin(ctap, protocol_type())
            protocol = client.protocol
            rp, pin = "pin-test.invalid", "1234-test"
            digest = hashlib.sha256(b"independent client data").digest()
            assert ctap.info.options["clientPin"] is False
            assert "uv" not in ctap.info.options
            assert ctap.info.pin_uv_protocols == [2, 1]
            assert client.get_pin_retries() == (8, False)

            def presence_probes(expected):
                # CTAP 2.0 selection: an empty auth parameter is not a bad PIN.
                # Auto-select without a callback, return PIN state, persist nothing.
                requests = (
                    lambda: ctap.make_credential(digest, {"id": rp}, {"id": b"probe"},
                        [{"type": "public-key", "alg": -7}], pin_uv_param=b"",
                        pin_uv_protocol=protocol.VERSION),
                    lambda: ctap.get_assertion(rp, digest, pin_uv_param=b"",
                        pin_uv_protocol=protocol.VERSION),
                )
                before_revision = device.revision
                before_retries = client.get_pin_retries()
                for request in requests:
                    for mode in (0, 1, 2):
                        device.mode = mode
                        before_decisions = device.decisions
                        error(expected, request)
                        assert device.decisions == before_decisions
                        assert device.revision == before_revision
                device.mode = 0
                assert client.get_pin_retries() == before_retries

            presence_probes(0x35)  # PIN_NOT_SET, without any dialog.

            # Bad authenticated ciphertext and invalid Unicode code-point lengths
            # must fail without setting a PIN or decrementing any retries.
            peer, shared = client._get_shared_secret()
            encrypted = protocol.encrypt(shared, b"1234" + bytes(60))
            invalid_peer = {1: 2, 3: -25, -1: 1, -2: bytes(32), -3: bytes(32)}
            error(0x02, lambda: ctap.client_pin(protocol.VERSION, 3, key_agreement=invalid_peer,
                new_pin_enc=encrypted, pin_uv_param=bytes(16 if protocol.VERSION == 1 else 32)))
            error(0x33, lambda: ctap.client_pin(protocol.VERSION, 3, key_agreement=peer,
                new_pin_enc=encrypted, pin_uv_param=bytes(16 if protocol.VERSION == 1 else 32)))
            for short in ("中", "中文测"):
                raw = short.encode()
                encrypted = protocol.encrypt(shared, raw + bytes(64 - len(raw)))
                error(0x37, lambda: ctap.client_pin(protocol.VERSION, 3, key_agreement=peer,
                    new_pin_enc=encrypted, pin_uv_param=protocol.authenticate(shared, encrypted)))
            assert ctap.get_info().options["clientPin"] is False
            device.mode = 1
            before = device.revision
            error(0x27, lambda: client.set_pin(pin))
            assert device.revision == before
            device.mode = 0
            client.set_pin(pin)
            assert ctap.get_info().options["clientPin"] is True
            presence_probes(0x31)  # PIN_INVALID is the specified selection reply.
            error(0x33, lambda: client.set_pin("another-pin"))

            def token(permission=3, site=rp, value=None):
                before_decisions = device.decisions
                try:
                    return client.get_pin_token(pin if value is None else value, permission, site)
                finally:
                    assert device.decisions == before_decisions, "PIN verification opened an approval"

            def make(auth=None, site=rp, protocol_id=None):
                return ctap.make_credential(digest, {"id": site}, {"id": b"user", "name": "alice"},
                    [{"type": "public-key", "alg": -7}], options={"rk": True},
                    pin_uv_param=auth, pin_uv_protocol=protocol_id)

            error(0x36, make)
            error(0x40, lambda: token(4))  # No credential-management capability.
            error(0x40, lambda: token(64))  # No persistent management either.
            error(0x14, lambda: client.get_pin_token(pin, 1))  # Scoped token needs RP.
            # getPinToken (legacy subcommand 5) explicitly forbids scope fields.
            # Reject before consent, retry commits or replacing an existing token.
            existing = token(1)
            peer, shared = client._get_shared_secret()
            pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
            for extra in ({"permissions": 4}, {"permissions_rpid": "other.invalid"},
                          {"permissions": 1, "permissions_rpid": rp}):
                before_decisions, before_revision = device.decisions, device.revision
                before_retries = client.get_pin_retries()
                error(0x02, lambda: ctap.client_pin(protocol.VERSION, 5,
                    key_agreement=peer, pin_hash_enc=protocol.encrypt(shared, pin_hash), **extra))
                assert device.decisions == before_decisions
                assert device.revision == before_revision
                assert client.get_pin_retries() == before_retries
            rejected_scope = make(protocol.authenticate(existing, digest), protocol_id=protocol.VERSION)
            assert rejected_scope.auth_data.is_user_verified()
            t = token(2)
            error(0x33, lambda: make(protocol.authenticate(t, digest), protocol_id=protocol.VERSION))
            t = token(1, "other.invalid")
            error(0x33, lambda: make(protocol.authenticate(t, digest), protocol_id=protocol.VERSION))

            t = token(1)
            auth_param = protocol.authenticate(t, digest)
            before = device.decisions
            created = make(auth_param, protocol_id=protocol.VERSION)
            assert device.decisions == before + 1  # Token does not grant presence.
            assert created.auth_data.is_user_verified() and created.auth_data.is_user_present()
            public = created.auth_data.credential_data.public_key
            public.verify(bytes(created.auth_data) + digest, created.att_stmt["sig"])
            credential = created.auth_data.credential_data.credential_id
            error(0x33, lambda: make(auth_param, protocol_id=protocol.VERSION))  # consumed

            def assertion(t=None, site=rp, protocol_id=None):
                return ctap.get_assertion(site, digest, [{"type": "public-key", "id": credential}],
                    pin_uv_param=None if t is None else protocol.authenticate(t, digest), pin_uv_protocol=protocol_id)

            t = token(2)
            signed = assertion(t, protocol_id=protocol.VERSION)
            assert signed.auth_data.is_user_verified()
            public.verify(bytes(signed.auth_data) + digest, signed.signature)
            error(0x33, lambda: assertion(t, protocol_id=protocol.VERSION))
            plain = assertion()
            assert plain.auth_data.is_user_present() and not plain.auth_data.is_user_verified()

            t = token(2)
            device.mode = 1
            error(0x27, lambda: assertion(t, protocol_id=protocol.VERSION))
            device.mode = 0
            error(0x33, lambda: assertion(t, protocol_id=protocol.VERSION))
            t = token(2)
            device.seconds += 30
            error(0x38, lambda: assertion(t, protocol_id=protocol.VERSION))
            t = token(2)
            device.boot = "33" * 16
            error(0x33, lambda: assertion(t, protocol_id=protocol.VERSION))
            t = token(2)
            device.enrollment = "44" * 16
            error(0x33, lambda: assertion(t, protocol_id=protocol.VERSION))

            # PIN and tokens belong to a canonical device identity, including
            # case aliases; another enrolled device gets neither capability.
            device.serial = device.serial.lower()
            assert ctap.get_info().options["clientPin"] is True
            t = token(2)
            device.serial = "fedcba9876543210"
            assert ctap.get_info().options["clientPin"] is False
            error(0x35, lambda: assertion(t, protocol_id=protocol.VERSION))
            client.set_pin(pin)
            error(0x33, lambda: assertion(t, protocol_id=protocol.VERSION))
            device.control("RESET_PIN")
            device.serial = "0123456789abcdef"

            # A successful PIN change invalidates an outstanding token and accepts
            # four Unicode scalar values, independent of UTF-8 byte count.
            t = token(2)
            client.change_pin(pin, "中文测试")
            pin = "中文测试"
            error(0x33, lambda: assertion(t, protocol_id=protocol.VERSION))
            token(2)
            legacy = client.get_pin_token(pin)  # CTAP2.0 getPinToken subcommand 5
            before_decisions = device.decisions
            # Both legacy and scoped token issuance ignore approval policy, but
            # that must not approve an assertion or a PIN change.
            device.mode = 1
            legacy = client.get_pin_token(pin)
            token(2)
            assert device.decisions == before_decisions
            error(0x27, lambda: client.change_pin(pin, "denied-new-pin"))
            device.mode = 0
            legacy = client.get_pin_token(pin)
            assert assertion(legacy, protocol_id=protocol.VERSION).auth_data.is_user_verified()
            device.mode = 2
            before = device.revision
            error(0x2d, lambda: client.change_pin(pin, "canceled-new-pin"))
            assert device.revision == before
            device.mode = 0

            for expected in (0x31, 0x31, 0x34):
                error(expected, lambda: token(value="wrong-pin"))
            assert client.get_pin_retries() == (5, True)
            error(0x34, token)
            device.boot = "55" * 16
            assert client.get_pin_retries() == (5, False)
            token()
            assert client.get_pin_retries() == (8, False)
            error(0x31, lambda: token(value="wrong-pin"))
            assert client.get_pin_retries() == (7, False)

            device.close()
            device = Bridge(executable, path)
            ctap = Ctap2(device)
            client = ClientPin(ctap, protocol_type())
            assert client.get_pin_retries() == (7, False)  # Persistent retry decrement.
            for expected in (0x31, 0x31, 0x34):
                error(expected, lambda: token(value="wrong-pin"))
            device.boot = "66" * 16
            for expected in (0x31, 0x31, 0x34):
                error(expected, lambda: token(value="wrong-pin"))
            device.boot = "77" * 16
            error(0x32, lambda: token(value="wrong-pin"))
            assert client.get_pin_retries()[0] == 0
            error(0x32, token)
            device.close()
            device = Bridge(executable, path)
            client = ClientPin(Ctap2(device), protocol_type())
            assert client.get_pin_retries()[0] == 0
            error(0x32, token)  # Restart does not resurrect eight guesses.
            device.control("RESET_PIN")  # Explicit local safe-end recovery, not CTAP.
            ctap = Ctap2(device)
            assert ctap.info.options["clientPin"] is False
            recovered = assertion()
            public.verify(bytes(recovered.auth_data) + digest, recovered.signature)
            device.close()
            device = Bridge(executable, path, legacy=True)
            ctap = Ctap2(device)
            client = ClientPin(ctap, protocol_type())
            assert not ctap.info.options["clientPin"]
            migrated = assertion()
            public.verify(bytes(migrated.auth_data) + digest, migrated.signature)
            client.set_pin(pin)  # First write upgrades the old format with credentials intact.
            assert assertion(token(2), protocol_id=protocol.VERSION).auth_data.is_user_verified()
        finally:
            device.close()
    print(f"PASS: independent python-fido2 PIN protocol {protocol_type.VERSION}, signed UV, scoping, consent, retry persistence and lockout")


def failed_write(executable):
    with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as directory:
        path = Path(directory) / "pin-test.dpapi"
        device = Bridge(executable, path)
        try:
            ctap = Ctap2(device)
            client = ClientPin(ctap)
            client.set_pin("1234-test")
            device.mode = 3
            before = device.revision
            error(0x7f, lambda: client.get_pin_token("1234-test", 3, "pin-test.invalid"))
            assert device.revision == before
            device.mode = 0
            error(0x7f, client.get_pin_retries)  # Ambiguous write latches fault.
        finally:
            device.close()
        with Bridge(executable, path) as reopened:
            assert ClientPin(Ctap2(reopened)).get_pin_retries() == (8, False)
    print("PASS: failed retry commit returns no PIN token and stops subsequent work")


def run_preflight(executable, protocol_type):
    with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as folder:
        with Bridge(executable, Path(folder) / "pin-test.dpapi") as device:
            ctap = Ctap2(device)
            protocol = protocol_type()
            client = ClientPin(ctap, protocol)
            rp, pin = "preflight.invalid", "synthetic-pin-1234"
            digest = hashlib.sha256(b"one browser login challenge").digest()
            client.set_pin(pin)

            def token(legacy=False):
                return client.get_pin_token(pin) if legacy else client.get_pin_token(pin, 3, rp)

            t = token()
            created = ctap.make_credential(digest, {"id": rp}, {"id": b"test", "name": "synthetic"},
                [{"type": "public-key", "alg": -7}], options={"rk": True},
                pin_uv_param=protocol.authenticate(t, digest), pin_uv_protocol=protocol.VERSION)
            credential = created.auth_data.credential_data.credential_id
            public = created.auth_data.credential_data.public_key
            allow = [{"type": "public-key", "id": credential}]

            def assertion(t, up=True, challenge=digest, site=rp, ids=allow, extensions=None):
                return ctap.get_assertion(site, challenge, ids, extensions=extensions,
                    options=None if up is None else {"up": up},
                    pin_uv_param=protocol.authenticate(t, challenge), pin_uv_protocol=protocol.VERSION)

            # Same protocol sequence observed in Windows' real HID log. Each
            # Bridge.call has a distinct authenticated request ID, like TLS.
            for legacy in (False, True):
                for up in (True, None):
                    t = token(legacy)
                    before, revision = device.decisions, device.revision
                    probe = assertion(t, False)
                    assert device.decisions == before + 1
                    assert not probe.auth_data.is_user_present() and probe.auth_data.is_user_verified()
                    public.verify(bytes(probe.auth_data) + digest, probe.signature)
                    ctap.get_info()  # Background discovery must preserve the grant.
                    device.serial = device.serial.swapcase()
                    signed = assertion(t, up)
                    assert signed.auth_data.is_user_present() and signed.auth_data.is_user_verified()
                    public.verify(bytes(signed.auth_data) + digest, signed.signature)
                    assert signed.auth_data.counter == probe.auth_data.counter + 1
                    assert device.decisions == before + 1 and device.revision == revision + 2
                    error(0x33, lambda: assertion(t))  # Consumed, even for the exact same body.

            # A changed challenge with a VALID HMAC, RP, allowList or extension
            # may not inherit consent. A newly requested consent is denied here.
            changed = hashlib.sha256(b"different challenge").digest()
            for kwargs in ({"challenge": changed}, {"site": "other.invalid"},
                           {"ids": allow + [{"type": "public-key", "id": b"other"}]},
                           {"extensions": {"unknown": True}}):
                t = token(legacy=True)
                assertion(t, False)
                before, revision = device.decisions, device.revision
                device.mode = 1
                error(0x27, lambda: assertion(t, **kwargs))
                assert device.decisions == before + 1 and device.revision == revision
                device.mode = 0
                error(0x33, lambda: assertion(t))

            # Repeated silent requests cannot turn a one-time grant into a
            # general-purpose approval or extend the original PIN deadline.
            t = token()
            assertion(t, False)
            before = device.decisions
            device.mode = 1
            error(0x27, lambda: assertion(t, False))
            assert device.decisions == before + 1
            device.mode = 0
            error(0x33, lambda: assertion(t))

            # Explicit denial, cancel while awaiting approval, and a failed
            # response delivery all invalidate the deferred PIN token.
            for mode, status in ((1, 0x27), (2, 0x2d)):
                t = token()
                device.mode = mode
                revision = device.revision
                error(status, lambda: assertion(t, False))
                assert device.revision == revision
                device.mode = 0
                error(0x33, lambda: assertion(t))
            t = token()
            assertion(t, False)
            device.control("CANCEL_RESPONSE")
            error(0x33, lambda: assertion(t))

            t = token()
            assertion(t, False)
            device.seconds += 30
            error(0x38, lambda: assertion(t))
            for attribute, changed_id in (("boot", "33" * 16), ("enrollment", "44" * 16),
                                          ("serial", "abcdef0123456789")):
                t = token()
                assertion(t, False)
                previous = getattr(device, attribute)
                setattr(device, attribute, changed_id)
                error(0x35 if attribute == "serial" else 0x33, lambda: assertion(t))
                setattr(device, attribute, previous)

            # New token, PIN change, and an intervening other operation must
            # all force a fresh approval rather than reusing the old grant.
            for interruption in ("token", "pin", "query"):
                t = token()
                assertion(t, False)
                if interruption == "token":
                    t = token()
                elif interruption == "pin":
                    client.change_pin(pin, "new-synthetic-pin")
                    pin = "new-synthetic-pin"
                    t = token()
                else:
                    ctap.client_pin(protocol.VERSION, 1)
                before = device.decisions
                device.mode = 1
                error(0x27, lambda: assertion(t))
                assert device.decisions == before + 1
                device.mode = 0

    print(f"PASS: preflight protocol {protocol.VERSION}: one approval, real signatures, "
          "scope isolation, single use, cancellation, expiry and PIN/device session changes")



def run_attestation(executable):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from fido2.attestation import Attestation
    from fido2.attestation.base import AttestationType

    with tempfile.TemporaryDirectory(prefix="pf2-pin-interop-") as folder:
        path = Path(folder) / "pin-test.dpapi"
        certificate = None
        for reopen in range(2):
            with Bridge(executable, path) as device:
                ctap = Ctap2(device)
                client = ClientPin(ctap)
                protocol = client.protocol
                if not reopen:
                    client.set_pin("synthetic-apple-pin")
                for rp in ("apple.com", "ordinary.invalid", "apple.com.invalid"):
                    digest = hashlib.sha256((rp + str(reopen)).encode()).digest()
                    token = client.get_pin_token("synthetic-apple-pin", 3, rp)
                    created = ctap.make_credential(digest, {"id": rp}, {"id": b"test"},
                        [{"type": "public-key", "alg": -7}], options={"rk": True},
                        pin_uv_param=protocol.authenticate(token, digest), pin_uv_protocol=protocol.VERSION)
                    from fido2 import cbor
                    assert len(cbor.encode(dict(created))) <= 1976
                    verified = Attestation.for_type(created.fmt)().verify(created.att_stmt, created.auth_data, digest)
                    assert created.auth_data.is_user_verified() and created.auth_data.is_user_present()
                    credential = created.auth_data.credential_data
                    assert credential.aaguid == ctap.info.aaguid
                    if rp == "apple.com":
                        assert verified.attestation_type == AttestationType.BASIC
                        der = created.att_stmt["x5c"][0]
                        cert = x509.load_der_x509_certificate(der)
                        assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Authenticator Attestation"
                        assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                        assert usage.digital_signature and not usage.key_cert_sign
                        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
                        assert cert.subject == cert.issuer
                        assert cert.public_key().public_numbers().x != int.from_bytes(credential.public_key[-2], "big")
                        assert certificate is None or certificate == der
                        certificate = der
                    else:
                        assert verified.attestation_type == AttestationType.SELF and "x5c" not in created.att_stmt
                    token = client.get_pin_token("synthetic-apple-pin", 2, rp)
                    signed = ctap.get_assertion(rp, digest, [{"type": "public-key", "id": credential.credential_id}],
                        pin_uv_param=protocol.authenticate(token, digest), pin_uv_protocol=protocol.VERSION)
                    credential.public_key.verify(bytes(signed.auth_data) + digest, signed.signature)
    print("PASS: Apple packed certificate, independent signatures, PIN/UP/UV, RP scope and identity persistence")


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve(strict=True)
    for protocol in (PinProtocolV1, PinProtocolV2):
        run_protocol(executable, protocol)
        run_preflight(executable, protocol)
    failed_write(executable)
    run_attestation(executable)
