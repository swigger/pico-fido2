"""Regression checks for the native controller using disposable .invalid credentials.

Requires a physically paired controller and one connected device. A full run creates
one nonresident credential without changing the PIN; --authenticate-only reuses it.
"""

import os
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import secrets
import subprocess
import threading
import time

from fido2 import cbor
from fido2.attestation import Attestation
from fido2.cose import CoseKey
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
import hid

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTROLLER = ROOT / ("build/native-controller/Release/pico-fido-cli.exe" if os.name == "nt" else "build/native-controller/pico-fido-cli")
STATE_FILE = ROOT / "build/test-native-credential.cbor"
RP_ID = "pico-fido2-native-test.invalid"
VID_PID = (0x1D50, 0x619B)


class ControlReports:
    def __init__(self):
        self.open()

    def open(self):
        matches = [
            item for item in hid.enumerate(*VID_PID)
            if item["usage_page"] == 0xFF31 and item["usage"] == 1
        ]
        if len(matches) != 1:
            raise RuntimeError("Connect exactly one ESP32 controller")
        self.device = hid.device()
        self.device.open_path(matches[0]["path"])

    def close(self):
        self.device.close()

    def get(self, report):
        packet = bytes(self.device.get_feature_report(report, 64))
        assert len(packet) == 64 and packet[0] == report
        return packet[1:]

    def put(self, report, data):
        packet = bytes([report]) + data.ljust(63, b"\0")
        assert len(packet) == 64
        assert self.device.send_feature_report(packet) == len(packet)

    def await_request(self, future):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if future.done():
                future.result()
                raise AssertionError("Request completed without approval")
            status = self.get(1)
            assert status[:4] == b"PRP2"
            if status[4]:
                return status
            time.sleep(0.05)
        raise TimeoutError("No pending confirmation request")

    def trusted_id(self):
        slots = self.get(13)[:48] + self.get(14)[:16]
        for offset in range(0, 64, 16):
            key_id = slots[offset:offset + 16]
            if key_id != bytes(16):
                return key_id
        raise RuntimeError("Physically pair the native controller before testing")

    def invalid_signature(self, generation, key_id):
        self.put(11, generation + key_id)
        self.put(3, generation + bytes(32))
        self.put(4, generation + bytes(32))


def approve(controller, control):
    # hidapi opens devices exclusively on macOS; let the controller in.
    control.close()
    try:
        result = subprocess.run(
            [str(controller), "--approve", "--rp", RP_ID],
            capture_output=True, text=True, encoding="utf-8", timeout=35,
        )
    finally:
        control.open()
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip(), flush=True)


def save_credential(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_bytes(cbor.encode(state))


def register(ctap, control, pool, event, controller):
    challenge = secrets.token_bytes(32)
    future = pool.submit(
        ctap.make_credential, challenge,
        {"id": RP_ID, "name": "Native controller regression test"},
        {"id": secrets.token_bytes(16), "name": "native-test"},
        [{"type": "public-key", "alg": -7}], options={"rk": False}, event=event,
    )
    generation = control.await_request(future)[7:11]
    control.invalid_signature(generation, bytes(16))
    time.sleep(0.4)
    assert not future.done() and control.get(1)[6] == 2
    print("PASS: unpaired controller rejected; no unattended approval", flush=True)

    known_id = control.trusted_id()
    control.invalid_signature(generation, known_id)
    time.sleep(0.4)
    assert not future.done() and control.get(1)[6] == 2
    print("PASS: trusted ID with invalid signature rejected", flush=True)

    approve(controller, control)
    response = future.result(timeout=10)
    assert response.auth_data.is_user_present()
    Attestation.for_type(response.fmt)().verify(
        response.att_stmt, response.auth_data, challenge,
    )
    credential = response.auth_data.credential_data
    state = {
        "id": credential.credential_id,
        "public_key": dict(credential.public_key),
        "counter": response.auth_data.counter,
    }
    save_credential(state)
    print("PASS: native EXE registration and independent attestation verification", flush=True)

    control.invalid_signature(generation, known_id)
    assert control.get(1)[6] == 3
    print("PASS: consumed request cannot be approved again", flush=True)
    return state


def authenticate(ctap, control, pool, event, controller, state):
    challenge = secrets.token_bytes(32)
    future = pool.submit(
        ctap.get_assertion, RP_ID, challenge,
        [{"type": "public-key", "id": state["id"]}], options={"up": True}, event=event,
    )
    control.await_request(future)
    approve(controller, control)
    response = future.result(timeout=10)
    assert response.auth_data.is_user_present()
    assert response.auth_data.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest()
    CoseKey.parse(state["public_key"]).verify(
        bytes(response.auth_data) + challenge, response.signature,
    )
    assert response.auth_data.counter > state["counter"]
    state["counter"] = response.auth_data.counter
    save_credential(state)
    print("PASS: native EXE login, independent signature and increasing counter", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authenticate-only", action="store_true")
    parser.add_argument("--controller", type=Path, default=DEFAULT_CONTROLLER)
    args = parser.parse_args()
    if not args.controller.is_file():
        parser.error(f"Build the native controller first: {args.controller}")

    devices = []
    for device in CtapHidDevice.list_devices():
        if (device.descriptor.vid, device.descriptor.pid) == VID_PID:
            devices.append(device)
        else:
            device.close()
    if len(devices) != 1:
        for device in devices:
            device.close()
        raise RuntimeError("Connect exactly one ESP32 FIDO device")

    device = devices[0]
    control = None
    pool = ThreadPoolExecutor(max_workers=1)
    event = threading.Event()
    timer = threading.Timer(50, event.set)
    timer.start()
    try:
        ctap = Ctap2(device)
        control = ControlReports()
        state = (
            cbor.decode(STATE_FILE.read_bytes()) if args.authenticate_only
            else register(ctap, control, pool, event, args.controller)
        )
        authenticate(ctap, control, pool, event, args.controller, state)
    finally:
        event.set()
        timer.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
        if control:
            control.close()
        device.close()


if __name__ == "__main__":
    main()
