"""Compare ESP32-S3 update artifacts with a supplied partition-table baseline.

Read-only: no device connection, reset, flash read/write, eFuse operation or
subprocess. A reference CSV is not evidence of the attached device's layout.
Uses the selected ESP-IDF checkout's own partition parser and verifier.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


def need(condition, message):
    if not condition:
        raise ValueError(message)


def parser_from(idf):
    file = Path(idf).resolve(strict=True) / "components/partition_table/gen_esp32part.py"
    spec = importlib.util.spec_from_file_location("relay_idf_partitions", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.offset_part_table = 0x8000
    return module


def table_from(module, path):
    path = Path(path).resolve(strict=True)
    need(path.is_file() and 0 < path.stat().st_size <= 65536, "Invalid partition-table file size")
    data = path.read_bytes()
    if data.startswith(b"\xaa\x50"):
        need(len(data) <= 4096, "Partition-table binary exceeds one sector")
        table = module.PartitionTable.from_binary(data)
    else:
        table = module.PartitionTable.from_csv(data.decode("utf-8-sig"))
    table.verify()
    table.verify_size_fits(4 * 1024 * 1024)
    return table


def fields(partition):
    return (partition.type, partition.subtype, partition.offset, partition.size,
            partition.encrypted, partition.readonly)


def compare(module, baseline, candidate, image_size):
    old = {p.name: p for p in baseline}
    new = {p.name: p for p in candidate}
    need(len(old) == len(baseline) and len(new) == len(candidate), "Duplicate partition name")
    need(old.keys() == new.keys(), "Partition names were added or removed")
    need("factory" in old and "nvs" in old and "part0" in old, "Missing application/NVS/FIDO partition")
    for table in (old, new):
        apps = [p for p in table.values() if p.type == module.APP_TYPE]
        need(len(apps) == 1 and apps[0].name == "factory" and apps[0].subtype == 0,
             "Only a single factory application layout is supported")
        need(fields(table["nvs"])[:4] == (1, 2, 0x9000, 0x6000), "Unexpected NVS layout")
        need(fields(table["part0"])[:4] == (0x40, 1, 0x200000, 0x100000), "Unexpected FIDO storage layout")
    for name, partition in old.items():
        if name != "factory":
            need(fields(partition) == fields(new[name]), f"Data partition changed: {name}")
    previous, app = old["factory"], new["factory"]
    need(previous.offset == app.offset == 0x10000, "Application offset changed")
    need(not app.encrypted and not previous.encrypted and not app.readonly and not previous.readonly,
         "Encrypted/read-only application requires a different update procedure")
    need(app.size >= previous.size, "Application partition shrank")
    need(0 < image_size <= app.size, "Application image does not fit the new partition")
    erased = (image_size + 4095) & ~4095
    need(erased <= app.size, "Application erase range exceeds its new partition")
    spans = [(0x8000, 0x9000), (app.offset, app.offset + erased)]
    for partition in old.values():
        if partition.name == "factory":
            continue
        for first, last in spans:
            need(last <= partition.offset or first >= partition.offset + partition.size,
                 f"Proposed erase range overlaps existing data: {partition.name}")
    return {
        "partition_table_differs": any(fields(p) != fields(new[p.name]) for p in baseline),
        "app_only_fits_baseline": image_size <= previous.size and erased <= previous.size,
        "old_app_size": previous.size,
        "new_app_size": app.size,
        "app_bytes": image_size,
        "app_sector_span": [hex(app.offset), hex(app.offset + erased)],
        "preserved_data": [dict(name=p.name, offset=hex(p.offset), size=p.size) for p in baseline if p.name != "factory"],
    }


def inspect(build_directory, baseline_path):
    build = Path(build_directory).resolve(strict=True)
    description = json.loads((build / "project_description.json").read_text(encoding="utf-8"))
    need(description.get("target") == "esp32s3", "Build target must be esp32s3")
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    need(re.search(r"^ENABLE_ESP_EFUSE_KEYS:BOOL=OFF$", cache, re.M), "New eFuse provisioning is not disabled")
    config = (build / "sdkconfig").read_text(encoding="utf-8")
    need("CONFIG_PARTITION_TABLE_OFFSET=0x8000" in config, "Unsupported partition-table location")
    need("# CONFIG_SECURE_BOOT is not set" in config and "# CONFIG_SECURE_FLASH_ENC_ENABLED is not set" in config,
         "Signed/encrypted firmware requires a different update procedure")
    module = parser_from(description["idf_path"])
    baseline_path = Path(baseline_path).resolve(strict=True)
    table_path = build / "partition_table/partition-table.bin"
    app_path = build / "pico_fido2.bin"
    baseline, candidate = table_from(module, baseline_path), table_from(module, table_path)
    result = compare(module, baseline, candidate, app_path.stat().st_size)
    app_bytes = app_path.read_bytes()
    need(len(app_bytes) >= 24 and app_bytes[0] == 0xE9 and int.from_bytes(app_bytes[12:14], "little") == 9,
         "Not an ESP32-S3 application image")
    result.update({
        "scope": "file layout comparison only; attached device, eFuses and bootloader compatibility are NOT verified",
        "no_device_operation_performed": True,
        "baseline": str(baseline_path),
        "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
        "artifacts_for_review": [
            {"file": str(table_path), "offset": "0x8000", "bytes": table_path.stat().st_size,
             "sha256": hashlib.sha256(table_path.read_bytes()).hexdigest()},
            {"file": str(app_path), "offset": "0x10000", "bytes": len(app_bytes),
             "sha256": hashlib.sha256(app_bytes).hexdigest()},
        ],
        "excluded": ["bootloader", "NVS", "FIDO data", "eFuse", "full erase", "factory merged image"],
    })
    return result


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--build-dir", required=True, type=Path)
    cli.add_argument("--baseline-partitions", required=True, type=Path,
                     help="Previously captured device partition table or explicitly identified reference CSV")
    args = cli.parse_args()
    try:
        print(json.dumps(inspect(args.build_dir, args.baseline_partitions), indent=2, ensure_ascii=False))
    except (ValueError, OSError, RuntimeError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
