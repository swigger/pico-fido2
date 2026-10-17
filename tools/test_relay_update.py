"""Offline regression for update-layout checks using the actual IDF parser."""
import os
import copy
from pathlib import Path
import tempfile
import unittest
import check_relay_update as update

ROOT = Path(__file__).resolve().parents[1]


class UpdateLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        idf = os.environ.get("IDF_PATH")
        if not idf:
            raise unittest.SkipTest("set IDF_PATH to an ESP-IDF 5.5 checkout")
        cls.parser = update.parser_from(idf)

    def setUp(self):
        self.old = update.table_from(self.parser, ROOT / "pico-keys-sdk/config/esp32/partitions.csv")
        self.new = update.table_from(self.parser, ROOT / "config/esp32/relay-partitions.csv")

    def compare(self, size=0x100100):
        return update.compare(self.parser, self.old, self.new, size)

    def test_growth_requires_reviewed_table(self):
        result = self.compare()
        self.assertTrue(result["partition_table_differs"])
        self.assertFalse(result["app_only_fits_baseline"])
        self.assertEqual(result["app_sector_span"], ["0x10000", "0x111000"])
        self.assertEqual({p["name"] for p in result["preserved_data"]}, {"nvs", "phy_init", "part0"})

    def test_identical_layout_and_app_fit(self):
        self.old = copy.deepcopy(self.new)
        result = self.compare()
        self.assertFalse(result["partition_table_differs"])
        self.assertTrue(result["app_only_fits_baseline"])

    def test_data_mutations_refused(self):
        for name in ("nvs", "phy_init", "part0"):
            for field, value in (("offset", 0x300000), ("size", 8192), ("encrypted", True), ("readonly", True)):
                with self.subTest(name=name, field=field):
                    saved = copy.deepcopy(self.new)
                    setattr(self.new[name], field, value)
                    with self.assertRaises(ValueError):
                        self.compare()
                    self.new = saved

    def test_missing_extra_or_duplicate_partitions_refused(self):
        for action in ("missing", "extra", "duplicate"):
            with self.subTest(action=action):
                saved = copy.deepcopy(self.new)
                if action == "missing":
                    self.new.pop()
                else:
                    extra = copy.deepcopy(self.new[-1])
                    if action == "extra":
                        extra.name = "other"
                    self.new.append(extra)
                with self.assertRaises(ValueError):
                    self.compare()
                self.new = saved

    def test_bad_application_shape_refused(self):
        for field, value in (("offset", 0x20000), ("size", 0xF0000), ("encrypted", True), ("subtype", 0x10)):
            with self.subTest(field=field):
                saved = copy.deepcopy(self.new)
                setattr(self.new["factory"], field, value)
                with self.assertRaises(ValueError):
                    self.compare()
                self.new = saved
        for size in (0, 0x1F0001):
            with self.assertRaises(ValueError):
                self.compare(size)

    def test_binary_checksum_is_verified(self):
        with tempfile.TemporaryDirectory(prefix="pf2-partition-test-") as directory:
            path = Path(directory) / "table.bin"
            encoded = bytearray(self.new.to_binary())
            path.write_bytes(encoded)
            self.assertEqual(len(update.table_from(self.parser, path)), 4)
            encoded[12] ^= 1
            path.write_bytes(encoded)
            with self.assertRaises(RuntimeError):
                update.table_from(self.parser, path)


if __name__ == "__main__":
    unittest.main()
