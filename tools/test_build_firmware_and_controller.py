"""Regression checks for fail-fast builds and firmware reuse, without SDKs."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "build_firmware_and_controller.py"
spec = importlib.util.spec_from_file_location("release_build", SCRIPT)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildTests(unittest.TestCase):
    def firmware(self, directory):
        path = Path(directory) / "esp32s3supermini-test.bin"
        data = bytearray(0x20000)
        for offset in (0, 0x10000):
            data[offset] = 0xE9
            data[offset + 12] = 9
        data[0x8000:0x8002] = b"\xaa\x50"
        path.write_bytes(data)
        licenses = Path(directory) / "LICENSES"
        licenses.mkdir()
        (licenses / "LICENSE").write_text("test fixture")
        return path

    def test_help_needs_no_tools(self):
        with patch.object(build, "run", side_effect=AssertionError("help ran a command")), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                build.main(["--help"])
        self.assertEqual(result.exception.code, 0)

    def test_reject_app_only_or_wrong_chip(self):
        with tempfile.TemporaryDirectory() as directory:
            image = self.firmware(directory)
            build.validate_firmware(image)
            data = bytearray(image.read_bytes())
            data[0x10000 + 12] = 0
            image.write_bytes(data)
            with self.assertRaises(build.BuildError):
                build.validate_firmware(image)
            image.write_bytes(b"\xe9" * 1024)
            with self.assertRaises(build.BuildError):
                build.validate_firmware(image)

    def test_reuse_checks_checksum_and_licenses(self):
        with tempfile.TemporaryDirectory() as directory:
            image = self.firmware(directory)
            builder = build.Builder(build.parser().parse_args(["--firmware", str(image)]))
            builder.check_reused_firmware()
            (Path(directory) / "SHA256SUMS").write_text("0" * 64 + "  " + image.name + "\n")
            with self.assertRaisesRegex(build.BuildError, "checksum"):
                builder.check_reused_firmware()
            (Path(directory) / "SHA256SUMS").unlink()
            (Path(directory) / "LICENSES/LICENSE").unlink()
            with self.assertRaisesRegex(build.BuildError, "LICENSES"):
                builder.check_reused_firmware()

    def test_no_build_on_preflight_failure(self):
        with patch.object(build.Builder, "preflight", side_effect=build.BuildError("missing Qt")), \
             patch.object(build.Builder, "build_firmware") as firmware, \
             patch.object(build.Builder, "build_controller") as controller, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(build.main([]), 2)
        firmware.assert_not_called()
        controller.assert_not_called()

    def test_check_only_does_not_build(self):
        with patch.object(build.Builder, "preflight"), patch.object(build.Builder, "build_firmware") as firmware, \
             patch.object(build.Builder, "build_controller") as controller:
            self.assertEqual(build.main(["--check-only"]), 0)
        firmware.assert_not_called()
        controller.assert_not_called()

    def test_all_missing_tools_reported_before_downloads(self):
        with patch.object(build.shutil, "which", return_value=None), \
             patch.object(build.Builder, "check_submodules"), patch.object(build.Builder, "check_idf"), \
             patch.object(build.Builder, "prepare_go") as download:
            builder = build.Builder(build.parser().parse_args(["--firmware-only"]))
            with self.assertRaises(build.BuildError) as error:
                builder.preflight()
            for tool in ("git", "cmake", "ninja"):
                self.assertIn("Missing " + tool, str(error.exception))
        download.assert_not_called()

    def test_firmware_only_does_not_require_qt_or_go(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(build.Builder, "tool"), patch.object(build.Builder, "check_submodules"), \
             patch.object(build.Builder, "check_idf"), patch.object(build, "run"), \
             patch.object(build.Builder, "prepare_go") as go, patch.object(build.Builder, "check_qt") as qt:
            builder = build.Builder(build.parser().parse_args(["--firmware-only", "--build-dir", directory, "--output-dir", directory]))
            builder.idf_command = ["idf"]
            builder.preflight()
        go.assert_not_called()
        qt.assert_not_called()

    def test_copy_notices_preserves_component_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            for component in ("a", "b"):
                (source / component).mkdir(parents=True)
                (source / component / "LICENSE").write_text(component)
            destination = Path(directory) / "LICENSES"
            build.copy_notices(source, destination)
            self.assertEqual((destination / "a/LICENSE").read_text(), "a")
            self.assertEqual((destination / "b/LICENSE").read_text(), "b")

    def test_macdeployqt_options_follow_installed_version(self):
        with tempfile.TemporaryDirectory() as directory:
            qt = Path(directory)
            (qt / "bin").mkdir()
            (qt / "bin/qmake").touch()
            (qt / "bin/macdeployqt").touch()
            (qt / "plugins/platforms").mkdir(parents=True)
            (qt / "plugins/platforms/libqcocoa.dylib").touch()
            query = f"QT_VERSION:6.8.3\nQT_INSTALL_BINS:{qt / 'bin'}\nQT_INSTALL_PLUGINS:{qt / 'plugins'}"
            for usage, expected in (("-always-overwrite", []), ("-always-overwrite -no-codesign", ["-no-codesign"])):
                with patch.object(build, "HOST", "Darwin"), patch.object(build, "EXE", ""), \
                     patch.object(build, "run", side_effect=[query, usage]):
                    builder = build.Builder(build.parser().parse_args(["--qt-path", directory]))
                    builder.check_qt()
                    self.assertEqual(builder.mac_deploy_options, expected)

    def test_checksum_manifest_uses_lf_on_every_host(self):
        # Runs on Windows too: GNU sha256sum treats a CR as part of the filename.
        with tempfile.TemporaryDirectory() as directory, patch.object(build, "run", return_value="test-commit"):
            root = Path(directory)
            (root / "payload with spaces.bin").write_bytes(b"test payload")
            builder = build.Builder(build.parser().parse_args([]))
            builder.write_manifest(root)
            data = (root / "SHA256SUMS").read_bytes()
            self.assertNotIn(b"\r", data)
            for line in data.decode().splitlines():
                expected, name = line.split("  ", 1)
                self.assertEqual(build.sha256(root / name), expected)


if __name__ == "__main__":
    unittest.main()
