#!/usr/bin/env python3
"""Build and package the ESP32-S3 relay firmware and native desktop controller.

Only the Python standard library is needed. Run --help for setup instructions.
All downloads, dependency checks and CMake configuration happen before building.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
HOST = platform.system()
EXE = ".exe" if HOST == "Windows" else ""
APP = "Pico FIDO Controller.app"
GO_SOURCE = ROOT / "tools/relay-storage"
NOTICE = re.compile(r"^(LICENSE|LICENCE|COPYING|NOTICE|AUTHORS)([._-]|$)", re.I)


class BuildError(Exception):
    pass


def run(command, *, cwd=ROOT, env=None, capture=False):
    command = [str(x) for x in command]
    print("+ " + subprocess.list2cmdline(command), flush=True)
    try:
        result = subprocess.run(command, cwd=cwd, env=env, text=True,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.STDOUT if capture else None)
    except OSError as exc:
        raise BuildError(str(exc)) from exc
    if result.returncode:
        raise BuildError(f"Command failed ({result.returncode}): {subprocess.list2cmdline(command)}\n"
                         + (result.stdout or "See output above."))
    return (result.stdout or "").strip()


def version(text):
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        raise BuildError(f"Cannot read version: {text}")
    return tuple(int(x or 0) for x in match.groups())


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(stream.read()).hexdigest()


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_notices(source, destination):
    count = 0
    for directory, dirs, files in os.walk(source):
        dirs[:] = [d for d in dirs if d not in (".git", "build", "__pycache__")]
        for name in files:
            if NOTICE.match(name) or name == "qt_attribution.json":
                path = Path(directory) / name
                copy(path, destination / path.relative_to(source))
                count += 1
    if not count:
        raise BuildError(f"No license texts found in {source}")


def validate_firmware(path):
    if not path.is_file():
        raise BuildError(f"Firmware does not exist: {path}")
    if not re.fullmatch(r"esp32s3supermini-[\w.-]+\.bin", path.name):
        raise BuildError("Merged firmware must be named esp32s3supermini-<version>.bin so the GUI can find it.")
    data = path.read_bytes()
    if not 0x10000 + 24 < len(data) <= 4 * 1024 * 1024:
        raise BuildError("Expected a merged ESP32-S3 image, between 64 KiB and 4 MiB.")
    if any(data[offset] != 0xE9 or data[offset + 12:offset + 14] != b"\x09\x00"
           for offset in (0, 0x10000)) or data[0x8000:0x8002] != b"\xaa\x50":
        raise BuildError("Firmware must contain ESP32-S3 bootloader at 0, partitions at 0x8000 and app at 0x10000.")


def parser():
    p = argparse.ArgumentParser(
        description="One-command ESP32-S3 relay firmware + Qt controller build and release packaging.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""Prerequisites (checked BEFORE firmware/controller compilation):
  All: Python >= 3.10, Git, CMake >= 3.24, Ninja; recursive Git submodules.
       Internet on the first run for pinned CMake/Go dependencies and Qt notices.
  Firmware: ESP-IDF 5.5.6 installed for esp32s3. Activate export.sh/export.ps1
       first (ESP-IDF terminal on Windows); IDF_PATH, its Python virtualenv and
       xtensa-esp-elf tools must be available. No hardware is needed or flashed.
  Controller: Go >= the version in tools/relay-storage/go.mod, Qt 6 Widgets.
  Windows x64: Visual Studio 2022 Desktop C++ + Windows SDK; Qt msvc2022_64
       with windeployqt. Use an x64 Native Tools terminal (then activate IDF).
  macOS: Xcode Command Line Tools; Qt with macdeployqt, codesign and ditto.
       Homebrew: brew install cmake ninja go qtbase
  Linux (Debian/Ubuntu): C/C++ compiler, pkg-config, patchelf, dpkg-query;
       Qt 6 Widgets/DBus, libsecret and libudev headers. For example:
       sudo apt install build-essential cmake ninja-build pkg-config patchelf \
         qt6-base-dev qt6-base-dev-tools libsecret-1-dev libudev-dev
       Install a sufficiently new Go separately. Runtime needs a desktop session
       with Secret Service (GNOME Keyring/KWallet) and permission for USB hidraw.

Setup:
  git submodule update --init --recursive
  Install ESP-IDF v5.5.6 with its install.sh esp32s3 (install.ps1 on Windows),
  then activate export.sh/export.ps1. IDF is not needed with --firmware FILE.
  --qt-path is the Qt KIT prefix, not its bin directory; QT_ROOT_DIR,
  QT_INSTALL_DIR and qmake6/qmake on PATH are also recognized.

Examples (run from any directory; paths supplied are relative to your cwd):
  python build_firmware_and_controller.py --qt-path C:/Qt/6.8.3/msvc2022_64
  python3 build_firmware_and_controller.py --qt-path /opt/homebrew/opt/qtbase
  python3 build_firmware_and_controller.py --check-only --qt-path /usr
  python3 build_firmware_and_controller.py --firmware-only
  python3 build_firmware_and_controller.py --firmware dist/firmware/esp32s3supermini-7.3.bin

Outputs:
  dist/firmware/: merged factory image, separate app/bootloader/partition images,
       flashing metadata, firmware licenses and SHA256SUMS. Factory images are
       for blank devices; use the documented update procedure for populated keys.
  dist/PicoFido2-<version>-<os>-<arch>.zip (Windows/macOS), .tar.gz (Linux).
       Every desktop package contains firmware, GUI, CLI, storage helper and
       LICENSES/. macOS stores these inside the app bundle. Linux bundles Qt
       and dependent libraries, excluding glibc/graphics drivers; build on the
       oldest distribution you intend to support (CI uses Ubuntu 22.04).
       macOS builds for the runner's architecture, ad-hoc signed by default;
       this is not Apple notarization. --codesign-identity uses your certificate.

--check-only also downloads/verifies dependencies and configures CMake (including
small compiler probes), but does not build project targets or publish packages.
Missing tools/libraries are reported as preflight errors, with exit code 2.
Compiler/source, disk, or network failures can still occur; exit code 1 after
preflight. Build caches live in --build-dir; finished archives are written
atomically. Existing output directories not owned by this script are preserved.
""")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--firmware-only", action="store_true", help="Build only ESP32-S3 firmware; Qt/Go/native tools are not required.")
    mode.add_argument("--firmware", type=Path, metavar="BIN", help="Reuse a merged firmware image; skip ESP-IDF/toolchain requirements.")
    p.add_argument("--firmware-licenses", type=Path, help="License directory accompanying --firmware (default: adjacent LICENSES/).")
    p.add_argument("--qt-path", type=Path, help="Qt 6 kit prefix containing bin/qmake and lib/cmake/Qt6.")
    p.add_argument("--idf-path", type=Path, help="ESP-IDF checkout (default: IDF_PATH); activate its environment first.")
    p.add_argument("--idf-python", type=Path, help="ESP-IDF virtualenv Python (default: IDF_PYTHON_ENV_PATH, then current Python).")
    p.add_argument("--build-dir", type=Path, default=ROOT / "build/firmware-controller", help="Build/cache directory (default: repository build/firmware-controller).")
    p.add_argument("--output-dir", type=Path, default=ROOT / "dist", help="Package directory (default: repository dist).")
    p.add_argument("--version", default="dev", help="Archive label, e.g. v1.0.0 (default: dev; does not change firmware protocol version).")
    p.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 8), help="Parallel build jobs (default: CPU count capped at 8).")
    p.add_argument("--check-only", action="store_true", help="Run the entire dependency/configuration preflight and exit without a build.")
    p.add_argument("--codesign-identity", default="-", help="macOS signing identity (default: - for ad-hoc).")
    return p


class Builder:
    def __init__(self, args):
        self.a = args
        self.build = args.build_dir.resolve()
        self.output = args.output_dir.resolve()
        self.native = self.build / "controller"
        self.idf_build = self.build / "firmware"
        self.env = os.environ.copy()
        self.goenv = dict(self.env, CGO_ENABLED="0", GOTOOLCHAIN="local", GOFLAGS="-mod=readonly")
        self.errors = []
        self.firmware = args.firmware.resolve() if args.firmware else None
        self.firmware_licenses = None
        self.modules = []
        self.linux_libraries = {}
        self.linux_copyrights = {}

    def check(self, action):
        try:
            return action()
        except (BuildError, OSError, ValueError) as exc:
            self.errors.append(str(exc))
            return None

    def tool(self, name, minimum=None):
        path = shutil.which(name)
        if not path:
            raise BuildError(f"Missing {name} on PATH; see --help for installation instructions.")
        if minimum:
            output = run([path, "version" if name == "go" else "--version"], capture=True,
                         env=self.goenv if name == "go" else self.env)
            if version(output) < minimum:
                raise BuildError(f"{name} >= {'.'.join(map(str, minimum))} required; found {output.splitlines()[0]}")
        return path

    def fail_preflight(self):
        if self.errors:
            raise BuildError("Preflight failed; no project targets were built:\n  - " + "\n  - ".join(self.errors))

    def check_submodules(self):
        status = run(["git", "submodule", "status", "--recursive"], capture=True)
        missing = [line for line in status.splitlines() if line.startswith(("-", "U"))]
        if missing:
            raise BuildError("Uninitialized/conflicted submodules. Run: git submodule update --init --recursive\n" + "\n".join(missing))
        for name in ("pico-fido/src/fido/fido.c", "pico-openpgp/src/openpgp/openpgp.c",
                     "pico-keys-sdk/src/pico_keys.h", "LICENSE"):
            if not (ROOT / name).is_file():
                raise BuildError(f"Missing source {name}; initialize recursive submodules.")

    def check_qt(self):
        prefix = self.a.qt_path or os.environ.get("QT_ROOT_DIR") or os.environ.get("QT_INSTALL_DIR")
        candidates = ([str(Path(prefix) / "bin" / (name + EXE)) for name in ("qmake6", "qmake")]
                      if prefix else [shutil.which(name) for name in ("qmake6", "qmake")])
        qmake = next((p for p in candidates if p and Path(p).is_file()), None)
        if not qmake:
            raise BuildError("Qt qmake not found. Supply --qt-path <Qt 6 kit prefix>.")
        query = run([qmake, "-query"], capture=True)
        self.qt = dict(line.split(":", 1) for line in query.splitlines() if ":" in line)
        self.qt_prefix = Path(prefix or self.qt["QT_INSTALL_PREFIX"]).resolve()
        if version(self.qt["QT_VERSION"]) < (6, 0, 0):
            raise BuildError("Release packaging requires Qt 6.")
        if HOST in ("Windows", "Darwin"):
            name = "windeployqt.exe" if HOST == "Windows" else "macdeployqt"
            self.deploy = Path(self.qt["QT_INSTALL_BINS"]) / name
            if not self.deploy.is_file():
                raise BuildError(f"Missing Qt deployment tool: {self.deploy}")
            # macdeployqt prints usage but returns 1 for -help.
            if HOST == "Windows":
                run([self.deploy, "--help"], capture=True)
        plugin = {"Linux": "libqxcb.so", "Darwin": "libqcocoa.dylib", "Windows": "qwindows.dll"}[HOST]
        if not (Path(self.qt["QT_INSTALL_PLUGINS"]) / "platforms" / plugin).is_file():
            raise BuildError(f"Missing Qt platform plugin {plugin}; install the full desktop kit.")

    def check_idf(self):
        path = self.a.idf_path or os.environ.get("IDF_PATH")
        if not path:
            raise BuildError("IDF_PATH is unset. Activate ESP-IDF 5.5.6 export.sh/export.ps1, or use --firmware BIN.")
        self.idf = Path(path).resolve()
        if not (self.idf / "tools/idf.py").is_file():
            raise BuildError(f"Invalid ESP-IDF path: {self.idf}")
        self.env["IDF_PATH"] = str(self.idf)
        virtualenv = os.environ.get("IDF_PYTHON_ENV_PATH")
        self.python = self.a.idf_python or (Path(virtualenv) / ("Scripts/python.exe" if HOST == "Windows" else "bin/python") if virtualenv else Path(sys.executable))
        result = run([self.python, self.idf / "tools/idf.py", "--version"], env=self.env, capture=True)
        if version(result) != (5, 5, 6):
            raise BuildError(f"Use the tested ESP-IDF 5.5.6 (dependencies.lock); found {result}.")
        run([self.python, self.idf / "tools/idf_tools.py", "check"], env=self.env, capture=True)
        run([self.python, self.idf / "tools/idf_tools.py", "check-python-dependencies"], env=self.env, capture=True)
        self.tool("xtensa-esp-elf-gcc")
        self.tool("xtensa-esp-elf-g++")
        self.idf_command = [self.python, self.idf / "tools/idf.py", "-B", self.idf_build,
                            "-DIDF_TARGET=esp32s3", f"-DSDKCONFIG={self.idf_build.as_posix()}/sdkconfig",
                            "-DENABLE_REMOTE_PRESENCE=ON", "-DENABLE_OTP_APP=OFF", "-DENABLE_OATH_APP=OFF",
                            "-DENABLE_ESP_EFUSE_KEYS=OFF", "-DLED_ACTIVITY_ONLY=ON"]

    def check_reused_firmware(self):
        validate_firmware(self.firmware)
        self.firmware_licenses = (self.a.firmware_licenses or self.firmware.parent / "LICENSES").resolve()
        if not self.firmware_licenses.is_dir() or not any(self.firmware_licenses.rglob("*LICENSE*")):
            raise BuildError("Reused firmware needs its LICENSES directory; use --firmware-licenses DIR.")
        sums = self.firmware.parent / "SHA256SUMS"
        if sums.is_file():
            entries = dict((line.split()[1].lstrip("*"), line.split()[0]) for line in sums.read_text().splitlines() if line.strip())
            if entries.get(self.firmware.name) != sha256(self.firmware):
                raise BuildError("Firmware SHA256SUMS is missing this image or its checksum does not match.")

    def preflight(self):
        print("=== Preflight: tools, dependencies, deployment and configuration ===", flush=True)
        if HOST not in ("Linux", "Darwin", "Windows"):
            raise BuildError(f"Unsupported host: {HOST}")
        self.check(lambda: self.tool("git"))
        self.check(lambda: self.tool("cmake", (3, 24, 0)))
        self.check(lambda: self.tool("ninja"))
        self.check(self.check_submodules)
        self.check(self.check_reused_firmware if self.firmware else self.check_idf)
        if not self.a.firmware_only:
            required_go = version(re.search(r"^go (.+)$", (GO_SOURCE / "go.mod").read_text(), re.M)[1])
            self.check(lambda: self.tool("go", required_go))
            self.check(self.check_qt)
            if HOST == "Windows":
                for tool in ("cl", "link", "rc", "mt"):
                    self.check(lambda tool=tool: self.tool(tool))
            else:
                for tool in ("cc", "c++"):
                    self.check(lambda tool=tool: self.tool(tool))
            if HOST == "Darwin":
                for tool in ("xcrun", "codesign", "ditto", "otool"):
                    self.check(lambda tool=tool: self.tool(tool))
                self.check(lambda: run(["xcrun", "--show-sdk-path"], capture=True))
                if self.a.codesign_identity != "-":
                    def identity():
                        identities = run(["security", "find-identity", "-v", "-p", "codesigning"], capture=True)
                        if self.a.codesign_identity not in identities:
                            raise BuildError("Requested codesign identity is not in the login keychain.")
                    self.check(identity)
            if HOST == "Linux":
                for tool in ("pkg-config", "patchelf", "ldd", "dpkg-query"):
                    self.check(lambda tool=tool: self.tool(tool))
                self.check(lambda: run(["pkg-config", "--exists", "libsecret-1", "libudev"], capture=True))
        self.fail_preflight()
        self.build.mkdir(parents=True, exist_ok=True)
        self.output.mkdir(parents=True, exist_ok=True)
        for directory in (self.build, self.output):
            with tempfile.TemporaryFile(dir=directory) as stream:
                stream.write(b"writable")
        # Complete every download and configure step before either project builds.
        if not self.a.firmware_only:
            self.check(self.prepare_go)
            self.check(self.prepare_qt_licenses)
            self.check(self.configure_controller)
            if HOST == "Linux":
                self.check(self.prepare_linux)
        if not self.firmware:
            self.check(lambda: run(self.idf_command + ["reconfigure"], env=self.env))
        self.fail_preflight()
        print("=== Preflight passed ===", flush=True)

    def prepare_go(self):
        run(["go", "mod", "download"], cwd=GO_SOURCE, env=self.goenv)
        run(["go", "mod", "verify"], cwd=GO_SOURCE, env=self.goenv)
        modules = run(["go", "list", "-deps", "-f", "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}",
                       "./cmd/relay-storage-helper"], cwd=GO_SOURCE, env=self.goenv, capture=True)
        for line in sorted(set(modules.splitlines())):
            if not line or line.startswith("pico-fido2/"):
                continue
            name, ver, directory = line.split("|")
            notices = [p for p in Path(directory).iterdir() if p.is_file() and NOTICE.match(p.name)]
            if not ver or not notices:
                raise BuildError(f"Missing Go module/license: {name}")
            self.modules.append((name, ver, notices))
        goroot = Path(run(["go", "env", "GOROOT"], cwd=GO_SOURCE, env=self.goenv, capture=True))
        self.go_license = next((p for p in (goroot / "LICENSE", goroot.parent / "LICENSE") if p.is_file()), None)
        if not self.go_license:
            raise BuildError(f"Missing Go toolchain LICENSE under {goroot}")

    def prepare_qt_licenses(self):
        # Include Qt's third-party attributions as well as its top-level licenses.
        ver = self.qt["QT_VERSION"]
        self.qt_notices = self.build / "dependencies" / f"qtbase-{ver}-notices"
        if (self.qt_notices / ".complete").is_file():
            return
        url = f"https://github.com/qt/qtbase/archive/refs/tags/v{ver}.tar.gz"
        archive = self.build / "dependencies" / f"qtbase-{ver}.tar.gz"
        archive.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading Qt {ver} license/attribution source: {url}", flush=True)
        with urllib.request.urlopen(url, timeout=120) as response, archive.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        count = 0
        with tarfile.open(archive) as tar:
            for member in tar:
                relative = Path(*Path(member.name).parts[1:])
                if not member.isfile() or relative.is_absolute() or ".." in relative.parts:
                    continue
                if "LICENSES" not in relative.parts and not NOTICE.match(relative.name) and relative.name != "qt_attribution.json":
                    continue
                target = self.qt_notices / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                count += 1
        if not count:
            raise BuildError("Qt source archive contained no notices.")
        (self.qt_notices / "SOURCE.txt").write_text(url + "\nSHA256: " + sha256(archive) + "\n", encoding="utf-8")
        (self.qt_notices / ".complete").touch()

    def configure_controller(self):
        run(["cmake", "-S", ROOT / "tools/native-controller", "-B", self.native,
             "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTING=OFF",
             "-DPICO_CONTROLLER_GUI=ON", "-DENABLE_RELAY_DIAGNOSTICS=OFF", "-DPICO_FIRMWARE_IMAGE=",
             "-DPICO_MACOS_CODESIGN_IDENTITY=", f"-DCMAKE_PREFIX_PATH={self.qt_prefix.as_posix()}"], env=self.env)

    def dependencies(self, binary):
        result = run(["ldd", binary], capture=True)
        if "not found" in result:
            raise BuildError(f"Unresolved runtime dependency for {binary}:\n{result}")
        dependencies = {}
        for line in result.splitlines():
            match = re.match(r"\s*(\S+) => (/\S+)", line)
            if match and not re.match(r"^(lib(c|m|pthread|dl|rt|resolv|util)\.so|ld-linux)", match[1]):
                dependencies[match[1]] = Path(match[2])
        return dependencies

    def prepare_linux(self):
        self.plugins = []
        plugin_root = Path(self.qt["QT_INSTALL_PLUGINS"])
        for kind in ("platforms", "imageformats", "xcbglintegrations"):
            for path in (plugin_root / kind).glob("*.so"):
                if kind == "platforms" and path.name not in ("libqxcb.so", "libqoffscreen.so"):
                    continue
                self.plugins.append(path)
        roots = self.plugins + [Path(self.qt["QT_INSTALL_LIBS"]) / f"libQt6{name}.so.6" for name in ("Widgets", "DBus")]
        for package, library in (("libsecret-1", "libsecret-1.so.0"), ("libudev", "libudev.so.1")):
            directory = run(["pkg-config", "--variable=libdir", package], capture=True)
            roots.append(Path(directory) / library)
        for path in roots:
            if path not in self.plugins:
                self.linux_libraries[path.name] = path
            self.linux_libraries.update(self.dependencies(path))
        for path in list(self.linux_libraries.values()) + self.plugins:
            # A Debian package's copyright file includes its upstream licenses.
            # usrmerge can expose /lib files through /usr/lib (or vice versa),
            # while dpkg records only the original spelling. Match the real file.
            result = run(["dpkg-query", "-S", "*/" + path.name], capture=True)
            owners = [line.split(": ", 1)[0] for line in result.splitlines()
                      if ": " in line and Path(line.split(": ", 1)[1]).resolve() == path.resolve()]
            if not owners:
                raise BuildError(f"Cannot identify the system package/license for {path}")
            package = owners[0]
            copyright_file = Path("/usr/share/doc") / package.split(":")[0] / "copyright"
            if not copyright_file.is_file():
                raise BuildError(f"Missing copyright file for bundled {path}: {copyright_file}")
            self.linux_copyrights[package.replace(":", "_")] = copyright_file

    def build_firmware(self):
        run(["cmake", "--build", self.idf_build, "--parallel", self.a.jobs], env=self.env)
        images = list(self.idf_build.glob("esp32s3supermini-*.bin"))
        if len(images) != 1:
            raise BuildError(f"Expected exactly one merged firmware image in {self.idf_build}")
        validate_firmware(images[0])
        target = self.output / "firmware"
        with tempfile.TemporaryDirectory(prefix="firmware-", dir=self.build) as temp:
            staged = Path(temp)
            for name in (images[0].name, "pico_fido2.bin", "bootloader/bootloader.bin",
                         "partition_table/partition-table.bin", "flasher_args.json", "flash_args", "sdkconfig"):
                copy(self.idf_build / name, staged / name)
            licenses = staged / "LICENSES"
            for name in ("pico-fido", "pico-openpgp", "pico-keys-sdk", "managed_components"):
                copy_notices(ROOT / name, licenses / name)
            copy_notices(self.idf / "components", licenses / "esp-idf/components")
            copy(self.idf / "LICENSE", licenses / "esp-idf/LICENSE")
            copy(ROOT / "LICENSE", licenses / "PROJECT-LICENSE.txt")
            self.write_manifest(staged)
            if target.exists():
                if not (target / "build-manifest.json").is_file():
                    raise BuildError(f"Refusing to replace an unowned directory: {target}")
                shutil.rmtree(target)
            shutil.copytree(staged, target)
        self.firmware = target / images[0].name
        self.firmware_licenses = target / "LICENSES"

    def controller_licenses(self, destination):
        copy(ROOT / "LICENSE", destination / "PROJECT-LICENSE.txt")
        copy(ROOT / "tools/native-controller/THIRD_PARTY.txt", destination / "THIRD_PARTY.txt")
        for name in ("relay_mbedtls", "relay_hidapi"):
            copy_notices(self.native / "_deps" / f"{name}-src", destination / name)
        shutil.copytree(self.qt_notices, destination / "Qt", ignore=shutil.ignore_patterns(".complete"))
        shutil.copytree(self.firmware_licenses, destination / "firmware")
        for name, ver, notices in self.modules:
            directory = re.sub(r"[^a-zA-Z0-9.@_-]", "_", name + "@" + ver)
            for notice in notices:
                copy(notice, destination / "PicoFidoStorage" / directory / notice.name)
        copy(self.go_license, destination / "PicoFidoStorage/GO-LICENSE.txt")
        for name in ("go.mod", "go.sum"):
            copy(GO_SOURCE / name, destination / "PicoFidoStorage" / name)
        for package, path in self.linux_copyrights.items():
            copy(path, destination / "system" / package / "copyright")

    def deploy_linux(self, stage):
        # Preflight resolves the Qt/plugin/libsecret closure. Check real targets
        # too so a new C++ dependency cannot silently produce a broken archive.
        for name in ("Esp32KeyConfirm", "pico-fido-cli"):
            deps = self.dependencies(stage / name)
            unknown = set(deps) - set(self.linux_libraries)
            if unknown:
                raise BuildError(f"Unplanned runtime dependencies: {sorted(unknown)}; update preflight roots.")
        for name, source in self.linux_libraries.items():
            copy(source, stage / "lib" / name)
        plugin_root = Path(self.qt["QT_INSTALL_PLUGINS"])
        for source in self.plugins:
            copy(source, stage / "plugins" / source.relative_to(plugin_root))
        for path in [stage / "Esp32KeyConfirm", stage / "pico-fido-cli", *list((stage / "lib").iterdir()), *list((stage / "plugins").rglob("*.so"))]:
            relative = os.path.relpath(stage / "lib", path.parent)
            run(["patchelf", "--set-rpath", "$ORIGIN/" + relative, path])
        (stage / "qt.conf").write_text("[Paths]\nPrefix=.\nPlugins=plugins\n", encoding="utf-8")
        for path in [stage / "Esp32KeyConfirm", stage / "pico-fido-cli", *list((stage / "plugins").rglob("*.so"))]:
            self.dependencies(path)

    def write_manifest(self, directory):
        manifest = {"version": self.a.version, "source_commit": run(["git", "rev-parse", "HEAD"], capture=True),
                    "platform": HOST, "architecture": platform.machine(), "firmware_idf": "5.5.6"}
        (directory / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
        (directory / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.relative_to(directory).as_posix()}\n" for p in files), encoding="utf-8")

    def build_controller(self):
        run(["cmake", "--build", self.native, "--parallel", self.a.jobs, "--target", "Esp32KeyConfirm", "pico-fido-cli"], env=self.env)
        system = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}[HOST]
        arch = {"AMD64": "x86_64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
        label = f"PicoFido2-{self.a.version}-{system}-{arch}"
        with tempfile.TemporaryDirectory(prefix="package-", dir=self.build) as temp:
            stage = Path(temp) / label
            stage.mkdir()
            if HOST == "Darwin":
                shutil.copytree(self.native / APP, stage / APP, symlinks=True)
                binaries = stage / APP / "Contents/MacOS"
                resources = stage / APP / "Contents/Resources"
            else:
                binaries = resources = stage
                copy(self.native / ("Esp32KeyConfirm" + EXE), binaries / ("Esp32KeyConfirm" + EXE))
            copy(self.native / ("pico-fido-cli" + EXE), binaries / ("pico-fido-cli" + EXE))
            helper = binaries / ("PicoFidoStorage" + EXE)
            run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", helper,
                 "./cmd/relay-storage-helper"], cwd=GO_SOURCE, env=self.goenv)
            run([helper, "--version"])
            copy(self.firmware, resources / self.firmware.name)
            self.controller_licenses(resources / "LICENSES")
            if HOST == "Windows":
                run([self.deploy, "--release", "--no-translations", "--compiler-runtime", binaries / "Esp32KeyConfirm.exe"], env=self.env)
            elif HOST == "Darwin":
                run([self.deploy, stage / APP, "-always-overwrite", "-no-codesign",
                     f"-libpath={self.qt['QT_INSTALL_LIBS']}", f"-executable={binaries / 'pico-fido-cli'}"])
                run(["codesign", "--force", "--deep", "--timestamp=none", "--sign", self.a.codesign_identity, stage / APP])
                run(["codesign", "--verify", "--deep", "--strict", stage / APP])
            else:
                self.deploy_linux(stage)
            # This command only generates a random ID; it neither opens USB nor
            # reads/writes the user's keychain, profiles or credentials.
            run([binaries / ("pico-fido-cli" + EXE), "--storage-new-id"])
            gui = binaries / ("Pico FIDO Controller" if HOST == "Darwin" else "Esp32KeyConfirm" + EXE)
            run([gui, "--storage-new-id"], env=dict(self.env, QT_QPA_PLATFORM="offscreen"))
            copy(ROOT / "ESP32-FIDO2使用说明.txt", stage / "使用说明.txt")
            (stage / "README.txt").write_text(
                "Launch: " + (APP if HOST == "Darwin" else "Esp32KeyConfirm" + EXE) + "\n"
                "pico-fido-cli is for terminal use; PicoFidoStorage is the controller's helper.\n"
                "Keep the package together. Licenses are in LICENSES/ (macOS: app Contents/Resources/LICENSES).\n"
                "The merged firmware is for blank ESP32-S3 devices. See the included instructions before flashing.\n"
                "Linux: desktop Secret Service and USB hidraw permission are required; see tools/native-controller/BUILD.txt.\n"
                "Source: https://github.com/swigger/pico-fido2\n", encoding="utf-8")
            self.write_manifest(stage)
            if HOST == "Darwin":
                archive = Path(temp) / (label + ".zip")
                run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", stage, archive])
            else:
                archive = Path(shutil.make_archive(str(Path(temp) / label), "zip" if HOST == "Windows" else "gztar", root_dir=temp, base_dir=label))
            final = self.output / archive.name
            partial = self.output / (archive.name + ".partial")
            copy(archive, partial)
            partial.replace(final)
            (self.output / (archive.name + ".sha256")).write_text(f"{sha256(final)}  {final.name}\n", encoding="utf-8")
            print(f"Package ready: {final}", flush=True)


def main(argv=None):
    if sys.version_info < (3, 10):
        print("Python >= 3.10 is required.", file=sys.stderr)
        return 2
    p = parser()
    args = p.parse_args(argv)
    if args.jobs < 1 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.version):
        p.error("--jobs must be positive; --version must contain only letters, digits, dots, underscores and hyphens.")
    if args.firmware_licenses and not args.firmware:
        p.error("--firmware-licenses requires --firmware.")
    builder = Builder(args)
    preflight_done = False
    try:
        builder.preflight()
        preflight_done = True
        if args.check_only:
            return 0
        if not args.firmware:
            builder.build_firmware()
        if not args.firmware_only:
            builder.build_controller()
        print(f"Done. Outputs: {builder.output}")
        return 0
    except (BuildError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1 if preflight_done else 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
