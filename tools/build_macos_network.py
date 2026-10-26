#!/usr/bin/env python3
"""Build the unsigned macOS network bundle and actual-source host controls.

No activation, signing, runtime capture, or entitlement acceptance is performed.
Compiler/control output stays in the private output directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import signal
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "infrastructure/endpoint/macos-network"
BRIDGE = ROOT / "core-engines/macos-network/src/macos"
POLICY = "faf8a5d37afe9cdc39b09b3562832b0db72b9c0b03281dd1ce701fc889f1dc64"
DEV = dict(team_id="TESTTEAM00", agent_identifier="com.example.athernex.agent",
           container_identifier="com.example.athernex.network", provider_identifier="com.example.athernex.network.provider",
           app_group="TESTTEAM00.com.example.athernex.network", mach_service_name="TESTTEAM00.com.example.athernex.network.ipc")


class BuildFailure(Exception):
    pass


def identity(value):
    if not isinstance(value, dict) or set(value) != set(DEV):
        raise BuildFailure("identity")
    if not isinstance(value["team_id"], str) or not re.fullmatch(r"[A-Z0-9]{10}", value["team_id"]):
        raise BuildFailure("identity")
    for key, item in value.items():
        if key == "team_id":
            continue
        if not isinstance(item, str) or len(item) > 255 or "." not in item or any(
                not re.fullmatch(r"[A-Za-z0-9-]{1,63}", p) for p in item.split(".")):
            raise BuildFailure("identity")
    if len({value[k] for k in ("agent_identifier", "container_identifier", "provider_identifier")}) != 3:
        raise BuildFailure("identity")
    if not value["mach_service_name"].startswith(value["app_group"] + "."):
        raise BuildFailure("identity")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildFailure("identity")
        result[key] = value
    return result


def read_identity(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise BuildFailure("identity")
    # NOFOLLOW refuses a substituted symlink; NONBLOCK prevents a substituted
    # FIFO from blocking before the descriptor's type can be checked.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise BuildFailure("identity")
        data = stream.read(4097)
    if len(data) > 4096:
        raise BuildFailure("identity")
    return identity(json.loads(data.decode("utf-8"), object_pairs_hook=unique_object))


def prepare_output(path):
    if path.is_symlink():
        raise BuildFailure("output")
    parent = path.parent.resolve(strict=True)
    path = parent / path.name
    if os.name == "posix":
        for ancestor in [parent, *parent.parents]:
            metadata = ancestor.stat()
            if metadata.st_uid not in (0, os.geteuid()) or (metadata.st_mode & 0o022 and not (
                    metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)):
                raise BuildFailure("output_parent")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise BuildFailure("output")
    path.mkdir(mode=0o700, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or (os.name == "posix" and metadata.st_uid != os.geteuid()):
        raise BuildFailure("output_owner")
    if os.name == "posix":
        path.chmod(0o700)
    return path


def write_plist(path, data):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=True))
    path.chmod(0o644)


def bundle(output, ident):
    app = output / "AthernexNetwork.app"
    provider = app / "Contents/Library/SystemExtensions" / (ident["provider_identifier"] + ".systemextension")
    for directory, kind, executable in ((app, "container", "AthernexNetwork"), (provider, "provider", "AthernexNetworkProvider")):
        info = dict(CFBundleIdentifier=ident[kind + "_identifier"], CFBundleExecutable=executable,
                    CFBundlePackageType="APPL" if kind == "container" else "SYSX", CFBundleInfoDictionaryVersion="6.0",
                    CFBundleVersion="1", CFBundleShortVersionString="0.1", LSMinimumSystemVersion="13.0",
                    AXNetworkIdentity=ident, AXNetworkPolicy=POLICY,
                    NSSystemExtensionUsageDescription="Observe new socket-flow metadata while allowing traffic.")
        if kind == "provider":
            info["NetworkExtension"] = dict(NEMachServiceName=ident["mach_service_name"],
                NEProviderClasses={"com.apple.networkextension.filter-data": "AthernexNetworkProvider.NetworkProvider"})
        write_plist(directory / "Contents/Info.plist", info)
        (directory / "Contents/MacOS").mkdir(mode=0o755, parents=True)
        entitlements = {"com.apple.security.app-sandbox": True,
            "com.apple.security.application-groups": [ident["app_group"]],
            "com.apple.developer.networking.networkextension": ["content-filter-provider-systemextension"]}
        if kind == "container":
            entitlements["com.apple.developer.system-extension.install"] = True
        # Release signing inputs are outside the installed app tree and are not
        # an authorization to sign or activate this unsigned build.
        write_plist(output / (kind + ".entitlements.plist"), entitlements)
    return app, provider


COMPILE_PHASES = {"counters_compile", "provider_compile", "container_compile", "source_controls_compile", "bridge_controls_compile"}
CONTROL_LINES = {
    "source_controls": b"Network metadata controls passed; mocked callbacks and XPC sessions only\n",
    "bridge_controls": b"Network bridge controls passed; no live peer authentication proof\n",
}


def compiler_diagnostics(log, phase, code, development):
    if not development or phase not in COMPILE_PHASES or code == 0:
        return
    owned = {str(p.resolve()): p.relative_to(ROOT).as_posix() for tree in (SOURCE, BRIDGE)
             for p in tree.rglob("*") if p.is_file() and p.suffix in (".swift", ".m", ".h", ".c")}
    with log.open("rb") as stream:
        data = stream.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
    entries = []
    for line in data.splitlines():
        match = re.fullmatch(r"(.+\.(?:swift|m|h|c)):(\d+):(?:(\d+):)?\s*(?:fatal error|error|warning):\s*(.*)", line)
        if not match:
            continue
        raw, row, column, message = match.groups()
        path = str(Path(raw).resolve())
        if path not in owned or int(row) > 1_000_000 or int(column or "0") > 1_000_000:
            continue
        message = re.sub(r"/[^\s\"'<>]*", "<path>", message)
        message = "".join(c if 32 <= ord(c) < 127 else " " for c in message)[:240]
        entries.append(dict(source=owned[path], line=int(row), column=int(column or "0"), message=message))
        if len(entries) == 20:
            break
    print(json.dumps(dict(phase=phase, exit_code=code, compiler_diagnostics=entries), sort_keys=True))


def run(output, phase, command, timeout=180, development=False):
    log = output / (phase + ".log")
    with log.open("xb") as stream:
        log.chmod(0o600)
        child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise BuildFailure(phase + "_cleanup") from error
            raise BuildFailure(phase + "_timeout")
    if code != 0:
        compiler_diagnostics(log, phase, code, development)
    if code != 0 or log.stat().st_size > 4 * 1024 * 1024:
        raise BuildFailure(phase)
    if phase in CONTROL_LINES and log.read_bytes() != CONTROL_LINES[phase]:
        raise BuildFailure(phase + "_receipt")
    return dict(phase=phase, exit_code=code, log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())


def build(output, ident, development=False):
    if platform.system() != "Darwin":
        raise BuildFailure("macos_required")
    machine = platform.machine()
    if machine not in ("arm64", "x86_64"):
        raise BuildFailure("architecture")
    app, provider = bundle(output, ident)
    sdk = subprocess.run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
    try:
        sdkpath = sdk.stdout.decode("utf-8").strip()
    except UnicodeError as error:
        raise BuildFailure("sdk") from error
    if sdk.returncode or not sdkpath.startswith("/") or "\n" in sdkpath or len(sdkpath) > 4096:
        raise BuildFailure("sdk")
    cc = ["/usr/bin/xcrun", "clang", "-isysroot", sdkpath, "-target", machine + "-apple-macos12.0",
          "-Wall", "-Wextra", "-Werror", "-I", str(SOURCE / "Shared"), "-I", str(BRIDGE)]
    if development and ident != DEV:
        raise BuildFailure("development_identity")
    def step(phase, command, timeout=180):
        return run(output, phase, command, timeout=timeout, development=development)
    checks = [step("counters_compile", cc + ["-std=c11", "-c", str(SOURCE / "Shared/Counters.c"), "-o", str(output / "counters.o")])]
    swift = ["/usr/bin/xcrun", "swiftc", "-sdk", sdkpath, "-target", machine + "-apple-macos13.0",
             "-swift-version", "5", "-parse-as-library", "-O"]
    shared = [str(SOURCE / "Shared/Primitives.swift"), str(SOURCE / "Shared/Identity.swift")]
    provider_sources = [str(SOURCE / "Provider" / f) for f in ("SourceState.swift", "Projection.swift", "ProviderIPC.swift", "NetworkProvider.swift", "Main.swift")]
    frameworks = ["-framework", "Foundation", "-framework", "Security", "-framework", "NetworkExtension"]
    import_header = ["-import-objc-header", str(SOURCE / "Shared/Bridge.h")]
    checks.append(step("provider_compile", swift + ["-module-name", "AthernexNetworkProvider"] + import_header + shared + provider_sources +
                      [str(output / "counters.o")] + frameworks + ["-o", str(provider / "Contents/MacOS/AthernexNetworkProvider")]))
    checks.append(step("container_compile", swift + ["-module-name", "AthernexNetwork"] + shared +
                      [str(SOURCE / "Container/Main.swift")] + frameworks + ["-framework", "SystemExtensions", "-framework", "AppKit",
                       "-o", str(app / "Contents/MacOS/AthernexNetwork")]))
    controls = [str(SOURCE / "Provider" / f) for f in ("SourceState.swift", "Projection.swift", "ProviderIPC.swift")]
    checks.append(step("source_controls_compile", swift + ["-D", "AX_TESTS", "-module-name", "NetworkSourceControls"] + import_header + shared + controls +
                      [str(SOURCE / "Tests/Controls.swift"), str(output / "counters.o")] + frameworks + ["-o", str(output / "source-controls")]))
    checks.append(step("source_controls", [str(output / "source-controls")], timeout=30))
    checks.append(step("bridge_controls_compile", cc + ["-fobjc-arc", "-fblocks", str(BRIDGE / "client.m"),
                      str(BRIDGE / "inspection.m"), str(SOURCE / "Tests/BridgeControls.m")] + frameworks[:4] + ["-o", str(output / "bridge-controls")]))
    checks.append(step("bridge_controls", [str(output / "bridge-controls")], timeout=30))
    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--development", action="store_true")
    selection.add_argument("--identity-file", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.development:
            ident = identity(dict(DEV))
        else:
            ident = read_identity(args.identity_file)
        output = prepare_output(args.output)
        checks = build(output, ident, development=args.development)
        report = dict(schema=1, unsigned=True, native_network_executed=False, activation_performed=False,
                      production_readiness=False, checks=checks)
        result = output / "build.json"
        result.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8"); result.chmod(0o600)
        print("Unsigned network components and actual-source controls passed; no activation or native flow proof")
        return 0
    except BuildFailure as error:
        print("Network component build refused: " + str(error), file=sys.stderr)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Network component build refused: input_or_tool_failure", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
