"""Portable mocked build controls; no Apple runtime or activation claim."""
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import types
import tempfile
import unittest
from unittest import mock

from tools import build_macos_network as b


class NetworkBuildTests(unittest.TestCase):
    def test_identity_refuses_injection_unknown_fields_and_aliases(self):
        self.assertEqual(b.identity(dict(b.DEV)), b.DEV)
        for key, value in (("agent_identifier", 'test.agent" or true'), ("team_id", "secret-value"),
                           ("app_group", "test..group"), ("mach_service_name", "other.group.service"),
                           ("provider_identifier", b.DEV["agent_identifier"]), ("provider_identifier", "a" * 256)):
            d = dict(b.DEV); d[key] = value
            with self.subTest(key=key), self.assertRaises(b.BuildFailure):
                b.identity(d)
        with self.assertRaises(b.BuildFailure):
            b.identity(dict(b.DEV, requirement="true"))
        with self.assertRaises(b.BuildFailure):
            json.loads('{"team_id":"one","team_id":"two"}', object_pairs_hook=b.unique_object)

    def test_output_and_fixed_bundle_shape_preserve_unsigned_boundary(self):
        with tempfile.TemporaryDirectory() as t:
            out = b.prepare_output(Path(t) / "output")
            app, provider = b.bundle(out, dict(b.DEV), bundle_version=b.DEV_BUNDLE_VERSION, short_version=b.DEV_SHORT_VERSION)
            for path, role, exe in ((app, "container", "AthernexNetwork"), (provider, "provider", "AthernexNetworkProvider")):
                info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
                self.assertEqual(info["CFBundleIdentifier"], b.DEV[role + "_identifier"])
                self.assertEqual(info["CFBundleExecutable"], exe)
                self.assertEqual(info["LSMinimumSystemVersion"], "13.0")
                self.assertEqual(info["AXNetworkIdentity"], b.DEV)
                self.assertEqual(info["CFBundleVersion"], b.DEV_BUNDLE_VERSION)
                self.assertEqual(info["CFBundleShortVersionString"], b.DEV_SHORT_VERSION)
                ent = plistlib.loads((out / (role + ".entitlements.plist")).read_bytes())
                self.assertEqual(ent["com.apple.developer.networking.networkextension"], ["content-filter-provider-systemextension"])
            self.assertEqual(sorted(p.relative_to(app).as_posix() for p in app.rglob("*") if p.is_file()), [
                "Contents/Info.plist", "Contents/Library/SystemExtensions/" + b.DEV["provider_identifier"] + ".systemextension/Contents/Info.plist"])
            with self.assertRaises(b.BuildFailure):
                b.prepare_output(out)

    def test_identity_read_is_bounded_and_refuses_nonregular_inputs(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "identity.json"
            path.write_text(json.dumps(b.DEV), encoding="utf-8")
            self.assertEqual(b.read_identity(path), b.DEV)
            path.write_bytes(b" " * 4097)
            with self.assertRaises(b.BuildFailure):
                b.read_identity(path)
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeError):
                b.read_identity(path)
            with self.assertRaises(b.BuildFailure):
                b.read_identity(Path(t))
            if os.name == "posix":
                link = Path(t) / "link"; link.symlink_to(path)
                with self.assertRaises(b.BuildFailure):
                    b.read_identity(link)
                fifo = Path(t) / "fifo"; os.mkfifo(fifo)
                with self.assertRaises(b.BuildFailure):
                    b.read_identity(fifo)

    @unittest.skipIf(os.name == "nt", "POSIX symlink control")
    def test_output_symlink_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "target"; target.mkdir()
            link = Path(t) / "link"; link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(b.BuildFailure):
                b.prepare_output(link)
            self.assertFalse(list(target.iterdir()))

    @unittest.skipIf(os.name == "nt", "POSIX replacement and ownership control")
    def test_writable_parent_and_foreign_leaf_refuse_without_chmodding_parent(self):
        with tempfile.TemporaryDirectory() as t:
            parent = Path(t).resolve() / "shared"; parent.mkdir(); parent.chmod(0o770)
            with self.assertRaisesRegex(b.BuildFailure, "^output_parent$"):
                b.prepare_output(parent / "private")
            self.assertEqual(parent.stat().st_mode & 0o777, 0o770)
            parent.chmod(0o700); out = parent / "private"; out.mkdir()
            native = Path.lstat; injected = []
            def metadata(path):
                if path == out:
                    injected.append(True)
                    result = native(path)
                    return types.SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid() + 1)
                return native(path)
            with mock.patch.object(Path, "lstat", metadata), self.assertRaisesRegex(b.BuildFailure, "^output_owner$"):
                b.prepare_output(out)
            self.assertTrue(injected, "Foreign-owner metadata was not exercised")

    @unittest.skipIf(os.name == "nt", "POSIX canonical-parent alias control")
    def test_symlink_ancestor_keeps_foreign_owner_check_on_canonical_leaf(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve(); real = root / "real"; real.mkdir(mode=0o700)
            alias = root / "alias"; alias.symlink_to(real, target_is_directory=True)
            requested = alias / "private"; canonical = real / "private"
            self.assertNotEqual(requested, canonical)
            self.assertEqual(b.prepare_output(requested), canonical)
            native = Path.lstat; injected = []
            def metadata(path):
                if path == canonical:
                    injected.append(True)
                    result = native(path)
                    return types.SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid() + 1)
                return native(path)
            with mock.patch.object(Path, "lstat", metadata), self.assertRaisesRegex(b.BuildFailure, "^output_owner$"):
                b.prepare_output(requested)
            self.assertTrue(injected, "Canonical foreign-owner metadata was not exercised")
            self.assertEqual(canonical.stat().st_mode & 0o777, 0o700)

    def test_mocked_command_plan_compiles_actual_sources_without_signing_or_activation(self):
        with tempfile.TemporaryDirectory() as t:
            commands = []
            def command(out, phase, argv, timeout=180, development=False):
                commands.append((phase, argv, timeout))
                return dict(phase=phase, exit_code=0, log_sha256="a" * 64)
            sdk = subprocess.CompletedProcess([], 0, stdout=b"/synthetic/Apple.sdk\n")
            with mock.patch.object(b.platform, "system", return_value="Darwin"), \
                 mock.patch.object(b.platform, "machine", return_value="arm64"), \
                 mock.patch.object(b.subprocess, "run", return_value=sdk), mock.patch.object(b, "run", side_effect=command):
                checks = b.build(Path(t), dict(b.DEV), bundle_version="2.3.4", short_version="1.2.3")
            self.assertEqual(len(checks), 12)
            phases = {phase: argv for phase, argv, _ in commands}
            self.assertIn("SourceState.swift", " ".join(phases["source_controls_compile"]))
            self.assertIn("ProviderIPC.swift", " ".join(phases["source_controls_compile"]))
            self.assertIn("inspection.m", " ".join(phases["bridge_controls_compile"]))
            self.assertIn("arm64-apple-macos13.0", phases["provider_compile"])
            self.assertIn("arm64-apple-macos12.0", phases["bridge_controls_compile"])
            for _, argv, _ in commands:
                self.assertNotIn("codesign", argv)
                self.assertNotIn("systemextensionsctl", argv)
                self.assertNotIn("open", argv)

    def test_lifecycle_build_and_controls_compile_owned_sources_without_activation(self):
        with tempfile.TemporaryDirectory() as t:
            commands = []
            def command(out, phase, argv, timeout=180, development=False):
                commands.append((phase, argv, timeout))
                return dict(phase=phase, exit_code=0, log_sha256="a" * 64)
            sdk = subprocess.CompletedProcess([], 0, stdout=b"/synthetic/Apple.sdk\n")
            with mock.patch.object(b.platform, "system", return_value="Darwin"), \
                 mock.patch.object(b.platform, "machine", return_value="x86_64"), \
                 mock.patch.object(b.subprocess, "run", return_value=sdk), mock.patch.object(b, "run", side_effect=command):
                b.build(Path(t), dict(b.DEV), development=True, bundle_version=b.DEV_BUNDLE_VERSION, short_version=b.DEV_SHORT_VERSION)
            phases = {phase: (argv, timeout) for phase, argv, timeout in commands}
            native = phases["upgrade_native_compile"][0]
            self.assertIn(str(b.SOURCE / "Container/Native.m"), native)
            self.assertIn("-c", native); self.assertIn("-fobjc-arc", native); self.assertIn("-fblocks", native)
            container = phases["container_compile"][0]
            self.assertEqual(container[container.index("-import-objc-header") + 1], str(b.SOURCE / "Container/Bridge.h"))
            for name in ("UpgradeModel.swift", "UpgradeJSON.swift", "UpgradeConnection.swift", "UpgradeController.swift", "Main.swift"):
                self.assertIn(str(b.SOURCE / "Container" / name), container)
            self.assertIn(str(Path(t) / "upgrade-native.o"), container)
            swift_control = phases["upgrade_controls_compile"][0]
            self.assertIn(str(b.SOURCE / "Container/UpgradeModel.swift"), swift_control)
            self.assertIn(str(b.SOURCE / "Container/UpgradeJSON.swift"), swift_control)
            self.assertIn(str(b.SOURCE / "Tests/UpgradeControls.swift"), swift_control)
            self.assertNotIn(str(b.SOURCE / "Container/UpgradeController.swift"), swift_control)
            bridge_control = phases["upgrade_bridge_controls_compile"][0]
            for name in ("client.m", "inspection.m", "upgrade_inspection.m"):
                self.assertIn(str(b.BRIDGE / name), bridge_control)
            self.assertIn(str(b.SOURCE / "Tests/UpgradeBridgeControls.m"), bridge_control)
            for phase in ("upgrade_controls", "upgrade_bridge_controls"):
                self.assertEqual(phases[phase][1], 30)
                self.assertEqual(len(phases[phase][0]), 1)
            self.assertEqual([phase for phase, _, _ in commands].count("upgrade_native_compile"), 1)
            self.assertLess([p for p, _, _ in commands].index("upgrade_native_compile"), [p for p, _, _ in commands].index("container_compile"))
            for _, argv, _ in commands:
                self.assertFalse(any(arg in ("codesign", "systemextensionsctl", "open", "--activate", "--replace") for arg in argv))

    def test_readonly_upgrade_exceptions_are_exact_and_container_only(self):
        with tempfile.TemporaryDirectory() as t:
            b.bundle(Path(t), dict(b.DEV), bundle_version="2.0.0", short_version="1.0.0")
            container = plistlib.loads((Path(t) / "container.entitlements.plist").read_bytes())
            provider = plistlib.loads((Path(t) / "provider.entitlements.plist").read_bytes())
            key = "com.apple.security.temporary-exception.files.absolute-path.read-only"
            self.assertEqual(container[key], ["/Library/SystemExtensions/", "/Library/Application Support/AthernexNetwork/"])
            self.assertNotIn(key, provider)
            self.assertNotIn("com.apple.security.temporary-exception.files.absolute-path.read-write", container)
            self.assertEqual(set(provider), {"com.apple.security.app-sandbox", "com.apple.security.application-groups",
                                            "com.apple.developer.networking.networkextension"})

    def test_upgrade_controls_require_exact_receipt_even_when_child_exits_zero(self):
        for phase in ("upgrade_controls", "upgrade_bridge_controls"):
            for text in (b"", b"unapproved private diagnostic\n", b"extra\n" + b.CONTROL_LINES[phase], b.CONTROL_LINES[phase]):
                with self.subTest(phase=phase, exact=text == b.CONTROL_LINES[phase]), tempfile.TemporaryDirectory() as t:
                    child = mock.Mock(); child.wait.return_value = 0
                    def spawn(command, **kwargs):
                        kwargs["stdout"].write(text)
                        kwargs["stdout"].flush()
                        return child
                    output = io.StringIO()
                    with mock.patch.object(b.subprocess, "Popen", side_effect=spawn), contextlib.redirect_stdout(output):
                        if text == b.CONTROL_LINES[phase]:
                            self.assertEqual(b.run(Path(t), phase, ["synthetic-control"], timeout=30)["exit_code"], 0)
                        else:
                            with self.assertRaisesRegex(b.BuildFailure, "^" + phase + "_receipt$"):
                                b.run(Path(t), phase, ["synthetic-control"], timeout=30)
                    self.assertEqual(output.getvalue(), "")
                    if os.name != "nt":
                        self.assertEqual((Path(t) / (phase + ".log")).stat().st_mode & 0o777, 0o600)

    def test_failed_build_exposes_only_fixed_phase_and_keeps_private_log(self):
        with tempfile.TemporaryDirectory() as t:
            child = mock.Mock(); child.wait.return_value = 9
            with mock.patch.object(b.subprocess, "Popen", return_value=child):
                with self.assertRaisesRegex(b.BuildFailure, "^provider_compile$"):
                    b.run(Path(t), "provider_compile", ["synthetic-compiler"])
            if os.name != "nt":
                self.assertEqual((Path(t) / "provider_compile.log").stat().st_mode & 0o777, 0o600)
            stderr = io.StringIO()
            identity = Path(t) / "private.json"; identity.write_text('{"raw":"sensitive-fixture"}')
            with contextlib.redirect_stderr(stderr):
                rc = b.main(["--output", str(Path(t) / "out"), "--identity-file", str(identity),
                             "--bundle-version", "1.0.0", "--short-version", "0.1.0"])
            self.assertEqual(rc, 1)
            self.assertIn("build refused: identity", stderr.getvalue())
            self.assertNotIn("sensitive-fixture", stderr.getvalue())
            self.assertNotIn(str(identity), stderr.getvalue())

    def test_owned_compiler_group_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as t:
            child = mock.Mock(); child.pid = 123; child.wait.side_effect = [subprocess.TimeoutExpired("compiler", 180), -9]
            with mock.patch.object(b.subprocess, "Popen", return_value=child), \
                 mock.patch.object(b.os, "killpg", create=True) as kill, \
                 mock.patch.object(b.signal, "SIGKILL", 9, create=True):
                with self.assertRaisesRegex(b.BuildFailure, "^provider_compile_timeout$"):
                    b.run(Path(t), "provider_compile", ["synthetic-compiler"])
                kill.assert_called_once_with(123, 9)
                self.assertEqual(child.wait.call_args_list, [mock.call(timeout=180), mock.call(timeout=5)])

    def test_control_exit_zero_without_exact_receipt_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            child = mock.Mock(); child.wait.return_value = 0
            with mock.patch.object(b.subprocess, "Popen", return_value=child):
                with self.assertRaisesRegex(b.BuildFailure, "^source_controls_receipt$"):
                    b.run(Path(t), "source_controls", ["synthetic-control"])

    def test_development_compiler_projection_is_bounded_owned_and_never_runtime(self):
        with tempfile.TemporaryDirectory() as t:
            log = Path(t) / "build.log"
            source = b.SOURCE / "Provider/Projection.swift"
            lines = [f"{source}:12:3: error: source type at /private/unapproved/path {chr(27)}" for _ in range(30)]
            lines += ["/private/unknown.swift:1:1: error: ignored"]
            log.write_text("\n".join(lines), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                b.compiler_diagnostics(log, "provider_compile", 1, True)
            result = json.loads(stdout.getvalue())
            self.assertEqual(len(result["compiler_diagnostics"]), 20)
            self.assertNotIn("/private/unapproved", stdout.getvalue())
            self.assertNotIn(str(b.ROOT), stdout.getvalue())
            for development, phase, code in ((False, "provider_compile", 1), (True, "source_controls", 1), (True, "provider_compile", 0)):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    b.compiler_diagnostics(log, phase, code, development)
                self.assertEqual(stdout.getvalue(), "")

    def test_versions_accept_only_bounded_canonical_numeric_components(self):
        for build, short in (("1.0.0", "0.0.0"), ("9.10.99", "0.1.0"), ("9999.99.99", "9999.99.99")):
            self.assertEqual(b.bundle_versions(build, short), (build, short))
        invalid = (None, True, 1, [], "", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03",
                   "1.2.3b1", "1.2.3+build", "-1.2.3", "+1.2.3", "1.-2.3", "1.2.-3", "1..3",
                   "1.2.3\n", " 1.2.3", "1.2.3 ", "１.2.3", "1.٢.3", "10000.0.0", "1.100.0", "1.0.100",
                   "9" * 4096, "1.2.3\x00")
        for value in invalid:
            for build, short, reason in ((value, "1.0.0", "bundle_version"), ("1.0.0", value, "short_version")):
                with self.subTest(value=value, reason=reason), self.assertRaisesRegex(b.BuildFailure, "^" + reason + "$"):
                    b.bundle_versions(build, short)
        with self.assertRaisesRegex(b.BuildFailure, "^bundle_version$"):
            b.bundle_versions("0.1.0", "0.1.0")

    def test_missing_or_invalid_production_versions_refuse_before_output_mutation(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); ident = root / "identity.json"; ident.write_text(json.dumps(b.DEV), encoding="utf-8")
            existing = root / "existing"; existing.mkdir(); sentinel = existing / "preserved"; sentinel.write_bytes(b"unchanged")
            before = existing.stat().st_mode
            cases = ([], ["--bundle-version", "1.0.0"], ["--short-version", "0.1.0"],
                     ["--bundle-version", "01.0.0", "--short-version", "0.1.0"],
                     ["--bundle-version", "1.0.0", "--short-version", "private-invalid-version"])
            for output in (root / "missing", existing):
                for options in cases:
                    stderr = io.StringIO(); stdout = io.StringIO()
                    with self.subTest(output=output.name, options=options), \
                         mock.patch.object(b, "prepare_output") as prepare, mock.patch.object(b, "build") as build, \
                         contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                        self.assertEqual(b.main(["--output", str(output), "--identity-file", str(ident), *options]), 1)
                    prepare.assert_not_called(); build.assert_not_called()
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn(stderr.getvalue(), ("Network component build refused: bundle_version\n",
                                                      "Network component build refused: short_version\n"))
            self.assertFalse((root / "missing").exists())
            self.assertEqual(existing.stat().st_mode, before)
            self.assertEqual(sentinel.read_bytes(), b"unchanged")
            self.assertEqual(sorted(p.name for p in existing.iterdir()), ["preserved"])

    def test_bundle_and_build_reject_invalid_versions_before_writing(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "not-created"
            for make in (b.bundle, b.build):
                for versions in ((None, "1.0.0"), ("1.0.0", None), ("1.0.0", "1.2")):
                    with self.subTest(make=make.__name__, versions=versions), self.assertRaises(b.BuildFailure):
                        make(out, dict(b.DEV), bundle_version=versions[0], short_version=versions[1])
                    self.assertFalse(out.exists())
            with self.assertRaisesRegex(b.BuildFailure, "^development_version$"):
                b.build(out, dict(b.DEV), development=True, bundle_version="2.0.0", short_version="1.0.0")
            self.assertFalse(out.exists())

    def test_explicit_release_versions_reach_both_bundle_roles_and_private_report(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); ident = root / "identity.json"; ident.write_text(json.dumps(b.DEV), encoding="utf-8")
            def assemble(output, identity, development=False, *, bundle_version, short_version):
                self.assertFalse(development)
                b.bundle(output, identity, bundle_version=bundle_version, short_version=short_version)
                return []
            declarations = (("5.7.8", "2.3.4"), ("5.7.9", "2.3.4"), ("6.0.0", "2.4.0"))
            provider_plists = []
            for index, (build_version, release_version) in enumerate(declarations):
                output = root / str(index)
                with mock.patch.object(b, "build", side_effect=assemble) as build, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(b.main(["--output", str(output), "--identity-file", str(ident),
                                             "--bundle-version", build_version, "--short-version", release_version]), 0)
                self.assertEqual(build.call_count, 1)
                app = output / "AthernexNetwork.app"
                provider = app / "Contents/Library/SystemExtensions" / (b.DEV["provider_identifier"] + ".systemextension")
                for directory in (app, provider):
                    info = plistlib.loads((directory / "Contents/Info.plist").read_bytes())
                    self.assertEqual((info["CFBundleVersion"], info["CFBundleShortVersionString"]),
                                     (build_version, release_version))
                provider_plists.append((provider / "Contents/Info.plist").read_bytes())
                report = json.loads((output / "build.json").read_text())
                self.assertEqual((report["bundle_version"], report["short_version"]), (build_version, release_version))
                self.assertFalse(report["activation_performed"])
                self.assertFalse(report["production_readiness"])
            self.assertEqual(len(set(provider_plists)), 3)

    def test_development_versions_are_deterministic_and_cannot_be_overridden(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); snapshots = []
            def assemble(output, identity, development=False, *, bundle_version, short_version):
                self.assertTrue(development)
                self.assertEqual((bundle_version, short_version), ("1.0.0", "0.1.0"))
                b.bundle(output, identity, bundle_version=bundle_version, short_version=short_version)
                return []
            for index in range(2):
                output = root / str(index)
                with mock.patch.object(b, "build", side_effect=assemble), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(b.main(["--output", str(output), "--development"]), 0)
                snapshots.append([(p.relative_to(output).as_posix(), p.read_bytes()) for p in sorted(output.rglob("*")) if p.is_file()])
            self.assertEqual(snapshots[0], snapshots[1])
            for extra in (["--bundle-version", "1.0.0"], ["--short-version", "0.1.0"],
                          ["--bundle-version", "2.0.0", "--short-version", "1.0.0"]):
                stderr = io.StringIO()
                with mock.patch.object(b, "prepare_output") as prepare, contextlib.redirect_stderr(stderr):
                    self.assertEqual(b.main(["--output", str(root / "rejected"), "--development", *extra]), 1)
                prepare.assert_not_called()
                self.assertEqual(stderr.getvalue(), "Network component build refused: development_version\n")
            self.assertFalse((root / "rejected").exists())


if __name__ == "__main__":
    unittest.main()
