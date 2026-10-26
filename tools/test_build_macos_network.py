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
            app, provider = b.bundle(out, dict(b.DEV))
            for path, role, exe in ((app, "container", "AthernexNetwork"), (provider, "provider", "AthernexNetworkProvider")):
                info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
                self.assertEqual(info["CFBundleIdentifier"], b.DEV[role + "_identifier"])
                self.assertEqual(info["CFBundleExecutable"], exe)
                self.assertEqual(info["LSMinimumSystemVersion"], "13.0")
                self.assertEqual(info["AXNetworkIdentity"], b.DEV)
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
            parent = Path(t) / "shared"; parent.mkdir(); parent.chmod(0o770)
            with self.assertRaisesRegex(b.BuildFailure, "^output_parent$"):
                b.prepare_output(parent / "private")
            self.assertEqual(parent.stat().st_mode & 0o777, 0o770)
            parent.chmod(0o700); out = parent / "private"; out.mkdir()
            native = Path.lstat
            def metadata(path):
                if path == out:
                    result = native(path)
                    return types.SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid() + 1)
                return native(path)
            with mock.patch.object(Path, "lstat", metadata), self.assertRaisesRegex(b.BuildFailure, "^output_owner$"):
                b.prepare_output(out)

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
                checks = b.build(Path(t), dict(b.DEV))
            self.assertEqual(len(checks), 7)
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
                rc = b.main(["--output", str(Path(t) / "out"), "--identity-file", str(identity)])
            self.assertEqual(rc, 1)
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


if __name__ == "__main__":
    unittest.main()
