"""Synthetic fixtures only: no observations from the user's VM."""
import importlib.util
import io
from contextlib import redirect_stdout, redirect_stderr
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "inspect_ext4", Path(__file__).resolve().parents[1] / "inspect_ext4.py")
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

# Entirely synthetic command results, not VM evidence.
DOCKER = {"Driver": "overlay2", "DockerRootDir": "/var/lib/docker"}
MOUNT = {"filesystems": [{"source": "/dev/sda1", "fstype": "ext4",
                          "options": "rw,relatime,errors=remount-ro,prjquota",
                          "target": "/"}]}
FEATURES = "Filesystem features: has_journal ext_attr project quota\n"


def fixture_runner(docker=DOCKER, mount=MOUNT, features=FEATURES):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        values = [docker, mount, features]
        value = values[len(calls) - 1]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, subprocess.CompletedProcess):
            return value
        text = json.dumps(value) if isinstance(value, (dict, list)) else value
        return subprocess.CompletedProcess(argv, 0, stdout=text, stderr="SECRET stderr")

    return run, calls


class DiscoveryTests(unittest.TestCase):
    def discover(self, **fixtures):
        runner, calls = fixture_runner(**fixtures)
        with patch.object(sys, "platform", "linux"):
            report = probe.inspect(runner=runner)
        return report, calls

    def test_ext4_present_features_and_readonly_command_contract(self):
        report, calls = self.discover()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["filesystem"], "ext4")
        self.assertEqual(report["device"], "/dev/sda1")
        self.assertEqual(report["mountpoint"], "/")
        self.assertEqual(report["features"], {"project": True, "quota": True})
        self.assertIs(report["prjquota_visible"], True)
        self.assertIs(report["enforcement_verified"], False)
        self.assertEqual([c[0] for c in calls], [
            ["docker", "info", "--format", '{"Driver":{{json .Driver}},"DockerRootDir":{{json .DockerRootDir}}}'],
            ["findmnt", "--json", "--target", "/var/lib/docker", "--output", "SOURCE,FSTYPE,OPTIONS,TARGET"],
            ["tune2fs", "-l", "/dev/sda1"]])
        for _, kw in calls:
            self.assertEqual(kw["env"]["LC_ALL"], "C")
            self.assertGreater(kw["timeout"], 0)
            self.assertFalse(kw["shell"])
        self.assertNotIn("SECRET", json.dumps(report))

    def test_features_missing_are_false_not_unknown(self):
        report, _ = self.discover(features="Filesystem features: has_journal ext_attr\n")
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["features"], {"project": False, "quota": False})

    def test_absent_empty_or_duplicate_features_are_unknown(self):
        for text in ("", "Filesystem state: clean\n", "Filesystem features:\n",
                     FEATURES + FEATURES, "Filesystem features: SECRET=token\n"):
            with self.subTest(text=text):
                report, _ = self.discover(features=text)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["features"], {"project": None, "quota": None})
                self.assertEqual(report["errors"], ["tune2fs_invalid_features"])
                self.assertNotIn("SECRET", json.dumps(report))

    def test_options_only_match_exact_prjquota_without_leaks(self):
        for options, expected in (("rw,relatime,errors=remount-ro", False),
                                  ("rw,prjquota=SECRET", False),
                                  ("rw,noprjquota,usrquota", False),
                                  ("rw,prjquota,password=SECRET", True)):
            with self.subTest(options=options):
                mount = {"filesystems": [dict(MOUNT["filesystems"][0], options=options)]}
                report, _ = self.discover(mount=mount)
                self.assertEqual(report["status"], "complete")
                self.assertIs(report["prjquota_visible"], expected)
                self.assertNotIn("SECRET", json.dumps(report))
                self.assertNotIn("options", report)

    def test_unsupported_filesystems_do_not_read_superblock(self):
        for fs in ("xfs", "btrfs", "overlay", "tmpfs"):
            with self.subTest(fs=fs):
                mount = {"filesystems": [dict(MOUNT["filesystems"][0], fstype=fs)]}
                report, calls = self.discover(mount=mount)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["filesystem"], fs)
                self.assertEqual(report["errors"], ["unsupported_filesystem"])
                self.assertEqual(len(calls), 2)
                self.assertEqual(report["features"], {"project": None, "quota": None})

    def test_unsafe_device_is_not_executed_or_disclosed(self):
        for source in ("UUID=SECRET", "/dev/sda1[/SECRET]", "/dev/../SECRET",
                       "/dev/sda1;SECRET", "/etc/SECRET", "-SECRET", None, 123,
                       "/dev//SECRET", "/dev/", "/dev/sda1\nSECRET"):
            with self.subTest(source=source):
                mount = {"filesystems": [dict(MOUNT["filesystems"][0], source=source)]}
                report, calls = self.discover(mount=mount)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["errors"], ["unsafe_device"])
                self.assertIsNone(report["device"])
                self.assertEqual(len(calls), 2)
                self.assertNotIn("SECRET", json.dumps(report))

    def test_command_failures_are_bounded_generic_and_stop_discovery(self):
        cases = [
            (FileNotFoundError("SECRET"), "unavailable"),
            (PermissionError("SECRET"), "unavailable"),
            (subprocess.TimeoutExpired("SECRET", 10, output="SECRET", stderr="SECRET"), "timeout"),
            (subprocess.CompletedProcess([], 1, "SECRET", "SECRET"), "failed"),
            (subprocess.CompletedProcess([], True, FEATURES, "SECRET"), "invalid_output"),
            # Deliberately malformed CompletedProcess: test-only type violation.
            (subprocess.CompletedProcess([], "0", FEATURES, "SECRET"), "invalid_output"),  # type: ignore
            (subprocess.CompletedProcess([], 0, None, "SECRET"), "invalid_output"),
            (subprocess.CompletedProcess([], 0, b"SECRET", "SECRET"), "invalid_output"),
            (subprocess.CompletedProcess([], 0, "SECRET" * 200000, "SECRET"), "invalid_output"),
        ]
        for stage in ("docker", "findmnt", "tune2fs"):
            for value, suffix in cases:
                with self.subTest(stage=stage, suffix=suffix, value=type(value).__name__):
                    report, calls = self.discover(**{dict(docker="docker", findmnt="mount", tune2fs="features")[stage]: value})
                    self.assertEqual(report["status"], "incomplete")
                    self.assertEqual(report["errors"], [stage + "_" + suffix])
                    self.assertEqual(len(calls), ("docker", "findmnt", "tune2fs").index(stage) + 1)
                    self.assertNotIn("SECRET", json.dumps(report))
                    self.assertIs(report["enforcement_verified"], False)

    def test_invalid_docker_json_or_metadata_stops_without_leaks(self):
        cases = ["SECRET", "", "null", "true", "12", "[]", "{}",
                 '{"Driver":"overlay2","Driver":"SECRET","DockerRootDir":"/var/lib/docker"}',
                 "[" * 1100 + "]" * 1100,
                 dict(DOCKER, Driver=None), dict(DOCKER, Driver=12),
                 dict(DOCKER, Driver="SECRET\n"), dict(DOCKER, Driver="x" * 65),
                 {"Driver": "overlay2"}, {"DockerRootDir": "/var/lib/docker"}]
        for root in (None, 42, "", "relative/SECRET", "/var/../SECRET", "/var//SECRET",
                     "/var/SECRET\n", "/var/SECRET token", "/var/SECRET?token", "/" + "x" * 4096):
            cases.append(dict(DOCKER, DockerRootDir=root))
        for value in cases:
            with self.subTest(value=value):
                report, calls = self.discover(docker=value)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["errors"], ["docker_invalid_metadata"])
                self.assertEqual(len(calls), 1)
                self.assertIsNone(report["driver"])
                self.assertIsNone(report["docker_root_dir"])
                self.assertNotIn("SECRET", json.dumps(report))

    def test_extra_metadata_is_not_published(self):
        report, _ = self.discover(docker=dict(DOCKER, RegistryConfig={"password": "SECRET"}),
                                  features="password: SECRET\n" + FEATURES)
        self.assertEqual(report["status"], "complete")
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertEqual(set(report), {"status", "errors", "driver", "docker_root_dir",
                                      "filesystem", "device", "mountpoint", "features",
                                      "prjquota_visible", "enforcement_verified"})

    def test_invalid_findmnt_metadata_is_incomplete_without_leaks(self):
        cases = ["SECRET", "", "null", "true", "12", "[]", {},
                 {"filesystems": None}, {"filesystems": []}, {"filesystems": {}},
                 {"filesystems": [None]}, {"filesystems": [MOUNT["filesystems"][0]] * 2},
                 '{"filesystems":[],"filesystems":[]}', "[" * 1100 + "]" * 1100]
        base = MOUNT["filesystems"][0]
        for key in ("fstype", "target", "options"):
            missing = dict(base)
            del missing[key]
            cases.append({"filesystems": [missing]})
            for value in (None, 123, [], {}, "", "SECRET\n"):
                cases.append({"filesystems": [dict(base, **{key: value})]})
        for target in ("relative/SECRET", "/var/../SECRET", "/var//SECRET", "/var/SECRET?token",
                       "/var/lib/dock", "/other", "/" + "x" * 4096):
            cases.append({"filesystems": [dict(base, target=target)]})
        for options in ("rw,,prjquota", ",rw", "rw,", "rw, prjquota", "x" * 65537):
            cases.append({"filesystems": [dict(base, options=options)]})
        cases.append({"filesystems": [dict(base, children=[base])]})
        for value in cases:
            with self.subTest(value=value):
                report, calls = self.discover(mount=value)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["errors"], ["findmnt_invalid_metadata"])
                self.assertEqual(len(calls), 2)
                self.assertIsNone(report["filesystem"])
                self.assertIsNone(report["mountpoint"])
                self.assertIsNone(report["prjquota_visible"])
                self.assertNotIn("SECRET", json.dumps(report))

    def test_missing_source_remains_unknown_without_tune2fs(self):
        mount = dict(MOUNT["filesystems"][0])
        del mount["source"]
        report, calls = self.discover(mount={"filesystems": [mount]})
        self.assertEqual(report["errors"], ["unsafe_device"])
        self.assertEqual(len(calls), 2)

    def test_safe_mapper_and_nested_mount_are_accepted(self):
        mount = {"filesystems": [dict(MOUNT["filesystems"][0],
                                     source="/dev/mapper/vg-root", target="/var/lib")]}
        report, calls = self.discover(mount=mount)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["device"], "/dev/mapper/vg-root")
        self.assertEqual(calls[-1][0], ["tune2fs", "-l", "/dev/mapper/vg-root"])

    def test_cli_non_linux_emits_only_json_and_nonzero_exit(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "platform", "win32"), redirect_stdout(out), redirect_stderr(err):
            code = probe.main([])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["errors"], ["unsupported_platform"])
        self.assertEqual(err.getvalue(), "")

    def test_cli_has_no_mutating_or_fixture_flags(self):
        for args in (["--enable"], ["--device", "/dev/SECRET"], ["--fixture", "SECRET"]):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(probe, "inspect", side_effect=AssertionError("must not probe")):
                with redirect_stdout(out), redirect_stderr(err):
                    code = probe.main(args)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out.getvalue())["errors"], ["invalid_arguments"])
            self.assertIs(json.loads(out.getvalue())["enforcement_verified"], False)
            self.assertNotIn("SECRET", out.getvalue() + err.getvalue())
            self.assertEqual(err.getvalue(), "")

    def test_non_linux_is_incomplete_without_commands(self):
        def forbidden(*args, **kwargs):
            self.fail("A command ran outside Linux")
        with patch.object(sys, "platform", "win32"):
            report = probe.inspect(runner=forbidden)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["errors"], ["unsupported_platform"])
        self.assertIs(report["enforcement_verified"], False)


if __name__ == "__main__":
    unittest.main()
