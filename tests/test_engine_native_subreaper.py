#!/usr/bin/env python3
"""Host Linux tests for native supervisor process ownership and waitpid reaping.

These validate source semantics, not APK Bionic compatibility. No user EXE.
"""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


BIN = Path(os.environ.get("RM11_ENGINE_SUBREAPER_BIN",
                          "/tmp/rm11-engine-subprocess-test-supervisor"))


class NativeSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "signed_apk_native_library_dir"
        self.root.mkdir()
        self.native = self.root / "libwineprobe.so"
        self.env = dict(os.environ, RM11_ENGINE_APK_LIB_DIR=str(self.root))

    def tearDown(self):
        self.temp.cleanup()

    def script(self, body):
        self.native.write_text("#!/bin/sh\n" + body + "\n")
        self.native.chmod(0o700)

    def run_supervisor(self, timeout=6):
        return subprocess.run([str(BIN), str(self.native)],
                              env=self.env, text=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              timeout=timeout)

    def test_direct_signed_native_entrypoint_exits_and_is_reaped(self):
        self.script("echo RM11_WORKER_START\nexit 0")
        out = self.run_supervisor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("RM11_WORKER_START", out.stdout)
        self.assertIn("RM11_ENGINE_NATIVE_REAP_COMPLETED reaped=", out.stderr)

    def test_orphan_descendant_reaped_without_touching_unrelated_process(self):
        self.script("(sleep 0.25; echo RM11_ORPHAN_SURVIVED) &\necho RM11_DESCENDANT_FORKED\nexit 0")
        unrelated = subprocess.Popen(["sleep", "20"])
        try:
            started = time.monotonic()
            out = self.run_supervisor()
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertLess(time.monotonic()-started, 4.5)
            self.assertIn("RM11_DESCENDANT_FORKED", out.stdout)
            self.assertIn("RM11_ORPHAN_SURVIVED", out.stdout,
                          "root launcher exit must not kill live game child")
            self.assertIn("RM11_ENGINE_NATIVE_REAP_COMPLETED", out.stderr)
            self.assertIsNone(unrelated.poll(),
                              "must not signal process outside owned group")
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_term_to_supervisor_terminates_owned_process_group(self):
        self.script("echo RM11_SLEEP_STARTED\nsleep 30")
        proc = subprocess.Popen([str(BIN), str(self.native)], env=self.env,
                                text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "RM11_SLEEP_STARTED")
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 128+signal.SIGTERM, err)
            self.assertIn("RM11_ENGINE_NATIVE_REAP_COMPLETED", err)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)

    def test_cannot_execute_unsigned_or_nested_user_paths(self):
        self.script("exit 0")
        out = subprocess.run([str(BIN), str(self.native)], text=True,
                             capture_output=True, timeout=3,
                             env={k:v for k,v in self.env.items()
                                  if k != "RM11_ENGINE_APK_LIB_DIR"})
        self.assertEqual(out.returncode, 64)
        nested = self.root / "subdirectory"
        nested.mkdir()
        child = nested / "libwineprobe.so"
        child.write_text("#!/bin/sh\nexit 0\n")
        child.chmod(0o700)
        out = subprocess.run([str(BIN), str(child)], text=True,
                             capture_output=True, timeout=3, env=self.env)
        self.assertEqual(out.returncode, 64)
        renamed = self.root / "untrusted.sh"
        renamed.write_text("#!/bin/sh\nexit 0\n")
        renamed.chmod(0o700)
        out = subprocess.run([str(BIN), str(renamed)], text=True,
                             capture_output=True, timeout=3, env=self.env)
        self.assertEqual(out.returncode, 64)


if __name__ == "__main__":
    unittest.main()
