# SPDX-License-Identifier: MIT
"""Fail-closed static test for a real Android FEX 4-instruction probe.

This checks source-level diagnostic/liveness invariants only. Passing this
test never means FEX actually executed on a physical Android device.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "native-engine/android-c3d8c0-original-fex-ldso-probe-app"
JAVA = ANDROID / "app/src/main/java/org/kernix/originalfexldso/MainActivity.java"
CHILD = ROOT / "native-engine/android-host/kernix_g2e_c3d8c0_android_original_ldso_four_fex_child.cpp"
WORKFLOW = ROOT / ".github/workflows/kernix-g2e-c3d8c0-android-original-ldso-four-fex-debug-apk.yml"


class AndroidOriginalFEXDiagnosticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = JAVA.read_text(encoding="utf-8")
        cls.cpp = CHILD.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_separate_app_and_pinned_native_libraries(self):
        for value in (
            "org.kernix.originalfexldso",
            "runner.sha256",
            "fexcore.sha256",
            "sha256(runner).equals(expected)",
            "sha256(core).equals(expectedCore)",
            "new AlertDialog.Builder(this)",
        ):
            self.assertIn(value, self.java)
        self.assertIn("libFEXCore.so", self.workflow)
        self.assertIn("FEX-Emu/FEX.git", self.workflow)
        self.assertNotIn("assembleRelease", self.workflow)
        self.assertNotIn("gh release create", self.workflow)

    def test_native_stdout_drain_never_waits_on_undrained_pipe(self):
        for fragment in (
            "File.createTempFile(",
            "builder.redirectErrorStream(true);",
            "builder.redirectOutput(trace);",
            "child.waitFor(25,TimeUnit.SECONDS)",
            "child.destroyForcibly()",
            "traceTail(trace)",
            "trace.length()",
            "RandomAccessFile(trace",
            "finally {",
            "trace.delete()",
        ):
            self.assertIn(fragment, self.java)
        self.assertNotIn("child.getInputStream()", self.java)
        self.assertNotIn("readAllBytes(trace.toPath())", self.java)
        self.assertLess(
            self.java.index("builder.redirectOutput(trace);"),
            self.java.index("child.waitFor(25,TimeUnit.SECONDS)"),
        )

    def test_each_native_stage_has_flushed_crash_friendly_marker(self):
        self.assertIn('std::fprintf(stderr,"KERNIX_C3D8C0_STAGE=%s\\n",name);', self.cpp)
        self.assertIn("std::fflush(stderr);", self.cpp)
        required = (
            "ORIGINAL_ELF_SHA256_VALIDATED",
            "ORIGINAL_GUEST_MEMORY_STAGING_VERIFIED",
            "ORIGINAL_LDSO_SOURCE_CALL_PROVED",
            "NATIVE_SOURCE_PTLOAD_WX_AND_GUEST_STACK_GUARD_PASS",
            "ORIGINAL_X86_STACK_SNAPSHOT_COMPLETE",
            "GUARDED_HOST_CALLRET_STACK_READY",
            "REAL_FEX_CONTEXT_INITCORE_PASS",
            "FEX_GUEST_THREAD_AND_CPUSTATE_READY",
            "FEX_EXECUTETHREAD_RETURNED",
            "ORIGINAL_GUEST_CALL_PUSH_RBP_AND_RETURN_RIP_PROVED",
            "ORIGINAL_LDSO_SOURCE_BYTES_RESTORED",
            "ORIGINAL_GUEST_STACK_16_BYTES_RESTORED",
            "FEX_CONTEXT_GUEST_MEMORY_AND_HOST_STACK_RELEASED",
        )
        for stage in required:
            self.assertIn('c7p::Stage("'+stage+'")', self.cpp)
        self.assertLess(
            self.cpp.index('c7p::Stage("FEX_GUEST_THREAD_AND_CPUSTATE_READY")'),
            self.cpp.index("ctx->ExecuteThread(thread);"),
        )
        self.assertLess(
            self.cpp.index("ctx->ExecuteThread(thread);"),
            self.cpp.index('c7p::Stage("FEX_EXECUTETHREAD_RETURNED")'),
        )

    def test_true_execution_requires_guest_and_restore_gates(self):
        for value in (
            "ctx->ExecuteThread(thread);",
            "DenyAllGuestSyscalls",
            "EnableExitOnHLT",
            "OriginalFEXGuardedCallRetStack",
            "call.originalReturnRIP",
            "OriginalFileBackedBytesRestored",
            "originalGuestStackBytes",
            "GUEST_LINUX_SYSCALLS_FORWARDED=0",
            "COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",
            "WINE_OR_WINDOWS_PE_EXECUTED=0",
            "KERNIX_C3D8C0_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_FOUR_FEX_INSTRUCTIONS_PASS",
        ):
            self.assertIn(value, self.cpp)
        self.assertIn("SUCCESS_MARKER_NOT_UNIQUE_OR_ABSENT", self.java)
        self.assertIn("UNEXPECTED_DEVICE_RESULT_PROTOCOL_REJECTED", self.java)
        self.assertNotIn("MAP_FIXED", self.cpp)


if __name__ == "__main__":
    unittest.main()
