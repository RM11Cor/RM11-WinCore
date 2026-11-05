# SPDX-License-Identifier: MIT
"""Guard live Android FEX original ELF syscall integration, source-only.
This is NOT actual phone execution and must not claim Wine/glibc progress.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
class G0ElfHostBridgeContract(unittest.TestCase):
    def test_integrated_into_real_existing_android_fex_elf(self):
        s=(ROOT/"native-engine/android-host/kernix_fexcore_elf64_exec_probe.cpp").read_text()
        a=s.split("void HandleSyscall(",1)[1].split("unsigned Count = 0;",1)[0]
        for term in (
            '#include "kernix_g0_guest_syscall_dispatch.h"',
            '#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"',
            "DecodePinnedFexCpuState(",
            "DispatchVerifiedGuestTrap(",
            "frameWitness.decoded.nextGuestRIP != expectedNext",
            "GuestStack{trustedStackStart,trustedStackStart+trustedStackSize,true}",
            "MessageRegion{image.message,image.message+image.messageSize,",
            "KERNIX_G0_REAL_FEX_ELF64_GUEST_WRITE_VM_BRIDGE_PASS",
            "KERNIX_G0_REAL_FEX_ELF64_GUEST_GETPID_BRIDGE_PASS",
            "KERNIX_G0_ANDROID_BIONIC_GUEST_ELF_REAL_WRITE_GETPID_BOUNDARY_COMPLETED",
            "FixedGuestSyscalls syscalls{guest,",
        ):
            self.assertIn(term,s)
        self.assertNotIn("::write(",a,"No direct host write in FEX trap")
        self.assertNotIn("::syscall(",a,"Do not forward guest number to host")
        self.assertNotIn("static_cast<uint64_t>(getpid())",a,"No direct guest RAX PID bypass")
        self.assertIn("out.guestReturn!=::getpid()",a)
        self.assertIn("guest.containsReadOnlyMessage",s)
        self.assertIn("loadFixedGuestELF(",s)
        self.assertIn("EnableExitOnHLT()",s)
    def test_android_audit_compiles_real_fex_and_embedded_gnu_elf(self):
        w=(ROOT/".github/workflows/kernix-fexcore-android-ndk-audit.yml").read_text()
        self.assertIn("kernix_fexcore_elf64_exec_probe.cpp",w)
        self.assertIn("libkernix_fexcore_elf64_exec_probe.so",w)
        self.assertIn("kernix_g0_guest_syscall_dispatch.h",w)
        self.assertIn("kernix_g2e_c2_original_fex_cpu_state_adapter.h",w)
        self.assertIn("KERNIX_G0_REAL_FEX_ELF64_GUEST_WRITE_VM_BRIDGE_PASS",w)
        self.assertIn("KERNIX_G0_REAL_FEX_ELF64_GUEST_GETPID_BRIDGE_PASS",w)
        self.assertNotIn("G0_ANDROID_DEVICE_EXECUTED=1",w)
if __name__=="__main__":
    unittest.main()
