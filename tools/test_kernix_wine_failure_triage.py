"""Synthetic Wine diagnostic fixtures; no real game launch in CI."""
import unittest
from kernix_wine_failure_triage import triage_lines
class WineTriageTests(unittest.TestCase):
    def test_halt_then_breakpoint(self):
        x=triage_lines(["Loaded libarm64ecfex.dll", "HALT: Coudln't find any available virtual memory start addresses after 16 tries", "Exception 0x80000003"])
        self.assertTrue(x["address_halt_before_breakpoint"])
        self.assertFalse(x["root_cause_confirmed"])
    def test_android_exit_is_not_game_failure(self):
        x=triage_lines(["display_resumed", "display_exit_requested", "display_interrupted"])
        self.assertFalse(x["fex_address_space_halt_observed"])
    def test_reverse_event_order_is_not_conflated(self):
        x=triage_lines(["Exception 0x80000003", "Couldn't find any available virtual memory start addresses after 16 tries"])
        self.assertFalse(x["address_halt_before_breakpoint"])
    def test_wrapper_claim_is_not_gpu_attestation(self):
        x=triage_lines(["dxwrapperConfig (raw): gpuName=NVIDIA GeForce GTX 480,videoMemorySize=2048,vkd3dVersion=3.0.1-arm64ec"])
        self.assertEqual(x["wrapper_config_claims"]["videoMemorySize"],"2048")
        self.assertFalse(x["vkd3d_device_creation_verified"])
if __name__=="__main__":unittest.main()
