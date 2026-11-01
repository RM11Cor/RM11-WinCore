"""Unit tests for no-guess per-game component compatibility."""
import unittest
from kernix_component_registry import validate, propose

BASE = {"schema":"kernix.component-registry.v1","components":[]}
SCAN = {"schema":"kernix.pe-import-audit.v1","graphics_api_indicators":["Direct3D 11"]}
HASH = "a"*64

def component(ident, kind, requires=None):
    return {"id":ident,"kind":kind,"version":"test-only","abi":"arm64ec","sha256":HASH,
            "verified":True,"requires":requires or []}

class RegistryTest(unittest.TestCase):
    def test_empty_does_not_invent_dxvk(self):
        p=propose(BASE,SCAN)
        self.assertEqual(p["missing_verified_component_kinds"],["dxvk"])
        self.assertFalse(p["may_select_automatically"])
    def test_d3d12_requires_vkd3d(self):
        p=propose(BASE,{**SCAN,"graphics_api_indicators":["Direct3D 12"]})
        self.assertEqual(p["required_graphics_wrapper_kinds"],["vkd3d"])
    def test_dxgi_only_is_ambiguous(self):
        p=propose(BASE,{**SCAN,"graphics_api_indicators":["DXGI (version unspecified)"]})
        self.assertTrue(p["insufficient_evidence"])
    def test_unverified_rejected(self):
        bad=component("dx","dxvk");bad["verified"]=False
        with self.assertRaises(ValueError):validate({**BASE,"components":[bad]})
    def test_dependency_cycle_rejected(self):
        a=component("a","dxvk",["b"]);b=component("b","fex",["a"])
        with self.assertRaises(ValueError):validate({**BASE,"components":[a,b]})
    def test_missing_dependency_rejected(self):
        with self.assertRaises(ValueError):
            validate({**BASE,"components":[component("dx","dxvk",["missing"])]})
    def test_valid_does_not_claim_runtime_compatibility(self):
        p=propose({**BASE,"components":[component("dx","dxvk")]},SCAN)
        self.assertEqual(p["missing_verified_component_kinds"],[])
        self.assertTrue(p["needs_runtime_validation"])
        self.assertFalse(p["may_select_automatically"])

if __name__=="__main__":unittest.main()
