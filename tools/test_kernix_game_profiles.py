"""Offline per-game profile validation tests; no engine execution."""
import copy
import unittest
from kernix_game_profiles import validate_profile, profile_key

HASH = "a" * 64
BASE = {"schema":"kernix.component-registry.v1","components":[]}
PROFILE = {"schema":"kernix.game-profile.v1","game_sha256":HASH,
           "mode":"balanced","components":{},"enabled":False}

def component(ident, kind, requires=(), abi="arm64ec"):
    return {"id":ident, "kind":kind, "version":"synthetic-test",
            "abi":abi, "sha256":"b"*64, "verified":True, "requires":list(requires)}

class GameProfileTests(unittest.TestCase):
    def test_empty_safe_profile(self):
        result=validate_profile(PROFILE,BASE)
        self.assertFalse(result["launch_qualified"])
        self.assertFalse(result["profile_enabled"])
    def test_invalid_hash(self):
        with self.assertRaises(ValueError): profile_key("../game.exe")
    def test_enabled_profile_refused(self):
        p={**PROFILE,"enabled":True}
        with self.assertRaises(ValueError):validate_profile(p,BASE)
    def test_unverified_component_refused(self):
        p={**PROFILE,"components":{"dxvk":"test-dx"}}
        with self.assertRaises(ValueError):validate_profile(p,BASE)
    def test_wrong_component_slot_refused(self):
        r={**BASE,"components":[component("test-fex","fex")]}
        p={**PROFILE,"components":{"dxvk":"test-fex"}}
        with self.assertRaises(ValueError):validate_profile(p,r)
    def test_runtime_conflict(self):
        r={**BASE,"components":[component("wine","wine"),component("proton","proton")]}
        p={**PROFILE,"components":{"wine":"wine","proton":"proton"}}
        with self.assertRaises(ValueError):validate_profile(p,r)
    def test_missing_dependency(self):
        r={**BASE,"components":[component("dx","dxvk",["cpu"]),component("cpu","fex")]}
        p={**PROFILE,"components":{"dxvk":"dx"}}
        with self.assertRaises(ValueError):validate_profile(p,r)
    def test_dependency_complete_still_disabled(self):
        r={**BASE,"components":[component("dx","dxvk",["cpu"]),component("cpu","fex")]}
        p={**PROFILE,"components":{"dxvk":"dx","fex":"cpu"}}
        result=validate_profile(p,r)
        self.assertFalse(result["launch_qualified"])
    def test_reject_host_incompatible_abi(self):
        r={**BASE,"components":[component("dx","dxvk",abi="x86_64")]}
        p={**PROFILE,"components":{"dxvk":"dx"}}
        with self.assertRaises(ValueError):validate_profile(p,r)

if __name__ == "__main__": unittest.main()
