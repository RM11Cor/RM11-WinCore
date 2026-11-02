"""KERNIX deterministic native runtime composition contract tests."""
import copy
import unittest
from kernix_runtime_resolver import compose

GAME = "a"*64
def item(kind, version, digest, requires=(), abi="arm64"):
    return {
        "id": kind+"-"+version, "kind": kind, "version": version,
        "abi": abi, "sha256": digest*64, "verified": True,
        "requires": list(requires),
    }

def fixture():
    fex=item("fex","2610","a")
    turnip=item("turnip","27","b")
    wine=item("wine","11","c",requires=[fex["id"]])
    dxvk=item("dxvk","3.1","d",requires=[turnip["id"]])
    old=item("dxvk","2.7","e",requires=[turnip["id"]])
    return {"schema":"kernix.component-registry.v1","components":[fex,turnip,wine,dxvk,old]}

SEL = {"fex":"fex-2610","turnip":"turnip-27","wine":"wine-11","dxvk":"dxvk-3.1"}

class ResolverTests(unittest.TestCase):
    def test_complete_lock_is_deterministic_and_dependency_ordered(self):
        reg=fixture()
        r=compose(reg,SEL,GAME,required=["dxvk"])
        flipped=compose(reg,dict(reversed(list(SEL.items()))),GAME,required=["dxvk"])
        self.assertEqual(r,flipped)
        self.assertLess([x["id"] for x in r["components"]].index("fex-2610"),
                        [x["id"] for x in r["components"]].index("wine-11"))
        self.assertFalse(r["runtime_tested"])
        self.assertFalse(r["installable"])
        self.assertEqual(len(r["plan_sha256"]),64)

    def test_older_version_preserved_when_selected(self):
        sel={**SEL,"dxvk":"dxvk-2.7"}
        r=compose(fixture(),sel,GAME,required=["dxvk"])
        self.assertEqual(r["slots"]["dxvk"],"dxvk-2.7")
        self.assertNotEqual(r["plan_sha256"],
                            compose(fixture(),SEL,GAME,required=["dxvk"])["plan_sha256"])

    def test_missing_dependency_rejected(self):
        reg=fixture()
        reg["components"][3]["requires"]=["turnip-27","dxvk-2.7"]
        with self.assertRaisesRegex(ValueError,"DEPENDENCY_NOT_SELECTED"):
            compose(reg,SEL,GAME)

    def test_unverified_payload_rejected(self):
        reg=fixture()
        reg["components"][0]["verified"]=False
        with self.assertRaisesRegex(ValueError,"COMPONENT_NOT_VERIFIED"):
            compose(reg,SEL,GAME)

    def test_wrong_kind_and_abi_rejected(self):
        sel=dict(SEL);sel["wine"]="turnip-27"
        with self.assertRaisesRegex(ValueError,"MISMATCHED_COMPONENT_KIND"):
            compose(fixture(),sel,GAME)
        reg=fixture();reg["components"][2]["abi"]="x86_64"
        with self.assertRaisesRegex(ValueError,"HOST_ABI_INCOMPATIBLE"):
            compose(reg,SEL,GAME)

    def test_no_windows_runtime_or_fex_rejected(self):
        for key in ("fex","wine","turnip"):
            selection=dict(SEL);selection.pop(key)
            with self.assertRaisesRegex(ValueError,"MISSING_BOOTSTRAP_COMPONENTS"):
                compose(fixture(),selection,GAME)

    def test_d3d12_requirement_must_be_present(self):
        with self.assertRaisesRegex(ValueError,"MISSING_GAME_GRAPHICS_REQUIREMENTS"):
            compose(fixture(),SEL,GAME,required=["vkd3d"])

    def test_unknown_component_and_bad_game_digest_rejected(self):
        with self.assertRaises(ValueError):
            compose(fixture(),{**SEL,"dxvk":"latest"},GAME)
        with self.assertRaises(ValueError):
            compose(fixture(),SEL,"bad")

    def test_empty_live_registry_must_not_create_usable_recipe(self):
        with self.assertRaises(ValueError):
            compose({"schema":"kernix.component-registry.v1","components":[]},SEL,GAME)

if __name__=="__main__":
    unittest.main()
