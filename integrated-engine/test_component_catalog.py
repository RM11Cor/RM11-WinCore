import importlib.util
import pathlib
import unittest
from unittest.mock import patch

MODULE = pathlib.Path(__file__).with_name("update_component_catalog.py")
spec = importlib.util.spec_from_file_location("version_catalog", MODULE)
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


class CatalogDiscoveryTests(unittest.TestCase):
    def test_reject_tag_injection(self):
        for tag in ("../bad", "v1/evil", "", "foo\\nbar", "x"*120):
            self.assertFalse(catalog.valid_tag(tag))
        for tag in ("v3.1.1", "FEX-2610", "Proton-11.0", "wine-11.0-rc1"):
            self.assertTrue(catalog.valid_tag(tag))

    def test_filters_prereleases_and_downloads_no_files(self):
        c = {"id": "dxvk", "source": "github_releases", "upstream": "doitsujin/dxvk"}
        with patch.object(catalog, "github_json", return_value=[
            {"tag_name":"v3.1.1","draft":False,"prerelease":False,
             "assets":[{"browser_download_url":"https://evil.example/execute"}]},
            {"tag_name":"v99-beta","prerelease":True},
            {"tag_name":"../injection"},
        ]):
            versions=catalog.get_versions(c)
        self.assertEqual([v["tag"] for v in versions], ["v3.1.1"])
        self.assertFalse(versions[0]["installable"])
        self.assertFalse(versions[0]["abi_verified"])
        self.assertFalse(versions[0]["runtime_tested"])
        self.assertNotIn("assets", versions[0])

    def test_wine_latest_uses_numeric_tag_not_github_listing_order(self):
        wine = {"id": "wine", "source": "github_tags", "upstream": "wine-mirror/wine"}
        versions = [
            {"tag": "wine-20050930"},
            {"tag": "wine-10.20"},
            {"tag": "wine-11.9"},
            {"tag": "wine-11.21"},
            {"tag": "wine-11.0-rc1"},
        ]
        self.assertEqual(catalog.observed_latest(wine, versions), "wine-11.21")
        self.assertEqual(catalog.wine_version_rank("wine-11.21"), (11, 21, 0))

    def test_retains_old_versions_and_turnip_manual_review(self):
        cfg={"components":[
            {"id":"dxvk","source":"github_releases","upstream":"doitsujin/dxvk"},
            {"id":"turnip","source":"manual_verified_packages","upstream":None},
        ]}
        old={"components":[
            {"id":"dxvk","versions":[{"tag":"v2.7","installable":False}]},
            {"id":"turnip","versions":[{"tag":"turnip-reviewed-A8xx","installable":True}]},
        ]}
        with patch.object(catalog,"get_versions",return_value=[
            {"tag":"v3.1.1","installable":False}
        ]):
            result=catalog.build_catalog(old,cfg)
        self.assertEqual([v["tag"] for v in result["components"][0]["versions"]],
                         ["v2.7","v3.1.1"])
        self.assertEqual(result["components"][1]["versions"],old["components"][1]["versions"])

if __name__=="__main__":
    unittest.main()
