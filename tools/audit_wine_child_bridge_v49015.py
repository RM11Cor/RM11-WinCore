#!/usr/bin/env python3
"""Fail-closed audit of RM11 Wine-child Vulkan bridge wiring.
This check never equates compiled binaries with an active Wine hook.
"""
import json
from pathlib import Path
src=Path("tools/engine_vnext_wine_vulkan_bridge.c").read_text()
launcher=Path("app/src/main/java/com/rm11/autocore/runtime/NovaWineExeLauncher.java").read_text()
bridge_symbol="rm11_vnext_open_vulkan"
# Avoid counting the implementation or its header as an actual native caller.
roots=(Path("app/src/main/cpp"),Path("tools"),Path("enginebridge"))
native_callers=[]
for root in roots:
 if not root.exists():continue
 for p in root.rglob("*"):
  if p.suffix not in (".c",".cpp",".cc") or p.name=="engine_vnext_wine_vulkan_bridge.c":continue
  text=p.read_text(errors="replace")
  if bridge_symbol+"(" in text:
   native_callers.append(str(p))
report={
 "schema":"rm11.wine-child-vulkan-wiring.v1",
 "bridge_implementation_present":bridge_symbol+"(" in src,
 "native_call_sites":native_callers,
 "wine_loader_source_call_verified":False,
 "wine_child_bridge_active":False,
 "dxvk_wine_activation_verified":False,
 "android_vulkan_wsi_verified":False,
 "safely_enable_d3d11":False,
 "reason":"PINNED_WINEPROBE_IS_LEGACY_BINARY_NO_VERIFIED_BRIDGE_CALL_SITE"
}
Path("audit").mkdir(exist_ok=True)
Path("audit/v49015-wine-child-bridge-gate.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
assert report["bridge_implementation_present"]
assert not report["native_call_sites"], "Unexpected caller: manually verify linkage before activating graphics"
assert "RM11_V458_ANDROID_VULKAN_FALLBACK" in launcher
print("RM11_V49015_BRIDGE_CODE_EXISTS_BUT_WINE_CHILD_WIRING_NOT_PROVEN")
