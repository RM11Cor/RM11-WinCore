#!/usr/bin/env python3
"""Read-only audit of the signed Android APK's actual graphics closure.
No claim of device functionality: packaging is distinct from dlopen and Present.
"""
import argparse, json, hashlib, zipfile
from pathlib import Path

FILES = {
 "wine_launcher":"lib/arm64-v8a/libwineprobe.so",
 "wineserver":"lib/arm64-v8a/libwineserverrm11.so",
 "wine_ntdll":"lib/arm64-v8a/libwine_ntdll.so",
 "winex11":"lib/arm64-v8a/libwine_winex11.so",
 "libX11":"lib/arm64-v8a/libX11.so",
 "turnip":"lib/arm64-v8a/libvulkan_freedreno.so",
 "wine_d3d11_dxvk_candidate":"assets/engine/providers/dxvk/x64/d3d11.dll",
 "wine_dxgi_dxvk_candidate":"assets/engine/providers/dxvk/x64/dxgi.dll",
 "private_mesa_loader_required_by_v479":"lib/arm64-v8a/librm11_vkloader_v473.so",
 "private_mesa_icd_required_by_v479":"lib/arm64-v8a/librm11_vkdriver_v473.so",
 "xkb_manifest":"assets/x11/xkb-data-manifest.json",
 "xkb_bundle":"assets/x11/xkb-data.zip"
}
def audit(apk):
 with zipfile.ZipFile(apk) as z:
  names=set(z.namelist())
  rows={}
  for label,path in FILES.items():
   if path not in names:
    rows[label]={"packaged":False,"path":path}
   else:
    item=z.getinfo(path)
    rows[label]={"packaged":True,"path":path,"bytes":item.file_size,
       "sha256":hashlib.sha256(z.read(path)).hexdigest()}
  present=lambda name:rows[name]["packaged"]
  status=("REQUIRED_V479_NATIVE_LOADER_MISSING" if not (
    present("private_mesa_loader_required_by_v479") and
    present("private_mesa_icd_required_by_v479")) else
    "REQUIRED_V479_FILES_PACKAGED_BUT_DEVICE_LOAD_UNVERIFIED")
  dxvk="CANDIDATE_NOT_WINE_PREFIX_ACTIVATION_PROOF"
  return {"schema":"rm11.signed.graphics.closure.audit.v1",
   "apk":Path(apk).name,"files":rows,
   "v479_private_wsi":status,
   "dxvk_status":dxvk,
   "d3d11_device_proof":"UNVERIFIED",
   "swapchain_present_proof":"UNVERIFIED",
   "android_frame_proof":"UNVERIFIED"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("apk")
 p.add_argument("--out",required=True)
 a=p.parse_args()
 report=audit(a.apk)
 Path(a.out).parent.mkdir(parents=True,exist_ok=True)
 Path(a.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"v479_private_wsi":report["v479_private_wsi"],
   "files_packaged":sum(v["packaged"] for v in report["files"].values()),
   "files_expected":len(report["files"])},sort_keys=True))
if __name__=="__main__":main()
