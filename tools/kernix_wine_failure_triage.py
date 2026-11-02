#!/usr/bin/env python3
"""Read-only Wine startup triage. No GPU/FEX attestation or inferred crash cause."""
import argparse
import json
import re
import zipfile
from pathlib import Path
MAX_BYTES=16*1024*1024
PATTERNS={
"fex_address_space_halt":re.compile(r"(?:Coudln't|Couldn't|Could not) find any available virtual memory start addresses after\s+(\d+)\s+tries",re.I),
"wine_breakpoint":re.compile(r"(?:Unhandled exception|Exception)\s+0x80000003",re.I),
"wine_game_offset":re.compile(r"\b(tlou-ii(?:\.exe)?)\s*\+\s*(?:0x)?([0-9a-f]{5,})",re.I),
"winedbg_crash":re.compile(r"winedbg:\s*Internal crash",re.I),
"arm64ec_fex_load":re.compile(r"Loaded.*libarm64ecfex\.dll",re.I),
"d3d12_load":re.compile(r"Loaded.*d3d12\.dll",re.I),
"vulkan_load":re.compile(r"Loaded.*vulkan-1\.dll",re.I),
}
def triage_lines(lines):
    events=[]
    wrapper={}
    for index,line in enumerate(lines,1):
        if len(line)>32768:continue
        if "dxwrapperConfig (raw):" in line:
            val=line.split("dxwrapperConfig (raw):",1)[-1]
            for key in ("gpuName","videoMemorySize","vkd3dVersion"):
                hit=re.search(r"(?:^|,)"+key+r"=([^,\r\n]+)",val)
                if hit:wrapper[key]=hit.group(1)
        for kind,pattern in PATTERNS.items():
            hit=pattern.search(line)
            if not hit or len(events)>=100:continue
            ev={"kind":kind,"line":index}
            if kind=="fex_address_space_halt":ev["tries"]=int(hit.group(1))
            if kind=="wine_game_offset":
                ev["module"]=hit.group(1).lower()
                ev["offset_hex"]=hit.group(2).lower()
            events.append(ev)
    halt=next((e for e in events if e["kind"]=="fex_address_space_halt"),None)
    bp=next((e for e in events if e["kind"]=="wine_breakpoint"),None)
    return {"schema":"kernix.wine-startup-triage.v1","observed":events,
        "wrapper_config_claims":wrapper,"fex_address_space_halt_observed":bool(halt),
        "wine_breakpoint_observed":bool(bp),
        "address_halt_before_breakpoint":bool(halt and bp and halt["line"]<bp["line"]),
        "fex_version_verified":False,"vkd3d_device_creation_verified":False,
        "first_rendered_frame_verified":False,"root_cause_confirmed":False,
        "diagnostic_note":"Wine log content only; no actual FEX package/version or GPU runtime attestation."}
def read_log(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>MAX_BYTES:
        raise ValueError("BAD_INPUT_SIZE")
    if p.suffix.lower()==".zip":
        with zipfile.ZipFile(p) as z:
            matches=[i for i in z.infolist() if i.filename=="wine_debug.log" and not i.is_dir()]
            if len(matches)!=1 or matches[0].file_size>MAX_BYTES:
                raise ValueError("MISSING_OR_OVERSIZED_WINE_LOG")
            return z.read(matches[0]).decode("utf-8","replace").splitlines()
    return p.read_text(encoding="utf-8",errors="replace").splitlines()
def main():
    p=argparse.ArgumentParser();p.add_argument("report");a=p.parse_args()
    print(json.dumps(triage_lines(read_log(a.report)),ensure_ascii=False,indent=2))
if __name__=="__main__":main()
