#!/usr/bin/env python3
"""Contract tests with the EXACT audited upstream Winefile release source.

Specify WINEFILE_ORIGINAL to test against the downloaded pinned Git revision.
No external network access, APK publishing or runtime modification here.
"""
from pathlib import Path
import importlib.util
import os
import sys

root=Path(__file__).resolve().parents[1]
p=root/"tools/patch_winefile_smooth_v428.py"
spec=importlib.util.spec_from_file_location("rm11_v428",p)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original=Path(os.environ["WINEFILE_ORIGINAL"]).read_text(encoding="utf-8")
out=module.patch_source(original)
assert out.count("RM11_V428_WINEFILE_BATCHED_LIST_REPAINT")==2
assert out.count("WM_SETREDRAW")-original.count("WM_SETREDRAW")==6
assert out.count("InvalidateRect")-original.count("InvalidateRect")==3
assert out.count("LB_RESETCONTENT")==original.count("LB_RESETCONTENT")
assert out.count("CreateWindowExW")==original.count("CreateWindowExW")
assert out.count("WS_POPUP")==original.count("WS_POPUP")
assert out.count("SHFileOperation")==original.count("SHFileOperation")
assert out.count("SendMessageW(child->right.hwnd, WM_SETREDRAW, TRUE, 0);")>=2
try:
    module.patch_source(out)
    raise AssertionError("double patch should fail")
except ValueError:
    pass
print("PASS: actual upstream source accepted; folder-navigation repaint transaction balanced")
print("WARNING: not compiled or on-device verified. Do not call this a functional APK.")
