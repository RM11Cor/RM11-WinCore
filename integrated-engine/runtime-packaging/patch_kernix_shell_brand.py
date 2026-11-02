#!/usr/bin/env python3
"""Brand the staged RM11 engine build as KERNIX without touching native runtime binaries.

This is a verifiable *shell/branding* pass, NOT a claim that the old RM11 UI
has been migrated. Keeps a separate package identity until migration safety.
"""
import argparse
from pathlib import Path

def patch(root):
    root=Path(root).resolve()
    strings=root/"app/src/main/res/values/strings.xml"
    drawer=root/"app/src/main/java/com/winlator/star/ui/AppDrawer.kt"
    manifest=root/"app/src/main/AndroidManifest.xml"
    for p in (strings,drawer,manifest):
        if not p.is_file(): raise ValueError("MISSING_KERNIX_UI_FILE: "+str(p))
    text=strings.read_text(encoding="utf-8")
    old='<string name="app_name">Bannerlator Bionic</string>'
    new='<string name="app_name">KERNIX Engine</string>'
    if text.count(old)!=1: raise ValueError("UNEXPECTED_UPSTREAM_APP_NAME")
    strings.write_text(text.replace(old,new,1),encoding="utf-8")
    d=drawer.read_text(encoding="utf-8")
    anchor='        DrawerSectionHeader("Library")'
    if d.count(anchor)!=1 or 'KERNIX · RM11-WinCore' in d:
        raise ValueError("UNEXPECTED_UPSTREAM_DRAWER")
    # Use an existing Compose drawer component, no XML drawables or new dependencies.
    d=d.replace(anchor,
        '        DrawerSectionHeader("KERNIX · RM11-WinCore")\n'+anchor,1)
    drawer.write_text(d,encoding="utf-8")
    m=manifest.read_text(encoding="utf-8")
    if 'android:label="@string/app_name"' not in m:
        raise ValueError("UNEXPECTED_UPSTREAM_MANIFEST_LABEL")
    # Keep manifest label reference; app_name string above is now KERNIX.
    print("KERNIX_SHELL_BRANDING_PATCH_PASS")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--upstream",required=True)
    args=parser.parse_args()
    patch(args.upstream)
