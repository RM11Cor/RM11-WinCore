#!/usr/bin/env python3
"""Attach RM11 component catalog viewer after pinned KERNIX upstream patch.
No network calls, dynamic executable installation or modification of game profiles.
"""
import argparse
import shutil
from pathlib import Path

MANIFEST_ANCHOR = "        <!-- Main activity -->"
ACTIVITY = "com.winlator.star.rm11.RM11ComponentLibraryActivity"
MENU_ANCHOR = '        DrawerSectionHeader("System", showDivider = true)'
MENU = '''        DrawerIconItem(
            label = "RM11 Component Library",
            icon = Icons.Filled.Info,
            onClick = {
                context.startActivity(
                    Intent(context, com.winlator.star.rm11.RM11ComponentLibraryActivity::class.java)
                )
            },
        )
'''

def patch(root, source):
    root=Path(root).resolve()
    source=Path(source).resolve()
    target=root/"app/src/main/java/com/winlator/star/rm11/RM11ComponentLibraryActivity.java"
    source_class=source/"integrated-engine/runtime-packaging/RM11ComponentLibraryActivity.java"
    source_catalog=source/"integrated-engine/component-versions.json"
    dest_catalog=root/"app/src/main/assets/rm11_component_versions.json"
    manifest_path=root/"app/src/main/AndroidManifest.xml"
    menu_path=root/"app/src/main/java/com/winlator/star/ui/AppDrawer.kt"
    for p in (source_class,source_catalog,manifest_path,menu_path):
        if not p.is_file(): raise RuntimeError("RM11_REQUIRED_SOURCE_MISSING "+str(p))
    manifest=manifest_path.read_text(encoding="utf-8")
    drawer=menu_path.read_text(encoding="utf-8")
    if manifest.count(MANIFEST_ANCHOR)!=1 or drawer.count(MENU_ANCHOR)!=1:
        raise RuntimeError("RM11_UPSTREAM_UI_ANCHOR_CHANGED")
    if ACTIVITY in manifest or "RM11 Component Library" in drawer or target.exists() or dest_catalog.exists():
        raise RuntimeError("RM11_COMPONENT_UI_ALREADY_PATCHED")
    if source_catalog.stat().st_size > 1024*1024: raise RuntimeError("RM11_CATALOG_TOO_LARGE")
    manifest=manifest.replace(MANIFEST_ANCHOR,
       '        <activity android:name="'+ACTIVITY+
       '" android:exported="false" android:label="RM11 Components" />\n'+MANIFEST_ANCHOR,1)
    drawer=drawer.replace(MENU_ANCHOR,MENU_ANCHOR+"\n"+MENU,1)
    target.parent.mkdir(parents=True,exist_ok=True)
    dest_catalog.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source_class,target)
    shutil.copyfile(source_catalog,dest_catalog)
    manifest_path.write_text(manifest,encoding="utf-8")
    menu_path.write_text(drawer,encoding="utf-8")
    print("RM11_COMPONENT_CATALOG_UI_PATCH_PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream",required=True)
    p.add_argument("--source-root",required=True)
    args=p.parse_args()
    patch(args.upstream,args.source_root)

if __name__=="__main__":
    main()
