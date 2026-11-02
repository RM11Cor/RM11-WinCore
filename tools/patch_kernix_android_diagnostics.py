#!/usr/bin/env python3
"""Apply isolated KERNIX diagnostic Android UI to a pinned upstream checkout.

Fail closed if any upstream anchor changes. The workflow operates on a CI-only
checkout, never on a user's installed emulator, game folders, or Wine prefixes.
"""
import argparse
import shutil
from pathlib import Path

ACTIVITY = "com.winlator.star.kernix.KernixDiagnosticsActivity"
MANIFEST_ANCHOR = "        <!-- Main activity -->"
DRAWER_ANCHOR = '        DrawerSectionHeader("System", showDivider = true)'
DRAWER_INSERT = '''        DrawerIconItem(
            label = "KERNIX Game Diagnostics",
            icon = Icons.Filled.Info,
            onClick = {
                context.startActivity(
                    Intent(context, com.winlator.star.kernix.KernixDiagnosticsActivity::class.java)
                )
            },
        )
'''

def patch(src_root, destination, dry_run=False):
    src_root = Path(src_root).resolve()
    destination = Path(destination).resolve()
    manifest_path = destination / "app/src/main/AndroidManifest.xml"
    drawer_path = destination / "app/src/main/java/com/winlator/star/ui/AppDrawer.kt"
    java_path = destination / "app/src/main/java/com/winlator/star/kernix/KernixDiagnosticsActivity.java"
    java_source = src_root / "android-bridge/KernixDiagnosticsActivity.java"
    observer_source = src_root / "android-bridge/KernixDisplaySessionObserver.java"
    observer_dest = java_path.parent / "KernixDisplaySessionObserver.java"
    main_path = destination / "app/src/main/java/com/winlator/star/MainActivity.kt"
    init_anchor = "        super.onCreate(savedInstanceState)\n        splashScreen.setKeepOnScreenCondition"
    if not java_source.is_file() or not observer_source.is_file() or not manifest_path.is_file() or not drawer_path.is_file() or not main_path.is_file():
        raise ValueError("KERNIX_BRIDGE_SOURCE_MISSING")

    manifest = manifest_path.read_text(encoding="utf-8")
    drawer = drawer_path.read_text(encoding="utf-8")
    main = main_path.read_text(encoding="utf-8")
    if main.count(init_anchor) != 1 or observer_dest.exists() or "KernixDisplaySessionObserver" in main:
        raise ValueError("KERNIX_UPSTREAM_MAIN_ACTIVITY_ANCHOR_CHANGED")
    if manifest.count(MANIFEST_ANCHOR) != 1 or drawer.count(DRAWER_ANCHOR) != 1:
        raise ValueError("KERNIX_UPSTREAM_UI_ANCHORS_CHANGED")
    if ACTIVITY in manifest or "KERNIX Game Diagnostics" in drawer or java_path.exists():
        raise ValueError("KERNIX_BRIDGE_ALREADY_PRESENT")

    # Non-exported activity is reachable only via the KERNIX app's own drawer.
    new_manifest = manifest.replace(
        MANIFEST_ANCHOR,
        '        <activity android:name="' + ACTIVITY +
        '" android:exported="false" android:label="KERNIX Diagnostics" />\n' +
        MANIFEST_ANCHOR,
        1,
    )
    new_drawer = drawer.replace(DRAWER_ANCHOR, DRAWER_ANCHOR + "\n" + DRAWER_INSERT, 1)
    if "ACTION_OPEN_DOCUMENT" not in java_source.read_text(encoding="utf-8"):
        raise ValueError("KERNIX_MISSING_SAFE_ANDROID_FILE_PICKER")

    new_main = main.replace(init_anchor, "        super.onCreate(savedInstanceState)\n        com.winlator.star.kernix.KernixDisplaySessionObserver.install(application)\n        splashScreen.setKeepOnScreenCondition", 1)
    if not dry_run:
        java_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(java_source, java_path)
        shutil.copyfile(observer_source, observer_dest)
        main_path.write_text(new_main, encoding="utf-8")
        manifest_path.write_text(new_manifest, encoding="utf-8")
        drawer_path.write_text(new_drawer, encoding="utf-8")
    print("KERNIX_ANDROID_DIAGNOSTICS_BRIDGE_" + ("DRY_RUN_PASS" if dry_run else "PATCH_PASS"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    patch(args.source_root, args.upstream, args.dry_run)

if __name__ == "__main__":
    main()
