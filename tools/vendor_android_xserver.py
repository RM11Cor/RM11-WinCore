#!/usr/bin/env python3
"""Vendor pinned MIT Android X11 server source during RM11 signed APK CI.

Use only a GitHub-pinned upstream source tree, never prebuilt unverified APKs.
Copy Java implementation and drawables into the RM11 source set, patch socket
binding to loopback only, and retain upstream license/provenance.
"""
import hashlib
from pathlib import Path
import shutil
import sys

SHA="51e907880d4295ee3c381a593c738ca365c066fb"


def copy_to_app(root):
    source = root / "library/src/main"
    java = source / "java/au/com/darkside/xserver"
    icons = source / "res/drawable"
    licence = root / "LICENSE"
    if not (java / "XServer.java").is_file() or not (java / "ScreenView.java").is_file():
        raise RuntimeError("Pinned upstream Android XServer Java root missing")
    if not licence.read_text().startswith("Copyright 2012 Matt Kwan"):
        raise RuntimeError("Upstream MIT license missing or changed")
    java_files = sorted(java.rglob("*.java"))
    if len(java_files) != 31:
        raise RuntimeError("Unexpected upstream X11 Java file count: " + str(len(java_files)))
    for path in java_files:
        rel = path.relative_to(source / "java")
        dst = Path("app/src/main/java") / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        data=path.read_text()
        if path.name=="XServer.java":
            old="new ServerSocket(port);"
            if data.count(old)!=1: raise RuntimeError("Unexpected upstream XServer socket constructor")
            data=data.replace(old,
                'new ServerSocket(port, 8, InetAddress.getByName("127.0.0.1"));')
            if "new ServerSocket(port);" in data: raise RuntimeError("Unbound socket remained")
        if path.name=="XServer.java":
            # X11 pixmap format fields are depth, BITS_PER_PIXEL, scanline pad.
            # The pinned upstream advertises depth=32 but bpp=24, pad=8 while
            # Drawable uses 24-bit BGR packed data for ZPixmap. Wine's 32-bit
            # XImage transport needs a coherent 32/32/32 format instead.
            old="new Format((byte) 32, (byte) 24, (byte) 8)"
            if data.count(old)!=1: raise RuntimeError("X11 32-bit pixmap upstream changed")
            data=data.replace(old,"new Format((byte) 32, (byte) 32, (byte) 32)")
        if path.name=="Drawable.java":
            old="n = 3 * width * height;"
            if data.count(old)!=1: raise RuntimeError("Unexpected ZPixmap PutImage size")
            data=data.replace(old,"n = 4 * width * height;")
            old="int r = io.readByte();\n                int alpha ="
            new="int r = io.readByte();\n                io.readByte();    // X11 32-bpp pixel padding / unused alpha\n                int alpha ="
            if data.count(old)!=1: raise RuntimeError("Unexpected ZPixmap RGB reader")
            data=data.replace(old,new)
            old="n = wh * 3;"
            if data.count(old)!=1: raise RuntimeError("Unexpected ZPixmap GetImage size")
            data=data.replace(old,"n = wh * 4;")
            old="io.writeByte((byte) ((n >> 16) & 0xff));"
            if data.count(old)!=1: raise RuntimeError("Unexpected ZPixmap RGB writer")
            data=data.replace(old,old+"\n                    io.writeByte((byte) ((n >> 24) & 0xff));")
        if path.name=="Cursor.java":
            old="package au.com.darkside.xserver;"
            if data.count(old)!=1: raise RuntimeError("Missing upstream Cursor package")
            data=data.replace(old,old+"\nimport com.rm11.autocore.R;")
        dst.write_text(data)
    icon_files = sorted(icons.glob("*.png"))
    if len(icon_files) < 60: raise RuntimeError("Missing upstream X cursor drawables")
    dst_icons=Path("app/src/main/res/drawable")
    dst_icons.mkdir(parents=True,exist_ok=True)
    for p in icon_files:
        dst=dst_icons/p.name
        if dst.exists():
            raise RuntimeError("Would overwrite RM11 drawable "+dst.name)
        shutil.copy2(p,dst)
    license_destination=Path("app/src/main/assets/third_party/android-xserver-LICENSE.txt")
    license_destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(licence,license_destination)
    metadata=Path("app/src/main/assets/third_party/android-xserver-origin.txt")
    metadata.write_text(
        "Upstream: https://github.com/nwrkbiz/android-xserver\n"+
        "Commit: "+SHA+"\n"+
        "License: MIT; see android-xserver-LICENSE.txt\n"+
        "RM11 patches: loopback binding, host R resources, 32-bit ZPixmap X11 protocol coherence\n"+
        "Mode: embedded X11 core server, NOT Vulkan/DXVK or full Xorg\n")
    code=Path("app/src/main/java/au/com/darkside/xserver/XServer.java").read_text()
    assert "new ServerSocket(port, 8, InetAddress.getByName(\"127.0.0.1\"));" in code
    print("RM11_EMBEDDED_ANDROID_X11_JAVA_SOURCE_V282",len(java_files),
          "java sources",len(icon_files),"cursor drawables")
    print("PINNED_MIT_UPSTREAM_COMMIT",SHA)
    print("LOOPBACK_ONLY_BOUND","127.0.0.1")
    print("LICENSE_SHA256",hashlib.sha256(license_destination.read_bytes()).hexdigest())


if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("Usage: vendor_android_xserver.py /tmp/pinned-android-xserver")
    copy_to_app(Path(sys.argv[1]).resolve())
