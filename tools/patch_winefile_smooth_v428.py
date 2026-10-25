#!/usr/bin/env python3
"""Experimental, fail-closed flicker-free Winefile navigation source patch.

This patches ONLY Winefile's own right/left listbox redraw during a folder
refresh, never Android Activity, X11 root geometry, or top-level HWNDs.
NOT installed in the APK until exact runtime-source match and physical tests.
Wine is LGPL; retain the original source notice when redistributing binaries.
"""
from pathlib import Path
import argparse

IDENTIFIER = "RM11_V428_WINEFILE_BATCHED_LIST_REPAINT"
FUNC_NAMES = ("static void scan_entry(", "static void refresh_right_pane(")

def once(s: str, old: str, new: str, label: str) -> str:
    n = s.count(old)
    if n != 1:
        raise ValueError(f"{label}: require exactly one audited anchor, found {n}")
    return s.replace(old, new, 1)

def isolate(s: str, name: str, following: str):
    if s.count(name) != 1:
        raise ValueError(f"{name}: ambiguous Wine source")
    start=s.index(name)
    end=s.find(following, start)
    if end < start:
        raise ValueError(f"{name}: unexpected source structure")
    return start,end,s[start:end]

def patch_source(s: str) -> str:
    if IDENTIFIER in s:
        raise ValueError("Already patched; will not apply twice.")
    if not all(s.count(name)==1 for name in FUNC_NAMES):
        raise ValueError("Unknown Winefile source revision; abort.")
    start,end,scan=isolate(s, FUNC_NAMES[0], "/* expand a directory entry */")
    scan=once(scan,
        "\t/* delete sub entries in left pane */\n",
        "\t/* "+IDENTIFIER+": suppress partial listbox paints during one navigation. */\n"
        "\tSendMessageW(child->left.hwnd, WM_SETREDRAW, FALSE, 0);\n"
        "\tSendMessageW(child->right.hwnd, WM_SETREDRAW, FALSE, 0);\n"
        "\t/* delete sub entries in left pane */\n", "scan begin")
    scan=once(scan,
        "\tchild->header_wdths_ok = FALSE;\n\n\tSetCursor(old_cursor);",
        "\tchild->header_wdths_ok = FALSE;\n"
        "\tSendMessageW(child->left.hwnd, WM_SETREDRAW, TRUE, 0);\n"
        "\tSendMessageW(child->right.hwnd, WM_SETREDRAW, TRUE, 0);\n"
        "\tInvalidateRect(child->left.hwnd, NULL, FALSE);\n"
        "\tInvalidateRect(child->right.hwnd, NULL, FALSE);\n"
        "\n\tSetCursor(old_cursor);", "scan end")
    s=s[:start]+scan+s[end:]
    start,end,refresh=isolate(s, FUNC_NAMES[1], "static void set_curdir(")
    refresh=once(refresh,
        "\tSendMessageW(child->right.hwnd, LB_RESETCONTENT, 0, 0);",
        "\t/* "+IDENTIFIER+": replace rows as one visible update. */\n"
        "\tSendMessageW(child->right.hwnd, WM_SETREDRAW, FALSE, 0);\n"
        "\tSendMessageW(child->right.hwnd, LB_RESETCONTENT, 0, 0);", "refresh begin")
    refresh=once(refresh,
        "\tset_header(&child->right);\n}",
        "\tset_header(&child->right);\n"
        "\tSendMessageW(child->right.hwnd, WM_SETREDRAW, TRUE, 0);\n"
        "\tInvalidateRect(child->right.hwnd, NULL, FALSE);\n}", "refresh end")
    s=s[:start]+refresh+s[end:]
    # Auditable invariant: no additional top-level windows, file mutation,
    # or cross-process command injection within this isolated source patch.
    assert s.count(IDENTIFIER)==2
    return s

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("input",type=Path)
    ap.add_argument("output",type=Path)
    args=ap.parse_args()
    if args.input.resolve()==args.output.resolve():
        ap.error("Will never overwrite upstream Wine source")
    s=args.input.read_text(encoding="utf-8")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(patch_source(s),encoding="utf-8")
    print("RM11_V428_BATCHED_NAVIGATION_SOURCE_PATCH_READY")
    print("Not in shipping APK. No X11, Wine runtime, or Android changes.")

if __name__=="__main__":
    main()
