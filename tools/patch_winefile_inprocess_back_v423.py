#!/usr/bin/env python3
"""Prepare a source-level in-process Winefile back arrow for the PINNED Wine source.

This file does NOT pretend that the rebuilt winefile.exe is packaged or ABI-tested.
Call only against the exact LGPL Winefile source revision used by our Wine runtime.
Fails closed when upstream source no longer matches the audited Wine 11 API.
"""
import argparse
import re
from pathlib import Path

MARKER = "RM11_WINEFILE_PARENT_COMMAND"
DEFINE = """
/* RM11 v4.0.23: parent navigation lives in Winefile's own Win32 process. */
#define RM11_WINEFILE_PARENT_COMMAND 0xe9f0
"""
PARENT = """
    case RM11_WINEFILE_PARENT_COMMAND: {
        HWND active = (HWND)SendMessageW(Globals.hmdiclient, WM_MDIGETACTIVE, 0, 0);
        ChildWnd *child = active ? (ChildWnd *)GetWindowLongPtrW(active, GWLP_USERDATA) : NULL;
        if (child && child->right.hwnd
                && SendMessageW(child->right.hwnd, LB_GETCOUNT, 0, 0) >= 2
                && SendMessageW(child->right.hwnd, LB_SETCURSEL, 1, 0) != LB_ERR) {
            /* Keep parent activation entirely inside the original Winefile
             * process, rather than messaging remote HWNDs or making popups. */
            SetFocus(child->right.hwnd);
            SendMessageW(active, WM_DISPATCH_COMMAND, MAKEWPARAM(ID_ACTIVATE, 0), 0);
        }
        break;
    }
"""
TOOLBAR = r"""
    /* RM11: compact back arrow after Shell and before the C:/D:/Z: drives.
     * No new X11 or top-level Win32 windows. */
    {
        static const WCHAR rm11_up[] = {0x2191, 0, 0};
        LRESULT arrow_string = SendMessageW(Globals.hdrivebar, TB_ADDSTRINGW, 0, (LPARAM)rm11_up);
        TBBUTTON arrow_button = {I_IMAGENONE, RM11_WINEFILE_PARENT_COMMAND,
                TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT,
                {0, 0}, 0, arrow_string};
        SendMessageW(Globals.hdrivebar, TB_INSERTBUTTONW, btn++, (LPARAM)&arrow_button);
    }
"""

def replace_once(text, old, new, name):
    if text.count(old) != 1:
        raise ValueError(f"{name}: expected one source anchor, found {text.count(old)}")
    return text.replace(old, new, 1)

def apply_patch(source):
    if MARKER in source:
        raise ValueError("already patched; do not apply twice")
    # Follow Wine 11's existing frame WM_COMMAND handler and Shell toolbar.
    source = replace_once(
        source,
        "/* globals */",
        DEFINE + "\n/* globals */",
        "global command definition",
    )
    # Wine uses tabs; minimal test fixtures and some source forks use spaces.
    # Bind to syntax, not decorative indentation.
    frame_pattern = r"(?m)^([ \t]+)case ID_FILE_EXIT:\r?\n"
    source, n = re.subn(frame_pattern,
                         lambda m: PARENT + m.group(0), source, count=2)
    if n != 1:
        raise ValueError(f"frame command dispatch: expected one anchor, found {n}")
    toolbar_pattern = (
        r"(?m)^([ \t]+)drivebarBtn\.idCommand = ID_DRIVE_SHELL_NS;\r?\n"
        r"\1SendMessageW\(Globals\.hdrivebar, TB_INSERTBUTTONW, btn\+\+, \(LPARAM\)&drivebarBtn\);\r?\n"
        r"\1drivebarBtn\.iString\+\+;\r?\n"
    )
    source, n = re.subn(toolbar_pattern, lambda m: m.group(0) + TOOLBAR,
                         source, count=2)
    if n != 1:
        raise ValueError(f"in-process drive toolbar: expected one anchor, found {n}")
    assert "WS_POPUP" not in TOOLBAR and "CreateWindowExW" not in TOOLBAR
    assert source.count("RM11_WINEFILE_PARENT_COMMAND") == 3
    return source

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.original.resolve() == args.output.resolve():
        parser.error("never patch or overwrite the upstream source in place")
    source = args.original.read_text(encoding="utf-8")
    result = apply_patch(source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result, encoding="utf-8")
    print("RM11_V423_IN_PROCESS_WINEFILE_SOURCE_PATCH_READY")
    print("NOT A BUILT WIN64/ARM64 EXE: requires pinned Wine source build, ABI and device tests")

if __name__ == "__main__":
    main()
