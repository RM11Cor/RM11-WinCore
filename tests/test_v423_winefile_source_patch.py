#!/usr/bin/env python3
"""Verify source patch transforms audited Winefile control flow without adding HWNDs."""
import importlib.util
from pathlib import Path

script=Path(__file__).resolve().parents[1]/"tools/patch_winefile_inprocess_back_v423.py"
spec=importlib.util.spec_from_file_location("rm11patch",script)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixture="""/* globals */
static LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT nmsg, WPARAM wparam, LPARAM lparam) {
    switch(LOWORD(wparam)) {
    case ID_FILE_EXIT:
        break;
    }
}
static void create_drive_bar(void) {
    TBBUTTON drivebarBtn = {0};
    drivebarBtn.idCommand = ID_DRIVE_SHELL_NS;
    SendMessageW(Globals.hdrivebar, TB_INSERTBUTTONW, btn++, (LPARAM)&drivebarBtn);
    drivebarBtn.iString++;
}
"""
patched=mod.apply_patch(fixture)
# Stock Wine 11.x uses tabs. Check both source formatting conventions.
tabbed=fixture.replace("    case ID_FILE_EXIT:", "\t\t\t\tcase ID_FILE_EXIT:")
tabbed=tabbed.replace("    drivebarBtn.idCommand", "\tdrivebarBtn.idCommand")
tabbed=tabbed.replace("    SendMessageW(Globals.hdrivebar", "\tSendMessageW(Globals.hdrivebar")
tabbed=tabbed.replace("    drivebarBtn.iString++;", "\tdrivebarBtn.iString++;")
# The exact Wine-source signatures were also checked against Wine tag 11.19.
assert mod.apply_patch(tabbed).count("RM11_WINEFILE_PARENT_COMMAND") == 3
for expected in ("case RM11_WINEFILE_PARENT_COMMAND:",
                 "TB_ADDSTRINGW", "TB_INSERTBUTTONW", "WM_DISPATCH_COMMAND",
                 "WM_MDIGETACTIVE", "BTNS_SHOWTEXT"):
    assert expected in patched,expected
assert patched.index("arrow_button") < patched.index("drivebarBtn.iString++;") + 1700
assert "SetParent(" not in patched and "WS_POPUP" not in patched
try:
    mod.apply_patch(patched)
    raise AssertionError("double patch allowed")
except ValueError:
    pass
try:
    mod.apply_patch("int main() { return 0; }")
    raise AssertionError("mismatched Wine source accepted")
except ValueError:
    pass
print("RM11_V423_WINEFILE_SOURCE_PATCH_TEST_PASS")
print("Source patch staging only, not a compiled/installed Winefile executable.")
