#!/usr/bin/env python3
"""Host-side architecture invariant; not a substitute for device GUI verification."""
from pathlib import Path
root = Path(__file__).resolve().parents[1]
helper = (root / "tools/rm11_winefile_single_window_arm64.c").read_text(encoding="utf-8")
ui = (root / "app/src/main/java/com/rm11/autocore/RM11NativeWineActivity.java").read_text(encoding="utf-8")
fit = (root / "app/src/main/java/com/rm11/autocore/runtime/NativeDesktopVisualEvidence.java").read_text(encoding="utf-8")
doc = (root / "docs/RM11-V423-WINDOW-SHELL-RECOVERY.md").read_text(encoding="utf-8")
for token in ("WS_POPUP", "WS_EX_TOPMOST", "navHost", "RM11WineFileBackHost422", "CreateWindowExW("):
    assert token not in helper, f"second X11 Win32 top-level must not return: {token}"
for token in ("EnumWindows(scan_frame", "WM_MDIDESTROY", "WM_MDIMAXIMIZE", "RM11_V421_PARENT_FOLDER_COMMAND_SENT"):
    assert token in helper, f"Winefile single document policy lost: {token}"
assert "installFileBackButton()" not in ui, "Android floating Back may not be restored"
assert "controlPopup.setFocusable(false)" in ui
assert "PopupWindow.INPUT_METHOD_NOT_NEEDED" in ui
assert "fitSingleVisibleTopLevelWindow()" in ui
assert 'if(mapped!=1)' in fit, "Phase-0 fallback must reject ambiguous root mapping"
assert "Phase 2" in doc and "TBBUTTON" in doc
print("RM11_V423_PHASE0_NO_POPUP_INVARIANT_PASS")
print("CI architecture check only: fullscreen and in-process arrow require REDMAGIC device testing.")
