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
assert 'if(winefileClassMatches==1)' in fit, "Must identify the Winefile top-level by WM_CLASS"
assert 'mapped==1 && winefileClassMatches==0' in fit, "Only single-window legacy fallback allowed"
assert 'RM11_V423_X11_NO_UNAMBIGUOUS_WINEFILE' in fit, "Reject uncertain X11 window ownership"
assert 'getProperty[0]=20' in fit and 'put32(getProperty,8,67)' in fit, "Use X11 WM_CLASS property"
assert 'frameFitOngoing' in ui and 'winefileGeometryVerified' in ui
assert 'Thread.sleep(170)' in ui, "Expected bounded geometry polling after map"
assert 'runOnUiThread(this::fitWinefileNativeX11Frame)' in ui
assert 'ui.postDelayed(this::fitWinefileNativeX11Frame,1800)' not in ui
assert 'requestWinefileMaximized();' not in ui, "Do not send blind Alt+Space on startup"
assert "cornerWhite>=110" in fit, "Boot overlay must reject bottom/right black bars"
assert "Phase 2" in doc and "TBBUTTON" in doc
print("RM11_V423_PHASE0_NO_POPUP_INVARIANT_PASS")
print("CI architecture check only: fullscreen and in-process arrow require REDMAGIC device testing.")
