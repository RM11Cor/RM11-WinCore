#!/usr/bin/env bash
set -euo pipefail
mkdir -p smoke
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.moammalsaad.alquflshamil.stable/com.r4.qaflshamil.MainActivity
sleep 6
adb shell uiautomator dump /sdcard/window.xml || true
adb pull /sdcard/window.xml smoke/window.xml || true
adb shell screencap -p /sdcard/alq_home.png
adb pull /sdcard/alq_home.png smoke/screenshot.png
adb logcat -d -s AndroidRuntime:E > smoke/crash.log
test -s smoke/screenshot.png
if grep -q "FATAL EXCEPTION" smoke/crash.log; then
  cat smoke/crash.log
  exit 1
fi
test -f smoke/window.xml
grep -E "القفل الشامل|إنشاء رمز الحماية|الخصوصية" smoke/window.xml
echo "Basic UI smoke test passed. This does not test Play Protect or device-dependent permissions."
