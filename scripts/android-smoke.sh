#!/usr/bin/env bash
set -euo pipefail
mkdir -p smoke
APP=com.moammalsaad.alquflshamil.stable
ACT=com.r4.qaflshamil.MainActivity
adb shell getprop ro.build.version.release | tee smoke/android-version.txt
adb shell getprop ro.build.version.sdk | tee -a smoke/android-version.txt
adb logcat -c
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am force-stop "$APP"
adb shell am start -W -n "${APP}/${ACT}" | tee smoke/am_start.txt
sleep 6
adb shell dumpsys activity activities > smoke/activities.txt
adb shell dumpsys package "$APP" > smoke/package.txt
adb shell uiautomator dump /sdcard/window.xml || true
adb pull /sdcard/window.xml smoke/window.xml || true
adb shell screencap -p /sdcard/alq_home.png
adb pull /sdcard/alq_home.png smoke/screenshot.png
adb logcat -d -v threadtime > smoke/logcat.txt
grep -E -A 50 "FATAL EXCEPTION|Process: $APP|ANR in $APP|AndroidRuntime.*Exception" smoke/logcat.txt > smoke/crashes.txt || true
test -s smoke/screenshot.png
if grep -q "FATAL EXCEPTION" smoke/crashes.txt; then cat smoke/crashes.txt; exit 1; fi
if grep -q "Force finishing activity.*$APP" smoke/logcat.txt; then echo "Activity force-finished"; exit 1; fi
if ! grep -E "mResumedActivity|topResumedActivity|ResumedActivity" smoke/activities.txt | grep -q "$APP"; then
  echo "App is not resumed; activity dump:"
  grep -E -m 15 "ResumedActivity|mResumedActivity|topResumedActivity|topActivity" smoke/activities.txt || true
  exit 1
fi
if ! grep -q -E "القفل الشامل|إنشاء رمز الحماية|الخصوصية" smoke/window.xml; then echo "Expected Arabic UI not found"; exit 1; fi
echo "PASS: app remains resumed, no startup crash"
