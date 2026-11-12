@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo R2_ATTEMPT_BEGIN > R2_BOOT_RAW.log
echo R2_SMOKE_ONLY_NO_GAME_ASSETS >> R2_BOOT_RAW.log
if not exist "ForzaHorizon5.exe" (
  echo R2_EXE_MISSING >> R2_BOOT_RAW.log
  echo R2_EXIT_CODE=2 >> R2_BOOT_RAW.log
  echo ForzaHorizon5.exe not found in this folder.
  pause
  exit /b 2
)
rem This uses the existing legal Steam login and installed Wine/FEX runtime.
rem No bypasses, Wine overrides, or game-file patches.
set WINEDEBUG=+seh,+loaddll
echo R2_LAUNCH_ATTEMPT >> R2_BOOT_RAW.log
"ForzaHorizon5.exe" >> R2_BOOT_RAW.log 2>&1
set "R2_CODE=%ERRORLEVEL%"
echo R2_EXIT_CODE=%R2_CODE% >> R2_BOOT_RAW.log
echo R2 smoke launch returned code %R2_CODE%.
echo Go back to Termux and run: python ~/fh5_runtime/boot_r2_stage.py --collect
echo Keep the raw Wine log private; upload only FH5_BOOT_R2_REPORTS.zip.
pause
exit /b %R2_CODE%
