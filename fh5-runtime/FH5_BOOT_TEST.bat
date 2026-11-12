@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Forza Horizon 5 boot observation only. Requires a legally installed,
rem licensed game and the corresponding Steam/Xbox services where applicable.
rem Place beside ForzaHorizon5.exe inside the game directory.
cd /d "%~dp0"
if not exist "ForzaHorizon5.exe" (
  echo FH5_BOOT_ERROR: GAME_EXE_NOT_FOUND
  echo Copy this .bat next to your legitimately installed ForzaHorizon5.exe.
  pause
  exit /b 2
)
set "WINEDEBUG=+seh,+loaddll"
set "DXVK_LOG_LEVEL=warn"
set "VKD3D_DEBUG=warn"
set "FH5_LOG=%~dp0FH5_BOOT_RAW.log"
echo FH5 BOOT DIAGNOSTIC > "%FH5_LOG%"
echo Game entry found; launching without patching game files. >> "%FH5_LOG%"
echo Note: the raw log can contain private local paths. >> "%FH5_LOG%"
echo Capturing loader and crash diagnostics...
"ForzaHorizon5.exe" >> "%FH5_LOG%" 2>&1
set "FH5_CODE=%ERRORLEVEL%"
echo RETURN_CODE=%FH5_CODE% >> "%FH5_LOG%"
echo Run completed. Return code: %FH5_CODE%
echo Raw log is beside the game. Do NOT upload raw log publicly.
echo A later privacy sanitizer should be used before sharing diagnostics.
pause
exit /b %FH5_CODE%
