# RM11-WinCore v2.4.13 — Windows Runtime Report Bridge

This Android update **imports a read-only ten-check diagnostic report**, with user consent using ACTION_OPEN_DOCUMENT.
Tests execute in the separate Ubuntu PRoot session inside Termux, not inside the APK.
No root, open TCP server, cross-app private file access, or game-file mutation is required.

- Reuses the v2.4.12 Vulkan 5-in-1 test (prior verified output).
- One Termux invocation runs isolated Wine PE64/PE32 smoke tests, Windows APIs, file IO,
  process creation, threads, DLL loading, and optional GUI test.
- DXVK D3D11 and VKD3D D3D12 remain **NOT_CONFIGURED** until separately installed and exercised;
  Wine's builtin D3D is not mislabelled DXVK.
- Importer rejects incomplete/duplicate results and files larger than 64 KiB.
- Keeps stable app ID com.rm11.autocore, increments versionCode to 14, and retains
  original GitHub Secrets and certificate SHA-256 verification.

This does not yet execute Wine inside the Android app. Later stages require a verified
sandboxed runtime bundling plan (and a genuinely executed D3D11/D3D12 smoke test).
