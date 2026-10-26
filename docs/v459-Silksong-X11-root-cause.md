# RM11 v4.0.59 — evidence-based X11 connection capacity repair

## Device evidence (user-supplied v4.0.58 ZIP; personal paths omitted)
- Game: Hollow Knight Silksong Windows x64 PE.
- Game executable launched and UnityMemory initialized.
- **Game wrapper exited 1** approximately 1.8 seconds after start.
- X11 TCP protocol handshake initially succeeded; Wine Winex11 Unix driver dlopen succeeded.
- Native Android Vulkan fallback **succeeded** (`RM11_V458_ANDROID_VULKAN_DLOPEN_SUCCESS`).
- Wine later logged `x11drv_init_thread_data: Can't open display: 127.0.0.1:2`.
- Relay, ~4.2 seconds into the game session: `active TCP clients: 24`,
  `accepted native X11 clients: 26`, `tcp accepted total: 27`.
- Java relay had a hard `MAX_CLIENTS=24` and immediately closed additional
  accepted TCP sockets upon `tryAcquire()` failure.
- X11 query: 11 root children, all unmapped; Surface sampled uniformly black.
- Wine emitted `seh:call_seh_handlers invalid frame` followed by
  `NtRaiseException Exception frame is not in stack limits`.

## Conclusions supported by those facts
1. The relay reached its hard maximum. This was a **real, deterministic transport
   bottleneck**. Because v4.0.58 lacked a rejection counter, the old report
   does not say exactly how many clients were dropped. It would be unsafe to
   assert that raising the limit alone guarantees graphics.
2. The Android Vulkan SONAME bridge already worked in v4.0.58 and repeating it
   cannot fix X11 socket starvation.
3. Wine raised a fatal SEH invalid-stack exception. The current trace does
   **not** prove whether it is a consequence of lost X11 transport or an
   independent ARM64EC/FEX/Wine execution defect.
4. X11 socket setup acceptance is not sufficient to assert that the selected
   Windows game created a mapped window; nor is a signed APK build.

## Repair applied in v4.0.59
- Increase bounded **Java TCP-to-Unix X11 relay capacity from 24 to 96**.
- Increase loopback TCP listen backlog from 16 to 128.
- Configure the private native X.Org service with `-maxclients 256`.
- Track relay reserved/peak clients and *actually dropped* connections, and
  retain separate Unix connect, IO, TCP EOF and native EOF counters.
- Preserve Vulkan fallback, Wine/FEX binaries, existing prefix, selected
  EXE files and user storage. No arbitrary GLES substitution for `libGL.so.1`.
- Classify each game process exit with a separate Wine-SEH/X11-capacity
  fingerprint, without claiming that a remaining SEH error is a GPU issue.

## Acceptance criteria on device
- Direct game launch must not reach `RM11_V459_RELAY_REJECTED_CLIENTS>0`.
- The relay must establish a stable connection with the native X.Org server
  and Wine's X11 clients. No recurring `Can't open display` attributable to
  the relay limit.
- A rendered game requires **at least one mapped game X11 window**, as well as
  the Android Surface showing corresponding non-black pixels.
- If relay rejection is 0 and the x64 game still exits with Wine
  `EXCEPTION_STACK_INVALID`, shift root-cause investigation to the
  ARM64EC FEX/Wine exception unwinder. Do **not** patch out exception handling
  or randomly replace Wine/runtime libraries.

This is a bounded root-cause repair of a **confirmed X11 capacity defect**,
not a declaration that all game crashes are resolved.
