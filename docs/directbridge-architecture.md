# RM11 DirectBridge — staged connection contract

Status: **local diagnostics only; no active remote connection**, no background server and no autonomous device control.

## Why
The user wants ChatGPT to inspect errors *inside RM11-WinCore*, without exporting an aShell log manually. This first stage instruments the RM11 Android app itself. It records each on-device Wine smoke attempt in app-private storage, with basic secret redaction and evidence-based symptom classification. It does not diagnose beyond the evidence nor prove a root cause. The current record is intentionally inspectable locally even with the network off.

## Next phase: actual authenticated connection (NOT IMPLEMENTED)
- Expose a minimum-privilege get_runtime_status and get_last_wine_diagnostic interface via a user-approved authenticated bridge. A plain HTTP endpoint, an unauthenticated tunnel, and GitHub public issues are forbidden transports.
- Start pairing *from the phone*. Use narrowly scoped, short-lived credentials (never embed a reusable shared secret in the signed APK or repository). Revoke from within the app.
- Prefer an encrypted outbound HTTPS transport with TLS certificate validation and authenticated cloud relay. The relay must map requests to the correct paired device and enforce expiry/replay protection.
- Require an explicit per-action user approval for any write, restart, settings change, file replacement or privileged shell request. Read-only diagnostics should also be opt-in and easily disabled.
- Mask user-controlled file names, passwords, tokens and personal identifiers before any telemetry leaves the phone. Default to no remote transmission. Retain bounded local records; no arbitrary folder traversal and no global Android permissions.
- GitHub access for source/build is separate from authorization to interact with the phone.
- Demonstrate end-to-end proof only when the ChatGPT MCP connector can actually call the paired diagnostic tools and see a fresh response. Until then, claim *not connected*.

## Stage 1 source
- DirectBridgeFailure: pure-Java classification of observed Wine diagnostic symptoms, never asserts proven root cause.
- DirectBridgeDiagnostics: app-private atomic last-attempt report, constrained runtime snapshots, explicit local status.
- MainActivity: saves each RM11 v2.5.6 Wine smoke report and adds a local DirectBridge diagnostic readout for verification.
- No Shizuku, aShell You, Android root, INTERNET permission, background task or APK build required for this source-only branch.
