# Changelog

All notable changes to `plausiden-inject` are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — 2026-04-17 cross-session cycle
- **`OPSEC.md`** (209 lines) — audience, threats covered / not
  covered (pre-corrupt DB, concurrent browser, kernel-level tools,
  EDR interference), per-platform operational caveats (Firefox
  SQLite lock, Chrome Sync sync-warning, Android ContentProvider
  permissions, macOS SIP / Full Disk Access, Windows Controlled
  Folder Access, iOS sandboxing), transaction discipline + rollback
  semantics, attribution scrubbing, known failure modes.
- **`LEGAL.md`** (8 sections) — own-device-writes authorization
  (CFAA + *Van Buren v. United States*, GDPR, EU member-state
  computer-abuse equivalents), §1512 / §1519 specific-intent risk
  when running during known proceedings, spoliation-doctrine
  cut-both-ways, Inject-data-as-evidence discovery obligations,
  platform-specific legal notes (Firefox MPL, Chrome ToS, Android
  permissions), the Prairie Land notification-cache section,
  primary-source citations. Paired with
  `PlausiDen-USB/LEGAL.md` and `PlausiDen-Browser-Ext/LEGAL.md`
  for the three mandated LEGAL docs per v1.2 §G.2.

### Security posture notes
- Docs-only cycle — no code changes. The additions codify the
  operational-security constraints integrators and operators
  need to know before deploying.
- The `tls.rs` `example.com` SNI fallback in `PlausiDen-Engine`
  that was flagged by the Browser-Ext leak audit has been fixed
  upstream. Inject consumes engine-network; no action required
  downstream.

### Known gaps
- `inject-macos`, `inject-windows`, `inject-ios` remain
  scaffold-only. `OPSEC.md` §4 documents the per-platform
  constraints awaiting implementation.
- Transaction-rollback code path has not been fully exercised
  under fault-injection — AVP-2 Tier 2 pass is pending.

## [0.1.0] - 2026-04-04

### Added
- `inject-core`: Injector trait, InjectionStrategy enum, Target, verification, rollback
- `inject-linux`: Firefox and Chrome SQLite injection (DirectInjection strategy)
- Scaffold crates: inject-macos, inject-windows, inject-android, inject-ios
- Hurd translator interposition architecture documented
