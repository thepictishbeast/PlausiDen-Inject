# CLAUDE.md — Instructions for Claude Code

## IMPORTANT: If this is the first message in a session or context was recently compacted, read this entire file before doing anything else.

## Project: plausiden-inject
Platform-specific injection adapters for the PlausiDen ecosystem. Bridges generated artifacts to OS data stores.

## Part of the PlausiDen Ecosystem
This repo is part of PlausiDen (PLAUSIbly DENiable) protection suite.

## Architecture
Cargo workspace with 6 crates:
- `inject-core` — Injector trait, InjectionStrategy enum (DirectInjection, TranslatorInterposition, Hybrid), Target, verification
- `inject-linux` — Firefox/Chrome SQLite injection (IMPLEMENTED), filesystem/logs/input/proc/translator (scaffold)
- `inject-macos` — Safari, Spotlight, CoreData, FSEvents (scaffold)
- `inject-windows` — NTFS, Registry, Prefetch, EventLog, Thumbcache, LNK, RecycleBin (scaffold)
- `inject-android` — ContentProvider, SQLite, SharedPrefs, MediaStore (scaffold)
- `inject-ios` — Contacts, Calendar, Photos, Sandbox (scaffold)

## Key Design: Injection Strategies
- DirectInjection (Tier 2): Modifies actual database files. Works everywhere but detectable by integrity checks.
- TranslatorInterposition (Tier 3): Hurd-style filesystem interposition. Non-destructive, reversible, no residue. Target for PlausiDenOS.
- Hybrid: Translator where available, direct as fallback.

## Code Standards
- Rust edition 2024. `gen` is reserved — never use as variable name.
- thiserror for errors. Never unwrap() in library code.
- rusqlite for SQLite operations.
- 80%+ test coverage for implemented modules.

## Narrative Framing
Civil rights tool. NEVER include personal political beliefs or ideology.
