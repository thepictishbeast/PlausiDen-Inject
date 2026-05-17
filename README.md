> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

# PlausiDen Inject

Platform-specific injection adapters that write PlausiDen-generated artifacts into real OS data stores. The bridge between synthetic data generation and forensic-level plausibility — because data that exists only in memory doesn't show up in forensic analysis.

## The Problem

Generated synthetic data is useless unless it appears in the same locations where forensic tools look for evidence: browser SQLite databases, filesystem metadata, system logs, registry entries. Each platform stores data differently. PlausiDen Inject handles the platform-specific logic of writing artifacts where they need to be.

## How It Works

```
plausiden-engine  →  artifact bytes  →  plausiden-inject  →  OS data store
                                            │
                                    ┌───────┼───────┐
                                    ▼       ▼       ▼
                                 Linux   macOS   Windows
                              Firefox  Safari   Registry
                              Chrome   Spotlight Prefetch
                              journald FSEvents  EVTX
```

## Injection Strategies

| Strategy | How | Pros | Cons |
|----------|-----|------|------|
| **DirectInjection** (Tier 2) | Modify actual database files | Works everywhere today | Detectable by integrity checks |
| **TranslatorInterposition** (Tier 3) | Filesystem interposition via Hurd-style translators | Non-destructive, reversible, no residue | Requires translator runtime |
| **Hybrid** | Translator where available, direct as fallback | Best of both | Complexity |

## Current Status

| Platform | Component | Status |
|----------|-----------|--------|
| Linux | Firefox history/cookies | Implemented |
| Linux | Chrome history/cookies | Implemented |
| Linux | Filesystem, logs, input, proc | Scaffolded |
| Linux | Hurd translator | Scaffolded |
| macOS | All modules | Scaffolded |
| Windows | All modules | Scaffolded |
| Android | All modules | Scaffolded |
| iOS | All modules | Scaffolded |

## Quick Start

```bash
git clone https://github.com/thepictishbeast/PlausiDen-Inject.git
cd PlausiDen-Inject
just check-all
```

## License

BSL 1.1 with Apache 2.0 change date of 2030-04-04.
