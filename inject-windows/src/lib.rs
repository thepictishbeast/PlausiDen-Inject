//! `inject-windows` -- Windows injection adapters for PlausiDen.
//!
//! Provides scaffolded adapters for Windows-specific data stores including
//! NTFS metadata, the Windows Registry, Prefetch files, Event Log,
//! thumbnail cache, LNK shortcut files, and the Recycle Bin.

pub mod eventlog;
pub mod lnk;
pub mod ntfs;
pub mod prefetch;
pub mod recycle_bin;
pub mod registry;
pub mod thumbcache;
