//! Re-export shim: the score-history command implementation moved to the
//! `jankurai-fleet` crate (W5 split). Every existing `crate::commands::history::X`
//! path keeps resolving unchanged.
pub use jankurai_fleet::history::*;
