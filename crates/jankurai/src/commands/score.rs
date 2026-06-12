//! Re-export shim: the score diff/trend implementation moved to the
//! `jankurai-fleet` crate (W5 split). Every existing `crate::commands::score::X`
//! path keeps resolving unchanged.
pub use jankurai_fleet::score::*;
