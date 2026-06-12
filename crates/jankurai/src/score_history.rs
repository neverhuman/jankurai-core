//! Re-export shim: the score-history engine moved to the `jankurai-fleet` crate
//! (W5 split). Every existing `crate::score_history::X` path keeps resolving
//! unchanged.
pub use jankurai_fleet::score_history::*;
