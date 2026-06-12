// CopyCodeReport type tree lives in jankurai-audit-kernel (W5 split) and the
// copy-code scanner lives in jankurai-audit-dedup. Both are re-exported here so
// every `crate::audit::copy_code::*` path (types + scanner) resolves unchanged.
pub use jankurai_audit_dedup::*;
pub use jankurai_audit_kernel::audit::copy_code::*;
