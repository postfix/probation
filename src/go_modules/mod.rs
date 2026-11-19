//! Go module proxy protection (row 19): `@v/list`, `@latest`, and the `.info`, `.mod` and `.zip`
//! of each version on the shared firewall machinery, plus the separately admitted checksum
//! database route. One protected GOPROXY, no fallback.

pub mod escape;
pub mod serve;
pub mod sumdb;
