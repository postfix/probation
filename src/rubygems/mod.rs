//! RubyGems: the bounded Marshal codec (LS-F13), the bounded gzip/zlib inflater (LS-F7)
//! and the gem identity rules. No Ruby object is ever loaded and no code executes.

pub mod inflate;
pub mod info;
pub mod marshal;
pub mod serve;
