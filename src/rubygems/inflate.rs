//! LS-F7: every accepted compressed RubyGems input is inflated under a size cap and a
//! ratio cap. Overrun refuses the metadata; it never passes the original bytes through.

use std::io::Read;

/// The ratio (inflated bytes per compressed byte consumed so far) enforced once more than
/// this many bytes have been inflated.
pub const RATIO_FLOOR_BYTES: u64 = 1024 * 1024;
pub const MAX_RATIO: u64 = 100;

/// Tuple indexes inflate to at most 128 MiB, quick gemspecs to at most 4 MiB (LS-F7).
pub const TUPLE_INDEX_CAP: u64 = 128 * 1024 * 1024;
pub const GEMSPEC_CAP: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InflateError {
    /// Not a well-formed gzip or zlib stream, or bytes after the last member.
    Malformed,
    /// The inflated size passed the family cap.
    TooLarge,
    /// More than 100:1 after the first MiB.
    Ratio,
}

/// Inflates `input` (gzip, concatenated members allowed; zlib when `zlib`) into at most
/// `cap` bytes.
pub fn inflate(input: &[u8], zlib: bool, cap: u64) -> Result<Vec<u8>, InflateError> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    if zlib {
        let mut reader = flate2::bufread::ZlibDecoder::new(input);
        loop {
            let n = reader.read(&mut chunk).map_err(|_| InflateError::Malformed)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            guard(out.len() as u64, input.len() as u64 - reader.get_ref().len() as u64, cap)?;
        }
        // A zlib stream ends at its checksum; anything after it is refused.
        if !reader.get_ref().is_empty() {
            return Err(InflateError::Malformed);
        }
    } else {
        let mut reader = flate2::bufread::MultiGzDecoder::new(input);
        loop {
            let n = reader.read(&mut chunk).map_err(|_| InflateError::Malformed)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            guard(out.len() as u64, input.len() as u64 - reader.get_ref().len() as u64, cap)?;
        }
        if !reader.get_ref().is_empty() {
            return Err(InflateError::Malformed);
        }
    }
    Ok(out)
}

fn guard(inflated: u64, consumed: u64, cap: u64) -> Result<(), InflateError> {
    if inflated > cap {
        return Err(InflateError::TooLarge);
    }
    if inflated > RATIO_FLOOR_BYTES && inflated > consumed.max(1) * MAX_RATIO {
        return Err(InflateError::Ratio);
    }
    Ok(())
}
