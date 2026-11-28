//! Row 17 closure check for the Marshal codec: whatever bytes arrive, the readers never panic,
//! never charge past the budget they were given, and whatever the tuple filter renders is itself
//! a valid index. Capped: 3 properties x 1,500 cases of at most 4 KiB, no I/O.

use probation::rubygems::inflate;
use probation::rubygems::marshal::{Limits, filter_tuple_index, validate_gemspec};
use proptest::prelude::*;

fn slice() -> Vec<u8> {
    let gz = std::fs::read(format!(
        "{}/tests/fixtures/rubygems/full-index-slice.4.8.gz",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let raw = inflate::inflate(&gz, false, inflate::TUPLE_INDEX_CAP).unwrap();
    raw[..raw.len().min(4096)].to_vec()
}

fn specs() -> Vec<Vec<u8>> {
    std::fs::read_dir(format!(
        "{}/tests/fixtures/rubygems",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .filter_map(|e| e.ok())
    .filter(|e| e.file_name().to_string_lossy().ends_with(".gemspec.rz"))
    .map(|e| {
        inflate::inflate(
            &std::fs::read(e.path()).unwrap(),
            true,
            inflate::GEMSPEC_CAP,
        )
        .unwrap()
    })
    .collect()
}

const SMALL: Limits = Limits {
    max_depth: 32,
    max_nodes: 5_000,
    memory_budget: 200_000,
};

/// A real stream with up to eight bytes overwritten, inserted or removed, or cut short.
fn mutated(base: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    let len = base.len();
    (
        prop::collection::vec((0..len, any::<u8>(), 0u8..3), 0..8),
        0..=len,
    )
        .prop_map(move |(edits, cut)| {
            let mut bytes = base.clone();
            for (at, byte, kind) in edits {
                let at = at.min(bytes.len().saturating_sub(1));
                if bytes.is_empty() {
                    break;
                }
                match kind {
                    0 => bytes[at] = byte,
                    1 => bytes.insert(at, byte),
                    _ => {
                        bytes.remove(at);
                    }
                }
            }
            bytes.truncate(cut.max(2).min(bytes.len()));
            bytes
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1500, max_shrink_iters: 200, .. ProptestConfig::default() })]

    /// Random bytes behind a valid header: no panic, and an Ok result stays inside the budget.
    #[test]
    fn marshal_random_streams_never_panic_and_never_overrun_the_budget(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut raw = vec![4u8, 8];
        raw.extend(body);
        if let Ok((out, stats)) = filter_tuple_index(&raw, SMALL, |_, _, _| true) {
            prop_assert!(stats.charged_bytes <= SMALL.memory_budget + out.len() as u64);
            prop_assert!(stats.nodes <= SMALL.max_nodes);
        }
        let _ = validate_gemspec(&raw, SMALL);
    }

    /// Mutations of a real index: errors are fine, panics and budget overruns are not, and
    /// what the filter renders is accepted by the filter again with every tuple kept.
    #[test]
    fn marshal_mutated_real_index_is_refused_or_rendered_validly(bytes in mutated(slice())) {
        let limits = Limits { memory_budget: 2_000_000, ..SMALL };
        if let Ok((out, stats)) = filter_tuple_index(&bytes, limits, |name, _, _| name.len() % 2 == 0) {
            {
                prop_assert!(stats.charged_bytes <= limits.memory_budget);
                let (again, again_stats) = filter_tuple_index(&out, limits, |_, _, _| true).expect("the output is a valid index");
                prop_assert_eq!(again_stats.kept, stats.kept);
                prop_assert_eq!(again, out);
            }
        }
    }

    /// Mutations of real quick gemspecs: refuse or validate, never panic.
    #[test]
    fn marshal_mutated_real_gemspec_never_panics(pick in 0usize..5, edits in prop::collection::vec((0usize..4096, any::<u8>()), 0..8)) {
        let all = specs();
        let mut bytes = all[pick % all.len()].clone();
        for (at, byte) in edits {
            let at = at % bytes.len();
            bytes[at] = byte;
        }
        let _ = validate_gemspec(&bytes, SMALL);
    }
}
