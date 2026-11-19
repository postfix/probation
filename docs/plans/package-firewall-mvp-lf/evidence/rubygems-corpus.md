# RubyGems real-corpus record (slice 17, 2026-11-18)

Source: live rubygems.org, fetched 2026-11-18 with curl; stored only under `.probation-scratch/rg17/` (deleted after the task), except five small quick gemspecs and a 1,663-tuple slice of the full index committed as fixtures in tests/fixtures/rubygems/. Measured by `real_corpus_measurement` in tests/rubygems_marshal.rs (release build, this host, Ruby 3.3.13 present only for the loader witness).

## Compressed-input record (LS-F7: "record the family's largest real compressed fixture and inflated size")

| File | Compressed | Inflated | Ratio | Tuples | Nodes | Nominal charge | Output |
|---|---|---|---|---|---|---|---|
| specs.4.8.gz (full index, largest) | 6,394,682 B | 26,277,749 B | 4.1:1 | 1,760,000 | 7,399,428 | 106,924,035 B | 26,275,440 B |
| latest_specs.4.8.gz | 1,692,730 B | 5,578,326 B | 3.3:1 | 201,277 | 1,020,179 | 28,261,232 B | 5,578,306 B |
| prerelease_specs.4.8.gz | 492,383 B | 2,250,440 B | 4.6:1 | 95,674 | 498,704 | 12,323,145 B | 2,250,273 B |
| 84 quick gemspecs (every 2,400th latest tuple plus well-known gems and platform gems) | 549 B to 2.6 KB | at most a few KB | n/a | n/a | n/a | n/a | n/a |

Filtering the full index: 0.93 s (release, one core), peak resident set of the whole test process 283 MB, against the 512 MiB budget (nominal charge 107 MB). The LS-F7 inflate cap for tuple indexes stays at the specified 128 MiB (the real full index inflates to 26 MB, about 5x headroom) and for quick gemspecs 4 MiB (real largest is about 10 KB inflated). The measured real ratio is 3.3 to 4.6:1, below the "5-10:1" the design guessed, so the 100:1 rule has more than 20x headroom. No valid input is refused by any cap: the caps were not raised because no real input is near them.

## Allow-list finding (LS-F13 widen-on-corpus clause)

All 84 real quick gemspecs validate under the specified allow-list: Gem::Specification (nested stream), Gem::Version, Gem::Requirement, Gem::Dependency, Gem::Platform (also the plain string form) and `Time` (Binary8). No Regexp, no Float outside what the allow-list covers, and no further class was needed, so the allow-list is NOT widened. All 1,760,000 + 201,277 + 95,674 real tuples parse under the tuple-index allow-list (nil, true, false, Integer, String with encoding ivar, Symbol and symlink, Array, Hash, object links, Gem::Version user-marshal); no tag outside the list was needed. One limit of the typed re-render: an object link to a container (Array, Hash) is refused as `BadLink`, because only Strings and Gem::Version objects are shared typed values; no real index file contains one.

Ruby 3.3.13 itself loads the filtered output of the committed real index slice and returns exactly the expected tuples (witness: marshal_filter_real_slice_is_loaded_by_ruby_with_the_denied_tuples_gone), and keep-everything re-rendering of that slice is byte-identical to Ruby's own dump.
