// Unsafe control for invariant 1 (OR-only merge / C1): the OSV lookup runs
// before the producer's own (blind) policy evaluation, so an OSV outcome
// could be used to decide before the producer snapshot has had a say.
fn evaluate(matched: bool) -> bool {
    matched
}

fn check() -> bool {
    true
}

async fn regression() -> bool {
    let matched = check(); // OSV asked before the producer's blind evaluate() — VIOLATION
    evaluate(matched)
}
