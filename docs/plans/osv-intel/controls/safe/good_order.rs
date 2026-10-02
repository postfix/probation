// Safe control for invariant 1: the producer's blind evaluate() always runs
// before OSV's check() is ever consulted.
fn evaluate(matched: bool) -> bool {
    matched
}

fn check() -> bool {
    true
}

async fn correct() -> bool {
    let blind = evaluate(false);
    if !blind {
        return blind;
    }
    let matched = check();
    evaluate(matched)
}
