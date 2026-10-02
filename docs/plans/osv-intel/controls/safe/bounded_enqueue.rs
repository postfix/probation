// Safe control for invariant 3: the enqueue send is wrapped in timeout(), so a
// full queue fails open rather than blocking the caller.
struct Sender;
impl Sender {
    async fn send(&self, _item: i32) -> Result<(), ()> {
        Ok(())
    }
}

async fn timeout<F>(_duration_ms: u64, fut: F) -> F {
    fut
}

async fn correct(tx: &Sender) {
    let _ = timeout(50, tx.send(1)).await;
}
