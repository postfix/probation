// Unsafe control for invariant 3 (C12a): the channel send is awaited with no
// timeout wrapper, so a full queue can block the caller instead of failing open.
struct Sender;
impl Sender {
    async fn send(&self, _item: i32) -> Result<(), ()> {
        Ok(())
    }
}

async fn regression(tx: &Sender) {
    tx.send(1).await.unwrap(); // VIOLATION: no timeout() around the enqueue
}
