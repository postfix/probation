// Safe control for invariant 3: the outbound POST call is wrapped in
// timeout(), so a hung connection fails the batch open rather than blocking.
struct Client;
impl Client {
    async fn post(&self) -> Result<(), ()> {
        Ok(())
    }
}

async fn send(client: &Client) -> Result<(), ()> {
    client.post().await
}

async fn timeout<F>(_duration_ms: u64, fut: F) -> F {
    fut
}

async fn correct(client: &Client) -> Result<(), ()> {
    timeout(50, send(client)).await
}
