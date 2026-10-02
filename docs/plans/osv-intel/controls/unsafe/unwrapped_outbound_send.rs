// Unsafe control for invariant 3 (C12c): the outbound POST is sent with no
// timeout wrapper, so a hung connection can block the caller instead of
// failing the batch open.
struct Client;
impl Client {
    async fn post(&self) -> Result<(), ()> {
        Ok(())
    }
}

async fn send(client: &Client) -> Result<(), ()> {
    client.post().await // the actual I/O primitive, matched separately
}

async fn regression(client: &Client) -> Result<(), ()> {
    send(client).await // VIOLATION: no timeout() around this call
}
