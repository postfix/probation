struct EnterprisePeer;
struct GoodStatus;

async fn cached_issuer_status(_: &EnterprisePeer) -> Result<GoodStatus, ()> { Ok(GoodStatus) }
fn grant_enterprise_certificate(_: GoodStatus) -> Result<(), ()> { Ok(()) }

async fn resolve_enterprise_certificate(peer: &EnterprisePeer) -> Result<(), ()> {
    let status = cached_issuer_status(peer).await?;
    grant_enterprise_certificate(status)
}
