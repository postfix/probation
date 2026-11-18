//! The synchronous publication gate: one short ordering point between policy/authority
//! publication and final artifact authorization plus response handoff (FIX-16-A).

use super::service_policy::ServicePolicyError;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicU64, Ordering},
};

/// Shared ordering point for local policy publication and response handoff.
#[derive(Default)]
pub struct PolicyPublicationGate {
    gate: RwLock<()>,
    generation: AtomicU64,
    /// Test seam run immediately before the read side is taken; absent from release builds.
    #[cfg(any(test, feature = "test-support"))]
    barrier: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl PolicyPublicationGate {
    pub(crate) fn read<T>(&self, inspect: impl FnOnce(u64) -> T) -> Result<T, ServicePolicyError> {
        let _guard = self.gate.read().map_err(|_| ServicePolicyError)?;
        Ok(inspect(self.generation()))
    }
    pub fn publish<T>(&self, update: impl FnOnce() -> T) -> Result<T, ServicePolicyError> {
        let _guard = self.gate.write().map_err(|_| ServicePolicyError)?;
        let result = update();
        self.generation.fetch_add(1, Ordering::Release);
        Ok(result)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn is_poisoned(&self) -> bool {
        self.gate.is_poisoned()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn set_barrier(&self, barrier: Arc<dyn Fn() + Send + Sync>) {
        *self.barrier.lock().unwrap() = Some(barrier);
    }

    pub fn authorize_current_policy<'a>(
        &'a self,
        prepared: &'a PreparedResponse,
    ) -> Result<AuthorizedResponse<'a>, ServicePolicyError> {
        authorize_current_policy(self, prepared)
    }
}

/// The final check: exact gate, publication generation and OSV generation, all read
/// inside one critical section with no await and no I/O.
pub fn authorize_current_policy<'a>(
    gate: &'a PolicyPublicationGate,
    prepared: &'a PreparedResponse,
) -> Result<AuthorizedResponse<'a>, ServicePolicyError> {
    #[cfg(any(test, feature = "test-support"))]
    {
        let barrier = gate.barrier.lock().unwrap().clone();
        if let Some(barrier) = barrier {
            barrier();
        }
    }
    let guard = gate.gate.read().map_err(|_| ServicePolicyError)?;
    let osv_current = prepared
        .osv
        .as_ref()
        .is_none_or(|osv| osv.counter.load(Ordering::Acquire) == osv.seen);
    if !std::ptr::eq(gate, Arc::as_ptr(&prepared.gate))
        || gate.generation() != prepared.generation
        || !osv_current
    {
        return Err(ServicePolicyError);
    }
    Ok(AuthorizedResponse {
        _guard: guard,
        prepared,
    })
}

/// The synchronous release guard `ArtifactResponse::into_response` calls: authorize
/// against the current gate, then hand the response off while the guard is held.
pub fn respond_order(
    gate: Arc<PolicyPublicationGate>,
    prepared: PreparedResponse,
) -> Result<axum::response::Response, ServicePolicyError> {
    let authorized = authorize_current_policy(&gate, &prepared)?;
    release_verified_response(authorized)
}

/// Owns the exact prepared response; authorization borrows it, so it cannot be replaced.
pub struct PreparedResponse {
    gate: Arc<PolicyPublicationGate>,
    generation: u64,
    osv: Option<OsvStamp>,
    response: Mutex<Option<PreparedBody>>,
}

/// The OSV generation (C1029) read before the response's OSV evaluation started.
#[derive(Clone)]
pub(crate) struct OsvStamp {
    counter: Arc<AtomicU64>,
    seen: u64,
}

enum PreparedBody {
    Http(axum::response::Response),
    Artifact(crate::artifacts::stream::ArtifactResponse),
}

#[derive(Clone)]
pub(crate) struct AuthorityReceipt {
    pub gate: Arc<PolicyPublicationGate>,
    pub generation: u64,
    osv: Option<OsvStamp>,
}

impl AuthorityReceipt {
    pub(crate) fn new(gate: Arc<PolicyPublicationGate>, generation: u64) -> Self {
        Self { gate, generation, osv: None }
    }

    pub(crate) fn with_osv(mut self, counter: Arc<AtomicU64>, seen: u64) -> Self {
        self.osv = Some(OsvStamp { counter, seen });
        self
    }
}

impl PreparedResponse {
    pub(crate) fn new(
        gate: Arc<PolicyPublicationGate>,
        generation: u64,
        response: axum::response::Response,
    ) -> Self {
        Self {
            gate,
            generation,
            osv: None,
            response: Mutex::new(Some(PreparedBody::Http(response))),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_receipt(receipt: AuthorityReceipt, response: axum::response::Response) -> Self {
        Self {
            gate: receipt.gate,
            generation: receipt.generation,
            osv: receipt.osv,
            response: Mutex::new(Some(PreparedBody::Http(response))),
        }
    }

    pub(crate) fn artifact(
        authority: AuthorityReceipt,
        response: crate::artifacts::stream::ArtifactResponse,
    ) -> Self {
        Self {
            gate: authority.gate,
            generation: authority.generation,
            osv: authority.osv,
            response: Mutex::new(Some(PreparedBody::Artifact(response))),
        }
    }
}

pub struct AuthorizedResponse<'a> {
    _guard: std::sync::RwLockReadGuard<'a, ()>,
    prepared: &'a PreparedResponse,
}

pub fn release_verified_response(
    authorization: AuthorizedResponse<'_>,
) -> Result<axum::response::Response, ServicePolicyError> {
    use axum::response::IntoResponse;
    match authorization
        .prepared
        .response
        .lock()
        .map_err(|_| ServicePolicyError)?
        .take()
        .ok_or(ServicePolicyError)?
    {
        PreparedBody::Http(response) => Ok(response),
        PreparedBody::Artifact(response) => Ok(response.into_response()),
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use axum::{body::Body, response::Response};

    #[tokio::test]
    async fn handoff_binds_gate_generation_and_exact_owned_response() {
        let gate = Arc::new(PolicyPublicationGate::default());
        let other = PolicyPublicationGate::default();
        let prepared = PreparedResponse::new(
            Arc::clone(&gate),
            0,
            Response::new(Body::from("exact verified response")),
        );
        assert!(other.authorize_current_policy(&prepared).is_err());
        let authorization = gate.authorize_current_policy(&prepared).unwrap();
        let (started, receiver) = std::sync::mpsc::channel();
        let writer_gate = Arc::clone(&gate);
        let writer = std::thread::spawn(move || {
            started.send(()).unwrap();
            writer_gate.publish(|| ()).unwrap();
        });
        receiver.recv().unwrap();
        assert_eq!(
            gate.generation(),
            0,
            "publication cannot pass a held final authorization"
        );
        let response = release_verified_response(authorization).unwrap();
        writer.join().unwrap();
        assert_eq!(gate.generation(), 1);
        assert!(
            gate.authorize_current_policy(&prepared).is_err(),
            "old generation cannot authorize another handoff"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 100)
                .await
                .unwrap()
                .as_ref(),
            b"exact verified response"
        );
    }

    #[test]
    fn poisoned_publication_gate_refuses_final_authorization() {
        let gate = Arc::new(PolicyPublicationGate::default());
        let prepared = PreparedResponse::new(Arc::clone(&gate), 0, Response::new(Body::empty()));
        let writer = Arc::clone(&gate);
        assert!(
            std::thread::spawn(move || {
                let _ = writer.publish(|| panic!("publication failed"));
            })
            .join()
            .is_err()
        );
        assert!(gate.authorize_current_policy(&prepared).is_err());
    }

    fn artifact_receipt(gate: &Arc<PolicyPublicationGate>) -> AuthorityReceipt {
        AuthorityReceipt::new(Arc::clone(gate), gate.generation())
    }

    async fn body(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 100).await.unwrap().to_vec()
    }

    fn prepared(gate: &Arc<PolicyPublicationGate>, osv: Option<(&Arc<AtomicU64>, u64)>) -> PreparedResponse {
        let mut receipt = artifact_receipt(gate);
        if let Some((counter, seen)) = osv {
            receipt = receipt.with_osv(Arc::clone(counter), seen);
        }
        PreparedResponse::with_receipt(receipt, Response::new(Body::from("exact bytes")))
    }

    /// C1029: a verdict change after the OSV generation was read refuses; unchanged delivers.
    #[tokio::test]
    async fn osv_generation_change_refuses_before_release() {
        let counter = Arc::new(AtomicU64::new(7));
        let gate = Arc::new(PolicyPublicationGate::default());
        let unchanged = respond_order(Arc::clone(&gate), prepared(&gate, Some((&counter, 7))));
        assert_eq!(body(unchanged.unwrap()).await, b"exact bytes");
        let stale = prepared(&gate, Some((&counter, 7)));
        counter.fetch_add(1, Ordering::Release);
        assert!(respond_order(Arc::clone(&gate), stale).is_err(), "stale OSV allow must not release");
    }

    #[tokio::test]
    async fn respond_order_refuses_after_publication_and_when_poisoned() {
        let gate = Arc::new(PolicyPublicationGate::default());
        let early = prepared(&gate, None);
        gate.publish(|| ()).unwrap();
        assert!(respond_order(Arc::clone(&gate), early).is_err());
        let poisoned = Arc::new(PolicyPublicationGate::default());
        let victim = prepared(&poisoned, None);
        let writer = Arc::clone(&poisoned);
        assert!(std::thread::spawn(move || { let _ = writer.publish(|| panic!("boom")); }).join().is_err());
        assert!(poisoned.is_poisoned());
        assert!(respond_order(poisoned, victim).is_err());
    }

    /// The barrier sits immediately before the read side; a publication ordered
    /// there, on another thread, governs the request. Ordering is by channel events.
    #[test]
    fn final_boundary_barrier_drives_cross_thread_publication() {
        for publish in [false, true] {
            let gate = Arc::new(PolicyPublicationGate::default());
            let prepared = prepared(&gate, None);
            let (reached_tx, reached_rx) = std::sync::mpsc::channel();
            let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
            let go_rx = Mutex::new(go_rx);
            gate.set_barrier(Arc::new(move || {
                reached_tx.send(()).unwrap();
                go_rx.lock().unwrap().recv().unwrap();
            }));
            let request_gate = Arc::clone(&gate);
            let request = std::thread::spawn(move || respond_order(request_gate, prepared).is_ok());
            reached_rx.recv().unwrap();
            if publish {
                let writer = Arc::clone(&gate);
                std::thread::spawn(move || writer.publish(|| ()).unwrap()).join().unwrap();
            }
            go_tx.send(()).unwrap();
            assert_eq!(request.join().unwrap(), !publish, "publication ordered before authorization governs");
        }
    }

    /// A writer queued around a held read side neither deadlocks the following request
    /// nor is lost; whether the request is delivered or refused depends on lock order,
    /// so only liveness (the watchdog) and the published generation are asserted.
    #[test]
    fn pending_writer_does_not_deadlock_read_or_handoff() {
        let gate = Arc::new(PolicyPublicationGate::default());
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder_gate = Arc::clone(&gate);
        let holder = std::thread::spawn(move || {
            holder_gate.read(|_| { held_tx.send(()).unwrap(); release_rx.recv().unwrap(); }).unwrap();
        });
        held_rx.recv().unwrap();
        let (writer_tx, writer_rx) = std::sync::mpsc::channel();
        let writer_gate = Arc::clone(&gate);
        let writer = std::thread::spawn(move || { writer_tx.send(()).unwrap(); writer_gate.publish(|| ()).unwrap(); });
        writer_rx.recv().unwrap();
        let prepared = prepared(&gate, None);
        let request_gate = Arc::clone(&gate);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let request = std::thread::spawn(move || { done_tx.send(respond_order(request_gate, prepared).is_ok()).unwrap(); });
        release_tx.send(()).unwrap();
        let _delivered = done_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("watchdog: deadlock");
        holder.join().unwrap();
        writer.join().unwrap();
        request.join().unwrap();
        assert_eq!(gate.generation(), 1);
    }
}
