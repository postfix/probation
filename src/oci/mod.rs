//! OCI distribution (Docker images, Helm charts, any OCI artifact): manifests, indexes, blobs, tag lists, referrers and the catalog
//! of a registry, gated by the firewall's policy before a byte reaches a client. See `serve` for the flow and `coords` for the layout.
pub mod coords;
pub mod serve;
