//! Maven repository protection (row 21): `maven-metadata.xml` (artifact, plugin-group and snapshot level) and
//! `archetype-catalog.xml` filtered by policy with their checksums rebuilt, and every file of a version (POM, JAR,
//! classifier files, `.module`, signatures and checksum sidecars) gated by the decision of its version or snapshot
//! build, on the shared firewall machinery; plus the deploy endpoints of the shared service.

pub mod coords;
pub mod meta;
pub mod serve;
pub mod xml;
