//! Conan 2 remote protection (row 23): the REST API's recipe and package revisions, the files of each revision and the
//! search documents, all served from the remote's own `v2/conans` tree under the firewall's decision.

pub mod coords;
pub mod serve;
