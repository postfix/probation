//! NuGet v3 protection (row 20): the service index, the flat container (`index.json`, `.nupkg`,
//! `.nuspec`, readme, icon), registration, search and autocomplete, the vulnerability and
//! repository-signature documents, and the publish endpoint of the shared service, on the shared
//! firewall machinery.

pub mod doc;
pub mod serve;
