//! The checksum database, admitted separately from the module routes (row 19, 03 family table):
//! `GOPROXY/sumdb/{db}/...` forwards the five read shapes of the sumdb protocol (`supported`,
//! `latest`, `lookup/{module}@{version}`, `tile/...`) to the one configured database origin and
//! nowhere else. It carries hashes only, never module content, so it is not an artifact route:
//! nothing here is gated, cached or decided by policy, no credential of the caller is forwarded,
//! and only the public registry has it (a private registry has no public checksum record).

use std::sync::Arc;

use crate::App;
use crate::go_modules::escape;
use crate::go_modules::serve::Rendered;
use crate::http::error::ApiError;
use crate::managed::report::Call;
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, UpstreamValidators};

/// A tile is at most 256 hashes of 32 bytes or 256 records; 4 MiB is far above both.
const CAP: u64 = 4 << 20;

fn digits(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit())
}

/// One group of a tile index: `x001` (not the last) or `234`; the last may end in `.p`.
fn tile_group(group: &str) -> bool {
    group.strip_prefix('x').map_or_else(|| digits(group, 3) && group.len() == 3, |rest| rest.len() == 3 && digits(rest, 3))
}

/// The URL path segments below the database root for a request path `{db}/{tail}`, or `None` when
/// it is not one of the protocol's reads or names another database.
pub fn segments_of(app: &App, rest: &str) -> Option<(Vec<String>, &'static str)> {
    let db = app.origins.origin(OriginKind::GoSumdb).host_str()?.to_owned();
    let tail = rest.strip_prefix(&db)?.strip_prefix('/')?;
    let parts: Vec<&str> = tail.split('/').collect();
    match parts.as_slice() {
        ["supported"] => Some((vec!["supported".into()], TEXT)),
        ["latest"] => Some((vec!["latest".into()], TEXT)),
        ["lookup", path @ ..] if !path.is_empty() => {
            let joined = path.join("/");
            let (module, version) = joined.rsplit_once('@')?;
            let (module, version) = (escape::module_of(module)?, escape::version_of(version)?);
            let mut out = vec!["lookup".to_owned()];
            let mut elements: Vec<String> = escape::module_segments(&module)?;
            let last = elements.pop()?;
            out.extend(elements);
            out.push(format!("{last}@{}", escape::escape(&version)?));
            Some((out, TEXT))
        }
        ["tile", height, level, rest @ ..] if !rest.is_empty() && rest.len() <= 6 => {
            if !digits(height, 2) || !(*level == "data" || digits(level, 2)) {
                return None;
            }
            // `x001/x234/567` or `x001/234.p/17`: the last group may end in `.p` and is then followed by a width.
            let (groups, width) = match rest.iter().position(|s| s.ends_with(".p")) {
                Some(at) if at + 2 == rest.len() => (&rest[..=at], Some(rest[at + 1])),
                Some(_) => return None,
                None => (rest, None),
            };
            let last = groups.len() - 1;
            let groups_ok = groups.iter().enumerate().all(|(i, group)| tile_group(if i == last { group.strip_suffix(".p").unwrap_or(group) } else { group }));
            if !groups_ok || width.is_some_and(|w| !digits(w, 3)) {
                return None;
            }
            Some((std::iter::once("tile").chain([*height, *level]).chain(rest.iter().copied()).map(str::to_owned).collect(), "application/octet-stream"))
        }
        _ => None,
    }
}

const TEXT: &str = "text/plain; charset=utf-8";

/// `GET /go/sumdb/{db}/...` on the public registry.
pub async fn serve(app: &App, rest: &str) -> Result<Rendered, ApiError> {
    let (segments, content_type) = segments_of(app, rest).ok_or(ApiError::NotFound)?;
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let url = app.origins.url_for(OriginKind::GoSumdb, &parts).map_err(|_| ApiError::NotFound)?;
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: None,
            private_cidrs: Vec::new(),
            // The caller's credential is never sent to the checksum database.
            read_authorization: None,
            accept: "*/*",
            validators: None::<UpstreamValidators>,
            max_bytes: CAP.min(app.config.max_metadata_bytes.get()),
        })
        .await;
    app.upstreams.record_upstream(Call::Go, &fetched);
    match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => Ok(Rendered { body: Arc::from(body.as_ref()), content_type }),
        Ok(MetadataResponse::Missing) => Err(ApiError::NotFound),
        Ok(MetadataResponse::NotModified { .. }) => Err(ApiError::UpstreamInvalid),
        Err(crate::upstream::UpstreamError::Timeout) => Err(ApiError::UpstreamTimeout),
        Err(error) => {
            tracing::warn!(%error, "the checksum database fetch failed");
            Err(ApiError::UpstreamFailure)
        }
    }
}
