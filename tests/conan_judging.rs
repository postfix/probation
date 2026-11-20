//! Row 23, recheck-1 round: how searches are judged. Its own test binary because it shortens a process-wide deadline: the judging is the
//! request's own work (shared per verdict, bounded per registry and in the process), a retry after a 504 finds what was made, an install is
//! never queued behind it, a policy published mid-search wins, and an unreadable list withholds its reference and nothing else.

mod common;

use std::sync::Arc;

use common::conan::{REMOTE, PUBLISH, at, base, revisions_doc, search_doc, serve_recipe};
use common::{FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, fake_origins, sample_config};
use probation::upstream::{OriginSet, Transport};
use url::Url;

/// The tests share a process-wide deadline knob: one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00Z";
const R: &str = "bbbb0000000000000000000000000001";

fn origins() -> OriginSet {
    fake_origins().with_conan(Url::parse(REMOTE).unwrap(), Url::parse(PUBLISH).unwrap())
}

struct H {
    server: Arc<TestServer>,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    _dir: tempfile::TempDir,
}

async fn harness() -> H {
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(&blocklist, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "")).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.cooldown_seconds = 0;
    config.max_references_per_project = std::num::NonZeroU32::new(100).unwrap();
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    H { server: Arc::new(server), registry, clock, _dir: dir }
}

fn refs(names: &[String]) -> String {
    search_doc(&names.iter().map(|name| format!("{name}/1.0@_/_")).collect::<Vec<_>>().iter().map(String::as_str).collect::<Vec<_>>())
}

fn lists_of(h: &H, name: &str) -> usize {
    h.registry.calls().iter().filter(|url| url.path().ends_with(&format!("/{name}/1.0/_/_/revisions"))).count()
}

fn gate_list(h: &H, name: &str, gate: &Arc<Gate>) {
    h.registry.answer(&at(&format!("{}/revisions", base(name, "1.0"))), FakeAnswer::GatedMetadata { body: revisions_doc(("reference", &format!("{name}/1.0@_/_")), &[(R, Some(OLD))]), gate: Arc::clone(gate) });
}

async fn search(server: &Arc<TestServer>) -> reqwest::Response {
    server.get("/conan/v2/conans/search?q=*").await
}

/// A retry after a 504 finds what the first attempt made: nothing is fetched twice, and the retry completes.
#[tokio::test]
async fn a_retry_after_a_504_finds_the_verdicts_the_first_attempt_made() {
    let _serial = SERIAL.lock().await;
    probation::conan::serve::set_judge_wait_ms(600);
    let h = harness().await;
    let names: Vec<String> = (0..30).map(|n| format!("pkg{n}")).collect();
    for name in &names {
        serve_recipe(&h.registry, name, "1.0", &[(R, OLD)]);
    }
    let gate = Gate::new();
    gate_list(&h, "pkg29", &gate);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    assert_eq!(search(&h.server).await.status().as_u16(), 504, "judging is slower than the deadline");
    let fast: usize = (0..29).map(|n| lists_of(&h, &format!("pkg{n}"))).sum();
    assert_eq!(fast, 29, "each list was read once");
    gate.release();
    gate.release();
    // (Past the 5 s the lists are shared for: only the verdicts of the first attempt can spare the retry its reads.)
    h.clock.advance_seconds(10);
    let again = search(&h.server).await;
    assert_eq!(again.status().as_u16(), 200);
    let listed = serde_json::from_str::<serde_json::Value>(&again.text().await.unwrap()).unwrap()["results"].as_array().unwrap().len();
    assert_eq!(listed, 30);
    let fast_after: usize = (0..29).map(|n| lists_of(&h, &format!("pkg{n}"))).sum();
    assert_eq!(fast_after, 29, "the retry read none of the lists the first attempt had judged");
    probation::conan::serve::set_judge_wait_ms(100_000);
}

/// Two searches at once make each verdict once (the second joins the first's work), and searches are bounded per registry.
#[tokio::test]
async fn simultaneous_searches_share_the_work_and_are_bounded() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let names: Vec<String> = (0..4).map(|n| format!("duo{n}")).collect();
    for name in &names {
        serve_recipe(&h.registry, name, "1.0", &[(R, OLD)]);
    }
    let gate = Gate::new();
    gate_list(&h, "duo3", &gate);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    let first = { let s = Arc::clone(&h.server); tokio::spawn(async move { search(&s).await.status().as_u16() }) };
    gate.wait_until_reached().await;
    let others: Vec<_> = (0..3).map(|_| { let s = Arc::clone(&h.server); tokio::spawn(async move { search(&s).await.status().as_u16() }) }).collect();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(lists_of(&h, "duo3"), 1, "four searches, one read of the list they all wait for");
    // The fifth search of the registry is refused (4 may judge at once).
    assert_eq!(search(&h.server).await.status().as_u16(), 503);
    gate.release();
    assert_eq!(first.await.unwrap(), 200);
    for other in others {
        assert_eq!(other.await.unwrap(), 200);
    }
}

/// An install is never queued behind judging: at most two lists of a registry are judged at once, the other fetch places stay free.
#[tokio::test]
async fn judging_leaves_fetch_places_for_installs() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let names: Vec<String> = (0..40).map(|n| format!("slow{n}")).collect();
    let gate = Gate::new();
    for name in &names {
        gate_list(&h, name, &gate);
    }
    serve_recipe(&h.registry, "fast", "1.0", &[(R, OLD)]);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    let judging = { let s = Arc::clone(&h.server); tokio::spawn(async move { search(&s).await.status().as_u16() }) };
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let started: usize = names.iter().map(|name| lists_of(&h, name)).sum();
    assert_eq!(started, 16, "a process judges 16 lists at once (half of max_upstream_requests), in lanes of its own, not more");
    // every judging lane is busy and the registry's four fetch places and half the upstream slots are free: an install's list is answered at once
    let started_at = std::time::Instant::now();
    assert_eq!(h.server.get("/conan/v2/conans/fast/1.0/_/_/revisions").await.status().as_u16(), 200, "an install's list is answered meanwhile");
    assert!(started_at.elapsed() < std::time::Duration::from_secs(5), "{:?}", started_at.elapsed());
    for _ in 0..40 {
        gate.release();
    }
    assert_eq!(judging.await.unwrap(), 200);
}

/// Memory: the lists decoded at once (a big one is several times its size) are bounded process-wide.
#[tokio::test]
async fn big_lists_are_decoded_a_few_at_a_time() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    for n in 0..12 {
        let mut body = String::from("{\"revisions\":[");
        for i in 0..15_000 {
            if i > 0 {
                body.push(',');
            }
            body.push_str(&format!("{{\"revision\":\"{n:02x}{i:07x}\"}}"));
        }
        body.push_str("]}");
        assert!(body.len() > 256 << 10);
        h.registry.answer(&at(&format!("{}/revisions", base(&format!("big{n}"), "1.0"))), FakeAnswer::Body(body));
    }
    let joins: Vec<_> = (0..12).map(|n| { let s = Arc::clone(&h.server); tokio::spawn(async move { s.get(&format!("/conan/v2/conans/big{n}/1.0/_/_/revisions")).await.status().as_u16() }) }).collect();
    for join in joins {
        assert_eq!(join.await.unwrap(), 200);
    }
    assert!(probation::conan::serve::peak_big() <= 4, "at most four big lists were in memory at once: {}", probation::conan::serve::peak_big());
}

/// R8: a policy published while a search judges wins: nothing it blocks is listed, whatever was judged before it.
#[tokio::test]
async fn a_block_published_mid_search_wins() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let names: Vec<String> = (0..3).map(|n| format!("mid{n}")).collect();
    for name in &names {
        serve_recipe(&h.registry, name, "1.0", &[(R, OLD)]);
    }
    let gate = Gate::new();
    gate_list(&h, "mid2", &gate);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    let judging = { let s = Arc::clone(&h.server); tokio::spawn(async move { serde_json::from_str::<serde_json::Value>(&search(&s).await.text().await.unwrap()).unwrap() }) };
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let blocked = common::snapshot(2, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", r#"{"ecosystem":"conan","name":"mid0","version":null,"reason":"malware"}"#);
    common::publish_blocklist(&h.server, &blocked, common::parse_rfc3339(NOW));
    gate.release();
    let answer = judging.await.unwrap();
    let listed: Vec<&str> = answer["results"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
    assert!(!listed.contains(&"mid0/1.0@_/_") && listed.contains(&"mid1/1.0@_/_") && listed.contains(&"mid2/1.0@_/_"), "{listed:?}");
}

/// R4: one unreadable list withholds its reference (reported in a header) and the others are served; a remote that is down fails the search.
#[tokio::test]
async fn an_unreadable_list_withholds_its_reference_and_a_failing_remote_fails_the_search() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    serve_recipe(&h.registry, "good", "1.0", &[(R, OLD)]);
    h.registry.answer(&at(&format!("{}/revisions", base("gone", "1.0"))), FakeAnswer::Missing);
    h.registry.answer(&at(&format!("{}/revisions", base("junk", "1.0"))), FakeAnswer::Body("not json".into()));
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&["good".into(), "gone".into(), "junk".into()])));
    let answer = search(&h.server).await;
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(answer.headers()["x-probation-withheld"], "2");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&answer.text().await.unwrap()).unwrap()["results"], serde_json::json!(["good/1.0@_/_"]));
    h.registry.answer(&at(&format!("{}/revisions", base("down", "1.0"))), FakeAnswer::Fail(probation::upstream::UpstreamError::Status(503)));
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&["good".into(), "down".into()])));
    assert_eq!(search(&h.server).await.status().as_u16(), 502);
}


fn big_search_doc(prefix: &str, n: usize) -> String {
    let mut names = vec![format!("{prefix}gated")];
    names.extend((0..n).map(|i| format!("{prefix}x{i}")));
    refs(&names)
}

/// N1: the big-decode permit is held for the decode only. Four searches with a big document, all waiting on a slow list, never keep a big
/// revision list (or anything else) waiting for a permit.
#[tokio::test]
async fn big_document_searches_waiting_on_a_slow_list_do_not_hold_up_a_big_list() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let gate = Gate::new();
    gate_list(&h, "ugated", &gate);
    // 12,000 references (about 400 KB, a big document); all but one are answered "not found" at once and withheld.
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(big_search_doc("u", 12_000)));
    let searches: Vec<_> = (0..4).map(|_| { let s = Arc::clone(&h.server); tokio::spawn(async move { search(&s).await.status().as_u16() }) }).collect();
    gate.wait_until_reached().await;
    let mut body = String::from("{\"revisions\":[");
    for i in 0..15_000 {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!("{{\"revision\":\"{i:09x}\"}}"));
    }
    body.push_str("]}");
    h.registry.answer(&at(&format!("{}/revisions", base("biglist", "1.0"))), FakeAnswer::Body(body));
    let started = std::time::Instant::now();
    assert_eq!(h.server.get("/conan/v2/conans/biglist/1.0/_/_/revisions").await.status().as_u16(), 200);
    assert!(started.elapsed() < std::time::Duration::from_secs(25), "a big list is not kept waiting for a permit by the searches: {:?}", started.elapsed());
    gate.release();
    for search in searches {
        let _ = search.await;
    }
}

/// N3: one search holds its result strings and one batch, not a tree of the document: 12,000 references (a big document) of which one list is
/// readable are answered in batches, the others withheld and counted.
#[tokio::test]
async fn a_search_of_many_unreadable_references_is_answered_in_batches() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    serve_recipe(&h.registry, "keep", "1.0", &[(R, OLD)]);
    let mut names = vec!["keep".to_owned()];
    names.extend((0..12_000).map(|i| format!("w{i}")));
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    let answer = search(&h.server).await;
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(answer.headers()["x-probation-withheld"], "12000");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&answer.text().await.unwrap()).unwrap()["results"], serde_json::json!(["keep/1.0@_/_"]));
}

/// One cold measurement: `count` references, each with one readable revision list, through the real store, policy and the OSV client against a
/// local OSV server, with `delay_ms` of network in front of every document the registry answers. Returns (status, listed, verdicts, seconds).
async fn measure_cold(count: usize, delay_ms: u64) -> (u16, usize, usize, f64) {
    probation::conan::serve::set_judge_wait_ms(1_800_000);
    let (osv_url, _osv) = common::osv_flagging(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    let server = Arc::new(TestServer::start_with_upstream_and_osv(common::config_with_open_blocklist(dir.path()), Arc::new(probation::clock::SystemClock), Arc::clone(&registry) as Arc<dyn Transport>, origins(), reqwest::Client::new(), osv_url).await);
    let names: Vec<String> = (0..count).map(|n| format!("cc{n}")).collect();
    for name in &names {
        serve_recipe(&registry, name, "1.0", &[(R, OLD)]);
    }
    registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    registry.set_delay_ms(delay_ms);
    let started = std::time::Instant::now();
    let answer = search(&server).await;
    let took = started.elapsed().as_secs_f64();
    let status = answer.status().as_u16();
    let listed = serde_json::from_str::<serde_json::Value>(&answer.text().await.unwrap()).map(|v| v["results"].as_array().map_or(0, Vec::len)).unwrap_or(0);
    let made = probation::conan::serve::verdict_count(&server.app());
    probation::conan::serve::set_judge_wait_ms(100_000);
    (status, listed, made, took)
}

/// M1, the measurement (run it with `--ignored --nocapture`): a ConanCenter-sized search (9,000 references) at 0, 50, 100 and 200 ms of network
/// per document. It prints one line per delay.
#[tokio::test]
#[ignore = "a measurement, not a check: cargo test --test conan_judging nine_thousand -- --ignored --nocapture"]
async fn nine_thousand_references_cold_measurement() {
    let _serial = SERIAL.lock().await;
    for delay in [0, 50, 100, 200] {
        let (status, listed, made, took) = measure_cold(9_000, delay).await;
        eprintln!("MEASURED delay_ms={delay} status={status} listed={listed} verdicts_made={made} seconds={took:.1} verdicts_per_second={:.1}", made as f64 / took);
    }
}

/// M1 as a check: a registry 100 ms away and a 1,500-reference search that does not fit one attempt (the attempt ends after 3 s) is answered
/// by a short sequence of retries, each continuing from the verdicts the earlier ones made (they are renewed when read, so they outlive the
/// sequence). The sequence is bounded, not endless.
#[tokio::test]
async fn a_search_too_large_for_one_attempt_converges_over_retries_at_100_ms() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let names: Vec<String> = (0..1_500).map(|n| format!("far{n}")).collect();
    for name in &names {
        serve_recipe(&h.registry, name, "1.0", &[(R, OLD)]);
    }
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    h.registry.set_delay_ms(100);
    probation::conan::serve::set_judge_wait_ms(3_000);
    let mut attempts = 0;
    let mut status = 0;
    while status != 200 && attempts < 8 {
        attempts += 1;
        status = search(&h.server).await.status().as_u16();
        // (the attempts come a minute apart: a verdict not renewed by the next attempt reading it would be gone by the third)
        h.clock.advance_seconds(70);
    }
    probation::conan::serve::set_judge_wait_ms(100_000);
    assert_eq!(status, 200, "converged after {attempts} attempts");
    assert!(attempts <= 6, "{attempts}");
    assert!(h.registry.calls().iter().filter(|u| u.path().ends_with("/revisions")).count() < 1_500 * 2, "nothing was fetched twice over");
}

/// N2 as a check (the measurement above is the number): a search of 3,000 readable references, cold, is judged in a few seconds (a verdict
/// costs one read of the store, not a commit), far inside the 60 s a Conan client waits.
#[tokio::test]
async fn a_search_of_three_thousand_references_is_judged_quickly() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let names: Vec<String> = (0..3_000).map(|n| format!("fast{n}")).collect();
    for name in &names {
        serve_recipe(&h.registry, name, "1.0", &[(R, OLD)]);
    }
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    let started = std::time::Instant::now();
    let answer = search(&h.server).await;
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&answer.text().await.unwrap()).unwrap()["results"].as_array().unwrap().len(), 3_000);
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "{:?}", started.elapsed());
}

/// Resident memory (VmRSS) and its high-water mark (VmHWM) of this process, in KiB. A measurement starts by resetting the mark; the corpus is
/// built with exact capacities and no big temporaries, so that what a request allocates is not hidden by freed heap that stays resident.
fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with(field)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap()
}
fn reset_peak() -> u64 {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    status_kib("VmRSS:")
}
fn peak_above(start: u64) -> u64 {
    status_kib("VmHWM:").saturating_sub(start)
}

/// The memory of searches (a measurement; `--ignored --nocapture`): a document of 500,000 references, 20,000 of them readable (so the answer is
/// not empty), searched by one request and, on a fresh process state, by four at once, both cold.
#[tokio::test]
#[ignore = "a measurement: cargo test --test conan_judging memory_of_half -- --ignored --nocapture"]
async fn memory_of_half_a_million_entry_searches() {
    let _serial = SERIAL.lock().await;
    probation::conan::serve::set_judge_wait_ms(1_800_000);
    for concurrent in [1usize, 4] {
        let h = harness().await;
        for n in 0..20_000 {
            serve_recipe(&h.registry, &format!("m{n}"), "1.0", &[(R, OLD)]);
        }
        let mut doc = String::with_capacity(12_000_000);
        doc.push_str("{\"results\":[");
        for n in 0..500_000 {
            if n > 0 {
                doc.push(',');
            }
            doc.push_str(&format!("\"m{n}/1.0@_/_\""));
        }
        doc.push_str("]}");
        eprintln!("document bytes {}", doc.len());
        h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(doc));
        let start = reset_peak();
        let started: Vec<_> = (0..concurrent).map(|_| { let s = Arc::clone(&h.server); tokio::spawn(async move { let a = s.get("/conan/v2/conans/search?q=*").await; let code = a.status().as_u16(); (code, serde_json::from_str::<serde_json::Value>(&a.text().await.unwrap()).map_or(0, |v| v["results"].as_array().map_or(0, Vec::len))) }) }).collect();
        let mut answers = Vec::new();
        for s in started {
            answers.push(s.await.unwrap());
        }
        eprintln!("MEMORY {concurrent} concurrent cold: answers (status, listed)={answers:?} heap above start peak_kib={}", peak_above(start));
    }
    probation::conan::serve::set_judge_wait_ms(100_000);
}

/// M2: a package search is decoded typed and judged in batches too: 100,000 package ids, mostly readable, are answered within a bound of
/// resident memory (peak RSS measured: see the evidence; the bound here is generous, the ignored test below measures 500,000).
async fn package_search_peak(ids: usize, compact: bool) -> (u64, usize, usize) {
    probation::conan::serve::set_judge_wait_ms(1_800_000);
    let h = harness().await;
    serve_recipe(&h.registry, "pk", "1.0", &[(R, OLD)]);
    let info = if compact { "{}" } else { r#"{"settings":{"os":"Linux","arch":"x86_64","build_type":"Release"},"options":{"shared":"False","fPIC":"True"},"requires":[]}"# };
    let mut doc = String::with_capacity(ids * (info.len() + 46) + 2);
    doc.push('{');
    for n in 0..ids {
        if n > 0 {
            doc.push(',');
        }
        doc.push_str(&format!("\"{n:040x}\":{info}"));
    }
    doc.push('}');
    let bytes = doc.len();
    h.registry.answer(&at(&format!("{}/revisions/{R}/search", base("pk", "1.0"))), FakeAnswer::Body(doc));
    // every package id has a readable list, but only the first 20,000 are served (the others are unreadable: withheld), so `kept` is not empty
    for n in 0..20_000.min(ids) {
        let id = format!("{n:040x}");
        common::conan::serve_package(&h.registry, "pk", "1.0", R, &id, &[("cccc0000000000000000000000000001", OLD)]);
    }
    let start = reset_peak();
    let answer = h.server.get(&format!("/conan/v2/conans/pk/1.0/_/_/revisions/{R}/search")).await;
    let status = answer.status().as_u16();
    let kept = serde_json::from_str::<serde_json::Value>(&answer.text().await.unwrap()).map_or(0, |v| v.as_object().map_or(0, |m| m.len()));
    let peak = peak_above(start);
    probation::conan::serve::set_judge_wait_ms(100_000);
    assert_eq!(status, 200);
    (peak, kept, bytes)
}

#[tokio::test]
async fn a_package_search_of_a_hundred_thousand_ids_is_answered_within_a_memory_bound() {
    let _serial = SERIAL.lock().await;
    let (peak, kept, bytes) = package_search_peak(100_000, false).await;
    eprintln!("MEMORY package search 100000 ids ({bytes} bytes): heap above start peak_kib={peak} kept={kept}");
    assert!(kept > 0, "{kept}");
    assert!(peak < 400 * 1024, "peak {peak} KiB");
}

/// The most ids a package search document holds: 16 MiB of `"<40 hex>":{}` is about 360,000 (the 500,000 bound is the entry bound; the byte
/// bound is reached first).
#[tokio::test]
#[ignore = "a measurement: cargo test --test conan_judging memory_of_the_largest -- --ignored --nocapture"]
async fn memory_of_the_largest_package_search() {
    let _serial = SERIAL.lock().await;
    let (peak, kept, bytes) = package_search_peak(360_000, true).await;
    eprintln!("MEMORY package search 360000 ids ({bytes} bytes): heap above start peak_kib={peak} kept={kept}");
}

async fn rows_of(h: &H, name: &str) -> u64 {
    h.server.app().store().count_project_references_in(0, probation_policy::Ecosystem::Conan, name).await.unwrap()
}

/// L3 and the anchor: a search writes no row, whether the remote dates the revisions or not; the first list read after it writes the anchor
/// rows (a remote that later reports an earlier time is held to the date first stored), and an undated revision's first-seen starts there.
#[tokio::test]
async fn a_search_writes_no_row_and_the_first_list_read_after_it_writes_the_anchor() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    serve_recipe(&h.registry, "dated", "1.0", &[(R, OLD)]);
    h.registry.answer(&at(&format!("{}/revisions", base("undated", "1.0"))), FakeAnswer::Body(common::conan::revisions_doc(("reference", "undated/1.0@_/_"), &[(R, None)])));
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&["dated".into(), "undated".into()])));
    let answer = search(&h.server).await;
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(rows_of(&h, "dated").await, 0, "a dated revision is judged without a row");
    assert_eq!(rows_of(&h, "undated").await, 0, "an undated one too: its first-seen starts at its first list or file request");
    for name in ["dated", "undated"] {
        assert_eq!(h.server.get(&format!("/conan/v2/conans/{name}/1.0/_/_/revisions")).await.status().as_u16(), 200);
        assert!(rows_of(&h, name).await >= 1, "{name}: the first list read writes the anchor row");
    }
}

/// M1, the retry sequence with the production 100 s deadline (`--ignored --nocapture`): 9,000 references, registry 200 ms away; one line per
/// attempt until the search is answered.
#[tokio::test]
#[ignore = "a measurement: cargo test --test conan_judging retry_sequence -- --ignored --nocapture"]
async fn retry_sequence_at_200_ms_with_the_production_deadline() {
    let _serial = SERIAL.lock().await;
    let (osv_url, _osv) = common::osv_flagging(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    let server = Arc::new(TestServer::start_with_upstream_and_osv(common::config_with_open_blocklist(dir.path()), Arc::new(probation::clock::SystemClock), Arc::clone(&registry) as Arc<dyn Transport>, origins(), reqwest::Client::new(), osv_url).await);
    let names: Vec<String> = (0..9_000).map(|n| format!("rs{n}")).collect();
    for name in &names {
        serve_recipe(&registry, name, "1.0", &[(R, OLD)]);
    }
    registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    registry.set_delay_ms(200);
    let total = std::time::Instant::now();
    for attempt in 1..=6 {
        let started = std::time::Instant::now();
        let status = search(&server).await.status().as_u16();
        eprintln!("RETRY attempt={attempt} status={status} seconds={:.1} verdicts={} total_seconds={:.1}", started.elapsed().as_secs_f64(), probation::conan::serve::verdict_count(&server.app()), total.elapsed().as_secs_f64());
        if status == 200 {
            break;
        }
    }
}

/// A search that finishes renews nothing: polling a search does not keep a verdict alive past its two minutes (an OSV change or a hold that
/// ends shows within two minutes, however often a client searches).
#[tokio::test]
async fn polling_a_finished_search_does_not_keep_its_verdicts_alive() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    serve_recipe(&h.registry, "fresh", "1.0", &[(R, OLD)]);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&["fresh".into()])));
    assert_eq!(search(&h.server).await.status().as_u16(), 200);
    h.clock.advance_seconds(100);
    assert_eq!(search(&h.server).await.status().as_u16(), 200);
    assert_eq!(lists_of(&h, "fresh"), 1, "inside its two minutes the verdict is read, not made again");
    h.clock.advance_seconds(30);
    assert_eq!(search(&h.server).await.status().as_u16(), 200);
    assert_eq!(lists_of(&h, "fresh"), 2, "the second search did not renew it: 130 s after it was made it is judged again");
}


/// R4-1: a client that gives up (its own timeout, well before the server's deadline) leaves the retry the verdicts the attempt made, and the
/// retries renew them: a search too large for one attempt converges although every attempt is abandoned and they come 30 s apart (a verdict
/// not renewed would be gone after four).
#[tokio::test]
async fn an_abandoned_search_converges_over_retries_at_100_ms() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let names: Vec<String> = (0..1_500).map(|n| format!("ab{n}")).collect();
    for name in &names {
        serve_recipe(&h.registry, name, "1.0", &[(R, OLD)]);
    }
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&names)));
    h.registry.set_delay_ms(100);
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_millis(1_500)).build().unwrap();
    let mut attempts = 0;
    let mut status = 0;
    while status != 200 && attempts < 20 {
        attempts += 1;
        status = client.get(h.server.url("/conan/v2/conans/search?q=*")).send().await.map_or(0, |r| r.status().as_u16());
        h.clock.advance_seconds(30);
    }
    assert_eq!(status, 200, "converged after {attempts} attempts");
}

/// R4-1: an attempt that finishes clears the unfinished mark: polling after it renews nothing (the 504 or the abort arms the renewal for
/// the retry only).
#[tokio::test]
async fn a_finished_attempt_ends_the_renewal_an_abandoned_one_started() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    serve_recipe(&h.registry, "late", "1.0", &[(R, OLD)]);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&["late".into()])));
    h.registry.set_delay_ms(600);
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_millis(300)).build().unwrap();
    assert!(client.get(h.server.url("/conan/v2/conans/search?q=*")).send().await.is_err(), "the client gave up");
    assert_eq!(search(&h.server).await.status().as_u16(), 200);
    let made = lists_of(&h, "late");
    h.clock.advance_seconds(100);
    assert_eq!(search(&h.server).await.status().as_u16(), 200);
    h.clock.advance_seconds(30);
    assert_eq!(search(&h.server).await.status().as_u16(), 200);
    assert_eq!(lists_of(&h, "late"), made + 1, "the poll inside the old window renewed nothing: the verdict was judged again");
}

/// The undated revision a search could never list: once its row exists (a list or file request wrote it) and the cooldown has passed, a
/// search lists it, by the row's first-seen.
#[tokio::test]
async fn a_search_lists_an_undated_revision_once_its_row_is_old_enough() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(&blocklist, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "")).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.cooldown_seconds = 86_400;
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339(NOW);
    let server = Arc::new(TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await);
    registry.answer(&at(&format!("{}/revisions", base("nodate", "1.0"))), FakeAnswer::Body(common::conan::revisions_doc(("reference", "nodate/1.0@_/_"), &[(R, None)])));
    registry.answer(&at("v2/conans/search"), FakeAnswer::Body(refs(&["nodate".into()])));
    let listed = |body: String| serde_json::from_str::<serde_json::Value>(&body).unwrap()["results"].as_array().unwrap().len();
    assert_eq!(listed(search(&server).await.text().await.unwrap()), 0, "undated and unseen: held by the cooldown");
    // (a list request writes the row, first seen now; the client is told the hold)
    let _ = server.get("/conan/v2/conans/nodate/1.0/_/_/revisions").await;
    // (the process forgets the package, as after an eviction or a restart: its row is all that is left)
    for n in 0..300 {
        let _ = server.get(&format!("/conan/v2/conans/forget{n}/1.0/_/_/revisions")).await;
    }
    clock.advance_seconds(2 * 86_400);
    assert_eq!(listed(search(&server).await.text().await.unwrap()), 1, "its row is two days old: listed");
}

/// R5-2: a request that is refused before judging starts (a blocked recipe, a 404) arms no renewal for the registry: only a search that began
/// to judge and stopped does.
#[tokio::test]
async fn a_search_refused_before_judging_arms_nothing() {
    let _serial = SERIAL.lock().await;
    let h = harness().await;
    let blocked = common::snapshot(2, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", r#"{"ecosystem":"conan","name":"blk","version":null,"reason":"malware"}"#);
    common::publish_blocklist(&h.server, &blocked, common::parse_rfc3339(NOW));
    let package_search = format!("/conan/v2/conans/blk/1.0/_/_/revisions/{R}/search");
    assert_eq!(h.server.get(&package_search).await.status().as_u16(), 403);
    assert_eq!(h.server.get(&format!("/conan/v2/conans/nothere/1.0/_/_/revisions/{R}/search")).await.status().as_u16(), 404);
    assert_eq!(h.server.get("/conan/v2/conans/search?q=*").await.status().as_u16(), 404, "the remote has no search document");
    assert_eq!(probation::conan::serve::unfinished_marks(&h.server.app()), 0);
}
