//! Row 17: the real native clients (RubyGems `gem` 3.6 and Bundler 2.5 on Ruby 3.3) against
//! the firewall on a real TCP port, with real gem files, real tuple indexes and real quick
//! gemspecs built by Ruby itself. Only the upstream is an in-process fake.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Uri};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::upstream::{OriginKind, OriginSet, Transport};
use sha2::{Digest, Sha256};
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn origins() -> OriginSet {
    fake_origins().with_rubygems(Url::parse("https://rubygems.invalid").unwrap())
}

fn path(segments: &[&str]) -> String {
    origins().url_for(OriginKind::RubygemsMetadata, segments).unwrap().path().to_owned()
}

const BUILD: &str = r#"
require 'rubygems/package'
require 'zlib'
require 'fileutils'
dir = ARGV[0]
specs = []
%w[1.0.0 2.0.0].each do |v|
  FileUtils.mkdir_p(File.join(dir, "src-#{v}", "lib"))
  File.write(File.join(dir, "src-#{v}", "lib", "demo.rb"), "module Demo; VERSION = '#{v}'; end\n")
  spec = Gem::Specification.new do |s|
    s.name = 'demo'; s.version = v; s.summary = 'demo'; s.authors = ['probation']; s.files = ['lib/demo.rb']; s.require_paths = ['lib']
    s.add_runtime_dependency 'rake', '>= 1' if v == '2.0.0'
  end
  Dir.chdir(File.join(dir, "src-#{v}")) { Gem::Package.build(spec) }
  FileUtils.cp(File.join(dir, "src-#{v}", "demo-#{v}.gem"), dir)
  File.binwrite(File.join(dir, "demo-#{v}.gemspec.rz"), Gem.deflate(Marshal.dump(spec)))
  specs << ['demo', spec.version, 'ruby']
end
gz = ->(name, data) { Zlib::GzipWriter.open(File.join(dir, name)) { |g| g.write(Marshal.dump(data)) } }
gz.('specs.4.8.gz', specs)
gz.('latest_specs.4.8.gz', [specs.last])
gz.('prerelease_specs.4.8.gz', [])
"#;

struct Native {
    server: TestServer,
    dir: tempfile::TempDir,
    _policy: Option<wiremock::MockServer>,
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap()
}

async fn ruby(dir: &Path, args: &[&str], env: &[(&str, String)]) -> (bool, String) {
    let dir = dir.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let env: Vec<(String, String)> = env.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
    // The proxy under test runs on this runtime, so the blocking client runs off it.
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new("ruby");
        command.args(&args).current_dir(&dir).env_remove("GEM_HOME").env_remove("GEM_PATH").env_remove("BUNDLE_GEMFILE");
        for (key, value) in &env {
            command.env(key, value);
        }
        let output = command.output().expect("ruby 3.x is the native baseline of this row");
        (output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
    })
    .await
    .unwrap()
}

/// `service`: the firewall runs as the shared service (`[service_policy]`), where nothing of a
/// caller's metadata is stored.
async fn start_in(service: bool) -> Native {
    let dir = tempfile::tempdir().unwrap();
    let (ok, log) = ruby(dir.path(), &["-e", BUILD, "--", dir.path().to_str().unwrap()], &[]).await;
    assert!(ok, "building the fixture gems: {log}");
    let sha = |name: &str| hex::encode(Sha256::digest(read(dir.path(), name)));
    let registry = FakeRegistry::new();
    registry.answer(
        &path(&["info", "demo"]),
        FakeAnswer::Body(format!(
            "---\n1.0.0 |checksum:{},created_at:{OLD}\n2.0.0 rake:>= 1|checksum:{},created_at:{YOUNG}\n",
            sha("demo-1.0.0.gem"),
            sha("demo-2.0.0.gem"),
        )),
    );
    registry.answer(&path(&["info", "rake"]), FakeAnswer::Body(format!("---\n13.0.0 |checksum:{},created_at:{OLD}\n", "00".repeat(32))));
    registry.answer(&path(&["versions"]), FakeAnswer::Body(format!("created_at: {NOW}\n---\ndemo 1.0.0,2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nrake 13.0.0 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")));
    registry.answer(&path(&["names"]), FakeAnswer::Body("---\ndemo\nrake\n".to_owned()));
    for v in ["1.0.0", "2.0.0"] {
        registry.answer(&path(&["gems", &format!("demo-{v}.gem")]), FakeAnswer::Bytes(read(dir.path(), &format!("demo-{v}.gem"))));
        registry.answer(&path(&["quick", "Marshal.4.8", &format!("demo-{v}.gemspec.rz")]), FakeAnswer::Bytes(read(dir.path(), &format!("demo-{v}.gemspec.rz"))));
    }
    // The registry's own list of versions published inside the cooldown window.
    registry.answer(&path(&["api", "v1", "timeframe_versions.json"]), FakeAnswer::Body(format!(r#"[{{"name":"demo","number":"2.0.0","platform":"ruby","version_created_at":"{YOUNG}"}}]"#)));
    for index in ["specs.4.8.gz", "latest_specs.4.8.gz", "prerelease_specs.4.8.gz"] {
        registry.answer(&path(&[index]), FakeAnswer::Bytes(read(dir.path(), index)));
    }
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(&blocklist, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "")).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.cooldown_seconds = 7 * 86_400;
    let clock = TestClock::at_rfc3339(NOW);
    let mut policy_server = None;
    if service {
        use probation::config::{FirewallToken, ServicePolicyConfig};
        use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
        let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
        let snapshot = ServicePolicySnapshot {
            version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
            place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
            layers: places.iter().map(|place| PlaceLayer {
                place: *place,
                layer: Layer { freeze_seconds: Some(7 * 86_400), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
                revision: 1,
            }).collect(),
            rate_limit: None, rate_limit_source: LimitSource::Default,
            registries: vec![RegistryDescriptor {
                registry: RegistryId(5), ecosystem: probation_policy::Ecosystem::RubyGems, target_url: None, trusted: false,
                registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None, token_origin: None,
            }],
        };
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET")).and(wiremock::matchers::path("/api/v1/policy/snapshot"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(snapshot)).mount(&mock).await;
        config.service_policy = Some(ServicePolicyConfig {
            server_url: mock.uri().parse().unwrap(),
            service_key_file: "/test/key".into(),
            service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
            sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
            trusted_proxies: vec![],
        });
        policy_server = Some(mock);
    }
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    Native { server, dir, _policy: policy_server }
}

fn env_for(home: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("GEM_HOME", home.join("gems").display().to_string()),
        ("GEM_PATH", home.join("gems").display().to_string()),
        ("HOME", home.display().to_string()),
        ("BUNDLE_APP_CONFIG", home.join("bundle").display().to_string()),
        ("BUNDLE_USER_HOME", home.join("bundle-home").display().to_string()),
    ]
}

/// Bundler's executable, found through Ruby itself. `None` (a loud skip) when this host has no
/// Ruby or no Bundler: these tests need the native clients and prove nothing without them.
fn bundle() -> Option<String> {
    let out = std::process::Command::new("ruby")
        .args(["-e", "puts File.join(Gem::Specification.find_by_name('bundler').gem_dir, 'exe', 'bundle')"])
        .output()
        .ok()?;
    let path = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (out.status.success() && std::path::Path::new(&path).is_file()).then_some(path)
}

macro_rules! need_bundler {
    () => {
        match bundle() {
            Some(path) => path,
            None => {
                eprintln!("SKIPPED: no ruby with a bundler gem on this host; the native RubyGems lane did NOT run");
                return;
            }
        }
    };
}

async fn gem_install_unwarmed(service: bool) {
    let _ = need_bundler!();
    let n = start_in(service).await;
    let source = n.server.url("/rubygems/");
    let home = tempfile::tempdir().unwrap();
    let env = env_for(home.path());
    // `demo` was never indexed by this firewall and its latest version (2.0.0) is young: the
    // client sees only what the tuple index lists, and installs the older eligible 1.0.0.
    let (ok, log) = ruby(home.path(), &["-S", "gem", "install", "demo", "--clear-sources", "--source", &source, "--no-document"], &env).await;
    assert!(ok, "gem install (service={service}): {log}");
    let (ok, listed) = ruby(home.path(), &["-S", "gem", "list", "demo"], &env).await;
    assert!(ok && listed.contains("demo (1.0.0)") && !listed.contains("2.0.0"), "service={service}: {listed}");
    n.server.shutdown().await;
    drop(n.dir);
}

#[tokio::test]
async fn native_gem_install_of_an_unseen_gem_with_a_young_latest_installs_the_older_version() {
    gem_install_unwarmed(false).await;
}

#[tokio::test]
async fn native_gem_install_of_an_unseen_gem_works_through_the_shared_service() {
    gem_install_unwarmed(true).await;
}

async fn bundler_flow(service: bool) {
    let bundle = need_bundler!();
    let n = start_in(service).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("Gemfile"), format!("source \"{}\"\ngem \"demo\"\n", n.server.url("/rubygems/"))).unwrap();
    let mut env = env_for(project.path());
    env.push(("BUNDLE_GEMFILE", project.path().join("Gemfile").display().to_string()));
    let (ok, log) = ruby(project.path(), &[&bundle, "install"], &env).await;
    assert!(ok, "bundle install: {log}");
    let lock = std::fs::read_to_string(project.path().join("Gemfile.lock")).unwrap();
    assert!(lock.contains("demo (1.0.0)") && !lock.contains("2.0.0"), "{lock}");
    let (ok, out) = ruby(project.path(), &[&bundle, "exec", "ruby", "-e", "require 'demo'; puts Demo::VERSION"], &env).await;
    assert!(ok && out.trim().ends_with("1.0.0"), "{out}");
    // A second run and `bundle update` with a populated cache: upstream's /versions checksum for
    // `demo` is the MD5 of the UNFILTERED info, which never equals the filtered file Bundler holds, so
    // it fetches `info/demo` again each run (a re-download, never a failure) and still locks 1.0.0.
    let (ok, log) = ruby(project.path(), &[&bundle, "install"], &env).await;
    assert!(ok, "second bundle install: {log}");
    let (ok, log) = ruby(project.path(), &[&bundle, "update", "demo"], &env).await;
    assert!(ok, "bundle update: {log}");
    let lock = std::fs::read_to_string(project.path().join("Gemfile.lock")).unwrap();
    assert!(lock.contains("demo (1.0.0)") && !lock.contains("2.0.0"), "{lock}");
    n.server.shutdown().await;
}

#[tokio::test]
async fn native_bundler_installs_the_eligible_version_through_the_compact_index() {
    bundler_flow(false).await;
}

#[tokio::test]
async fn native_bundler_installs_the_eligible_version_through_the_shared_service() {
    bundler_flow(true).await;
}

/// What `gem` and Bundler send on a plain read is on the allow-list of LS-F4, so reads from
/// the native clients stay cache-eligible (an unlisted header would cost hits, never safety).
#[tokio::test]
async fn rubygems_native_clients_send_only_allow_listed_headers() {
    let bundle = need_bundler!();
    let seen: Arc<Mutex<Vec<(Uri, HeaderMap)>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
        let sink = Arc::clone(&sink);
        async move {
            sink.lock().unwrap().push((uri, headers));
            axum::http::StatusCode::NOT_FOUND
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let source = format!("http://127.0.0.1:{port}/rubygems/");
    let home = tempfile::tempdir().unwrap();
    let env = env_for(home.path());
    let _ = ruby(home.path(), &["-S", "gem", "install", "nothing", "--clear-sources", "--source", &source], &env).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("Gemfile"), format!("source \"{source}\"\ngem \"nothing\"\n")).unwrap();
    let mut env = env_for(project.path());
    env.push(("BUNDLE_GEMFILE", project.path().join("Gemfile").display().to_string()));
    let _ = ruby(project.path(), &[&bundle, "install"], &env).await;
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 2, "both clients reached the tap: {}", seen.len());
    for (uri, headers) in seen.iter() {
        let class = classify_read(&RequestParts { uri, headers, extra_pseudo_headers: &[] }, &FamilyReadRules::RUBYGEMS);
        assert!(matches!(class, ReadClass::CacheEligible(_)), "a native client header is off the allow-list: {uri} {headers:?}");
    }
    let _: PathBuf = PathBuf::new();
}
