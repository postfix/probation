//! Row 17 (CR F9, SR17-6): `same_version` for RubyGems is Ruby's own `Gem::Version#==`,
//! checked against the real Ruby on every pair of a list of awkward spellings.

use probation_policy::Ecosystem;
use probation_policy::names::{canonical_version, same_version};

const SPELLINGS: &[&str] = &[
    "1",
    "1.0",
    "1.0.0",
    "1.00",
    "01.0",
    "1.0.0.0",
    "1.1",
    "1.0.a",
    "1.a",
    "1.0.A",
    "1.0.a.0",
    "1.0.pre",
    "1.0-pre",
    "1.0.pre.0",
    "1.0-rc1",
    "1.0.rc1",
    "1.0.RC1",
    "1.0.rc.1",
    "1.0-rc-1",
    "1.0-rc.pre",
    "1.0.pre.rc.pre.1",
    "2.0.0.beta2",
    "2.0.beta.2",
    "1.99999999999999999999999999999999999999999.0",
    "1.99999999999999999999999999999999999999999",
    "1.099999999999999999999999999999999999999999.0",
    "1.0099999999999999999999999999999999999999999",
    "10.0",
    "9.0",
    "1.0.0.1",
    "0",
    "0.0",
    "0.0.0.a",
    " 1.0 ",
    "1.0-",
    "1..0",
    ".1",
    "-1",
    "v1",
    "1.0_1",
    "1.0+1",
    "",
];

fn ruby_equal() -> Vec<String> {
    let script = r#"
      require 'rubygems'
      xs = ARGV
      xs.each do |a|
        xs.each do |b|
          ok = Gem::Version.correct?(a) && Gem::Version.correct?(b) && !a.strip.empty? && !b.strip.empty?
          puts [a, b, ok && Gem::Version.new(a) == Gem::Version.new(b)].join("\u0001")
        end
      end
      xs.each { |a| puts ["valid", a, Gem::Version.correct?(a) && !a.strip.empty?].join("\u0001") }
    "#;
    let out = std::process::Command::new("ruby")
        .args(["-e", script, "--"])
        .args(SPELLINGS)
        .output()
        .expect("ruby 3.x is the native baseline");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn gem_version_equality_matches_ruby_on_awkward_spellings() {
    for line in ruby_equal() {
        let parts: Vec<&str> = line.split('\u{1}').collect();
        if parts[0] == "valid" {
            let has = canonical_version(Ecosystem::RubyGems, parts[1]).is_some();
            assert_eq!(has, parts[2] == "true", "validity of {:?}", parts[1]);
        } else {
            let (a, b) = (parts[0], parts[1]);
            if parts[2] == "true" {
                assert!(
                    same_version(Ecosystem::RubyGems, a, b),
                    "Ruby says {a:?} == {b:?}"
                );
            } else if a != b {
                assert!(
                    !same_version(Ecosystem::RubyGems, a, b),
                    "Ruby says {a:?} != {b:?}"
                );
            }
        }
    }
}

/// No bypass by zero-padding or by a segment longer than any integer type.
#[test]
fn gem_version_segments_of_any_length_compare_without_limit() {
    let big = "9".repeat(60);
    assert!(same_version(
        Ecosystem::RubyGems,
        &format!("1.{big}"),
        &format!("1.0000{big}.0")
    ));
    assert!(!same_version(
        Ecosystem::RubyGems,
        &format!("1.{big}"),
        &format!("1.{big}1")
    ));
}
