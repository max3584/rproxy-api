//! The converter against the expected outputs in tests/fixtures/traefik/ (the
//! repository's): every directory there has a `cases` file, one case per line
//! (`<name> <arguments…>`, paths relative to the directory), and for each case the
//! output it must write byte for byte (`expected.yaml` for `default`,
//! `expected.<name>.yaml` / `.json` otherwise) and its notes on stderr
//! (`expected[.<name>].notes`). The first expected outputs came from the Python
//! converter this crate replaces (contrib/traefik2rproxy.py, v0.4.7), so they hold
//! the two to the same behaviour; tests/fixtures/traefik/README.md tells how to add a
//! case.
//!
//! `RPROXY_TRAEFIK_BLESS=1` writes the expected files from this converter instead
//! of comparing (for a new case; check what it wrote).

use std::path::{Path, PathBuf};
use std::process::Command;

const PREFIX: &str = "rproxy-traefik-convert: ";

fn fixtures() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/traefik")
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
	Command::new(env!("CARGO_BIN_EXE_rproxy-traefik-convert")).args(args).current_dir(dir).output().unwrap()
}

#[test]
fn expected_outputs() {
	let bless = std::env::var_os("RPROXY_TRAEFIK_BLESS").is_some();
	let mut dirs: Vec<PathBuf> = std::fs::read_dir(fixtures()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect();
	dirs.sort();
	let mut checked = 0;
	let mut failures = vec![];
	for dir in dirs {
		let cases = std::fs::read_to_string(dir.join("cases"))
			.unwrap_or_else(|_| panic!("{}: no cases file (tests/fixtures/traefik/README.md)", dir.display()));
		for line in cases.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
			let mut words = line.split_whitespace();
			let name = words.next().unwrap();
			let args: Vec<&str> = words.collect();
			let stem = if name == "default" { "expected".to_string() } else { format!("expected.{name}") };
			let ext = if args.contains(&"--json") { "json" } else { "yaml" };
			let out = run(&dir, &args);
			let stderr = String::from_utf8(out.stderr).unwrap();
			assert!(out.status.success(), "{} {name}: {stderr}", dir.display());
			let stdout = String::from_utf8(out.stdout).unwrap();
			let notes: String = stderr
				.lines()
				.map(|l| format!("{}\n", l.strip_prefix(PREFIX).unwrap_or_else(|| panic!("stderr line without the prefix: {l}"))))
				.collect();
			let (out_path, notes_path) = (dir.join(format!("{stem}.{ext}")), dir.join(format!("{stem}.notes")));
			if bless {
				std::fs::write(&out_path, &stdout).unwrap();
				std::fs::write(&notes_path, &notes).unwrap();
				continue;
			}
			let want = std::fs::read_to_string(&out_path).unwrap_or_else(|e| panic!("{}: {e}", out_path.display()));
			let want_notes = std::fs::read_to_string(&notes_path).unwrap_or_else(|e| panic!("{}: {e}", notes_path.display()));
			if stdout != want {
				failures.push(format!("{}:\n{}", out_path.display(), diff(&want, &stdout)));
			}
			if notes != want_notes {
				failures.push(format!("{}:\n{}", notes_path.display(), diff(&want_notes, &notes)));
			}
			checked += 1;
		}
	}
	assert!(failures.is_empty(), "{}", failures.join("\n"));
	assert!(bless || checked >= 10, "only {checked} cases");
}

/// The first lines that differ, with a little context.
fn diff(want: &str, got: &str) -> String {
	let (w, g): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
	let first = w.iter().zip(&g).position(|(a, b)| a != b).unwrap_or(w.len().min(g.len()));
	let from = first.saturating_sub(2);
	let mut out = String::new();
	for i in from..(first + 4).min(w.len().max(g.len())) {
		match (w.get(i), g.get(i)) {
			(Some(a), Some(b)) if a == b => out.push_str(&format!("   {a}\n")),
			(a, b) => {
				if let Some(a) = a {
					out.push_str(&format!(" - {a}\n"));
				}
				if let Some(b) = b {
					out.push_str(&format!(" + {b}\n"));
				}
			}
		}
	}
	out
}

#[test]
fn exit_codes_and_files() {
	let dir = fixtures().join("failover");
	// no input
	let out = run(&dir, &[]);
	assert_eq!(out.status.code(), Some(2));
	assert!(String::from_utf8_lossy(&out.stderr).contains("give --static, --dynamic or --docker"));
	// an input that cannot be read
	let out = run(&dir, &["--static", "missing.yml"]);
	assert_eq!(out.status.code(), Some(2));
	assert!(String::from_utf8_lossy(&out.stderr).starts_with(&format!("{PREFIX}missing.yml: ")));
	let out = run(&dir, &["--static", "cases"]);
	assert_eq!(out.status.code(), Some(2));
	assert!(String::from_utf8_lossy(&out.stderr).contains("unknown file type"));
	// a wrong flag value
	assert_eq!(run(&dir, &["--static", "traefik.yml", "--certs", "lego"]).status.code(), Some(2));
	// -o writes the file, notes still on stderr
	let tmp = std::env::temp_dir().join(format!("rproxy-traefik-convert-{}.yaml", std::process::id()));
	let out = run(&dir, &["--static", "traefik.yml", "-o", tmp.to_str().unwrap()]);
	assert!(out.status.success());
	assert!(out.stdout.is_empty());
	assert!(String::from_utf8_lossy(&out.stderr).contains("failover service app"));
	assert_eq!(std::fs::read_to_string(&tmp).unwrap(), std::fs::read_to_string(dir.join("expected.yaml")).unwrap());
	std::fs::remove_file(tmp).unwrap();
}
