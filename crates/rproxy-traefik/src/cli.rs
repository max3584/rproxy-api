//! The command line of `rproxy-traefik-convert` (the same flags as the Python
//! converter it replaces).
//!
//! ```text
//! rproxy-traefik-convert --static /etc/traefik/traefik.yml > /etc/rproxy/rproxy.yaml
//! rproxy-traefik-convert --static traefik.toml --dynamic dynamic/ --docker inspect.json -o rproxy.yaml
//! ```

use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};

use crate::convert::{check_capabilities, convert, Certs, Options};
use crate::load::{deep_merge, load_docker, load_dynamic, load_file, InputError};
use crate::value::{g, py_str, Map, Value};
use crate::{emit, NoteSink, Notes};

/// The prefix of the lines on stderr.
pub const PROG: &str = "rproxy-traefik-convert";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CertsArg {
	Acme,
	Certbot,
}

#[derive(Debug, Parser)]
#[command(name = "rproxy-traefik-convert", about = "Convert a Traefik configuration into an rproxy settings file.")]
pub struct Args {
	/// Traefik static configuration (traefik.yml / .toml)
	#[arg(long = "static")]
	pub static_: Option<String>,
	/// dynamic configuration file or directory (repeatable; default: the file provider of --static)
	#[arg(long)]
	pub dynamic: Vec<String>,
	/// output of `docker inspect <containers...>` (JSON) to read labels from
	#[arg(long)]
	pub docker: Option<String>,
	/// write here instead of stdout
	#[arg(short, long)]
	pub output: Option<String>,
	/// address for entry points written as :port
	#[arg(long, default_value = "0.0.0.0")]
	pub listen_addr: String,
	/// routers with a certResolver: rproxy's own ACME (global.acme, default) or certbot's files
	#[arg(long, value_enum, default_value = "acme")]
	pub certs: CertsArg,
	/// with --certs certbot: where certbot keeps certificates
	#[arg(long, default_value = "/etc/letsencrypt/live")]
	pub certbot_live: String,
	/// GET /capabilities of the target rproxy (JSON file), to check what it runs
	#[arg(long)]
	pub capabilities: Option<String>,
	/// write JSON instead of YAML
	#[arg(long)]
	pub json: bool,
}

/// Why converting did not produce a document.
#[derive(Debug)]
pub enum Error {
	/// Wrong arguments (exit code 2, with the usage).
	Usage(String),
	/// An input that cannot be read (exit code 2).
	Input(InputError),
}

/// A converted document and its notes.
#[derive(Debug)]
pub struct Output {
	/// The settings file: YAML with the notes as comments at the top, or JSON.
	pub text: String,
	/// The document itself.
	pub doc: Value,
	pub notes: Vec<String>,
}

fn non_empty(s: &Option<String>) -> Option<&str> {
	s.as_deref().filter(|s| !s.is_empty())
}

/// Reads the inputs the arguments name and converts them (what the command writes,
/// without writing it).
pub fn run(args: &Args) -> Result<Output, Error> {
	let mut notes = Notes::default();
	let (doc, capabilities) = read_and_convert(args, &mut notes)?;
	check_capabilities(&doc, capabilities.as_ref(), &mut notes);
	let text = if args.json {
		emit::to_json(&doc)
	} else {
		let mut header = vec![
			"Converted from the Traefik configuration by rproxy-traefik-convert.".to_string(),
			"Check it before use; see docs/MIGRATING-FROM-TRAEFIK.md.".to_string(),
		];
		if !notes.items.is_empty() {
			header.push(String::new());
			header.push("Not converted / to check:".into());
			header.extend(notes.items.iter().map(|n| format!("- {n}")));
		}
		let mut text: String = header.iter().map(|l| format!("{}\n", format!("# {l}").trim_end())).collect();
		text.push('\n');
		text.push_str(&emit::to_yaml(&doc));
		text
	};
	Ok(Output { text, doc, notes: notes.items })
}

fn read_and_convert(args: &Args, notes: &mut Notes) -> Result<(Value, Option<Value>), Error> {
	let static_path = non_empty(&args.static_);
	let static_ = match static_path {
		Some(p) => load_file(Path::new(p)).map_err(Error::Input)?,
		None => Value::Map(Map::new()),
	};
	let mut dynamic_paths: Vec<PathBuf> = args.dynamic.iter().map(PathBuf::from).collect();
	if dynamic_paths.is_empty() {
		if let Some(p) = static_path {
			let abs = std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p));
			let base = abs.parent().map(Path::to_path_buf).unwrap_or_default();
			for key in ["filename", "directory"] {
				if let Some(path) = g(&static_, &["providers", "file", key]).filter(|v| v.truthy()) {
					let path = PathBuf::from(py_str(path));
					dynamic_paths.push(if path.is_absolute() { path } else { base.join(path) });
				}
			}
		}
	}
	let mut dynamic = Value::Map(Map::new());
	for path in &dynamic_paths {
		deep_merge(&mut dynamic, load_dynamic(path).map_err(Error::Input)?);
	}
	if let Some(docker) = non_empty(&args.docker) {
		deep_merge(&mut dynamic, load_docker(Path::new(docker), notes).map_err(Error::Input)?);
	} else if g(&static_, &["providers", "docker"]).is_some() {
		notes.note("providers.docker", "Docker labels are read only with --docker (docker inspect output)");
	}
	if static_path.is_none() && dynamic_paths.is_empty() && non_empty(&args.docker).is_none() {
		return Err(Error::Usage("give --static, --dynamic or --docker".into()));
	}
	let capabilities = match non_empty(&args.capabilities) {
		Some(p) => Some(load_file(Path::new(p)).map_err(Error::Input)?),
		None => None,
	};
	let opts = Options {
		listen_addr: args.listen_addr.clone(),
		certbot_live: args.certbot_live.clone(),
		certs: match args.certs {
			CertsArg::Acme => Certs::Acme,
			CertsArg::Certbot => Certs::Certbot,
		},
	};
	let doc = convert(&static_, &dynamic, &opts, notes).map_err(Error::Input)?;
	Ok((doc, capabilities))
}
