//! rproxy-traefik-convert: converts a Traefik configuration into an rproxy settings
//! file (docs/MIGRATING-FROM-TRAEFIK.md). Exit code 2 when an input cannot be read
//! (or the arguments are wrong); settings that do not convert are listed on stderr
//! and in the output, with exit code 0.

use std::io::Write;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use rproxy_traefik::cli::{self, Args, Error, PROG};

fn main() -> ExitCode {
	let args = Args::parse();
	let out = match cli::run(&args) {
		Ok(out) => out,
		Err(Error::Usage(msg)) => Args::command().error(clap::error::ErrorKind::MissingRequiredArgument, msg).exit(),
		Err(Error::Input(e)) => {
			eprintln!("{PROG}: {e}");
			return ExitCode::from(2);
		}
	};
	let written = match args.output.as_deref().filter(|o| !o.is_empty()) {
		Some(path) => std::fs::write(path, &out.text).map_err(|e| format!("{path}: {e}")),
		None => std::io::stdout().write_all(out.text.as_bytes()).map_err(|e| e.to_string()),
	};
	if let Err(e) = written {
		eprintln!("{PROG}: {e}");
		return ExitCode::from(1);
	}
	for n in &out.notes {
		eprintln!("{PROG}: {n}");
	}
	ExitCode::SUCCESS
}
