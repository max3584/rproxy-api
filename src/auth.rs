use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

/// Bearer tokens read from a file, one per line. Several may be valid at once so
/// that a token can be rotated without a gap.
pub struct Tokens {
	path: Option<PathBuf>,
	tokens: RwLock<Vec<String>>,
}

fn read_tokens(path: &PathBuf) -> io::Result<Vec<String>> {
	let tokens: Vec<String> = std::fs::read_to_string(path)?
		.lines()
		.map(str::trim)
		.filter(|l| !l.is_empty() && !l.starts_with('#'))
		.map(String::from)
		.collect();
	if tokens.is_empty() {
		return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: no tokens", path.display())));
	}
	Ok(tokens)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Tokens {
	/// No token file: every request is allowed.
	pub fn disabled() -> Self {
		Tokens { path: None, tokens: RwLock::default() }
	}

	pub fn from_file(path: PathBuf) -> io::Result<Self> {
		let tokens = read_tokens(&path)?;
		Ok(Tokens { path: Some(path), tokens: RwLock::new(tokens) })
	}

	pub fn enabled(&self) -> bool {
		self.path.is_some()
	}

	/// Re-reads the token file; on error the current tokens stay in effect.
	pub fn reload(&self) -> io::Result<usize> {
		let Some(path) = &self.path else { return Ok(0) };
		let tokens = read_tokens(path)?;
		let count = tokens.len();
		*self.tokens.write().unwrap() = tokens;
		Ok(count)
	}

	/// Checks an `Authorization` header value.
	pub fn allows(&self, header: Option<&str>) -> bool {
		if !self.enabled() {
			return true;
		}
		let Some(presented) = header.and_then(|h| h.strip_prefix("Bearer ")).map(str::trim) else {
			return false;
		};
		// check every token so the time taken does not reveal which one matched
		self.tokens
			.read()
			.unwrap()
			.iter()
			.fold(false, |ok, t| constant_time_eq(t.as_bytes(), presented.as_bytes()) | ok)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rotates_tokens() {
		let dir = std::env::temp_dir().join(format!("rproxy-auth-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let file = dir.join("tokens");
		std::fs::write(&file, "# comment\nold\nnew\n").unwrap();

		let tokens = Tokens::from_file(file.clone()).unwrap();
		assert!(tokens.allows(Some("Bearer old")));
		assert!(tokens.allows(Some("Bearer new")));
		assert!(!tokens.allows(Some("Bearer nope")));
		assert!(!tokens.allows(Some("old")));
		assert!(!tokens.allows(None));

		std::fs::write(&file, "new\n").unwrap();
		assert_eq!(tokens.reload().unwrap(), 1);
		assert!(!tokens.allows(Some("Bearer old")));

		std::fs::write(&file, "\n").unwrap();
		assert!(tokens.reload().is_err());
		assert!(tokens.allows(Some("Bearer new")), "a bad file keeps the current tokens");
		std::fs::remove_dir_all(dir).unwrap();
	}

	#[test]
	fn disabled_allows_all() {
		assert!(Tokens::disabled().allows(None));
	}
}
