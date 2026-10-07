//! Verifying minisign signatures (#174): the self-update runs only binaries
//! whose signature checks out against the release key.
//!
//! Formats (https://jedisct1.github.io/minisign/):
//! - public key: `untrusted comment: ...` and base64 of `Ed` + key id (8 bytes)
//!   + Ed25519 public key (32 bytes)
//! - signature: `untrusted comment: ...`, base64 of the algorithm (`Ed`: the
//!   file itself is signed, `ED`: its BLAKE2b-512 hash, minisign's default) + key
//!   id + Ed25519 signature (64 bytes), `trusted comment: ...`, and base64 of the
//!   global signature over the signature bytes and the trusted comment.
//!
//! Ed25519 is ring's; BLAKE2b-512 is below (RFC 7693; no other crate needed).

use base64::Engine as _;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A minisign public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
	pub key_id: [u8; 8],
	pub key: [u8; 32],
}

/// A parsed `.minisig` file.
#[derive(Clone, Debug)]
pub struct Signature {
	prehashed: bool,
	key_id: [u8; 8],
	signature: [u8; 64],
	trusted_comment: String,
	global_signature: [u8; 64],
}

/// The base64 line of a key or signature file: the first line that is not a comment.
fn data_lines(text: &str) -> impl Iterator<Item = &str> {
	text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
}

impl PublicKey {
	/// Reads a `minisign.pub` file (or just its base64 line).
	pub fn parse(text: &str) -> Result<PublicKey, String> {
		let line = data_lines(text).next().ok_or("empty minisign public key")?;
		let raw = B64.decode(line).map_err(|e| format!("minisign public key: {e}"))?;
		if raw.len() != 42 || &raw[..2] != b"Ed" {
			return Err("not a minisign Ed25519 public key".into());
		}
		let mut key_id = [0u8; 8];
		key_id.copy_from_slice(&raw[2..10]);
		let mut key = [0u8; 32];
		key.copy_from_slice(&raw[10..42]);
		Ok(PublicKey { key_id, key })
	}

	/// The key id as minisign prints it (hex, most significant byte first).
	pub fn id(&self) -> String {
		self.key_id.iter().rev().map(|b| format!("{b:02X}")).collect()
	}
}

impl Signature {
	pub fn parse(text: &str) -> Result<Signature, String> {
		let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
		let mut next = || lines.next().ok_or_else(|| "minisign signature: too short".to_string());
		let mut line = next()?;
		if line.starts_with("untrusted comment:") {
			line = next()?;
		}
		let raw = B64.decode(line).map_err(|e| format!("minisign signature: {e}"))?;
		if raw.len() != 74 {
			return Err("minisign signature: wrong length".into());
		}
		let prehashed = match &raw[..2] {
			b"Ed" => false,
			b"ED" => true,
			_ => return Err("minisign signature: unknown algorithm".into()),
		};
		let mut key_id = [0u8; 8];
		key_id.copy_from_slice(&raw[2..10]);
		let mut signature = [0u8; 64];
		signature.copy_from_slice(&raw[10..74]);
		let trusted = next()?;
		let trusted_comment =
			trusted.strip_prefix("trusted comment: ").ok_or("minisign signature: no trusted comment")?.to_string();
		let global = B64.decode(next()?).map_err(|e| format!("minisign global signature: {e}"))?;
		let global_signature: [u8; 64] = global.try_into().map_err(|_| "minisign global signature: wrong length".to_string())?;
		Ok(Signature { prehashed, key_id, signature, trusted_comment, global_signature })
	}

	/// Checks the signature of `data`; the trusted comment when it is good.
	pub fn verify(&self, key: &PublicKey, data: &[u8]) -> Result<&str, String> {
		if self.prehashed {
			return self.verify_digest(key, &blake2b512(data));
		}
		self.check(key, data)
	}

	/// `verify` with the BLAKE2b-512 of the data (prehashed signatures only).
	fn verify_digest(&self, key: &PublicKey, digest: &[u8; 64]) -> Result<&str, String> {
		if !self.prehashed {
			return Err("a legacy signature needs the data itself".into());
		}
		self.check(key, digest)
	}

	fn check(&self, key: &PublicKey, message: &[u8]) -> Result<&str, String> {
		use ring::signature::{UnparsedPublicKey, ED25519};
		if self.key_id != key.key_id {
			let theirs: String = self.key_id.iter().rev().map(|b| format!("{b:02X}")).collect();
			return Err(format!("signed with key {theirs}, not the release key {}", key.id()));
		}
		let pk = UnparsedPublicKey::new(&ED25519, key.key);
		pk.verify(message, &self.signature).map_err(|_| "the signature does not match".to_string())?;
		let mut global = self.signature.to_vec();
		global.extend_from_slice(self.trusted_comment.as_bytes());
		pk.verify(&global, &self.global_signature).map_err(|_| "the trusted comment's signature does not match".to_string())?;
		Ok(&self.trusted_comment)
	}
}

/// The largest file a legacy (not prehashed) signature is checked for.
pub const LEGACY_MAX: u64 = 64 << 20;

/// Verifies what `reader` gives (a file: read in pieces when the signature is
/// prehashed, minisign's default) against the `.minisig` text with `key`.
pub fn verify_reader(key: &PublicKey, signature: &str, mut reader: impl std::io::Read) -> Result<String, String> {
	let sig = Signature::parse(signature)?;
	if !sig.prehashed {
		// a legacy signature needs the whole file in memory: only for small files
		// (security review L3; minisign signs prehashed by default)
		let mut data = vec![];
		std::io::Read::read_to_end(&mut reader.take(LEGACY_MAX + 1), &mut data).map_err(|e| e.to_string())?;
		if data.len() as u64 > LEGACY_MAX {
			return Err(format!("a legacy (not prehashed) signature is taken for files up to {} MiB only", LEGACY_MAX >> 20));
		}
		return sig.verify(key, &data).map(str::to_string);
	}
	let mut hash = Blake2b::default();
	let mut buf = vec![0u8; 1 << 16];
	loop {
		match reader.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => hash.update(&buf[..n]),
			Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
			Err(e) => return Err(e.to_string()),
		}
	}
	sig.verify_digest(key, &hash.finish()).map(str::to_string)
}

/// Verifies `data` against the `.minisig` text with `key`.
pub fn verify(key: &PublicKey, signature: &str, data: &[u8]) -> Result<String, String> {
	Signature::parse(signature)?.verify(key, data).map(str::to_string)
}

/// Signing, for tests and tools (the release workflow uses minisign itself).
#[doc(hidden)]
pub mod testing {
	use super::*;
	use ring::signature::{Ed25519KeyPair, KeyPair};

	/// A key pair from a 32-byte seed; (public key file text, key pair).
	pub fn key_pair(seed: [u8; 32], key_id: [u8; 8]) -> (String, Ed25519KeyPair) {
		let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("32 bytes");
		let mut raw = b"Ed".to_vec();
		raw.extend_from_slice(&key_id);
		raw.extend_from_slice(pair.public_key().as_ref());
		(format!("untrusted comment: minisign public key\n{}\n", B64.encode(raw)), pair)
	}

	/// A `.minisig` (prehashed, as minisign signs by default).
	pub fn sign(pair: &Ed25519KeyPair, key_id: [u8; 8], data: &[u8], trusted_comment: &str) -> String {
		let sig = pair.sign(&blake2b512(data));
		let mut raw = b"ED".to_vec();
		raw.extend_from_slice(&key_id);
		raw.extend_from_slice(sig.as_ref());
		let mut global = sig.as_ref().to_vec();
		global.extend_from_slice(trusted_comment.as_bytes());
		let global = pair.sign(&global);
		format!(
			"untrusted comment: signature from rproxy tests\n{}\ntrusted comment: {trusted_comment}\n{}\n",
			B64.encode(raw),
			B64.encode(global.as_ref())
		)
	}
}

// --- BLAKE2b-512 (RFC 7693) ---

const IV: [u64; 8] = [
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
	[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
	[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
	[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
	[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
	[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
	[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
	[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
	[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
	v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
	v[d] = (v[d] ^ v[a]).rotate_right(32);
	v[c] = v[c].wrapping_add(v[d]);
	v[b] = (v[b] ^ v[c]).rotate_right(24);
	v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
	v[d] = (v[d] ^ v[a]).rotate_right(16);
	v[c] = v[c].wrapping_add(v[d]);
	v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
	let mut m = [0u64; 16];
	for (i, w) in m.iter_mut().enumerate() {
		let mut b = [0u8; 8];
		b.copy_from_slice(&block[i * 8..i * 8 + 8]);
		*w = u64::from_le_bytes(b);
	}
	let mut v = [0u64; 16];
	v[..8].copy_from_slice(h);
	v[8..].copy_from_slice(&IV);
	v[12] ^= t as u64;
	v[13] ^= (t >> 64) as u64;
	if last {
		v[14] = !v[14];
	}
	for s in &SIGMA {
		g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
		g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
		g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
		g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
		g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
		g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
		g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
		g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
	}
	for i in 0..8 {
		h[i] ^= v[i] ^ v[i + 8];
	}
}

/// BLAKE2b with a 64-byte digest and no key, fed in pieces.
pub struct Blake2b {
	h: [u64; 8],
	t: u128,
	buf: [u8; 128],
	len: usize,
}

impl Default for Blake2b {
	fn default() -> Self {
		let mut h = IV;
		h[0] ^= 0x0101_0000 ^ 64;
		Blake2b { h, t: 0, buf: [0; 128], len: 0 }
	}
}

impl Blake2b {
	pub fn update(&mut self, mut data: &[u8]) {
		while !data.is_empty() {
			// the last block is compressed in `finish` (it is marked as the last)
			if self.len == 128 {
				self.t += 128;
				compress(&mut self.h, &self.buf, self.t, false);
				self.len = 0;
			}
			let n = (128 - self.len).min(data.len());
			self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
			self.len += n;
			data = &data[n..];
		}
	}

	pub fn finish(mut self) -> [u8; 64] {
		self.t += self.len as u128;
		self.buf[self.len..].fill(0);
		compress(&mut self.h, &self.buf, self.t, true);
		let mut out = [0u8; 64];
		for (i, w) in self.h.iter().enumerate() {
			out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
		}
		out
	}
}

/// BLAKE2b-512 of `data`.
pub fn blake2b512(data: &[u8]) -> [u8; 64] {
	let mut b = Blake2b::default();
	b.update(data);
	b.finish()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(b: &[u8]) -> String {
		b.iter().map(|x| format!("{x:02x}")).collect()
	}

	#[test]
	fn blake2b_test_vectors() {
		assert_eq!(
			hex(&blake2b512(b"")),
			"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
		);
		assert_eq!(
			hex(&blake2b512(b"abc")),
			"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
		);
		// across block boundaries, fed in pieces
		let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
		for split in [0, 1, 127, 128, 129, 256, 999, 1000] {
			let mut h = Blake2b::default();
			h.update(&data[..split]);
			h.update(&data[split..]);
			assert_eq!(h.finish(), blake2b512(&data), "split at {split}");
		}
		assert_ne!(blake2b512(&[0x61; 128]), blake2b512(&[0x61; 129]));
	}

	#[test]
	fn signatures_are_checked() {
		let id = [1, 2, 3, 4, 5, 6, 7, 8];
		let (pub_text, pair) = testing::key_pair([9; 32], id);
		let key = PublicKey::parse(&pub_text).unwrap();
		let sig = testing::sign(&pair, id, b"the binary", "timestamp:1 file:rproxy-api");
		assert_eq!(verify(&key, &sig, b"the binary").unwrap(), "timestamp:1 file:rproxy-api");
		assert!(verify(&key, &sig, b"the binary!").unwrap_err().contains("does not match"));
		assert_eq!(verify_reader(&key, &sig, &b"the binary"[..]).unwrap(), "timestamp:1 file:rproxy-api");
		assert!(verify_reader(&key, &sig, &b"the binary?"[..]).is_err());
		// a changed trusted comment
		let forged = sig.replace("file:rproxy-api", "file:other");
		assert!(verify(&key, &forged, b"the binary").unwrap_err().contains("trusted comment"));
		// another key
		let (other_text, _) = testing::key_pair([3; 32], [8; 8]);
		let other = PublicKey::parse(&other_text).unwrap();
		assert!(verify(&other, &sig, b"the binary").unwrap_err().contains("not the release key"));
		let (same_id_text, _) = testing::key_pair([4; 32], id);
		let same_id = PublicKey::parse(&same_id_text).unwrap();
		assert!(verify(&same_id, &sig, b"the binary").is_err());
		assert!(Signature::parse("garbage").is_err());
		assert!(PublicKey::parse("").is_err());
	}
}
