//! `oidc` (#59): sign-in through an OpenID Connect provider (Keycloak and
//! others) without an extra proxy. Authorization code flow with PKCE; the
//! session is an encrypted cookie (AES-256-GCM, key from `cookie_secret_file`)
//! holding the identity and the refresh token. ID tokens are verified with the
//! provider's JWKS (RS256/384/512, PS256, ES256/384), which is cached and
//! fetched again for an unknown key id.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use bytes::Bytes;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, StatusCode};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::auth::{one_line, SecretFile};
use crate::error::ApiError;

pub const DEFAULT_CALLBACK: &str = "/_rproxy/oidc/callback";
pub const DEFAULT_LOGOUT: &str = "/_rproxy/oidc/logout";
pub const DEFAULT_COOKIE: &str = "_rproxy_oidc";
const TIMEOUT: Duration = Duration::from_secs(10);
/// Sign-in must finish within this time.
const STATE_TTL: u64 = 600;
/// Clock differences accepted on `exp` / `iat`.
const LEEWAY: u64 = 60;
/// A session is refreshed this long before it expires.
const REFRESH_EARLY: u64 = 30;
/// JWKS is fetched again for an unknown key id at most this often.
const JWKS_REFETCH: Duration = Duration::from_secs(60);
/// A failed discovery is tried again after this long.
const DISCOVERY_RETRY: Duration = Duration::from_secs(10);
/// Browsers drop larger cookies.
const MAX_COOKIE: usize = 4000;
/// Identity headers set for the backend (and removed from what the client sent).
pub const IDENTITY_HEADERS: [&str; 4] = ["x-forwarded-user", "x-forwarded-email", "x-forwarded-groups", "x-forwarded-sub"];

fn now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Clone)]
struct Provider {
	issuer: String,
	authorization: String,
	token: String,
	jwks: String,
	end_session: Option<String>,
}

#[derive(Debug, Clone)]
enum Jwk {
	Rsa { n: Vec<u8>, e: Vec<u8> },
	Ec { curve: &'static str, point: Vec<u8> },
}

#[derive(Default)]
struct Jwks {
	keys: HashMap<String, Jwk>,
	fetched: Option<Instant>,
}

/// The signed-in user, as kept in the session cookie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
	pub sub: String,
	pub user: String,
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub email: String,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<String>,
	/// Unix seconds.
	pub exp: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub refresh: Option<String>,
}

/// A sign-in in progress (the state cookie).
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
	state: String,
	nonce: String,
	verifier: String,
	return_to: String,
	exp: u64,
}

/// What the middleware decided.
pub enum Outcome {
	/// Signed in. `set_cookie` is a renewed session for the response.
	Pass { session: Session, set_cookie: Option<HeaderValue> },
	/// Answer the client (sign-in redirect, callback, logout, errors).
	Respond { status: StatusCode, headers: Vec<(HeaderName, HeaderValue)>, body: String },
}

fn respond(status: StatusCode, body: &str) -> Outcome {
	Outcome::Respond { status, headers: vec![], body: format!("{body}\n") }
}

fn redirect(location: &str, cookies: Vec<HeaderValue>) -> Outcome {
	let mut headers = vec![];
	if let Ok(v) = HeaderValue::from_str(location) {
		headers.push((header::LOCATION, v));
	}
	headers.extend(cookies.into_iter().map(|c| (header::SET_COOKIE, c)));
	headers.push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
	Outcome::Respond { status: StatusCode::FOUND, headers, body: String::new() }
}

pub struct Oidc {
	pub name: String,
	issuer: String,
	client_id: String,
	client_secret: SecretFile<String>,
	key: SecretFile<[u8; 32]>,
	scopes: Vec<String>,
	pub callback_path: String,
	pub logout_path: String,
	cookie: String,
	groups_claim: String,
	tls: tokio_rustls::TlsConnector,
	provider: RwLock<Option<Provider>>,
	discovery_failed: RwLock<Option<Instant>>,
	jwks: RwLock<Jwks>,
	rng: SystemRandom,
}

impl std::fmt::Debug for Oidc {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Oidc").field("name", &self.name).field("issuer", &self.issuer).finish_non_exhaustive()
	}
}

/// The cookie key: at least 16 characters of secret, stretched with SHA-256.
fn parse_key(text: &str) -> Result<[u8; 32], String> {
	let secret = one_line(text)?;
	if secret.len() < 16 {
		return Err("the cookie secret must be at least 16 characters (e.g. openssl rand -base64 32)".into());
	}
	let mut h = Sha256::new();
	h.update(b"rproxy-oidc-cookie\0");
	h.update(secret.as_bytes());
	Ok(h.finalize().into())
}

/// Settings of an `oidc` middleware.
pub struct OidcSettings<'a> {
	pub issuer: &'a str,
	pub client_id: &'a str,
	pub client_secret_file: &'a str,
	pub cookie_secret_file: &'a str,
	pub scopes: &'a [String],
	pub ca_file: Option<&'a str>,
	pub callback_path: Option<&'a str>,
	pub logout_path: Option<&'a str>,
	pub cookie_name: Option<&'a str>,
	pub groups_claim: Option<&'a str>,
}

impl Oidc {
	pub fn new(name: &str, s: OidcSettings<'_>) -> Result<Oidc, ApiError> {
		let what = format!("middleware {name}");
		let up = crate::tlsconf::Upstream { ca_file: s.ca_file.map(str::to_string), ..Default::default() };
		let tls = crate::tlsconf::client_config(&up).map_err(|e| ApiError::invalid(format!("{what}: ca_file: {}", e.message)))?;
		Ok(Oidc {
			name: name.to_string(),
			issuer: s.issuer.trim_end_matches('/').to_string(),
			client_id: s.client_id.to_string(),
			client_secret: SecretFile::open(s.client_secret_file, &format!("{what}: client_secret_file"), one_line)?,
			key: SecretFile::open(s.cookie_secret_file, &format!("{what}: cookie_secret_file"), parse_key)?,
			scopes: s.scopes.to_vec(),
			callback_path: s.callback_path.unwrap_or(DEFAULT_CALLBACK).to_string(),
			logout_path: s.logout_path.unwrap_or(DEFAULT_LOGOUT).to_string(),
			cookie: s.cookie_name.unwrap_or(DEFAULT_COOKIE).to_string(),
			groups_claim: s.groups_claim.unwrap_or("groups").to_string(),
			tls: tokio_rustls::TlsConnector::from(tls),
			provider: RwLock::default(),
			discovery_failed: RwLock::default(),
			jwks: RwLock::default(),
			rng: SystemRandom::new(),
		})
	}

	/// SIGHUP: read the secret files again.
	pub fn reload(&self) {
		self.client_secret.reload(true);
		self.key.reload(true);
	}

	fn state_cookie(&self) -> String {
		format!("{}_state", self.cookie)
	}

	/// Whether this middleware answers the path itself (callback, logout),
	/// whichever route it belongs to.
	pub fn owns(&self, path: &str) -> bool {
		path == self.callback_path || path == self.logout_path
	}

	/// Runs the middleware for one request. `authority` is the Host the client used.
	pub async fn handle(&self, parts: &Parts, https: bool, authority: &str) -> Outcome {
		let Some(key) = self.key.get() else {
			return respond(StatusCode::SERVICE_UNAVAILABLE, "sign-in is not available (cookie secret unreadable)");
		};
		let path = parts.uri.path();
		if path == self.callback_path {
			return self.callback(parts, https, authority, &key).await;
		}
		if path == self.logout_path {
			return self.logout(https, authority).await;
		}
		if let Some(session) = cookie(&parts.headers, &self.cookie).and_then(|c| self.open::<Session>(&key, &self.cookie, &c)) {
			if session.exp > now() + REFRESH_EARLY {
				return Outcome::Pass { session, set_cookie: None };
			}
			if let Some(token) = &session.refresh {
				match self.refresh(token).await {
					Ok(fresh) => {
						let set = self.session_cookie(&key, &fresh, https);
						return Outcome::Pass { session: fresh, set_cookie: set };
					}
					Err(e) => info!(event = "oidc.refresh", middleware = %self.name, user = %session.user, error = %e, "signing in again"),
				}
			}
		}
		self.sign_in(parts, https, authority, &key).await
	}

	async fn sign_in(&self, parts: &Parts, https: bool, authority: &str, key: &[u8; 32]) -> Outcome {
		// only browsers navigating can follow the redirect; API calls get 401
		if parts.method != Method::GET && parts.method != Method::HEAD {
			return respond(StatusCode::UNAUTHORIZED, "sign-in required");
		}
		let provider = match self.provider().await {
			Ok(p) => p,
			Err(e) => {
				warn!(event = "oidc.error", middleware = %self.name, error = %e);
				return respond(StatusCode::BAD_GATEWAY, "the sign-in provider is not available");
			}
		};
		let pending = Pending {
			state: self.random(),
			nonce: self.random(),
			verifier: self.random(),
			return_to: parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string(),
			exp: now() + STATE_TTL,
		};
		let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
		let mut scopes = vec!["openid".to_string()];
		scopes.extend(self.scopes.iter().filter(|s| *s != "openid").cloned());
		let query = form(&[
			("response_type", "code"),
			("client_id", &self.client_id),
			("redirect_uri", &self.redirect_uri(https, authority)),
			("scope", &scopes.join(" ")),
			("state", &pending.state),
			("nonce", &pending.nonce),
			("code_challenge", &challenge),
			("code_challenge_method", "S256"),
		]);
		let sep = if provider.authorization.contains('?') { '&' } else { '?' };
		let sealed = self.seal(key, &self.state_cookie(), &pending);
		let cookie = set_cookie(&self.state_cookie(), &sealed, https, Some(STATE_TTL));
		redirect(&format!("{}{sep}{query}", provider.authorization), cookie.into_iter().collect())
	}

	async fn callback(&self, parts: &Parts, https: bool, authority: &str, key: &[u8; 32]) -> Outcome {
		let q = parse_query(parts.uri.query().unwrap_or(""));
		let clear_state = set_cookie(&self.state_cookie(), "", https, Some(0));
		let Some(pending) = cookie(&parts.headers, &self.state_cookie()).and_then(|c| self.open::<Pending>(key, &self.state_cookie(), &c)) else {
			return respond(StatusCode::BAD_REQUEST, "no sign-in in progress (or it took too long); open the page again");
		};
		if pending.exp < now() || q.get("state").map(String::as_str) != Some(pending.state.as_str()) {
			return respond(StatusCode::BAD_REQUEST, "the sign-in does not match; open the page again");
		}
		if let Some(err) = q.get("error") {
			warn!(event = "oidc.error", middleware = %self.name, error = %err, description = %q.get("error_description").cloned().unwrap_or_default());
			return respond(StatusCode::FORBIDDEN, "sign-in was refused by the provider");
		}
		let Some(code) = q.get("code") else { return respond(StatusCode::BAD_REQUEST, "no authorization code") };
		let tokens = self
			.token(&[
				("grant_type", "authorization_code"),
				("code", code),
				("redirect_uri", &self.redirect_uri(https, authority)),
				("code_verifier", &pending.verifier),
			])
			.await;
		let session = match tokens {
			Ok(t) => self.session_from(&t, Some(&pending.nonce), None).await,
			Err(e) => Err(e),
		};
		let session = match session {
			Ok(s) => s,
			Err(e) => {
				warn!(event = "oidc.error", middleware = %self.name, error = %e);
				return respond(StatusCode::BAD_GATEWAY, "sign-in failed");
			}
		};
		info!(event = "oidc.login", middleware = %self.name, user = %session.user);
		let mut cookies: Vec<HeaderValue> = clear_state.into_iter().collect();
		cookies.extend(self.session_cookie(key, &session, https));
		// only paths on this site, never another origin
		let back = if pending.return_to.starts_with('/') && !pending.return_to.starts_with("//") { pending.return_to } else { "/".into() };
		redirect(&back, cookies)
	}

	async fn logout(&self, https: bool, authority: &str) -> Outcome {
		let clear = set_cookie(&self.cookie, "", https, Some(0));
		let home = format!("{}://{authority}/", if https { "https" } else { "http" });
		let target = match self.provider().await {
			Ok(Provider { end_session: Some(end), .. }) => {
				let sep = if end.contains('?') { '&' } else { '?' };
				format!("{end}{sep}{}", form(&[("client_id", &self.client_id), ("post_logout_redirect_uri", &home)]))
			}
			_ => "/".into(),
		};
		redirect(&target, clear.into_iter().collect())
	}

	fn redirect_uri(&self, https: bool, authority: &str) -> String {
		format!("{}://{authority}{}", if https { "https" } else { "http" }, self.callback_path)
	}

	fn session_cookie(&self, key: &[u8; 32], session: &Session, https: bool) -> Option<HeaderValue> {
		let mut sealed = self.seal(key, &self.cookie, session);
		if sealed.len() > MAX_COOKIE && session.refresh.is_some() {
			// too big for a browser: keep the identity, sign in again when it expires
			warn!(event = "oidc.cookie", middleware = %self.name, size = sealed.len(), "session too large; the refresh token is not kept");
			sealed = self.seal(key, &self.cookie, &Session { refresh: None, ..session.clone() });
		}
		set_cookie(&self.cookie, &sealed, https, None)
	}

	fn random(&self) -> String {
		let mut b = [0u8; 32];
		self.rng.fill(&mut b).expect("the system random source works");
		URL_SAFE_NO_PAD.encode(b)
	}

	/// base64url(nonce || AES-256-GCM(json)); the cookie name is the associated data.
	fn seal<T: Serialize>(&self, key: &[u8; 32], name: &str, value: &T) -> String {
		let mut nonce = [0u8; 12];
		self.rng.fill(&mut nonce).expect("the system random source works");
		let mut data = serde_json::to_vec(value).unwrap_or_default();
		let k = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key).expect("32-byte key"));
		k.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(name.as_bytes()), &mut data)
			.expect("sealing a cookie does not fail");
		let mut out = nonce.to_vec();
		out.extend(data);
		URL_SAFE_NO_PAD.encode(out)
	}

	fn open<T: for<'de> Deserialize<'de>>(&self, key: &[u8; 32], name: &str, text: &str) -> Option<T> {
		let raw = URL_SAFE_NO_PAD.decode(text).ok()?;
		if raw.len() < 12 + 16 {
			return None;
		}
		let (nonce, rest) = raw.split_at(12);
		let mut data = rest.to_vec();
		let k = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key).ok()?);
		let plain = k.open_in_place(Nonce::try_assume_unique_for_key(nonce).ok()?, Aad::from(name.as_bytes()), &mut data).ok()?;
		serde_json::from_slice(plain).ok()
	}

	async fn get_json(&self, url: &str) -> Result<Value, String> {
		let (status, body) = super::crowdsec::call(&self.tls, Method::GET, url, accept_json(), Bytes::new(), TIMEOUT).await?;
		if !status.is_success() {
			return Err(format!("{url}: HTTP {status}"));
		}
		serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))
	}

	async fn provider(&self) -> Result<Provider, String> {
		if let Some(p) = self.provider.read().unwrap().clone() {
			return Ok(p);
		}
		if self.discovery_failed.read().unwrap().is_some_and(|t| t.elapsed() < DISCOVERY_RETRY) {
			return Err("the provider's discovery failed a moment ago".into());
		}
		let url = format!("{}/.well-known/openid-configuration", self.issuer);
		let found = self.get_json(&url).await.and_then(|d| {
			let s = |k: &str| d.get(k).and_then(Value::as_str).map(str::to_string);
			let need = |k: &str| s(k).ok_or_else(|| format!("{url}: no {k}"));
			let issuer = need("issuer")?;
			if issuer.trim_end_matches('/') != self.issuer {
				return Err(format!("{url}: issuer {issuer} is not {}", self.issuer));
			}
			Ok(Provider {
				issuer,
				authorization: need("authorization_endpoint")?,
				token: need("token_endpoint")?,
				jwks: need("jwks_uri")?,
				end_session: s("end_session_endpoint"),
			})
		});
		match found {
			Ok(p) => {
				*self.provider.write().unwrap() = Some(p.clone());
				Ok(p)
			}
			Err(e) => {
				*self.discovery_failed.write().unwrap() = Some(Instant::now());
				Err(e)
			}
		}
	}

	/// A POST to the token endpoint with the client's credentials (client_secret_basic).
	async fn token(&self, params: &[(&str, &str)]) -> Result<Value, String> {
		let provider = self.provider().await?;
		let secret = self.client_secret.get().ok_or("the client secret file cannot be read")?;
		let mut headers = accept_json();
		let basic = STANDARD.encode(format!("{}:{}", encode(&self.client_id), encode(&secret)));
		headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Basic {basic}")).map_err(|e| e.to_string())?);
		headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
		let (status, body) =
			super::crowdsec::call(&self.tls, Method::POST, &provider.token, headers, Bytes::from(form(params)), TIMEOUT).await?;
		let v: Value = serde_json::from_slice(&body).map_err(|e| format!("token endpoint: {e}"))?;
		if !status.is_success() {
			let err = v.get("error").and_then(Value::as_str).unwrap_or("");
			return Err(format!("token endpoint: HTTP {status} {err}"));
		}
		Ok(v)
	}

	async fn refresh(&self, token: &str) -> Result<Session, String> {
		let t = self.token(&[("grant_type", "refresh_token"), ("refresh_token", token)]).await?;
		self.session_from(&t, None, Some(token)).await
	}

	/// The session from a token response: the ID token verified and its claims read.
	async fn session_from(&self, tokens: &Value, nonce: Option<&str>, old_refresh: Option<&str>) -> Result<Session, String> {
		let id_token = tokens.get("id_token").and_then(Value::as_str).ok_or("the token response has no id_token")?;
		let claims = self.verify(id_token, nonce).await?;
		let text = |k: &str| claims.get(k).and_then(Value::as_str).unwrap_or("").to_string();
		let sub = text("sub");
		if sub.is_empty() {
			return Err("the ID token has no sub".into());
		}
		let user = [text("preferred_username"), text("email")].into_iter().find(|s| !s.is_empty()).unwrap_or_else(|| sub.clone());
		let groups = claim_path(&claims, &self.groups_claim)
			.and_then(Value::as_array)
			.map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
			.unwrap_or_default();
		let exp = claims.get("exp").and_then(Value::as_u64).ok_or("the ID token has no exp")?;
		let refresh = tokens.get("refresh_token").and_then(Value::as_str).or(old_refresh).map(str::to_string);
		Ok(Session { sub, user, email: text("email"), groups, exp, refresh })
	}

	/// Checks the signature (JWKS), issuer, audience, expiry and nonce of an ID token.
	pub async fn verify(&self, jwt: &str, nonce: Option<&str>) -> Result<Value, String> {
		let provider = self.provider().await?;
		let mut parts = jwt.split('.');
		let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
			return Err("the ID token is not a JWT".into());
		};
		let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
		let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
		let kid = header.get("kid").and_then(Value::as_str).unwrap_or("").to_string();
		let sig = URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())?;
		let message = format!("{h}.{p}");
		let key = self.key_for(&provider, &kid).await?;
		verify_signature(alg, &key, message.as_bytes(), &sig)?;
		let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
		if claims.get("iss").and_then(Value::as_str) != Some(provider.issuer.as_str()) {
			return Err("the ID token is from another issuer".into());
		}
		let aud_ok = match claims.get("aud") {
			Some(Value::String(a)) => *a == self.client_id,
			Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(&self.client_id)),
			_ => false,
		};
		if !aud_ok {
			return Err("the ID token is not for this client".into());
		}
		if claims.get("exp").and_then(Value::as_u64).is_none_or(|exp| exp + LEEWAY < now()) {
			return Err("the ID token has expired".into());
		}
		if let Some(n) = nonce {
			if claims.get("nonce").and_then(Value::as_str) != Some(n) {
				return Err("the ID token's nonce does not match".into());
			}
		}
		Ok(claims)
	}

	async fn key_for(&self, provider: &Provider, kid: &str) -> Result<Jwk, String> {
		if let Some(k) = self.find_key(kid) {
			return Ok(k);
		}
		let may_fetch = self.jwks.read().unwrap().fetched.is_none_or(|t| t.elapsed() >= JWKS_REFETCH);
		if may_fetch {
			let doc = self.get_json(&provider.jwks).await?;
			let keys = parse_jwks(&doc);
			let mut j = self.jwks.write().unwrap();
			j.keys = keys;
			j.fetched = Some(Instant::now());
		}
		self.find_key(kid).ok_or_else(|| format!("no key {kid:?} in the provider's JWKS"))
	}

	fn find_key(&self, kid: &str) -> Option<Jwk> {
		let j = self.jwks.read().unwrap();
		match j.keys.get(kid) {
			Some(k) => Some(k.clone()),
			// a token without kid, and a provider with one key
			None if kid.is_empty() && j.keys.len() == 1 => j.keys.values().next().cloned(),
			None => None,
		}
	}

	/// Removes the identity headers and this middleware's cookies from the
	/// request, then sets the identity of `session`.
	pub fn pass_identity(&self, headers: &mut HeaderMap, session: &Session) {
		for h in IDENTITY_HEADERS {
			headers.remove(h);
		}
		strip_cookies(headers, &[&self.cookie, &self.state_cookie()]);
		let mut set = |name: &'static str, v: &str| {
			if let Ok(v) = HeaderValue::from_str(v) {
				headers.insert(HeaderName::from_static(name), v);
			}
		};
		set("x-forwarded-user", &session.user);
		set("x-forwarded-sub", &session.sub);
		if !session.email.is_empty() {
			set("x-forwarded-email", &session.email);
		}
		if !session.groups.is_empty() {
			set("x-forwarded-groups", &session.groups.join(","));
		}
	}
}

fn claim_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
	path.split('.').try_fold(v, |v, k| v.get(k))
}

fn parse_jwks(doc: &Value) -> HashMap<String, Jwk> {
	let mut out = HashMap::new();
	let b64 = |k: &Value, f: &str| k.get(f).and_then(Value::as_str).and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok());
	for k in doc.get("keys").and_then(Value::as_array).into_iter().flatten() {
		if k.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") {
			continue;
		}
		let kid = k.get("kid").and_then(Value::as_str).unwrap_or("").to_string();
		let jwk = match k.get("kty").and_then(Value::as_str) {
			Some("RSA") => match (b64(k, "n"), b64(k, "e")) {
				(Some(n), Some(e)) => Jwk::Rsa { n, e },
				_ => continue,
			},
			Some("EC") => {
				let curve = match k.get("crv").and_then(Value::as_str) {
					Some("P-256") => "P-256",
					Some("P-384") => "P-384",
					_ => continue,
				};
				match (b64(k, "x"), b64(k, "y")) {
					(Some(x), Some(y)) => {
						let mut point = vec![4u8];
						point.extend(x);
						point.extend(y);
						Jwk::Ec { curve, point }
					}
					_ => continue,
				}
			}
			_ => continue,
		};
		out.insert(kid, jwk);
	}
	out
}

fn verify_signature(alg: &str, key: &Jwk, message: &[u8], sig: &[u8]) -> Result<(), String> {
	let bad = || format!("the ID token's signature ({alg}) does not verify");
	match (alg, key) {
		("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", Jwk::Rsa { n, e }) => {
			let params: &signature::RsaParameters = match alg {
				"RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
				"RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
				"RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
				"PS256" => &signature::RSA_PSS_2048_8192_SHA256,
				"PS384" => &signature::RSA_PSS_2048_8192_SHA384,
				_ => &signature::RSA_PSS_2048_8192_SHA512,
			};
			RsaPublicKeyComponents { n, e }.verify(params, message, sig).map_err(|_| bad())
		}
		("ES256", Jwk::Ec { curve: "P-256", point }) => {
			UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point).verify(message, sig).map_err(|_| bad())
		}
		("ES384", Jwk::Ec { curve: "P-384", point }) => {
			UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point).verify(message, sig).map_err(|_| bad())
		}
		_ => Err(format!("the ID token's algorithm {alg:?} does not fit the key (or is not supported)")),
	}
}

fn accept_json() -> HeaderMap {
	let mut h = HeaderMap::new();
	h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
	h
}

/// Percent-encoding for query strings and forms (unreserved characters stay).
pub fn encode(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
			out.push(b as char);
		} else {
			out.push_str(&format!("%{b:02X}"));
		}
	}
	out
}

fn form(pairs: &[(&str, &str)]) -> String {
	pairs.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect::<Vec<_>>().join("&")
}

fn decode(s: &str) -> String {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		match bytes[i] {
			b'+' => out.push(b' '),
			b'%' if i + 2 < bytes.len() => {
				match u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"), 16) {
					Ok(b) => {
						out.push(b);
						i += 2;
					}
					Err(_) => out.push(b'%'),
				}
			}
			b => out.push(b),
		}
		i += 1;
	}
	String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(q: &str) -> HashMap<String, String> {
	q.split('&').filter(|p| !p.is_empty()).map(|p| {
		let (k, v) = p.split_once('=').unwrap_or((p, ""));
		(decode(k), decode(v))
	}).collect()
}

/// The value of a request cookie.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
	headers
		.get_all(header::COOKIE)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(';'))
		.filter_map(|c| c.trim().split_once('='))
		.find(|(k, _)| *k == name)
		.map(|(_, v)| v.to_string())
}

/// Removes the named cookies from the request's Cookie headers.
fn strip_cookies(headers: &mut HeaderMap, names: &[&str]) {
	let kept: Vec<String> = headers
		.get_all(header::COOKIE)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(';'))
		.map(str::trim)
		.filter(|c| !c.is_empty() && !names.iter().any(|n| c.split_once('=').map(|(k, _)| k) == Some(*n)))
		.map(str::to_string)
		.collect();
	headers.remove(header::COOKIE);
	if !kept.is_empty() {
		if let Ok(v) = HeaderValue::from_str(&kept.join("; ")) {
			headers.insert(header::COOKIE, v);
		}
	}
}

fn set_cookie(name: &str, value: &str, https: bool, max_age: Option<u64>) -> Option<HeaderValue> {
	let mut c = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
	if https {
		c.push_str("; Secure");
	}
	if let Some(a) = max_age {
		c.push_str(&format!("; Max-Age={a}"));
	}
	HeaderValue::from_str(&c).ok()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn oidc(dir: &std::path::Path) -> Oidc {
		std::fs::write(dir.join("client"), "s3cret\n").unwrap();
		std::fs::write(dir.join("cookie"), "0123456789abcdef0123\n").unwrap();
		Oidc::new(
			"sso",
			OidcSettings {
				issuer: "http://127.0.0.1:1/realms/x",
				client_id: "app",
				client_secret_file: dir.join("client").to_str().unwrap(),
				cookie_secret_file: dir.join("cookie").to_str().unwrap(),
				scopes: &[],
				ca_file: None,
				callback_path: None,
				logout_path: None,
				cookie_name: None,
				groups_claim: None,
			},
		)
		.unwrap()
	}

	fn dir(tag: &str) -> std::path::PathBuf {
		let d = std::env::temp_dir().join(format!("rproxy-oidc-{}-{tag}", std::process::id()));
		std::fs::create_dir_all(&d).unwrap();
		d
	}

	#[test]
	fn sealed_cookies_open_only_unchanged_with_the_same_key_and_name() {
		let d = dir("seal");
		let o = oidc(&d);
		let key = o.key.get().unwrap();
		let s = Session { sub: "1".into(), user: "alice".into(), email: String::new(), groups: vec!["a".into()], exp: 9, refresh: None };
		let sealed = o.seal(&key, "_rproxy_oidc", &s);
		assert_eq!(o.open::<Session>(&key, "_rproxy_oidc", &sealed), Some(s.clone()));
		assert_eq!(o.open::<Session>(&key, "other", &sealed), None, "bound to the cookie name");
		let mut raw = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
		let last = raw.len() - 1;
		raw[last] ^= 1;
		assert_eq!(o.open::<Session>(&key, "_rproxy_oidc", &URL_SAFE_NO_PAD.encode(raw)), None, "tampered");
		assert_eq!(o.open::<Session>(&[7u8; 32], "_rproxy_oidc", &sealed), None, "another key");
		assert_eq!(o.open::<Session>(&key, "_rproxy_oidc", "garbage"), None);
		std::fs::remove_dir_all(d).unwrap();
	}

	#[test]
	fn short_cookie_secrets_and_missing_files_are_refused() {
		let d = dir("bad");
		std::fs::write(d.join("client"), "x\n").unwrap();
		std::fs::write(d.join("cookie"), "short\n").unwrap();
		let settings = |cookie: &str| OidcSettings {
			issuer: "http://a",
			client_id: "c",
			client_secret_file: d.join("client").to_str().unwrap().to_string().leak(),
			cookie_secret_file: cookie.to_string().leak(),
			scopes: &[],
			ca_file: None,
			callback_path: None,
			logout_path: None,
			cookie_name: None,
			groups_claim: None,
		};
		let e = Oidc::new("sso", settings(d.join("cookie").to_str().unwrap())).unwrap_err();
		assert!(e.message.contains("16 characters"), "{}", e.message);
		let e = Oidc::new("sso", settings("/nonexistent/cookie")).unwrap_err();
		assert!(e.message.contains("cookie_secret_file"), "{}", e.message);
		std::fs::remove_dir_all(d).unwrap();
	}

	#[test]
	fn cookies_and_query_strings() {
		let mut h = HeaderMap::new();
		h.insert(header::COOKIE, HeaderValue::from_static("a=1; _rproxy_oidc=xyz; b=2"));
		assert_eq!(cookie(&h, "_rproxy_oidc").as_deref(), Some("xyz"));
		strip_cookies(&mut h, &["_rproxy_oidc"]);
		assert_eq!(h[header::COOKIE], "a=1; b=2");
		strip_cookies(&mut h, &["a", "b"]);
		assert!(!h.contains_key(header::COOKIE));
		let q = parse_query("code=a%2Fb&state=x+y&e=%zz");
		assert_eq!((q["code"].as_str(), q["state"].as_str(), q["e"].as_str()), ("a/b", "x y", "%zz"));
		assert_eq!(encode("a b/c~"), "a%20b%2Fc~");
	}

	#[test]
	fn identity_headers_replace_what_the_client_sent() {
		let d = dir("ident");
		let o = oidc(&d);
		let mut h = HeaderMap::new();
		h.insert("x-forwarded-user", HeaderValue::from_static("root"));
		h.insert("x-forwarded-groups", HeaderValue::from_static("admins"));
		h.insert(header::COOKIE, HeaderValue::from_static("_rproxy_oidc=secret; keep=1"));
		let s = Session { sub: "u1".into(), user: "alice".into(), email: "a@x".into(), groups: vec![], exp: 0, refresh: None };
		o.pass_identity(&mut h, &s);
		assert_eq!(h["x-forwarded-user"], "alice");
		assert_eq!(h["x-forwarded-email"], "a@x");
		assert!(!h.contains_key("x-forwarded-groups"), "not from the client");
		assert_eq!(h[header::COOKIE], "keep=1");
		std::fs::remove_dir_all(d).unwrap();
	}
}
