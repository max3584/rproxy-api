//! Authentication middlewares of `http` rules (#59): basic_auth, forward_auth
//! and oidc, against real sockets and in-test auth servers / OIDC providers.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use reqwest::StatusCode;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

use common::*;

/// Echoes the headers the backend received.
async fn echo_backend() -> SocketAddr {
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		axum::Json(json!({
			"uri": req.uri().to_string(), "user": h("x-forwarded-user"), "email": h("x-forwarded-email"),
			"groups": h("x-forwarded-groups"), "sub": h("x-forwarded-sub"), "authorization": h("authorization"),
			"cookie": h("cookie"), "x_user": h("x-user"), "x_other": h("x-other"), "who": h("x-who"),
		}))
	});
	serve(app).await
}

async fn serve(app: axum::Router) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

fn http_rule(port: u16, http: Value) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().unwrap()
}

fn workdir(tag: &str) -> std::path::PathBuf {
	let d = std::env::temp_dir().join(format!("rproxy-http-auth-{}-{tag}", std::process::id()));
	let _ = std::fs::remove_dir_all(&d);
	std::fs::create_dir_all(&d).unwrap();
	d
}

async fn body(r: reqwest::Response) -> Value {
	let text = r.text().await.unwrap();
	serde_json::from_str(&text).unwrap_or(Value::String(text))
}

#[tokio::test]
async fn basic_auth() {
	let dir = workdir("basic");
	let users = dir.join("users");
	// bcrypt, and htpasswd's default APR1 (`openssl passwd -apr1 -salt r31..... password`)
	std::fs::write(&users, format!("alice:{}\nbob:$apr1$r31.....$ARC3pREO82RIm0aQ2zszC0\n", bcrypt::hash("wonderland", 4).unwrap())).unwrap();
	let h = harness().await;
	let backend = echo_backend().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["auth"]}],
				"middlewares": {"auth": {"basic_auth": {"users_file": users, "realm": "tools", "user_header": "X-Forwarded-User"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = format!("http://127.0.0.1:{port}/x");

	let r = client().get(&url).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
	assert_eq!(r.headers()["www-authenticate"], "Basic realm=\"tools\"");
	let r = client().get(&url).basic_auth("alice", Some("wrong")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
	let r = client().get(&url).basic_auth("alice", Some("wonderland")).header("X-Forwarded-User", "root").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let v = body(r).await;
	assert_eq!(v["user"], "alice", "set by rproxy, not the client: {v}");
	assert_eq!(v["authorization"], "", "Authorization is not passed on: {v}");
	let r = client().get(&url).basic_auth("bob", Some("password")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(body(r).await["user"], "bob");

	// a missing users file is a mistake in the settings
	let (status, v) = h
		.post(http_rule(
			free_port(),
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["auth"]}],
				"middlewares": {"auth": {"basic_auth": {"users_file": dir.join("nope")}}},
			}),
		))
		.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	std::fs::remove_dir_all(dir).unwrap();
}

/// A ForwardAuth server: `X-Token: good` passes with X-User / X-Other; `login` redirects; others get 401.
async fn auth_server(seen: Arc<Mutex<Vec<HashMap<String, String>>>>) -> SocketAddr {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
		let seen = seen.clone();
		async move {
			let headers: HashMap<String, String> =
				req.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
			let token = headers.get("x-token").cloned().unwrap_or_default();
			seen.lock().unwrap().push(headers);
			match token.as_str() {
				"good" => axum::response::Response::builder()
					.status(200)
					.header("x-user", "alice")
					.header("x-other", "not copied")
					.body(axum::body::Body::from("ok"))
					.unwrap(),
				"login" => axum::response::Response::builder()
					.status(302)
					.header("location", "https://login.example/")
					.body(axum::body::Body::empty())
					.unwrap(),
				"slow" => {
					tokio::time::sleep(Duration::from_secs(3)).await;
					axum::response::Response::builder().status(200).body(axum::body::Body::empty()).unwrap()
				}
				_ => axum::response::Response::builder()
					.status(401)
					.header("x-reason", "no token")
					.body(axum::body::Body::from("denied by auth"))
					.unwrap(),
			}
		}
	});
	serve(app).await
}

#[tokio::test]
async fn forward_auth() {
	let seen = Arc::new(Mutex::new(vec![]));
	let auth = auth_server(seen.clone()).await;
	let backend = echo_backend().await;
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["fa"]}],
				"middlewares": {"fa": {"forward_auth": {"address": format!("http://{auth}/verify?x=1"), "response_headers": ["X-User"], "timeout": "1s"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = |p: &str| format!("http://127.0.0.1:{port}{p}");

	let r = client().post(url("/app/doc?a=b")).header("X-Token", "good").header("X-User", "forged").header("Host", "app.test").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let v = body(r).await;
	assert_eq!((v["x_user"].as_str(), v["x_other"].as_str()), (Some("alice"), Some("")), "{v}");
	let asked = seen.lock().unwrap().last().cloned().unwrap();
	assert_eq!(asked["x-forwarded-method"], "POST");
	assert_eq!(asked["x-forwarded-uri"], "/app/doc?a=b");
	assert_eq!(asked["x-forwarded-host"], "app.test");
	assert_eq!(asked["x-forwarded-proto"], "http");
	assert_eq!(asked["x-forwarded-for"], "127.0.0.1");
	assert_eq!(asked["x-token"], "good", "the client's headers go to the auth server");

	// the auth server's refusal goes to the client as it is
	let r = client().get(url("/")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
	assert_eq!(r.headers()["x-reason"], "no token");
	assert_eq!(r.text().await.unwrap(), "denied by auth");
	let r = client().get(url("/")).header("X-Token", "login").send().await.unwrap();
	assert_eq!((r.status(), r.headers()["location"].to_str().unwrap()), (StatusCode::FOUND, "https://login.example/"));
	// too slow, and not there
	let r = client().get(url("/")).header("X-Token", "slow").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT);
	let dead = {
		let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		l.local_addr().unwrap()
	};
	let port2 = free_port();
	let (status, v) = h
		.post(http_rule(
			port2,
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["fa"]}],
				"middlewares": {"fa": {"forward_auth": {"address": format!("http://{dead}/")}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let r = client().get(format!("http://127.0.0.1:{port2}/")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
}

fn now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

enum Signer {
	Rsa(RsaKeyPair),
	Ec(EcdsaKeyPair),
}

/// An OpenID provider in the test: discovery, JWKS, token endpoint (code with
/// PKCE, refresh), logout.
struct Provider {
	signer: Signer,
	base: String,
	/// code -> (nonce, code_challenge)
	codes: HashMap<String, (String, String)>,
	/// Lifetime of issued ID tokens.
	ttl: u64,
	refreshes: u32,
	/// Published instead of the signer's key.
	published: Option<Value>,
}

impl Provider {
	fn alg(&self) -> &'static str {
		match self.signer {
			Signer::Rsa(_) => "RS256",
			Signer::Ec(_) => "ES256",
		}
	}

	fn jwk(&self) -> Value {
		if let Some(k) = &self.published {
			return k.clone();
		}
		match &self.signer {
			Signer::Rsa(k) => {
				let c: ring::rsa::PublicKeyComponents<Vec<u8>> = k.public().into();
				json!({"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
					"n": URL_SAFE_NO_PAD.encode(&c.n), "e": URL_SAFE_NO_PAD.encode(&c.e)})
			}
			Signer::Ec(k) => {
				let point = k.public_key().as_ref();
				json!({"kty": "EC", "kid": "k1", "crv": "P-256",
					"x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65])})
			}
		}
	}

	fn id_token(&self, nonce: Option<&str>) -> String {
		let header = URL_SAFE_NO_PAD.encode(json!({"alg": self.alg(), "kid": "k1", "typ": "JWT"}).to_string());
		let mut claims = json!({"iss": self.base, "aud": ["rproxy", "other"], "sub": "u-1", "preferred_username": "alice",
			"email": "alice@example.com", "groups": ["dev", "ops"], "iat": now(), "exp": now() + self.ttl});
		if let Some(n) = nonce {
			claims["nonce"] = json!(n);
		}
		let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
		let message = format!("{header}.{payload}");
		let rng = SystemRandom::new();
		let sig = match &self.signer {
			Signer::Rsa(k) => {
				let mut sig = vec![0; k.public().modulus_len()];
				k.sign(&RSA_PKCS1_SHA256, &rng, message.as_bytes(), &mut sig).unwrap();
				sig
			}
			Signer::Ec(k) => k.sign(&rng, message.as_bytes()).unwrap().as_ref().to_vec(),
		};
		format!("{message}.{}", URL_SAFE_NO_PAD.encode(sig))
	}
}

type Shared = Arc<Mutex<Provider>>;

async fn provider(signer: Signer) -> (Shared, String) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}/realms/test", listener.local_addr().unwrap());
	let p: Shared = Arc::new(Mutex::new(Provider { signer, base: base.clone(), codes: HashMap::new(), ttl: 300, refreshes: 0, published: None }));
	let discovery = {
		let base = base.clone();
		move || async move {
			axum::Json(json!({"issuer": base, "authorization_endpoint": format!("{base}/auth"), "token_endpoint": format!("{base}/token"),
				"jwks_uri": format!("{base}/jwks"), "end_session_endpoint": format!("{base}/logout")}))
		}
	};
	let jwks = {
		let p = p.clone();
		move || {
			let jwk = p.lock().unwrap().jwk();
			async move { axum::Json(json!({"keys": [{"kty": "oct", "kid": "ignored"}, jwk]})) }
		}
	};
	let token = {
		let p = p.clone();
		move |headers: axum::http::HeaderMap, form: axum::Form<HashMap<String, String>>| {
			let p = p.clone();
			async move {
				let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
				if auth != format!("Basic {}", STANDARD.encode("rproxy:client-secret")) {
					return (axum::http::StatusCode::UNAUTHORIZED, axum::Json(json!({"error": "invalid_client"})));
				}
				let mut p = p.lock().unwrap();
				match form.get("grant_type").map(String::as_str) {
					Some("authorization_code") => {
						let Some((nonce, challenge)) = p.codes.remove(form.get("code").map(String::as_str).unwrap_or("")) else {
							return (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"})));
						};
						let verifier = form.get("code_verifier").cloned().unwrap_or_default();
						if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != challenge {
							return (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant", "d": "pkce"})));
						}
						let id = p.id_token(Some(&nonce));
						(axum::http::StatusCode::OK, axum::Json(json!({"id_token": id, "refresh_token": "r-1", "access_token": "a", "expires_in": 300})))
					}
					Some("refresh_token") if form.get("refresh_token").map(String::as_str) == Some("r-1") => {
						p.refreshes += 1;
						p.ttl = 300;
						let id = p.id_token(None);
						(axum::http::StatusCode::OK, axum::Json(json!({"id_token": id, "access_token": "a", "expires_in": 300})))
					}
					_ => (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))),
				}
			}
		}
	};
	let app = axum::Router::new()
		.route("/realms/test/.well-known/openid-configuration", axum::routing::get(discovery))
		.route("/realms/test/jwks", axum::routing::get(jwks))
		.route("/realms/test/token", axum::routing::post(token));
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(p, base)
}

fn query(url: &str) -> HashMap<String, String> {
	let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
	q.split('&')
		.filter_map(|p| p.split_once('='))
		.map(|(k, v)| (k.to_string(), percent_decode(v)))
		.collect()
}

fn percent_decode(s: &str) -> String {
	let b = s.as_bytes();
	let mut out = vec![];
	let mut i = 0;
	while i < b.len() {
		if b[i] == b'%' && i + 2 < b.len() {
			out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
			i += 3;
		} else {
			out.push(if b[i] == b'+' { b' ' } else { b[i] });
			i += 1;
		}
	}
	String::from_utf8(out).unwrap()
}

/// The `name=value` part of the Set-Cookie headers of a response, by name.
fn set_cookies(r: &reqwest::Response) -> HashMap<String, String> {
	r.headers()
		.get_all("set-cookie")
		.iter()
		.filter_map(|v| v.to_str().ok())
		.filter_map(|c| c.split(';').next()?.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
		.collect()
}

async fn oidc_rule(h: &Harness, dir: &std::path::Path, issuer: &str, backend: SocketAddr) -> u16 {
	std::fs::write(dir.join("client"), "client-secret\n").unwrap();
	std::fs::write(dir.join("cookie"), "a-long-cookie-secret-for-tests\n").unwrap();
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "app", "match": "PathPrefix(`/app`)", "to": format!("http://{backend}"), "middlewares": ["sso"]},
					{"name": "public", "match": "PathPrefix(`/public`)", "to": format!("http://{backend}")},
				],
				"middlewares": {"sso": {"oidc": {"issuer": issuer, "client_id": "rproxy", "client_secret_file": dir.join("client"),
					"cookie_secret_file": dir.join("cookie"), "scopes": ["profile", "email"]}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

/// Signs in through the provider; returns the session cookie.
async fn sign_in(p: &Shared, port: u16, issuer: &str) -> String {
	let r = client().get(format!("http://127.0.0.1:{port}/app/page?x=1")).header("Host", "app.test:8443").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::FOUND);
	let location = r.headers()["location"].to_str().unwrap().to_string();
	assert!(location.starts_with(&format!("{issuer}/auth?")), "{location}");
	let q = query(&location);
	assert_eq!(q["redirect_uri"], "http://app.test:8443/_rproxy/oidc/callback");
	assert_eq!((q["client_id"].as_str(), q["scope"].as_str(), q["code_challenge_method"].as_str()), ("rproxy", "openid profile email", "S256"));
	let state_cookie = set_cookies(&r).remove("_rproxy_oidc_state").expect("state cookie");
	p.lock().unwrap().codes.insert("code-1".into(), (q["nonce"].clone(), q["code_challenge"].clone()));

	// a callback with another state is refused
	let bad = client()
		.get(format!("http://127.0.0.1:{port}/_rproxy/oidc/callback?code=code-1&state=forged"))
		.header("Host", "app.test:8443")
		.header("Cookie", format!("_rproxy_oidc_state={state_cookie}"))
		.send()
		.await
		.unwrap();
	assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

	let r = client()
		.get(format!("http://127.0.0.1:{port}/_rproxy/oidc/callback?code=code-1&state={}", q["state"]))
		.header("Host", "app.test:8443")
		.header("Cookie", format!("_rproxy_oidc_state={state_cookie}"))
		.send()
		.await
		.unwrap();
	assert_eq!(r.status(), StatusCode::FOUND, "{}", r.text().await.unwrap_or_default());
	assert_eq!(r.headers()["location"], "/app/page?x=1", "back to where the user was");
	let cookies = set_cookies(&r);
	assert_eq!(cookies.get("_rproxy_oidc_state").map(String::as_str), Some(""), "the state cookie is cleared");
	cookies["_rproxy_oidc"].clone()
}

async fn oidc_end_to_end(signer: Signer, tag: &str) {
	let dir = workdir(tag);
	let (p, issuer) = provider(signer).await;
	let backend = echo_backend().await;
	let h = harness().await;
	let port = oidc_rule(&h, &dir, &issuer, backend).await;
	let app = format!("http://127.0.0.1:{port}/app/page");

	// no session: browsers are sent to sign in, API calls get 401; other routes are open
	let r = client().post(&app).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
	let r = client().get(format!("http://127.0.0.1:{port}/public/x")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);

	let session = sign_in(&p, port, &issuer).await;
	let r = client()
		.get(&app)
		.header("Cookie", format!("theme=dark; _rproxy_oidc={session}"))
		.header("X-Forwarded-User", "root")
		.send()
		.await
		.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let v = body(r).await;
	assert_eq!(
		(v["user"].as_str(), v["email"].as_str(), v["groups"].as_str(), v["sub"].as_str()),
		(Some("alice"), Some("alice@example.com"), Some("dev,ops"), Some("u-1")),
		"{v}"
	);
	assert_eq!(v["cookie"], "theme=dark", "the session cookie stays with rproxy: {v}");

	// a tampered cookie is not a session
	let mut raw = URL_SAFE_NO_PAD.decode(&session).unwrap();
	raw[20] ^= 1;
	let r = client().get(&app).header("Cookie", format!("_rproxy_oidc={}", URL_SAFE_NO_PAD.encode(raw))).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::FOUND, "sent to sign in again");

	// a session about to expire is refreshed with the refresh token
	p.lock().unwrap().ttl = 5;
	let short = sign_in(&p, port, &issuer).await;
	let r = client().get(&app).header("Cookie", format!("_rproxy_oidc={short}")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(p.lock().unwrap().refreshes, 1);
	let renewed = set_cookies(&r).remove("_rproxy_oidc").expect("a renewed session");
	assert_ne!(renewed, short);
	assert_eq!(body(r).await["user"], "alice");
	let r = client().get(&app).header("Cookie", format!("_rproxy_oidc={renewed}")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(p.lock().unwrap().refreshes, 1, "the renewed session is good for a while");

	// logout clears the cookie and goes to the provider's end_session_endpoint
	let r = client().get(format!("http://127.0.0.1:{port}/_rproxy/oidc/logout")).header("Host", "app.test").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::FOUND);
	let location = r.headers()["location"].to_str().unwrap().to_string();
	assert!(location.starts_with(&format!("{issuer}/logout?client_id=rproxy&post_logout_redirect_uri=http%3A%2F%2Fapp.test%2F")), "{location}");
	assert_eq!(set_cookies(&r).get("_rproxy_oidc").map(String::as_str), Some(""));
	std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn oidc_with_rs256() {
	let der = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/oidc/rsa2048.der")).unwrap();
	oidc_end_to_end(Signer::Rsa(RsaKeyPair::from_der(&der).unwrap()), "rs256").await;
}

#[tokio::test]
async fn oidc_with_es256() {
	let rng = SystemRandom::new();
	let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng).unwrap();
	oidc_end_to_end(Signer::Ec(key), "es256").await;
}

#[tokio::test]
async fn oidc_refuses_tokens_it_cannot_trust() {
	let dir = workdir("untrusted");
	// the provider signs with a key its JWKS does not publish
	let der = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/oidc/rsa2048.der")).unwrap();
	let (p, issuer) = provider(Signer::Rsa(RsaKeyPair::from_der(&der).unwrap())).await;
	let rng = SystemRandom::new();
	let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let backend = echo_backend().await;
	let h = harness().await;
	let port = oidc_rule(&h, &dir, &issuer, backend).await;
	let r = client().get(format!("http://127.0.0.1:{port}/app")).send().await.unwrap();
	let q = query(r.headers()["location"].to_str().unwrap());
	let state_cookie = set_cookies(&r).remove("_rproxy_oidc_state").unwrap();
	{
		let mut p = p.lock().unwrap();
		// the JWKS publishes the RSA key; the token is signed with another key
		p.codes.insert("c".into(), (q["nonce"].clone(), q["code_challenge"].clone()));
		p.published = Some(p.jwk());
		p.signer = Signer::Ec(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng).unwrap());
	}
	let r = client()
		.get(format!("http://127.0.0.1:{port}/_rproxy/oidc/callback?code=c&state={}", q["state"]))
		.header("Cookie", format!("_rproxy_oidc_state={state_cookie}"))
		.send()
		.await
		.unwrap();
	assert_eq!(r.status(), StatusCode::BAD_GATEWAY, "sign-in fails");
	assert!(!set_cookies(&r).contains_key("_rproxy_oidc"));
	std::fs::remove_dir_all(dir).unwrap();
}
