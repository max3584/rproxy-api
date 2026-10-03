//! Restoring rules from MariaDB. Runs only when RPROXY_TEST_DATABASE_URL points
//! at a scratch database (CI starts one); the test recreates `forward_rules`.

use sqlx::mysql::MySqlPoolOptions;
use sqlx::Executor;

use rproxy_api::config::db;
use rproxy_api::core::rule::{Protocol, SourceIp};
use rproxy_api::tls::config::{StartTls, TlsMode};

const WITH_OPTIONS: &str = "CREATE TABLE forward_rules (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	auth_id VARCHAR(255) NOT NULL,
	protocol VARCHAR(3) NOT NULL,
	src_addr VARCHAR(45) NOT NULL,
	src_port INT NOT NULL,
	src_port_end INT NULL,
	dist_addr VARCHAR(253) NOT NULL,
	dist_port INT NOT NULL,
	source_ip VARCHAR(16) NOT NULL DEFAULT 'proxy',
	udp_idle_secs INT NOT NULL DEFAULT 30,
	options JSON NULL
)";

/// The table before migration 005 (no ranges or TLS options).
const CURRENT: &str = "CREATE TABLE forward_rules (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	auth_id VARCHAR(255) NOT NULL,
	protocol VARCHAR(3) NOT NULL,
	src_addr VARCHAR(45) NOT NULL,
	src_port INT NOT NULL,
	dist_addr VARCHAR(253) NOT NULL,
	dist_port INT NOT NULL,
	source_ip VARCHAR(16) NOT NULL DEFAULT 'proxy',
	udp_idle_secs INT NOT NULL DEFAULT 30
)";

/// The table as it was before migration 002.
const LEGACY: &str = "CREATE TABLE forward_rules (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	auth_id VARCHAR(255) NOT NULL,
	protocol VARCHAR(3) NOT NULL,
	src_addr VARCHAR(45) NOT NULL,
	src_port INT NOT NULL,
	dist_addr VARCHAR(253) NOT NULL,
	dist_port INT NOT NULL
)";

#[tokio::test]
async fn loads_every_schema_version() {
	let Ok(url) = std::env::var("RPROXY_TEST_DATABASE_URL") else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let pool = MySqlPoolOptions::new().max_connections(1).connect(&url).await.unwrap();

	pool.execute("DROP TABLE IF EXISTS forward_rules").await.unwrap();
	pool.execute(WITH_OPTIONS).await.unwrap();
	pool.execute(
		r#"INSERT INTO forward_rules (auth_id, protocol, src_addr, src_port, src_port_end, dist_addr, dist_port, source_ip, options) VALUES
		 ('u1', 'udp', '0.0.0.0', 10000, 10099, 'media.local', 10000, 'proxy', NULL),
		 ('u2', 'tcp', '0.0.0.0', 993, NULL, 'imap.local', 143, 'proxy_v2',
		  '{"tls": {"mode": "terminate", "certificates": [{"cert_file": "/c.pem", "key_file": "/k.pem"}]}, "starttls": null, "extra_listen_addrs": ["::"]}'),
		 ('u3', 'tcp', '0.0.0.0', 25, NULL, 'mx.local', 25, 'proxy', '{"tls": {"mode": "terminate", "certificates": [{"cert_file": "/c", "key_file": "/k"}]}, "starttls": "smtp", "starttls_required": false, "allow_from": ["10.0.0.0/8"]}'),
		 ('u4', 'tcp', '0.0.0.0', 26, NULL, 'x', 1, 'proxy', '{"tls": {"mode": "nonsense"}}'),
		 ('u5', 'tcp', '0.0.0.0', 5432, NULL, 'db1.local', 5432, 'proxy',
		  '{"targets": [{"addr": "db1.local", "port": 5432, "weight": 2}, {"addr": "db2.local", "port": 5432, "backup": true}], "balance": "failover", "health_check": {"interval": "5s", "port": 5433}}'),
		 ('u6', 'tcp', '0.0.0.0', 8443, NULL, 'paused.local', 443, 'proxy', '{"enabled": false}'),
		 ('u7', 'tcp', '0.0.0.0', 8444, NULL, 'on.local', 443, 'proxy', '{"enabled": true}')"#,
	)
	.await
	.unwrap();
	let rules = db::load_rules(&url).await.unwrap();
	assert_eq!(rules.len(), 5, "the row with broken options and the paused one (#116) are skipped");
	assert!(rules.iter().all(|r| r.listen_port != 8443), "paused in the UI: not started");
	assert_eq!(rules[4].listen_port, 8444, "enabled: true is an ordinary rule");
	assert_eq!(rules[0].listen_port_end, Some(10099));
	assert_eq!(rules[1].tls.as_ref().unwrap().mode, TlsMode::Terminate);
	assert_eq!(rules[1].starttls, None);
	// more listen addresses (#99)
	assert_eq!(rules[1].extra_listen_addrs, vec!["::".to_string()]);
	assert_eq!((rules[2].starttls, rules[2].starttls_required), (Some(StartTls::Smtp), Some(false)));
	assert_eq!(rules[2].allow_from, vec!["10.0.0.0/8".to_string()]);
	// several targets (#98): dist_addr / dist_port are left to the targets
	let r = &rules[3];
	assert_eq!((r.remote_addr.as_str(), r.remote_port, r.targets.len()), ("", 0, 2));
	assert_eq!((r.targets[0].weight, r.targets[1].backup), (Some(2), true));
	assert_eq!(r.balance, rproxy_api::core::balance::Balance::Failover);
	assert_eq!(r.health_check.as_ref().unwrap().port, Some(5433));
	assert!(r.clone().validate(&Default::default()).is_ok());

	pool.execute("DROP TABLE forward_rules").await.unwrap();
	pool.execute(CURRENT).await.unwrap();
	pool.execute(
		"INSERT INTO forward_rules (auth_id, protocol, src_addr, src_port, dist_addr, dist_port, source_ip, udp_idle_secs) VALUES
		 ('u1', 'tcp', '0.0.0.0', 8080, 'example.com', 80, 'proxy_v2', 30),
		 ('u2', 'udp', '::', 5353, '10.0.0.1', 53, 'proxy', 90),
		 ('u3', 'tcp', '0.0.0.0', 8081, 'x', 99999, 'proxy', 30)",
	)
	.await
	.unwrap();

	let rules = db::load_rules(&url).await.unwrap();
	assert_eq!(rules.len(), 2, "the row with an out-of-range port is skipped");
	assert_eq!((rules[0].protocol, rules[0].listen_port, rules[0].source_ip), (Protocol::Tcp, 8080, SourceIp::ProxyV2));
	assert_eq!((rules[1].protocol, rules[1].listen_addr.as_str(), rules[1].udp_idle_secs), (Protocol::Udp, "::", Some(90)));

	pool.execute("DROP TABLE forward_rules").await.unwrap();
	pool.execute(LEGACY).await.unwrap();
	pool.execute(
		"INSERT INTO forward_rules (auth_id, protocol, src_addr, src_port, dist_addr, dist_port)
		 VALUES ('u1', 'TCP', '127.0.0.1', 9000, 'localhost', 22)",
	)
	.await
	.unwrap();

	let rules = db::load_rules(&url).await.unwrap();
	assert_eq!(rules.len(), 1);
	assert_eq!(rules[0].protocol, Protocol::Tcp, "upper-case protocol from old rows is accepted");
	assert_eq!(rules[0].source_ip, SourceIp::Proxy);
	assert_eq!(rules[0].udp_idle_secs, None, "legacy rows use the default idle timeout");

	pool.execute("DROP TABLE forward_rules").await.unwrap();
}
