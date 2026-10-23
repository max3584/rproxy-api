//! The files rules from the API may name (#319, `net::protected`): checked on
//! `POST /rules`, `PATCH /rules/...` and `PUT /rulesets/{name}`, dry runs too,
//! after the token's scopes (`acme_api::check_rule_scope`).
//!
//! - A token limited by `allow_certs` names no file at all (`403 file_not_allowed`):
//!   its certificates are the stored ones it may use.
//! - No file under the certificate store or the ACME storage, nor a secret of the
//!   settings or the options (`403 protected_file`).
//! - An OIDC client secret file is used only as the client secret of the same issuer
//!   and client, here and in every other rule (`409 secret_reuse`).

use crate::control::auth::Principal;
use crate::core::registry::Registry;
use crate::core::rule::Key;
use crate::error::ApiError;
use crate::net::protected::{self, FileRef, Use};

/// The rules the change replaces, whose files are left out of the comparison.
pub enum Replacing<'a> {
	Nothing,
	/// A PATCH: the parts it replaces (`tls`, `http`) of this rule.
	Rule {
		key: &'a Key,
		tls: bool,
		http: bool,
	},
	/// A rule set's PUT: all its rules.
	Ruleset(&'a str),
}

/// Checks the files of the rules of a change: (label for the errors, files) per rule.
pub async fn check(
	registry: &Registry,
	principal: &Principal,
	rules: &[(String, Vec<FileRef>)],
	replacing: Replacing<'_>,
) -> Result<(), ApiError> {
	if principal.limited_to_stored_certs() {
		if let Some((label, f)) = rules.iter().find_map(|(l, refs)| refs.first().map(|f| (l, f))) {
			return Err(ApiError::file_not_allowed(format!(
				"{label}{}: this token is limited to stored certificates (allow_certs) and may not name files in rules",
				f.field
			)));
		}
		return Ok(());
	}
	if rules.iter().all(|(_, refs)| refs.is_empty()) {
		return Ok(());
	}
	let global = registry.http_global();
	let entries = protected::current(registry.acme().map(|a| a.as_ref()), global.crowdsec().map(|b| b.key_file()));
	for (label, refs) in rules {
		for f in refs {
			if let Some(e) = protected::protecting(&f.path, &entries) {
				return Err(ApiError::protected_file(format!(
					"{label}{}: {} is {}; rules from the API may not name it",
					f.field, f.path, e.what
				)));
			}
		}
	}
	// OIDC client secrets: against each other and every other rule's files
	let existing = registry.file_refs().await;
	let new_client = rules.iter().flat_map(|(_, refs)| refs).any(|f| f.client.is_some());
	if !new_client && !existing.iter().any(|(_, _, refs)| refs.iter().any(|f| f.client.is_some())) {
		return Ok(());
	}
	let replacing = &replacing;
	let kept: Vec<(String, &FileRef)> = existing
		.iter()
		.filter(|(_, set, _)| match replacing {
			Replacing::Ruleset(name) => set.as_deref() != Some(name),
			_ => true,
		})
		.flat_map(|(key, _, refs)| {
			refs.iter()
				.filter(move |f| match replacing {
					Replacing::Rule { key: k, tls, http } if *k == key => {
						!(*tls && f.field.starts_with("tls.") || *http && f.field.starts_with("http."))
					}
					_ => true,
				})
				.map(move |f| (key.to_string(), f))
		})
		.collect();
	let mut uses: Vec<Use<'_>> = kept
		.iter()
		.map(|(rule, f)| Use {
			rule: format!("rule {rule}"),
			file: f,
			new: false,
		})
		.collect();
	for (label, refs) in rules {
		let rule = if label.is_empty() {
			"this rule".to_string()
		} else {
			label.trim_end_matches(": ").to_string()
		};
		uses.extend(refs.iter().map(|f| Use {
			rule: rule.clone(),
			file: f,
			new: true,
		}));
	}
	match protected::secret_conflicts(&uses).into_iter().next() {
		Some(conflict) => Err(ApiError::secret_reuse(conflict)),
		None => Ok(()),
	}
}

/// `POST /rules`.
pub async fn check_create(registry: &Registry, principal: &Principal, req: &crate::core::rule::RuleRequest) -> Result<(), ApiError> {
	let refs = protected::refs(req.tls.as_ref(), req.http.as_ref());
	check(registry, principal, &[(String::new(), refs)], Replacing::Nothing).await
}

/// `PATCH /rules/...`: the parts it replaces.
pub async fn check_update(
	registry: &Registry,
	principal: &Principal,
	key: &Key,
	req: &crate::core::rule::UpdateRequest,
) -> Result<(), ApiError> {
	let refs = protected::refs(req.tls.as_ref(), req.http.as_ref());
	let replacing = Replacing::Rule {
		key,
		tls: req.tls.is_some(),
		http: req.http.is_some(),
	};
	check(registry, principal, &[(String::new(), refs)], replacing).await
}

/// `PUT /rulesets/{name}`: every rule of the set (`rules[i]: ` in the errors).
pub async fn check_ruleset(
	registry: &Registry,
	principal: &Principal,
	name: &str,
	rules: &[crate::core::rule::RuleRequest],
) -> Result<(), ApiError> {
	let rules: Vec<(String, Vec<FileRef>)> = rules
		.iter()
		.enumerate()
		.map(|(i, r)| (format!("rules[{i}]: "), protected::refs(r.tls.as_ref(), r.http.as_ref())))
		.collect();
	check(registry, principal, &rules, Replacing::Ruleset(name)).await
}
