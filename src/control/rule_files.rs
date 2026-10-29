//! The files rules from the API may name (#319, `net::protected`): checked on
//! `POST /rules`, `PATCH /rules/...` and `PUT /rulesets/{name}`, dry runs too,
//! after the token's scopes (`acme_api::check_rule_scope`).
//!
//! - A token limited by `allow_certs` names no file at all (`403 file_not_allowed`):
//!   its certificates are the stored ones it may use.
//! - No file under the certificate store or the ACME storage, nor a secret of the
//!   settings or the options, nor one on a kernel filesystem (`/proc/self/environ`)
//!   (`403 protected_file`). A PATCH is judged by the rule it makes, so a protected
//!   file an older version accepted does not stay through a PATCH of the targets.
//! - An OIDC client secret file is used only as the client secret of the same issuer
//!   and client, here and in every other rule (`409 secret_reuse`).
//! - A key or secret file (`FileRef::is_secret`) another owner's rule names (a rule of
//!   another token, of a rule set of another token, of the settings file, or one restored
//!   without a known creator) is refused unless the token has `admin` (`409 file_in_use`,
//!   #323), without saying whose. A PATCH or a rule set's PUT may keep the files the rules
//!   it replaces name already. Checks run one at a
//!   time (`CHECKS`); a change that passed registers its files (`Intent`) until it is
//!   made, so a change checked meanwhile compares with them too. The change itself
//!   (resolving names, starting the rule) holds no lock, and a change without files
//!   takes none.
//!
//! The filesystem is looked at on a blocking thread (`spawn_blocking`).

use crate::control::auth::Principal;
use crate::core::registry::Registry;
use crate::core::rule::Key;
use crate::error::ApiError;
use crate::net::protected::{self, FileRef, Owner, Resolved, Use};

/// One check at a time (the comparison and registering the `Intent`).
static CHECKS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The files of changes that passed the check and are not made yet: (id, the token, files).
static PENDING: std::sync::Mutex<Vec<(u64, String, Vec<FileRef>)>> = std::sync::Mutex::new(Vec::new());

/// The files of a change that passed, counted by later checks until it is dropped
/// (after the change is made, or refused). Empty for a change without files.
#[must_use]
pub struct Intent(Option<u64>);

impl Drop for Intent {
	fn drop(&mut self) {
		if let Some(id) = self.0 {
			PENDING.lock().unwrap_or_else(|e| e.into_inner()).retain(|(i, _, _)| *i != id);
		}
	}
}

fn register(by: &str, refs: Vec<FileRef>) -> Intent {
	use std::sync::atomic::{AtomicU64, Ordering};
	static NEXT: AtomicU64 = AtomicU64::new(1);
	let id = NEXT.fetch_add(1, Ordering::Relaxed);
	PENDING.lock().unwrap_or_else(|e| e.into_inner()).push((id, by.to_string(), refs));
	Intent(Some(id))
}

/// The rules the change replaces, whose files are left out of the comparison.
pub enum Replacing<'a> {
	Nothing,
	/// A PATCH: the rule (its files are all in the change, as the PATCH makes it).
	Rule(&'a Key),
	/// A rule set's PUT: all its rules.
	Ruleset(&'a str),
}

/// Checks the files of the rules of a change: (label for the errors, files) per rule.
pub async fn check(
	registry: &Registry,
	principal: &Principal,
	rules: Vec<(String, Vec<FileRef>)>,
	replacing: Replacing<'_>,
) -> Result<Intent, ApiError> {
	if principal.limited_to_stored_certs() {
		if let Some((label, f)) = rules.iter().find_map(|(l, refs)| refs.first().map(|f| (l, f))) {
			return Err(ApiError::file_not_allowed(format!(
				"{label}{}: this token is limited to stored certificates (allow_certs) and may not name files in rules",
				f.field
			)));
		}
		return Ok(Intent(None));
	}
	if rules.iter().all(|(_, refs)| refs.is_empty()) {
		return Ok(Intent(None));
	}
	let _one = CHECKS.lock().await;
	let global = registry.http_global();
	let crowdsec = global.crowdsec();
	let entries = protected::current(registry.acme().map(|a| a.as_ref()), crowdsec.as_ref().map(|b| b.key_file()));
	let (replaced, others): (Vec<_>, Vec<_>) = registry.file_refs().await.into_iter().partition(|(key, set, _, _)| match &replacing {
		Replacing::Nothing => false,
		Replacing::Rule(k) => *k == key,
		Replacing::Ruleset(name) => set.as_deref() == Some(*name),
	});
	// what the replaced rules name already may stay (#323)
	let kept: Vec<FileRef> = replaced.into_iter().flat_map(|(_, _, _, refs)| refs).collect();
	let existing: Vec<(String, Owner, FileRef)> = others
		.into_iter()
		.flat_map(|(key, _, owner, refs)| refs.into_iter().map(move |f| (key.to_string(), owner.clone(), f)))
		.chain(
			PENDING
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.iter()
				.flat_map(|(_, by, refs)| refs.iter().map(|f| ("being changed".to_string(), Owner::Token(by.clone()), f.clone())))
				.collect::<Vec<_>>(),
		)
		.collect();
	let mine: Vec<FileRef> = rules.iter().flat_map(|(_, refs)| refs.iter().cloned()).collect();
	// a token with admin may name any owner's files
	let who = (!principal.has(crate::control::auth::Scope::Admin)).then(|| principal.name.clone());
	tokio::task::spawn_blocking(move || judge(&entries, &rules, &existing, &kept, who.as_deref()))
		.await
		.unwrap_or_else(|e| Err(ApiError::internal(format!("checking the files did not finish: {e}"))))?;
	Ok(register(&principal.name, mine))
}

fn judge(
	entries: &[protected::Entry],
	rules: &[(String, Vec<FileRef>)],
	existing: &[(String, Owner, FileRef)],
	kept: &[FileRef],
	who: Option<&str>,
) -> Result<(), ApiError> {
	for (label, refs) in rules {
		for f in refs {
			if let Some(what) = protected::protecting(&f.path, entries) {
				return Err(ApiError::protected_file(format!(
					"{label}{}: {} is {what}; rules from the API may not name it",
					f.field, f.path
				)));
			}
		}
	}
	if let Some(name) = who {
		owners(rules, existing, kept, name)?;
	}
	let existing: Vec<(String, FileRef)> = existing.iter().map(|(rule, _, f)| (rule.clone(), f.clone())).collect();
	// OIDC client secrets: against each other and every other rule's files
	let any_client = rules
		.iter()
		.flat_map(|(_, refs)| refs)
		.chain(existing.iter().map(|(_, f)| f))
		.any(|f| f.client.is_some());
	if !any_client {
		return Ok(());
	}
	let mut uses: Vec<Use<'_>> = existing
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

/// Key and secret files of other owners' rules (#323): refused, saying nothing of the
/// other rule (its key, owner, field). Files the replaced rules name already stay.
fn owners(rules: &[(String, Vec<FileRef>)], existing: &[(String, Owner, FileRef)], kept: &[FileRef], name: &str) -> Result<(), ApiError> {
	let theirs: Vec<Resolved> = existing
		.iter()
		.filter(|(_, owner, f)| f.is_secret() && !owner.is(name))
		.map(|(_, _, f)| protected::resolve(std::path::Path::new(&f.path)))
		.collect();
	if theirs.is_empty() {
		return Ok(());
	}
	let kept: Vec<Resolved> = kept.iter().filter(|f| f.is_secret()).map(|f| protected::resolve(std::path::Path::new(&f.path))).collect();
	for (label, refs) in rules {
		for f in refs.iter().filter(|f| f.is_secret()) {
			let r = protected::resolve(std::path::Path::new(&f.path));
			if !kept.iter().any(|k| k.same(&r)) && theirs.iter().any(|t| t.same(&r)) {
				return Err(ApiError::file_in_use(format!(
					"{label}{}: {} is a key or secret file a rule of another owner names (another token's, a rule set's of another token, \
					 or the settings file's); only a token with the admin scope may name it",
					f.field, f.path
				)));
			}
		}
	}
	Ok(())
}

/// `POST /rules`.
pub async fn check_create(registry: &Registry, principal: &Principal, req: &crate::core::rule::RuleRequest) -> Result<Intent, ApiError> {
	let refs = protected::refs(req.tls.as_ref(), req.http.as_ref());
	check(registry, principal, vec![(String::new(), refs)], Replacing::Nothing).await
}

/// `PATCH /rules/...`: the rule as the PATCH makes it (every file it will name, not only
/// those in the request). A request the PATCH itself refuses is left to it.
pub async fn check_update(
	registry: &Registry,
	principal: &Principal,
	key: &Key,
	req: &crate::core::rule::UpdateRequest,
) -> Result<Intent, ApiError> {
	// a restored rule that did not validate (#327): the body the PATCH makes of it
	let refs = match registry.invalid_patched(key, req) {
		Some(body) => protected::refs(body.tls.as_ref(), body.http.as_ref()),
		None => match registry.updated_spec(key, req.clone()).await {
			Ok((_, spec, _, _)) => protected::refs(Some(&spec.tls), spec.http.as_ref()),
			Err(_) => protected::refs(req.tls.as_ref(), req.http.as_ref()),
		},
	};
	check(registry, principal, vec![(String::new(), refs)], Replacing::Rule(key)).await
}

/// `PUT /rulesets/{name}`: every rule of the set (`rules[i]: ` in the errors).
pub async fn check_ruleset(
	registry: &Registry,
	principal: &Principal,
	name: &str,
	rules: &[crate::core::rule::RuleRequest],
) -> Result<Intent, ApiError> {
	let rules: Vec<(String, Vec<FileRef>)> = rules
		.iter()
		.enumerate()
		.map(|(i, r)| (format!("rules[{i}]: "), protected::refs(r.tls.as_ref(), r.http.as_ref())))
		.collect();
	check(registry, principal, rules, Replacing::Ruleset(name)).await
}
