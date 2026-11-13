// Checks of the config page (#406), part 2: what `rproxy-gateway render` made of a case's Gateway API YAML.
//
//   node scripts/check-config-page-render.mjs <out-dir> <case>
//
// Reads <out>/rendered/<case>.json (render's output) and <out>/expect/<case>.json, and fails unless
// every listener and route is Accepted and ResolvedRefs (and not Conflicted), render left no notes,
// it made rules, and the rules carry what the RproxyPolicy / RproxyMiddleware asked for. Writes the
// rules as a settings file (<out>/rendered/<case>.settings.json) for `rproxy-api --check-config`,
// with the certificate files render points at replaced by the test certificate (<out>/tls).

import fs from 'node:fs';
import path from 'node:path';

const [out, name] = process.argv.slice(2);
const rendered = JSON.parse(fs.readFileSync(path.join(out, 'rendered', `${name}.json`), 'utf8'));
const expect = JSON.parse(fs.readFileSync(path.join(out, 'expect', `${name}.json`), 'utf8'));
const problems = [];

const good = (conds) =>
	conds.every((c) => (c.type === 'Conflicted' ? c.status === 'False' : c.status === 'True')) &&
	['Accepted', 'ResolvedRefs'].every((t) => conds.some((c) => c.type === t));

const rules = [];
const sets = Object.entries(rendered);
if (sets.length !== 1) problems.push(`${sets.length} rule sets, not 1 (one Gateway)`);
for (const [set, v] of sets) {
	for (const l of v.listeners) if (!good(l.conditions)) problems.push(`${set}: listener ${l.name}: ${JSON.stringify(l.conditions)}`);
	for (const r of v.routes) if (!good(r.conditions)) problems.push(`${set}: ${r.kind} ${r.route}: ${JSON.stringify(r.conditions)}`);
	if (v.notes.length) problems.push(`${set}: notes ${JSON.stringify(v.notes)}`);
	if (v.rules.length === 0) problems.push(`${set}: no rules`);
	rules.push(...v.rules);
}
for (const field of expect.rule) if (!rules.some((r) => r[field] !== undefined)) problems.push(`no rule has ${field} (from the RproxyPolicy)`);
for (const kind of expect.middlewares) {
	if (!rules.some((r) => Object.values(r.http?.middlewares || {}).some((m) => kind in m))) problems.push(`no rule has a ${kind} middleware (from the RproxyMiddleware)`);
}

// --- the settings file's rule against render's: each recipe's fields either match, or a note says
// Gateway API cannot express them (the note ids in gen.js). A field in neither list fails.

const ms = (d) => {
	if (typeof d !== 'string') return d;
	let total = 0;
	for (const [, n, u] of d.matchAll(/([0-9.]+)(ms|s|m|h|d)/g)) total += Number(n) * { ms: 1, s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[u];
	return total;
};
// limits with durations normalised (render writes 1s as 1s, idle 12h as 43200s)
const norm = (v) =>
	v && typeof v === 'object'
		? Array.isArray(v)
			? v.map(norm)
			: Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, x]) => [k, k === 'period' ? ms(x) : norm(x)]))
		: v;
const same = (a, b) => JSON.stringify(norm(a)) === JSON.stringify(norm(b));
const sameSet = (a = [], b = []) => same([...a].sort(), [...b].sort());
const middlewares = (r) => Object.values(r?.http?.middlewares || {});
const kinds = (r) => middlewares(r).flatMap((m) => Object.keys(m));

// field → how it is compared: 'equal', 'duration', 'set', a function (s, g) → ok, or a note id that must be there
const CROSS = {
	'web-acme': {
		protocol: 'equal',
		listen_port: 'equal',
		listen_addr: 'listen_addr',
		tls: (s, g) => s.mode === g?.mode && Array.isArray(g?.certificates) && g.certificates.length > 0,
		http: (s, g, notes) => {
			if (s.http3 && !notes.includes('http3')) return false;
			if (!s.http3 && g?.http3) return false;
			const sk = kinds({ http: s }).filter((k) => k !== 'headers');
			const gk = kinds({ http: g });
			// redirect_scheme in the settings file is a redirect_regex in render
			const want = sk.map((k) => (k === 'redirect_scheme' ? 'redirect_regex' : k));
			if (!want.every((k) => gk.includes(k))) return false;
			const hsts = middlewares({ http: s }).some((m) => m.headers?.hsts);
			const gHsts = middlewares({ http: g }).some((m) => m.headers?.response?.set?.['Strict-Transport-Security']);
			if (hsts !== gHsts) return false;
			const health = Object.values(s.services || {}).some((x) => x.health_check);
			return !health || notes.includes('health_check');
		},
	},
	'db-tcp': {
		protocol: 'equal',
		listen_port: 'equal',
		listen_addr: 'listen_addr',
		remote_addr: 'backends',
		remote_port: 'backends',
		targets: 'backends',
		balance: 'backends',
		health_check: 'backends',
		connect_timeout: 'duration',
		idle_timeout: 'duration',
		allow_from: 'set',
		limits: 'equal',
	},
	'game-udp': {
		protocol: 'equal',
		listen_port: 'equal',
		listen_addr: 'listen_addr',
		extra_listen_addrs: 'extra_listen_addrs',
		remote_addr: 'backends',
		remote_port: 'backends',
		udp_idle_secs: 'udp_idle_secs',
		limits: 'equal',
	},
	'sni-split': {
		protocol: 'equal',
		listen_port: 'equal',
		listen_addr: 'listen_addr',
		tls: (s, g, notes) => {
			if (s.mode !== g?.mode) return false;
			const pt = (t) => (t?.routes || []).filter((r) => r.passthrough);
			const [sp, gp] = [pt(s), pt(g)];
			// rproxy's *.x is one level; Gateway API's *.x (render: **.x) any depth
			const names = (rs, wide) => rs.flatMap((r) => r.server_names || [r.server_name]).map((n) => (wide ? n.replace(/^\*\./, '**.') : n));
			const widened = !sameSet(names(sp), names(sp, true));
			if (widened && !notes.includes('server_names')) return false;
			if (!sameSet(names(sp, true), names(gp))) return false;
			if (sp.some((r) => r.source_ip && r.source_ip !== 'proxy') && !notes.includes('source_ip')) return false;
			// the port of the target; its address is a pod's
			return sp.every((r) => gp.some((x) => (x.targets || []).some((t) => t.port === r.remote_port)));
		},
		http: (s, g, notes) => {
			const hosts = (h) => (h?.routes || []).map((r) => /Host\(`([^`]+)`\)/.exec(r.match)?.[1]);
			if (!sameSet(hosts(s), hosts(g))) return false;
			if (s.default && s.default.status !== 404 && !notes.includes('default')) return false;
			return true;
		},
	},
};

const key = (r) => `${r.protocol}/${r.listen_port}`;
const cross = CROSS[expect.recipe];
if (!cross) problems.push(`no cross-output mapping for the recipe ${expect.recipe}`);
for (const s of cross ? expect.settings : []) {
	const g = rules.find((r) => key(r) === key(s));
	if (!g) {
		problems.push(`the settings file's ${key(s)} rule has no rule from render`);
		continue;
	}
	for (const [field, value] of Object.entries(s)) {
		const how = cross[field];
		const ok =
			how === 'equal'
				? same(value, g[field])
				: how === 'duration'
					? ms(value) === ms(g[field])
					: how === 'set'
						? sameSet(value, g[field])
						: typeof how === 'function'
							? how(value, g[field], expect.notes)
							: typeof how === 'string'
								? expect.notes.includes(how) || (field === 'listen_addr' && ['0.0.0.0', '::'].includes(value))
								: false;
		if (!ok) problems.push(`${key(s)}.${field}: ${how === undefined ? 'no cross-output mapping for this field' : `the Gateway API output differs (${JSON.stringify(value)} / ${JSON.stringify(g[field])}) and no note says why`}`);
	}
}
for (const g of rules) if (cross && !expect.settings.some((s) => key(s) === key(g))) problems.push(`render made ${key(g)}, which the settings file does not have`);

// render's certificate files are the Secrets' contents: the test certificate
const tls = path.resolve(out, 'tls');
const text = JSON.stringify({ version: 1, rules }, null, 2)
	.replace(/"\/var\/run\/rproxy-gateway\/certs\/[0-9a-f]+\.crt"/g, JSON.stringify(path.join(tls, 'example.pem')))
	.replace(/"\/var\/run\/rproxy-gateway\/certs\/[0-9a-f]+\.key"/g, JSON.stringify(path.join(tls, 'example.key')));
fs.writeFileSync(path.join(out, 'rendered', `${name}.settings.json`), text);

if (problems.length) {
	for (const p of problems) console.error(`FAIL ${name} (render): ${p}`);
	process.exit(1);
}
