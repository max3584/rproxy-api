// Checks of the config page's generator (site/config/gen.js, #406), part 1 (Node, no network):
//
//   node scripts/check-config-page.mjs <out-dir> [rproxy-gateway GUIDE.md] [its en/GUIDE.md]
//
// - runs every recipe on its default input and a few variations, in Japanese and English;
// - checks the rules and global.acme it makes against docs/openapi.json (no field that is not there);
// - checks the guide anchors the page links to against the headings of the guides;
// - writes the outputs for scripts/check-config-page.sh, which runs them through
//   `rproxy-api --check-config`, kubeconform and `rproxy-gateway render`:
//     <out>/settings/<case>.yaml   the settings file as shown on the page
//     <out>/api/<case>.json        a settings file made of the JSON in the page's curl commands
//     <out>/gateway/<case>.yaml    the Gateway API YAML as shown on the page
//     <out>/world/<case>.yaml      the same plus the Services, EndpointSlices and Secrets render needs
//     <out>/expect/<case>.json     what the rendered rules must have (from the RproxyPolicy / RproxyMiddleware)
// The sni-split recipe's certificate paths are replaced by <out>/tls/example.{pem,key}, which the shell
// script creates (--check-config reads them).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RECIPES, SECTIONS, generate } from '../site/config/gen.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [out, gwJa, gwEn] = process.argv.slice(2);
if (!out) {
	console.error('usage: check-config-page.mjs <out-dir> [rproxy-gateway docs/GUIDE.md] [docs/en/GUIDE.md]');
	process.exit(2);
}
let failed = 0;
const fail = (m) => {
	failed++;
	console.error(`FAIL ${m}`);
};

// --- the cases ---------------------------------------------------------------

const VARIATIONS = {
	'web-acme': [
		{},
		{ challenge: 'tls-alpn-01', staging: true, http3: false, hsts: false, compress: false, health_path: '' },
		{ domain: 'shop.example.org', email: 'ops@example.org', app_url: 'https://10.0.0.7:8443', listen_addr: '::', service: 'shop', service_port: 443, namespace: 'web', gateway: 'public' },
	],
	'db-tcp': [
		{},
		{ targets: '10.0.1.11:5432', balance: 'round_robin', health_interval: '', connect_timeout: '', allow_from: '', max_connections: '' },
		{ listen_addr: '::', listen_port: 3306, targets: '[2001:db8::11]:3306, [2001:db8::12]:3306', balance: 'least_conn', idle_timeout: '0s', allow_from: '10.0.0.0/8\n2001:db8::/32', service: 'mysql', service_port: 3306 },
	],
	'game-udp': [
		{},
		{ ipv6: false, udp_idle_secs: '', max_sessions: '', per_source_sessions: '', packets_average: '' },
		{ listen_port: 7777, remote_addr: '2001:db8::80', remote_port: 7777, packets_average: 50, packets_burst: '', service_port: 7777 },
	],
	'sni-split': [
		{},
		{ source_ip: 'proxy', passthrough_names: '', sites: 'app.example.com http://10.0.0.5:8080' },
		{ passthrough_names: '*.a.example.com\n**.b.example.com', passthrough_target: '[2001:db8::131]:8443', source_ip: 'proxy_v1', default_status: 421, sites: 'wiki.example.com http://10.0.0.5:8080\ndocs.example.com https://10.0.0.9' },
	],
};
const BAD = [
	['db-tcp', { listen_port: 70000 }],
	['db-tcp', { targets: '10.0.1.11' }],
	['game-udp', { packets_average: 10, packets_burst: 5 }],
	['web-acme', { email: 'nobody' }],
	['sni-split', { sites: 'wiki.example.com' }],
];

for (const r of RECIPES) {
	if (!VARIATIONS[r.id]) fail(`${r.id}: no variations in scripts/check-config-page.mjs`);
	for (const f of r.fields) if (f.link && !SECTIONS[f.link]) fail(`${r.id}.${f.id}: unknown guide section ${f.link}`);
}

// --- docs/openapi.json: a small JSON Schema check ----------------------------

const openapi = JSON.parse(fs.readFileSync(path.join(root, 'docs/openapi.json'), 'utf8'));
const schemas = openapi.components.schemas;
const deref = (s) => (s && s.$ref ? deref(schemas[s.$ref.split('/').pop()]) : s);
const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v);

// errors of v against schema s (unknown keys are errors wherever the schema lists properties)
function validate(v, s, at, errs) {
	s = deref(s);
	if (!s) return errs;
	if (s.oneOf || s.anyOf) {
		const ok = (s.oneOf || s.anyOf).some((b) => validate(v, b, at, []).length === 0);
		if (!ok) errs.push(`${at}: matches none of the allowed shapes`);
		return errs;
	}
	if (s.type) {
		const types = [].concat(s.type);
		const t = typeOf(v);
		if (!types.includes(t) && !(t === 'integer' && types.includes('number')) && !(v === null && s.nullable)) {
			errs.push(`${at}: ${t}, not ${types.join('|')}`);
			return errs;
		}
	}
	if (s.enum && !s.enum.includes(v)) errs.push(`${at}: ${JSON.stringify(v)} is not one of ${s.enum.join(', ')}`);
	if (typeof v === 'number') {
		if (s.minimum !== undefined && v < s.minimum) errs.push(`${at}: below ${s.minimum}`);
		if (s.maximum !== undefined && v > s.maximum) errs.push(`${at}: above ${s.maximum}`);
	}
	if (Array.isArray(v)) {
		if (s.maxItems !== undefined && v.length > s.maxItems) errs.push(`${at}: more than ${s.maxItems} items`);
		v.forEach((x, i) => validate(x, s.items, `${at}[${i}]`, errs));
	} else if (v && typeof v === 'object') {
		for (const k of s.required || []) if (!(k in v)) errs.push(`${at}: ${k} is required`);
		const props = s.properties || {};
		for (const [k, x] of Object.entries(v)) {
			if (k in props) validate(x, props[k], `${at}.${k}`, errs);
			else if (s.additionalProperties && typeof s.additionalProperties === 'object') validate(x, s.additionalProperties, `${at}.${k}`, errs);
			else if (Object.keys(props).length > 0 || s.additionalProperties === false) errs.push(`${at}.${k}: not in docs/openapi.json`);
		}
	}
	return errs;
}

// --- the guides' anchors ------------------------------------------------------

// GitHub's heading ids (github-slugger): lower case, punctuation removed, spaces to hyphens
const slug = (h) => h.trim().toLowerCase().replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, '').replace(/ /g, '-');
function anchors(file) {
	const text = fs.readFileSync(file, 'utf8');
	const set = new Set();
	let fence = false;
	for (const line of text.split('\n')) {
		if (line.startsWith('```')) fence = !fence;
		const m = !fence && /^#{1,6} (.*)/.exec(line);
		if (m) set.add(slug(m[1]));
	}
	// the slug function must agree with the guide's own links to itself
	for (const m of text.matchAll(/\]\(#([^)]+)\)/g)) if (!set.has(m[1])) fail(`${file}: the guide links to #${m[1]}, which the slug function does not make`);
	return set;
}
const guides = { api: { ja: anchors(path.join(root, 'docs/GUIDE.md')), en: anchors(path.join(root, 'docs/en/GUIDE.md')) } };
if (gwJa && gwEn) guides.gw = { ja: anchors(gwJa), en: anchors(gwEn) };
else console.warn('note: no rproxy-gateway guides given; its anchors are not checked');
for (const [key, [doc, , ja, en]] of Object.entries(SECTIONS)) {
	if (!guides[doc]) continue;
	if (!guides[doc].ja.has(ja)) fail(`guide section ${key}: no heading #${ja} in the Japanese guide`);
	if (!guides[doc].en.has(en)) fail(`guide section ${key}: no heading #${en} in the English guide`);
}

// --- the API text → a settings file ------------------------------------------

// the curl commands as the page shows them: -X METHOD "URL" and -d '<json>' (single quotes, '\'' inside)
function apiCalls(text) {
	const calls = [];
	const re = /-X (\w+) "([^"]+)" \\\n {2}-d '((?:[^']|'\\'')*)'/g;
	for (const m of text.matchAll(re)) calls.push({ method: m[1], url: m[2], body: JSON.parse(m[3].replace(/'\\''/g, "'")) });
	return calls;
}

function apiSettings(calls, at) {
	const doc = { version: 1, rules: [] };
	for (const c of calls) {
		const p = new URL(c.url).pathname;
		if (c.method === 'POST' && p === '/rules') {
			for (const e of validate(c.body, schemas.RuleRequest, 'POST /rules', [])) fail(`${at}: ${e}`);
			doc.rules.push(c.body);
		} else if (c.method === 'PATCH' && p === '/config/global') {
			for (const e of validate(c.body, schemas.GlobalPatch, 'PATCH /config/global', [])) fail(`${at}: ${e}`);
			doc.global = { ...doc.global, ...c.body };
		} else fail(`${at}: ${c.method} ${p} is not a call this check knows`);
	}
	return doc;
}

// --- render's world: Services, EndpointSlices, Secrets ------------------------

function world(docs, ns, certPem, keyPem) {
	const extra = [{ apiVersion: 'gateway.networking.k8s.io/v1', kind: 'GatewayClass', metadata: { name: 'rproxy' }, spec: { controllerName: 'rproxy.max3584.net/gateway-controller' } }];
	const services = new Map();
	const secrets = new Set();
	for (const d of docs) {
		const proto = d.kind === 'UDPRoute' ? 'UDP' : 'TCP';
		for (const rule of d.spec?.rules || []) for (const b of rule.backendRefs || []) services.set(`${b.name}/${b.port}/${proto}`, b);
		for (const l of d.kind === 'Gateway' ? d.spec.listeners : []) for (const c of l.tls?.certificateRefs || []) secrets.add(c.name);
		if (d.kind === 'Certificate') secrets.add(d.spec.secretName);
	}
	let ip = 10;
	for (const key of services.keys()) {
		const [name, port, proto] = key.split('/');
		extra.push({ apiVersion: 'v1', kind: 'Service', metadata: { name, namespace: ns }, spec: { ports: [{ name: 'p', port: Number(port), protocol: proto }] } });
		extra.push({
			apiVersion: 'discovery.k8s.io/v1',
			kind: 'EndpointSlice',
			metadata: { name: `${name}-${proto.toLowerCase()}`, namespace: ns, labels: { 'kubernetes.io/service-name': name } },
			addressType: 'IPv4',
			ports: [{ name: 'p', port: Number(port), protocol: proto }],
			endpoints: [{ addresses: [`10.244.0.${ip++}`], conditions: { ready: true } }],
		});
	}
	for (const name of secrets) {
		extra.push({
			apiVersion: 'v1',
			kind: 'Secret',
			metadata: { name, namespace: ns },
			type: 'kubernetes.io/tls',
			data: { 'tls.crt': Buffer.from(certPem).toString('base64'), 'tls.key': Buffer.from(keyPem).toString('base64') },
		});
	}
	// JSON is YAML: render reads streams of documents
	return extra.map((d) => JSON.stringify(d)).join('\n---\n') + '\n';
}

function expectations(docs) {
	const e = { rule: [], middlewares: [] };
	for (const d of docs) {
		if (d.kind === 'RproxyPolicy') {
			const map = { allowFrom: 'allow_from', limits: 'limits', connectTimeout: 'connect_timeout', idleTimeout: 'idle_timeout' };
			for (const [k, v] of Object.entries(map)) if (d.spec[k] !== undefined) e.rule.push(v);
		}
		if (d.kind === 'RproxyMiddleware') e.middlewares.push(Object.keys(d.spec)[0]);
	}
	return e;
}

// --- run ----------------------------------------------------------------------

for (const dir of ['settings', 'api', 'gateway', 'world', 'expect', 'tls']) fs.mkdirSync(path.join(out, dir), { recursive: true });
const certFile = path.resolve(out, 'tls/example.pem');
const keyFile = path.resolve(out, 'tls/example.key');
const certPem = fs.existsSync(certFile) ? fs.readFileSync(certFile, 'utf8') : '';
const keyPem = fs.existsSync(keyFile) ? fs.readFileSync(keyFile, 'utf8') : '';
if (!certPem) console.warn(`note: ${certFile} does not exist yet; the Secrets for render are empty`);

let cases = 0;
for (const r of RECIPES) {
	for (const [i, variation] of (VARIATIONS[r.id] || []).entries()) {
		for (const lang of ['ja', 'en']) {
			const name = `${r.id}-${i}-${lang}`;
			const input = { ...variation };
			if (r.id === 'sni-split') Object.assign(input, { cert_file: certFile, key_file: keyFile });
			const o = generate(r.id, input, lang);
			cases++;
			if (o.errors.length) fail(`${name}: the generator reports ${o.errors.join('; ')}`);
			for (const [k, rule] of o.data.settings.rules.entries()) for (const e of validate(rule, schemas.RuleRequest, `rules[${k}]`, [])) fail(`${name} (settings): ${e}`);
			if (o.data.settings.global?.acme) for (const e of validate(o.data.settings.global, schemas.GlobalPatch, 'global', [])) fail(`${name} (settings): ${e}`);
			const calls = apiCalls(o.api);
			if (calls.length !== o.data.api.length) fail(`${name}: found ${calls.length} curl commands in the text, the generator made ${o.data.api.length}`);
			if (JSON.stringify(calls.map((c) => c.body)) !== JSON.stringify(o.data.api.map((c) => c.body))) fail(`${name}: the curl text does not carry the generator's JSON`);
			const docs = o.data.gateway;
			const ns = docs.find((d) => d.kind === 'Gateway').metadata.namespace;
			fs.writeFileSync(path.join(out, 'settings', `${name}.yaml`), o.settings);
			fs.writeFileSync(path.join(out, 'api', `${name}.json`), JSON.stringify(apiSettings(calls, name), null, 2));
			fs.writeFileSync(path.join(out, 'gateway', `${name}.yaml`), o.gateway);
			fs.writeFileSync(path.join(out, 'world', `${name}.yaml`), world(docs, ns, certPem, keyPem));
			fs.writeFileSync(path.join(out, 'expect', `${name}.json`), JSON.stringify(expectations(docs)));
		}
	}
}
for (const [id, input] of BAD) {
	if (generate(id, input, 'en').errors.length === 0) fail(`${id} ${JSON.stringify(input)}: the generator accepts a wrong input`);
}

console.log(`${cases} cases written to ${out}${failed ? `, ${failed} failure(s)` : ''}`);
process.exit(failed ? 1 : 0);
