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
