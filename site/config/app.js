// The config page's UI (#406): the form, the three outputs, copy, Japanese / English.
// Everything is made in the browser by gen.js; nothing is sent anywhere (the page's CSP has connect-src 'none').

import { RECIPES, defaults, generate, sectionLabel, sectionUrl } from './gen.js';

const UI = {
	title: { ja: 'rproxy 設定ジェネレータ', en: 'rproxy config generator' },
	lead: {
		ja: 'やりたいことを選び、ポートや転送先を入れると、同じ中身を 3 つの形で出します：rproxy の設定ファイル、制御 API の curl、Kubernetes の Gateway API。',
		en: 'Pick what you want to do and fill in ports and targets. The page writes the same setup in three forms: an rproxy settings file, control API curl commands, and Kubernetes Gateway API.',
	},
	privacy: {
		ja: 'すべてこのブラウザの中で作り、どこにも送りません。トークンや鍵は入れません（パスと <token> のような置き場所だけ）。',
		en: 'Everything is made in this browser and sent nowhere. No tokens or keys go in (only paths and placeholders such as <token>).',
	},
	footer: {
		ja: '出力は CI で rproxy-api --check-config・docs/openapi.json・Gateway API と rproxy の CRD・rproxy-gateway render に通しています。使う前に自分の環境でも確かめてください。',
		en: 'CI runs the outputs through rproxy-api --check-config, docs/openapi.json, the Gateway API and rproxy CRDs, and rproxy-gateway render. Check them in your own setup before use too.',
	},
	copy: { ja: 'コピー', en: 'Copy' },
	copied: { ja: 'コピーしました', en: 'Copied' },
	copyFailed: { ja: 'コピーできません。選んでコピーしてください', en: 'Could not copy; select the text and copy it' },
	guide: { ja: 'ガイド', en: 'Guide' },
	recipeGuide: { ja: 'このレシピの説明', en: 'This recipe in the guide' },
	reset: { ja: '既定に戻す', en: 'Reset' },
	errors: { ja: '入力を直してください（出力は今の入力のまま作っています）', en: 'Please fix the input (the outputs still follow it as it is)' },
	groups: {
		rproxy: { ja: 'rproxy のルール', en: 'The rproxy rule' },
		k8s: { ja: 'Kubernetes（Gateway API の出力だけ）', en: 'Kubernetes (the Gateway API output only)' },
		api: { ja: '制御 API（curl の出力だけ）', en: 'Control API (the curl output only)' },
	},
	tabs: {
		settings: { ja: '設定ファイル（YAML）', en: 'Settings file (YAML)' },
		api: { ja: '制御 API（curl）', en: 'Control API (curl)' },
		gateway: { ja: 'Gateway API（YAML）', en: 'Gateway API (YAML)' },
	},
	tabnotes: {
		settings: {
			ja: '/etc/rproxy/rproxy.yaml などに置き、RPROXY_CONFIG で指します。ファイルを変えると自動で読み直します。',
			en: 'Put it in /etc/rproxy/rproxy.yaml or similar and point RPROXY_CONFIG at it. rproxy re-reads the file when it changes.',
		},
		api: {
			ja: '動いている rproxy にルールを作ります。同じキーのルールが設定ファイルにあると 409 になります。',
			en: 'Creates the rules in a running rproxy. A rule with the same key in the settings file gives 409.',
		},
		gateway: {
			ja: 'rproxy-gateway を入れたクラスタに kubectl apply -f で当てます。',
			en: 'Apply it with kubectl apply -f to a cluster with rproxy-gateway installed.',
		},
	},
	tabGuides: { settings: 'api:2.1', api: 'api:2.3', gateway: 'gw:2.2' },
};

const state = { lang: 'ja', recipe: RECIPES[0].id, tab: 'settings', input: {} };

const store = {
	get(k) {
		try {
			return localStorage.getItem(k);
		} catch {
			return null;
		}
	},
	set(k, v) {
		try {
			localStorage.setItem(k, v);
		} catch {
			/* private windows: only a convenience */
		}
	},
};

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
	const e = document.createElement(tag);
	for (const [k, v] of Object.entries(attrs)) {
		if (k === 'class') e.className = v;
		else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
		else if (v !== undefined && v !== false) e.setAttribute(k, v === true ? '' : v);
	}
	for (const k of kids) if (k !== null && k !== undefined) e.append(k);
	return e;
};
const L = (o) => o[state.lang];

function guideLink(key, text) {
	return el('a', { href: sectionUrl(key, state.lang), target: '_blank', rel: 'noopener', class: 'guide', title: sectionLabel(key) }, text ?? sectionLabel(key).replace('rproxy-gateway GUIDE', 'gateway'));
}

function renderStatic() {
	document.documentElement.lang = state.lang;
	document.title = L(UI.title);
	for (const n of document.querySelectorAll('[data-t]')) n.textContent = L(UI[n.dataset.t]);
	for (const b of document.querySelectorAll('[data-lang]')) b.setAttribute('aria-pressed', String(b.dataset.lang === state.lang));
}

function renderRecipes() {
	const nav = $('recipes');
	nav.replaceChildren(
		...RECIPES.map((r) =>
			el(
				'button',
				{
					type: 'button',
					class: 'recipe-btn',
					'aria-pressed': String(r.id === state.recipe),
					onclick: () => {
						state.recipe = r.id;
						state.input = defaults(r.id);
						history.replaceState(null, '', `#${r.id}`);
						renderAll();
					},
				},
				L(r.title),
			),
		),
	);
}

function field(f) {
	const id = `f-${f.id}`;
	const value = state.input[f.id];
	const onInput = (e) => {
		const t = e.target;
		state.input[f.id] = t.type === 'checkbox' ? t.checked : t.value;
		renderOutput();
	};
	let control;
	if (f.type === 'select') {
		control = el('select', { id, oninput: onInput }, ...f.options.map((o) => el('option', { value: o, selected: String(value) === o }, o)));
	} else if (f.type === 'checkbox') {
		control = el('input', { id, type: 'checkbox', checked: !!value, oninput: onInput });
	} else if (f.type === 'lines') {
		control = el('textarea', { id, rows: Math.max(2, String(value).split('\n').length), spellcheck: 'false', oninput: onInput });
		control.value = value;
	} else {
		control = el('input', { id, type: 'text', inputmode: f.type === 'number' ? 'numeric' : undefined, spellcheck: 'false', oninput: onInput });
		control.value = value ?? '';
	}
	const help = L(f.help);
	return el(
		'div',
		{ class: `field ${f.type === 'checkbox' ? 'check' : ''}` },
		el('label', { for: id }, L(f.label)),
		control,
		el('div', { class: 'meta' }, help ? el('span', { class: 'help' }, help) : null, f.link ? guideLink(f.link) : null),
	);
}

function renderForm() {
	const r = RECIPES.find((x) => x.id === state.recipe);
	$('intro').replaceChildren(L(r.intro), ' ', guideLink(r.guide, L(UI.recipeGuide)), ' · ', guideLink(r.gwGuide, 'Gateway API'));
	const form = $('form');
	const groups = ['rproxy', 'k8s', 'api'].map((g) => {
		const fs = r.fields.filter((f) => f.group === g);
		return fs.length ? el('fieldset', { class: `group ${g}` }, el('legend', {}, L(UI.groups[g])), ...fs.map(field)) : null;
	});
	const reset = el('button', { type: 'button', class: 'reset', onclick: () => ((state.input = defaults(r.id)), renderAll()) }, L(UI.reset));
	form.replaceChildren(...groups.filter(Boolean), reset);
}

function renderTabs() {
	$('tabs').replaceChildren(
		...Object.keys(UI.tabs).map((k) =>
			el(
				'button',
				{
					type: 'button',
					role: 'tab',
					'aria-selected': String(k === state.tab),
					onclick: () => {
						state.tab = k;
						renderTabs();
						renderOutput();
					},
				},
				L(UI.tabs[k]),
			),
		),
	);
}

let last = null;
function renderOutput() {
	last = generate(state.recipe, state.input, state.lang);
	const errs = $('errors');
	errs.hidden = last.errors.length === 0;
	errs.replaceChildren(...(last.errors.length ? [el('li', { class: 'head' }, L(UI.errors)), ...last.errors.map((e) => el('li', {}, e))] : []));
	$('tabnote').replaceChildren(L(UI.tabnotes[state.tab]), ' ', guideLink(UI.tabGuides[state.tab]));
	$('code').textContent = last[state.tab];
}

function renderAll() {
	renderStatic();
	renderRecipes();
	renderForm();
	renderTabs();
	renderOutput();
}

async function copy() {
	const btn = $('copy');
	const text = last ? last[state.tab] : '';
	let ok = false;
	try {
		await navigator.clipboard.writeText(text);
		ok = true;
	} catch {
		// older browsers and non-secure contexts: select the text instead
		const range = document.createRange();
		range.selectNodeContents($('code'));
		const sel = getSelection();
		sel.removeAllRanges();
		sel.addRange(range);
		try {
			ok = document.execCommand('copy');
		} catch {
			ok = false;
		}
	}
	btn.textContent = L(ok ? UI.copied : UI.copyFailed);
	setTimeout(() => (btn.textContent = L(UI.copy)), 1500);
}

function start() {
	const saved = store.get('rproxy-config-lang');
	state.lang = saved === 'en' || saved === 'ja' ? saved : (navigator.language || '').startsWith('ja') ? 'ja' : 'en';
	const fromHash = location.hash.slice(1);
	if (RECIPES.some((r) => r.id === fromHash)) state.recipe = fromHash;
	state.input = defaults(state.recipe);
	for (const b of document.querySelectorAll('[data-lang]')) {
		b.addEventListener('click', () => {
			state.lang = b.dataset.lang;
			store.set('rproxy-config-lang', state.lang);
			renderAll();
		});
	}
	$('copy').addEventListener('click', copy);
	renderAll();
}

start();
