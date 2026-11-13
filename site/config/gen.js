// The config page's generator (#406): pure functions, no DOM, no network.
// The page (app.js) and the CI check (scripts/check-config-page.mjs) both import it,
// so what the page shows is what CI runs through `rproxy-api --check-config`,
// docs/openapi.json, the Gateway API / rproxy CRD schemas and `rproxy-gateway render`.
//
// Field names come from docs/openapi.json (rules, global) and from the CRDs of
// Gateway API v1.6 (standard), rproxy-gateway (RproxyPolicy, RproxyMiddleware)
// and cert-manager (ClusterIssuer, Certificate). Do not add a field here without
// finding it there.

const API_GUIDE = { ja: 'https://github.com/max3584/rproxy-api/blob/master/docs/GUIDE.md', en: 'https://github.com/max3584/rproxy-api/blob/master/docs/en/GUIDE.md' };
const GW_GUIDE = { ja: 'https://github.com/max3584/rproxy-gateway/blob/main/docs/GUIDE.md', en: 'https://github.com/max3584/rproxy-gateway/blob/main/docs/en/GUIDE.md' };

// Guide sections the page links to: [doc, section, ja anchor, en anchor].
// CI checks that every anchor is a heading of the guide (scripts/check-config-page.mjs).
export const SECTIONS = {
	'api:1.5': ['api', '1.5', '15-制御-api-の-unix-ソケットを開く', '15-opening-the-control-apis-unix-socket'],
	'api:2.1': ['api', '2.1', '21-設定ファイルで書く', '21-in-the-settings-file'],
	'api:2.3': ['api', '2.3', '23-制御-api-で作る', '23-through-the-control-api'],
	'api:3.1': ['api', '3.1', '31-udp', '31-udp'],
	'api:3.3': ['api', '3.3', '33-待ち受けのアドレスを複数にする', '33-several-listen-addresses'],
	'api:3.4': ['api', '3.4', '34-宛先を複数にする振り分けと切り替え', '34-several-targets-balancing-and-failover'],
	'api:3.5': ['api', '3.5', '35-ルール全体の接続の上限', '35-connection-limits-for-the-whole-rule'],
	'api:3.6': ['api', '3.6', '36-長く黙る接続', '36-connections-that-stay-quiet-for-long'],
	'api:4.1': ['api', '4.1', '41-名前で振り分けるsni', '41-routing-by-name-sni'],
	'api:4.2': ['api', '4.2', '42-終端するterminate', '42-terminating-terminate'],
	'api:4.6': ['api', '4.6', '46-自動の証明書acme', '46-automatic-certificates-acme'],
	'api:5.1': ['api', '5.1', '51-ルートサービスミドルウェア', '51-routes-services-and-middlewares'],
	'api:5.2': ['api', '5.2', '52-よく使うミドルウェア', '52-common-middlewares'],
	'api:5.3': ['api', '5.3', '53-80-番から-https-へ', '53-from-port-80-to-https'],
	'api:5.4': ['api', '5.4', '54-http3', '54-http3'],
	'api:6': ['api', '6.', '6-送信元-ip', '6-source-ip'],
	'api:7.1': ['api', '7.1', '71-トークン', '71-tokens'],
	'api:8': ['api', '8.', '8-global-の設定', '8-global-settings'],
	'api:10.3': ['api', '10.3', '103-dry-run', '103-dry-run'],
	'api:17.1': ['api', '17.1', '171-web-アプリを-https-で公開するacme', '171-a-web-app-over-https-acme'],
	'api:17.2': ['api', '17.2', '172-db-を-tcp-で中継する長く黙る接続', '172-a-tcp-proxy-for-a-database-long-idle-connections'],
	'api:17.3': ['api', '17.3', '173-udp-のゲームサーバ', '173-a-udp-game-server'],
	'api:17.4': ['api', '17.4', '174-1-つの-443-を名前で分ける', '174-splitting-one-443-by-name'],
	'gw:1.1': ['gw', '1.1', '11-gateway-api-の-crd', '11-gateway-apis-crds'],
	'gw:2.2': ['gw', '2.2', '22-gateway-と-httproute', '22-gateway-and-httproute'],
	'gw:3.1': ['gw', '3.1', '31-tls-の-secret-を-certificaterefs-で', '31-a-tls-secret-in-certificaterefs'],
	'gw:3.2': ['gw', '3.2', '32-cert-manager', '32-cert-manager'],
	'gw:3.3': ['gw', '3.3', '33-http-から-https-へリダイレクト', '33-redirect-http-to-https'],
	'gw:5.1': ['gw', '5.1', '51-tcproute-と-udproute', '51-tcproute-and-udproute'],
	'gw:5.2': ['gw', '5.2', '52-tlsroutepassthrough-と-terminate', '52-tlsroute-passthrough-and-terminate'],
	'gw:8.1': ['gw', '8.1', '81-rproxypolicy', '81-rproxypolicy'],
	'gw:8.2': ['gw', '8.2', '82-rproxymiddleware', '82-rproxymiddleware'],
	'gw:8.3': ['gw', '8.3', '83-rproxyrule', '83-rproxyrule'],
	'gw:14.1': ['gw', '14.1', '141-https-の-web-アプリcert-manager', '141-a-web-app-with-https-and-cert-manager'],
	'gw:14.2': ['gw', '14.2', '142-db-への-tcp長い-idletimeout', '142-tcp-to-a-db-with-a-long-idletimeout'],
	'gw:14.3': ['gw', '14.3', '143-udp', '143-udp'],
	'gw:14.4': ['gw', '14.4', '144-443-で-sni-の-passthrough', '144-sni-passthrough-on-443'],
};

/** The URL of a guide section in a language ('ja' | 'en'). */
export function sectionUrl(key, lang) {
	const s = SECTIONS[key];
	if (!s) throw new Error(`unknown guide section ${key}`);
	const base = (s[0] === 'api' ? API_GUIDE : GW_GUIDE)[lang];
	return `${base}#${lang === 'en' ? s[3] : s[2]}`;
}

/** The short name of a guide section ("GUIDE 4.6", "gateway 8.1"). */
export function sectionLabel(key) {
	const s = SECTIONS[key];
	return `${s[0] === 'api' ? 'GUIDE' : 'rproxy-gateway GUIDE'} ${s[1]}`;
}

// ---------------------------------------------------------------------------
// The recipes and their fields
//
// A field: {id, type: text | number | select | checkbox | lines, def, label: {ja, en},
// help: {ja, en}, link: a SECTIONS key, group: 'rproxy' | 'k8s' | 'api'}.
// 'lines' is one value per line (also split at commas).

const t = (ja, en) => ({ ja, en });

const K8S_FIELDS = (gateway) => [
	{ id: 'namespace', type: 'text', def: 'default', group: 'k8s', label: t('namespace', 'Namespace'), help: t('Gateway とルートを置く namespace', 'Where the Gateway and the routes live'), link: 'gw:2.2' },
	{ id: 'gateway', type: 'text', def: gateway, group: 'k8s', label: t('Gateway の名前', 'Gateway name'), help: t('', ''), link: 'gw:2.2' },
	{ id: 'gateway_class', type: 'text', def: 'rproxy', group: 'k8s', label: t('GatewayClass', 'GatewayClass'), help: t('rproxy-gateway の chart が作るクラス', 'The class the rproxy-gateway chart makes'), link: 'gw:2.2' },
];

const API_FIELDS = [
	{ id: 'api_url', type: 'text', def: 'http://127.0.0.1:8080', group: 'api', label: t('制御 API の URL', 'Control API URL'), help: t('RPROXY_API_ADDR と RPROXY_API_PORT', 'RPROXY_API_ADDR and RPROXY_API_PORT'), link: 'api:2.3' },
];

const SOCKET_FIELD = { id: 'api_socket', type: 'text', def: '/run/rproxy/api.sock', group: 'api', label: t('制御 API の Unix ソケット', 'Control API Unix socket'), help: t('global の ACME はソケットからだけ変えられます', 'global ACME changes only through the socket'), link: 'api:1.5' };

export const RECIPES = [
	{
		id: 'web-acme',
		title: t('HTTPS の Web アプリ（ACME）', 'Web app over HTTPS (ACME)'),
		intro: t(
			'Web アプリを Let\'s Encrypt の証明書で HTTPS にして公開します。80 番は HTTPS へリダイレクトします。',
			'Publish a web app over HTTPS with a Let\'s Encrypt certificate. Port 80 redirects to HTTPS.',
		),
		guide: 'api:17.1',
		gwGuide: 'gw:14.1',
		fields: [
			{ id: 'domain', type: 'text', def: 'app.example.com', group: 'rproxy', label: t('ドメイン', 'Domain'), help: t('証明書の名前。DNS をこのホストに向けておきます', 'The certificate\'s name; point its DNS at this host'), link: 'api:4.6' },
			{ id: 'email', type: 'text', def: 'admin@example.com', group: 'rproxy', label: t('ACME の連絡先のメール', 'ACME contact email'), help: t('CA からの連絡先', 'Where the CA writes to'), link: 'api:4.6' },
			{ id: 'challenge', type: 'select', def: 'http-01', options: ['http-01', 'tls-alpn-01'], group: 'rproxy', label: t('ACME の確かめ方', 'ACME challenge'), help: t('http-01 は 80 番、tls-alpn-01 は 443 番で答えます', 'http-01 answers on port 80, tls-alpn-01 on 443'), link: 'api:4.6' },
			{ id: 'staging', type: 'checkbox', def: false, group: 'rproxy', label: t('Let\'s Encrypt の staging で試す', 'Try with Let\'s Encrypt staging'), help: t('本番の回数の制限に当たりません', 'Avoids the production rate limits'), link: 'api:4.6' },
			{ id: 'listen_addr', type: 'text', def: '0.0.0.0', group: 'rproxy', label: t('待ち受けのアドレス', 'Listen address'), help: t('0.0.0.0 はすべての IPv4', '0.0.0.0 is every IPv4 address'), link: 'api:2.1' },
			{ id: 'app_url', type: 'text', def: 'http://127.0.0.1:3000', group: 'rproxy', label: t('アプリの URL', 'App URL'), help: t('rproxy から見たアプリ', 'The app as rproxy reaches it'), link: 'api:5.1' },
			{ id: 'health_path', type: 'text', def: '/', group: 'rproxy', label: t('ヘルスチェックのパス', 'Health check path'), help: t('空にするとしません', 'Empty: no health check'), link: 'api:5.1' },
			{ id: 'http3', type: 'checkbox', def: true, group: 'rproxy', label: t('HTTP/3 も受ける', 'Also serve HTTP/3'), help: t('UDP の 443 番も開けます', 'Open UDP 443 as well'), link: 'api:5.4' },
			{ id: 'hsts', type: 'checkbox', def: true, group: 'rproxy', label: t('HSTS のヘッダを付ける', 'Add the HSTS header'), help: t('ブラウザに次から HTTPS だけを使わせます', 'Browsers use only HTTPS from then on'), link: 'api:5.2' },
			{ id: 'compress', type: 'checkbox', def: true, group: 'rproxy', label: t('応答を圧縮する', 'Compress responses'), help: t('', ''), link: 'api:5.2' },
			{ id: 'service', type: 'text', def: 'app', group: 'k8s', label: t('アプリの Service', 'App Service'), help: t('Kubernetes の Service の名前', 'The Kubernetes Service\'s name'), link: 'gw:2.2' },
			{ id: 'service_port', type: 'number', def: 8080, group: 'k8s', label: t('Service のポート', 'Service port'), help: t('', ''), link: 'gw:2.2' },
			...K8S_FIELDS('web'),
			...API_FIELDS,
			SOCKET_FIELD,
		],
	},
	{
		id: 'db-tcp',
		title: t('DB への TCP（長く黙る接続）', 'TCP to a database (long idle)'),
		intro: t(
			'DB の前に置き、アプリの接続プールが長く黙って持つ接続を切らないようにします。主が落ちたら予備へ切り替えます。',
			'Sit in front of a database and keep the pool\'s long-idle connections open. Fail over to the standby when the primary is down.',
		),
		guide: 'api:17.2',
		gwGuide: 'gw:14.2',
		fields: [
			{ id: 'listen_addr', type: 'text', def: '10.0.0.2', group: 'rproxy', label: t('待ち受けのアドレス', 'Listen address'), help: t('アプリがつなぐアドレス', 'The address the apps connect to'), link: 'api:2.1' },
			{ id: 'listen_port', type: 'number', def: 5432, group: 'rproxy', label: t('待ち受けのポート', 'Listen port'), help: t('', ''), link: 'api:2.1' },
			{ id: 'targets', type: 'lines', def: '10.0.1.11:5432\n10.0.1.12:5432', group: 'rproxy', label: t('転送先（1 行に 1 つ）', 'Targets (one per line)'), help: t('アドレス:ポート。IPv6 は [2001:db8::1]:5432', 'address:port; IPv6 as [2001:db8::1]:5432'), link: 'api:3.4' },
			{ id: 'balance', type: 'select', def: 'failover', options: ['failover', 'round_robin', 'least_conn'], group: 'rproxy', label: t('振り分け方', 'Balance'), help: t('failover は先頭に送り、落ちたら次へ', 'failover: the first target, the next when it is down'), link: 'api:3.4' },
			{ id: 'health_interval', type: 'text', def: '5s', group: 'rproxy', label: t('ヘルスチェックの間隔', 'Health check interval'), help: t('空にするとしません', 'Empty: no health check'), link: 'api:3.4' },
			{ id: 'connect_timeout', type: 'text', def: '3s', group: 'rproxy', label: t('つなぐのを待つ時間', 'Connect timeout'), help: t('過ぎたら次の転送先へ', 'Then the next target is tried'), link: 'api:3.4' },
			{ id: 'idle_timeout', type: 'text', def: '12h', group: 'rproxy', label: t('黙った接続を切るまで', 'Idle timeout'), help: t('既定は 1h。0s で切りません', 'Default 1h; 0s never'), link: 'api:3.6' },
			{ id: 'allow_from', type: 'lines', def: '10.0.0.0/16', group: 'rproxy', label: t('受ける送信元（CIDR）', 'Allowed sources (CIDR)'), help: t('空にするとどこからでも', 'Empty: from anywhere'), link: 'api:4.2' },
			{ id: 'max_connections', type: 'number', def: 1000, group: 'rproxy', label: t('同時の接続の上限', 'Max connections'), help: t('空にすると上限なし', 'Empty: no limit'), link: 'api:3.5' },
			{ id: 'service', type: 'text', def: 'postgres', group: 'k8s', label: t('DB の Service', 'Database Service'), help: t('', ''), link: 'gw:5.1' },
			{ id: 'service_port', type: 'number', def: 5432, group: 'k8s', label: t('Service のポート', 'Service port'), help: t('', ''), link: 'gw:5.1' },
			...K8S_FIELDS('db'),
			...API_FIELDS,
		],
	},
	{
		id: 'game-udp',
		title: t('UDP のゲームサーバ', 'UDP game server'),
		intro: t(
			'UDP のゲームサーバを IPv4 と IPv6 で公開し、プレイヤーごとの使い過ぎを抑えます。',
			'Publish a UDP game server on IPv4 and IPv6, and keep each player within limits.',
		),
		guide: 'api:17.3',
		gwGuide: 'gw:14.3',
		fields: [
			{ id: 'listen_addr', type: 'text', def: '0.0.0.0', group: 'rproxy', label: t('待ち受けのアドレス', 'Listen address'), help: t('', ''), link: 'api:2.1' },
			{ id: 'ipv6', type: 'checkbox', def: true, group: 'rproxy', label: t('IPv6（::）でも受ける', 'Also listen on IPv6 (::)'), help: t('', ''), link: 'api:3.3' },
			{ id: 'listen_port', type: 'number', def: 27015, group: 'rproxy', label: t('待ち受けのポート', 'Listen port'), help: t('', ''), link: 'api:3.1' },
			{ id: 'remote_addr', type: 'text', def: '10.0.0.80', group: 'rproxy', label: t('ゲームサーバのアドレス', 'Game server address'), help: t('', ''), link: 'api:3.1' },
			{ id: 'remote_port', type: 'number', def: 27015, group: 'rproxy', label: t('ゲームサーバのポート', 'Game server port'), help: t('', ''), link: 'api:3.1' },
			{ id: 'udp_idle_secs', type: 'number', def: 120, group: 'rproxy', label: t('黙るセッションを捨てるまで（秒）', 'Session idle (seconds)'), help: t('既定は 30', 'Default 30'), link: 'api:3.1' },
			{ id: 'max_sessions', type: 'number', def: 4000, group: 'rproxy', label: t('セッションの上限（ルール全体）', 'Max sessions (whole rule)'), help: t('空にすると既定（16384）', 'Empty: the default (16384)'), link: 'api:3.5' },
			{ id: 'per_source_sessions', type: 'number', def: 4, group: 'rproxy', label: t('1 つの送信元のセッションの上限', 'Max sessions per source'), help: t('空にすると上限なし', 'Empty: no limit'), link: 'api:3.5' },
			{ id: 'packets_average', type: 'number', def: 200, group: 'rproxy', label: t('送信元ごとのデータグラム（毎秒の平均）', 'Datagrams per source (per second)'), help: t('空にすると上限なし', 'Empty: no limit'), link: 'api:3.5' },
			{ id: 'packets_burst', type: 'number', def: 400, group: 'rproxy', label: t('一度に受けるデータグラム', 'Datagram burst'), help: t('平均より大きく', 'At least the average'), link: 'api:3.5' },
			{ id: 'service', type: 'text', def: 'game', group: 'k8s', label: t('ゲームサーバの Service', 'Game server Service'), help: t('', ''), link: 'gw:5.1' },
			{ id: 'service_port', type: 'number', def: 27015, group: 'k8s', label: t('Service のポート', 'Service port'), help: t('', ''), link: 'gw:5.1' },
			...K8S_FIELDS('game'),
			...API_FIELDS,
		],
	},
	{
		id: 'sni-split',
		title: t('443 を名前で分ける（終端とそのまま）', 'Split 443 by name (terminate and passthrough)'),
		intro: t(
			'1 つの 443 番で、rproxy が終端するサイトと、証明書を持つ転送先へそのまま流す名前を分けます。',
			'On one port 443, terminate some sites in rproxy and pass other names untouched to a backend that has the certificate.',
		),
		guide: 'api:17.4',
		gwGuide: 'gw:14.4',
		fields: [
			{ id: 'listen_addr', type: 'text', def: '0.0.0.0', group: 'rproxy', label: t('待ち受けのアドレス', 'Listen address'), help: t('', ''), link: 'api:2.1' },
			{ id: 'cert_file', type: 'text', def: '/etc/rproxy/tls/example.pem', group: 'rproxy', label: t('証明書のファイル', 'Certificate file'), help: t('終端するサイトの証明書（PEM）', 'The terminated sites\' certificate (PEM)'), link: 'api:4.2' },
			{ id: 'key_file', type: 'text', def: '/etc/rproxy/tls/example.key', group: 'rproxy', label: t('鍵のファイル', 'Key file'), help: t('パスだけを書きます。鍵の中身はこのページに入れません', 'Only the path; the key itself never goes into this page'), link: 'api:4.2' },
			{ id: 'sites', type: 'lines', def: 'wiki.example.com http://10.0.0.5:8080\ngit.example.com http://10.0.0.6:3000', group: 'rproxy', label: t('終端するサイト（名前と URL）', 'Terminated sites (name and URL)'), help: t('1 行に「名前 URL」', '"name URL" on each line'), link: 'api:5.1' },
			{ id: 'default_status', type: 'number', def: 404, group: 'rproxy', label: t('どのサイトにも当たらないとき', 'Status for other names'), help: t('', ''), link: 'api:5.1' },
			{ id: 'passthrough_names', type: 'lines', def: '**.k8s.example.com', group: 'rproxy', label: t('そのまま流す名前', 'Names to pass through'), help: t('*.x は 1 階層、**.x は何階層でも', '*.x is one level, **.x any depth'), link: 'api:4.1' },
			{ id: 'passthrough_target', type: 'text', def: '10.2.255.131:443', group: 'rproxy', label: t('そのまま流す先', 'Passthrough target'), help: t('アドレス:ポート', 'address:port'), link: 'api:4.2' },
			{ id: 'source_ip', type: 'select', def: 'proxy_v2', options: ['proxy', 'proxy_v2', 'proxy_v1'], group: 'rproxy', label: t('流す先へ送信元の IP を渡す', 'Pass the client IP to it'), help: t('proxy は渡しません。proxy_v2 / v1 は PROXY protocol', 'proxy: no; proxy_v2 / v1: PROXY protocol'), link: 'api:6' },
			{ id: 'tls_secret', type: 'text', def: 'example-tls', group: 'k8s', label: t('証明書の Secret', 'Certificate Secret'), help: t('kubectl create secret tls で作ります', 'Made with kubectl create secret tls'), link: 'gw:3.1' },
			{ id: 'passthrough_service', type: 'text', def: 'secure-app', group: 'k8s', label: t('そのまま流す先の Service', 'Passthrough Service'), help: t('ポートは「そのまま流す先」のもの', 'Its port is the passthrough target\'s'), link: 'gw:5.2' },
			...K8S_FIELDS('edge'),
			...API_FIELDS,
		],
	},
];

/** The default input of a recipe. */
export function defaults(recipeId) {
	const r = recipe(recipeId);
	return Object.fromEntries(r.fields.map((f) => [f.id, f.def]));
}

export function recipe(id) {
	const r = RECIPES.find((x) => x.id === id);
	if (!r) throw new Error(`unknown recipe ${id}`);
	return r;
}

// ---------------------------------------------------------------------------
// Inline comments: c(value, {ja, en}) puts "# ..." after the value in YAML.

class Commented {
	constructor(value, note) {
		this.value = value;
		this.note = note;
	}
}
const c = (value, ja, en) => new Commented(value, { ja, en });

/** The value without comments (for JSON, the API and the checks). */
export function plain(v) {
	if (v instanceof Commented) return plain(v.value);
	if (Array.isArray(v)) return v.map(plain);
	if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]));
	return v;
}

// ---------------------------------------------------------------------------
// A small YAML writer: block style, short leaves in flow style like the guides.

const YAML_WORDS = /^(true|false|yes|no|on|off|y|n|null|~)$/i;

function scalar(v) {
	if (v === null || v === undefined) return 'null';
	if (typeof v === 'boolean' || typeof v === 'number') return String(v);
	const s = String(v);
	const plainOk =
		/^[A-Za-z0-9_/.][A-Za-z0-9_/.@+\-]*$/.test(s) &&
		!YAML_WORDS.test(s) &&
		!Number.isFinite(Number(s)) &&
		!/^[-+]?[0-9][0-9_]*$/.test(s) &&
		!/^[-+]?(\.[0-9]+|[0-9][0-9_]*\.[0-9_]*)([eE][-+]?[0-9]+)?$/.test(s);
	if (plainOk) return s;
	return `'${s.replace(/'/g, "''")}'`;
}

function flow(v) {
	if (v instanceof Commented) return null;
	if (Array.isArray(v)) {
		const parts = v.map(flow);
		return parts.includes(null) ? null : `[${parts.join(', ')}]`;
	}
	if (v && typeof v === 'object') {
		const entries = Object.entries(v);
		if (entries.length === 0) return '{}';
		const parts = entries.map(([k, x]) => {
			const f = flow(x);
			return f === null ? null : `${scalar(k)}: ${f}`;
		});
		return parts.includes(null) ? null : `{${parts.join(', ')}}`;
	}
	return scalar(v);
}

function depth(v) {
	if (v instanceof Commented) return depth(v.value);
	if (Array.isArray(v)) return 1 + Math.max(0, ...v.map(depth));
	if (v && typeof v === 'object') return 1 + Math.max(0, ...Object.values(v).map(depth));
	return 0;
}

// a collection is written in flow style when it is short and at most 2 levels deep
function flowIfShort(v, room) {
	if (depth(v) > 2) return null;
	const f = flow(v);
	return f !== null && f.length <= room ? f : null;
}

function yamlLines(v, indent, lang, out) {
	const pad = ' '.repeat(indent);
	if (Array.isArray(v)) {
		for (const item of v) {
			const raw = item instanceof Commented ? item.value : item;
			const note = item instanceof Commented ? `  # ${item.note[lang]}` : '';
			if (raw !== null && typeof raw === 'object') {
				const f = flowIfShort(raw, 96 - indent);
				if (f !== null) {
					out.push(`${pad}- ${f}${note}`);
					continue;
				}
				const sub = [];
				yamlLines(raw, indent + 2, lang, sub);
				if (sub.length === 0) {
					out.push(`${pad}- ${Array.isArray(raw) ? '[]' : '{}'}${note}`);
					continue;
				}
				sub[0] = `${pad}- ${sub[0].slice(indent + 2)}`;
				if (note) sub[0] += note;
				out.push(...sub);
			} else {
				out.push(`${pad}- ${scalar(raw)}${note}`);
			}
		}
		return;
	}
	for (const [k, item] of Object.entries(v)) {
		if (item === undefined) continue;
		const raw = item instanceof Commented ? item.value : item;
		const note = item instanceof Commented ? `  # ${item.note[lang]}` : '';
		const key = `${pad}${scalar(k)}:`;
		if (raw !== null && typeof raw === 'object') {
			const empty = Array.isArray(raw) ? raw.length === 0 : Object.keys(raw).length === 0;
			const f = empty ? (Array.isArray(raw) ? '[]' : '{}') : flowIfShort(raw, 96 - key.length);
			if (f !== null) {
				out.push(`${key} ${f}${note}`);
				continue;
			}
			out.push(`${key}${note}`);
			yamlLines(raw, indent + 2, lang, out);
		} else {
			out.push(`${key} ${scalar(raw)}${note}`);
		}
	}
}

/** One YAML document (an object, possibly with c() comments). */
export function toYaml(v, lang = 'ja') {
	const out = [];
	yamlLines(dropUndefined(v), 0, lang, out);
	return out.join('\n') + '\n';
}

function dropUndefined(v) {
	if (v instanceof Commented) return new Commented(dropUndefined(v.value), v.note);
	if (Array.isArray(v)) return v.filter((x) => x !== undefined).map(dropUndefined);
	if (v && typeof v === 'object') {
		return Object.fromEntries(
			Object.entries(v)
				.filter(([, x]) => x !== undefined)
				.map(([k, x]) => [k, dropUndefined(x)]),
		);
	}
	return v;
}

const comment = (text) =>
	text
		.split('\n')
		.map((l) => (l ? `# ${l}` : '#'))
		.join('\n');

// ---------------------------------------------------------------------------
// Input helpers

const str = (v) => String(v ?? '').trim();
const list = (v) =>
	String(v ?? '')
		.split(/[\n,]+/)
		.map((s) => s.trim())
		.filter(Boolean);
const num = (v) => {
	const s = str(v);
	if (s === '') return undefined;
	const n = Number(s);
	return Number.isFinite(n) ? n : NaN;
};

/** "host:port" or "[v6]:port" → {addr, port}. */
function hostPort(s) {
	const m = /^\[([^\]]+)\]:(\d+)$/.exec(s) || /^([^:\s]+):(\d+)$/.exec(s);
	return m ? { addr: m[1], port: Number(m[2]) } : null;
}

function check(errors, lang) {
	const msg = (ja, en) => errors.push(lang === 'en' ? en : ja);
	return {
		port(name, v) {
			if (!Number.isInteger(v) || v < 1 || v > 65535) msg(`${name}：1〜65535 のポートを入れてください`, `${name}: enter a port from 1 to 65535`);
		},
		positive(name, v) {
			if (v !== undefined && (!Number.isInteger(v) || v < 1)) msg(`${name}：1 以上の整数を入れてください`, `${name}: enter a whole number of 1 or more`);
		},
		required(name, v) {
			if (!str(v)) msg(`${name}：入れてください`, `${name}: required`);
		},
		target(name, s) {
			const hp = hostPort(s);
			if (!hp) msg(`${name}：「アドレス:ポート」で書いてください（${s}）`, `${name}: write "address:port" (${s})`);
			else this.port(name, hp.port);
			return hp;
		},
		duration(name, s) {
			if (s && !/^([0-9]+(\.[0-9]+)?(ms|s|m|h|d))+$/.test(s)) msg(`${name}：10s・5m・12h のような時間で書いてください`, `${name}: write a duration such as 10s, 5m or 12h`);
		},
		say: msg,
	};
}

/** URL → the Kubernetes Service port it implies (for the sites of sni-split). */
function urlPort(u) {
	const m = /^(https?):\/\/(\[[^\]]+\]|[^/:]+)(?::(\d+))?/.exec(u);
	if (!m) return null;
	return m[3] ? Number(m[3]) : m[1] === 'https' ? 443 : 80;
}

// a DNS label made from a host name (Service names of the sites)
const label = (host) =>
	host
		.split('.')[0]
		.toLowerCase()
		.replace(/[^a-z0-9-]/g, '-')
		.replace(/^-+|-+$/g, '') || 'site';

// ---------------------------------------------------------------------------
// The outputs

const API_TOKEN_NOTE = {
	ja: 'TOKEN には rules:write のスコープのトークンを入れておきます（GUIDE 7.1。このページはトークンを作りません）',
	en: 'Put a token with the rules:write scope in TOKEN first (GUIDE 7.1; this page makes no tokens)',
};

/** "curl ... -d '<json>'" with the JSON quoted for a POSIX shell. */
function curl({ method, url, body, socket }, lang) {
	const json = JSON.stringify(body, null, 2).replace(/'/g, "'\\''");
	const head = socket ? `sudo curl -s --unix-socket ${socket} -H "Authorization: Bearer $TOKEN"` : `curl -s -H "Authorization: Bearer $TOKEN"`;
	return `${head} -X ${method} "${url}" \\\n  -d '${json}'`;
}

function apiText(calls, notes, lang) {
	const lines = [comment(API_TOKEN_NOTE[lang])];
	for (const n of notes) lines.push(comment(n[lang]));
	lines.push(
		comment(
			lang === 'en'
				? 'Add ?dry_run=true to a URL to see what would change without changing anything (GUIDE 10.3)'
				: 'URL に ?dry_run=true を付けると、何も変えずに結果だけを見られます（GUIDE 10.3）',
		),
	);
	for (const call of calls) {
		lines.push('');
		if (call.note) lines.push(comment(call.note[lang]));
		lines.push(curl(call, lang));
	}
	return lines.join('\n') + '\n';
}

function yamlStream(docs, lang) {
	return docs.map((d) => (d.note ? comment(d.note[lang]) + '\n' : '') + toYaml(d.doc, lang)).join('---\n');
}

const gwMeta = (name, input, extra = {}) => ({ name, namespace: str(input.namespace), ...extra });

function gatewayDoc(input, listeners) {
	return {
		apiVersion: 'gateway.networking.k8s.io/v1',
		kind: 'Gateway',
		metadata: gwMeta(str(input.gateway), input),
		spec: { gatewayClassName: str(input.gateway_class), listeners },
	};
}

function route(kind, name, input, spec) {
	return { apiVersion: 'gateway.networking.k8s.io/v1', kind, metadata: gwMeta(name, input), spec };
}

const parent = (input, section) => ({ name: str(input.gateway), sectionName: section });

function policyDoc(name, input, section, spec) {
	return {
		apiVersion: 'rproxy.max3584.net/v1beta1',
		kind: 'RproxyPolicy',
		metadata: gwMeta(name, input),
		spec: { targetRefs: [{ group: 'gateway.networking.k8s.io', kind: 'Gateway', name: str(input.gateway), sectionName: section }], ...spec },
	};
}

const RULES = '/rules';

// --- 17.1 --------------------------------------------------------------------

function webAcme(input, lang, errors) {
	const ck = check(errors, lang);
	const domain = str(input.domain);
	const email = str(input.email);
	ck.required(lang === 'en' ? 'Domain' : 'ドメイン', domain);
	if (!/^[^@\s]+@[^@\s]+$/.test(email)) ck.say('メール：admin@example.com の形で書いてください', 'Email: write it as admin@example.com');
	const challenge = str(input.challenge) === 'tls-alpn-01' ? 'tls-alpn-01' : 'http-01';
	const resolver = challenge === 'http-01' ? 'le-http' : 'le-alpn';
	const appUrl = str(input.app_url);
	if (!/^https?:\/\/\S+$/.test(appUrl)) ck.say('アプリの URL：http:// か https:// で始めてください', 'App URL: start with http:// or https://');
	const listen = str(input.listen_addr);
	const health = str(input.health_path);
	const servicePort = num(input.service_port);
	ck.port(lang === 'en' ? 'Service port' : 'Service のポート', servicePort);

	const account = {
		directory: input.staging ? 'https://acme-staging-v02.api.letsencrypt.org/directory' : undefined,
		contact: [`mailto:${email}`],
		allowed_names: c([domain], '必須：取ってよい名前', 'required: the names it may obtain'),
	};
	const acme = {
		accounts: { letsencrypt: account },
		resolvers: { [resolver]: { account: 'letsencrypt', challenge } },
	};

	const middlewares = {};
	const used = [];
	if (input.hsts) {
		middlewares.secure = { headers: { hsts: { max_age: 31536000 }, content_type_nosniff: true } };
		used.push('secure');
	}
	if (input.compress) {
		middlewares.compress = { compress: {} };
		used.push('compress');
	}
	const http80 = c(
		{
			protocol: 'tcp',
			listen_addr: listen,
			listen_port: 80,
			http: {
				routes: [{ name: 'to-https', match: 'PathPrefix(`/`)', middlewares: ['to-https'] }],
				middlewares: { 'to-https': { redirect_scheme: { scheme: 'https', permanent: true } } },
			},
		},
		challenge === 'http-01' ? '80：ACME の http-01 に答え、ほかは HTTPS へ' : '80：HTTPS へリダイレクト',
		challenge === 'http-01' ? '80: answers ACME http-01, redirects the rest to HTTPS' : '80: redirects to HTTPS',
	);
	const https = c(
		{
			protocol: 'tcp',
			listen_addr: listen,
			listen_port: 443,
			tls: { mode: 'terminate', certificates: [{ acme: resolver, domains: [domain] }] },
			http: {
				http3: input.http3 ? true : undefined,
				routes: [{ name: 'app', match: `Host(\`${domain}\`)`, service: 'app', middlewares: used.length ? used : undefined }],
				services: { app: { servers: [{ url: appUrl }], health_check: health ? { path: health, interval: '10s' } : undefined } },
				middlewares: used.length ? middlewares : undefined,
			},
		},
		'443：終端して Web アプリへ',
		'443: terminates and sends to the web app',
	);
	const settings = { version: 1, global: { acme }, rules: [http80, https] };

	// API: global.acme through the socket (admin), then the two rules
	const api = [
		{
			method: 'PATCH',
			url: 'http://localhost/config/global',
			socket: str(input.api_socket),
			body: plain({ acme }),
			note: t(
				'1. global.acme を入れる（admin のトークン、Unix ソケットからだけ。GUIDE 8.）。設定ファイルに global.acme があれば要りません',
				'1. Set global.acme (an admin token, over the Unix socket only; GUIDE 8.). Not needed when the settings file has global.acme',
			),
		},
		{ method: 'POST', url: str(input.api_url) + RULES, body: plain(http80), note: t('2. 80 番のルール', '2. The port 80 rule') },
		{
			method: 'POST',
			url: str(input.api_url) + RULES,
			body: plain(https),
			note: t('3. 443 番のルール（ACME の証明書を使うので acme:write のスコープも要ります）', '3. The port 443 rule (it uses an ACME certificate, so the token also needs acme:write)'),
		},
	];

	// Gateway API: cert-manager instead of rproxy's ACME (rproxy-gateway GUIDE 3.2)
	const ns = str(input.namespace);
	const service = str(input.service);
	const secret = `${service}-tls`;
	const issuer = input.staging ? 'letsencrypt-staging' : 'letsencrypt';
	const filters = [];
	if (input.hsts) {
		filters.push({
			type: 'ResponseHeaderModifier',
			responseHeaderModifier: {
				set: [
					{ name: 'Strict-Transport-Security', value: 'max-age=31536000' },
					{ name: 'X-Content-Type-Options', value: 'nosniff' },
				],
			},
		});
	}
	if (input.compress) filters.push({ type: 'ExtensionRef', extensionRef: { group: 'rproxy.max3584.net', kind: 'RproxyMiddleware', name: 'compress' } });
	const docs = [
		{
			note: t(
				'cert-manager が証明書を取ります（rproxy の ACME は Gateway API からは使いません。rproxy-gateway GUIDE 3.2）',
				'cert-manager obtains the certificate (rproxy\'s own ACME is not used from Gateway API; rproxy-gateway GUIDE 3.2)',
			),
			doc: {
				apiVersion: 'cert-manager.io/v1',
				kind: 'ClusterIssuer',
				metadata: { name: issuer },
				spec: {
					acme: {
						server: input.staging ? 'https://acme-staging-v02.api.letsencrypt.org/directory' : 'https://acme-v02.api.letsencrypt.org/directory',
						email,
						privateKeySecretRef: { name: `${issuer}-account` },
						solvers: [{ http01: { gatewayHTTPRoute: { parentRefs: [{ name: str(input.gateway), namespace: ns, kind: 'Gateway', sectionName: 'http' }] } } }],
					},
				},
			},
		},
		{
			doc: {
				apiVersion: 'cert-manager.io/v1',
				kind: 'Certificate',
				metadata: gwMeta(secret, input),
				spec: { secretName: secret, dnsNames: [domain], issuerRef: { name: issuer, kind: 'ClusterIssuer', group: 'cert-manager.io' } },
			},
		},
		{
			doc: gatewayDoc(input, [
				{ name: 'http', port: 80, protocol: 'HTTP' },
				{ name: 'https', port: 443, protocol: 'HTTPS', hostname: domain, tls: { certificateRefs: [{ name: secret }] } },
			]),
		},
		{
			note: t('80 番に来たものは HTTPS へ（rproxy-gateway GUIDE 3.3）', 'Port 80 goes to HTTPS (rproxy-gateway GUIDE 3.3)'),
			doc: route('HTTPRoute', 'to-https', input, {
				parentRefs: [parent(input, 'http')],
				hostnames: [domain],
				rules: [{ filters: [{ type: 'RequestRedirect', requestRedirect: { scheme: 'https', statusCode: 301 } }] }],
			}),
		},
		{
			doc: route('HTTPRoute', service, input, {
				parentRefs: [parent(input, 'https')],
				hostnames: [domain],
				rules: [{ filters: filters.length ? filters : undefined, backendRefs: [{ name: service, port: servicePort }] }],
			}),
		},
	];
	if (input.compress) {
		docs.push({
			note: t('圧縮は標準のフィルタにないので RproxyMiddleware で（rproxy-gateway GUIDE 8.2）', 'Compression is not a standard filter: an RproxyMiddleware (rproxy-gateway GUIDE 8.2)'),
			doc: { apiVersion: 'rproxy.max3584.net/v1beta1', kind: 'RproxyMiddleware', metadata: gwMeta('compress', input), spec: { compress: {} } },
		});
	}
	const gwNotes = [];
	if (input.http3) gwNotes.push(t('HTTP/3 は Gateway API からは開けません（rproxy-gateway は TCP の HTTPS だけ）', 'HTTP/3 cannot be turned on from Gateway API (rproxy-gateway serves HTTPS over TCP)'));
	if (health) gwNotes.push(t('ヘルスチェックの代わりに、Pod の readinessProbe が転送先を決めます', 'Instead of the health check, the pods\' readinessProbe decides the backends'));
	if (challenge === 'tls-alpn-01') gwNotes.push(t('cert-manager は http-01 で確かめます（tls-alpn-01 はありません）', 'cert-manager checks with http-01 (it has no tls-alpn-01)'));
	return { settings, api, apiNotes: [], docs, gwNotes };
}

// --- 17.2 --------------------------------------------------------------------

function dbTcp(input, lang, errors) {
	const ck = check(errors, lang);
	const en = lang === 'en';
	const port = num(input.listen_port);
	ck.port(en ? 'Listen port' : '待ち受けのポート', port);
	const targets = list(input.targets)
		.map((s) => ck.target(en ? 'Targets' : '転送先', s))
		.filter(Boolean);
	if (targets.length === 0) ck.say('転送先：1 つ以上書いてください', 'Targets: write at least one');
	const interval = str(input.health_interval);
	const connect = str(input.connect_timeout);
	const idle = str(input.idle_timeout);
	ck.duration(en ? 'Health check interval' : 'ヘルスチェックの間隔', interval);
	ck.duration(en ? 'Connect timeout' : 'つなぐのを待つ時間', connect);
	ck.duration(en ? 'Idle timeout' : '黙った接続を切るまで', idle);
	const allow = list(input.allow_from);
	const max = num(input.max_connections);
	ck.positive(en ? 'Max connections' : '同時の接続の上限', max);
	const balance = ['failover', 'round_robin', 'least_conn'].includes(str(input.balance)) ? str(input.balance) : 'failover';
	const servicePort = num(input.service_port);
	ck.port(en ? 'Service port' : 'Service のポート', servicePort);

	const many = targets.length > 1;
	const rule = {
		protocol: 'tcp',
		listen_addr: str(input.listen_addr),
		listen_port: port,
		remote_addr: many ? undefined : targets[0]?.addr,
		remote_port: many ? undefined : targets[0]?.port,
		targets: many ? targets : undefined,
		balance: !many ? undefined : balance === 'failover' ? c(balance, '主に送り、落ちたら次へ', 'the first one; the next when it is down') : balance,
		health_check: interval ? { interval, timeout: '2s' } : undefined,
		connect_timeout: connect || undefined,
		idle_timeout: idle ? c(idle, 'プールの接続を既定の 1h で切らない', 'pooled connections outlive the 1h default') : undefined,
		allow_from: allow.length ? allow : undefined,
		limits: max !== undefined ? { max_connections: max } : undefined,
	};
	const settings = { version: 1, rules: [rule] };
	const api = [{ method: 'POST', url: str(input.api_url) + RULES, body: plain(rule) }];

	const service = str(input.service);
	const policy = {
		allowFrom: allow.length ? allow : undefined,
		limits: max !== undefined ? { max_connections: max } : undefined,
		connectTimeout: connect || undefined,
		idleTimeout: idle || undefined,
	};
	const docs = [
		{ doc: gatewayDoc(input, [{ name: 'postgres', port, protocol: 'TCP' }]) },
		{ doc: route('TCPRoute', service, input, { parentRefs: [parent(input, 'postgres')], rules: [{ backendRefs: [{ name: service, port: servicePort }] }] }) },
	];
	if (Object.values(policy).some((v) => v !== undefined)) {
		docs.push({
			note: t(
				'標準の Gateway API にない設定（送信元・接続の数・時間）は RproxyPolicy で（rproxy-gateway GUIDE 8.1）',
				'Settings standard Gateway API lacks (sources, connection counts, timeouts) go in an RproxyPolicy (rproxy-gateway GUIDE 8.1)',
			),
			doc: policyDoc(str(input.gateway), input, 'postgres', policy),
		});
	}
	const gwNotes = [t('転送先は Service の ready な Pod です。balance と health_check は要りません', 'The backends are the Service\'s ready pods: no balance or health_check')];
	return { settings, api, apiNotes: [], docs, gwNotes };
}

// --- 17.3 --------------------------------------------------------------------

function gameUdp(input, lang, errors) {
	const ck = check(errors, lang);
	const en = lang === 'en';
	const port = num(input.listen_port);
	const rport = num(input.remote_port);
	ck.port(en ? 'Listen port' : '待ち受けのポート', port);
	ck.port(en ? 'Game server port' : 'ゲームサーバのポート', rport);
	ck.required(en ? 'Game server address' : 'ゲームサーバのアドレス', input.remote_addr);
	const idle = num(input.udp_idle_secs);
	if (idle !== undefined && (!Number.isInteger(idle) || idle < 1 || idle > 86400)) ck.say('黙るセッション：1〜86400 秒', 'Session idle: 1 to 86400 seconds');
	const max = num(input.max_sessions);
	const perSrc = num(input.per_source_sessions);
	const avg = num(input.packets_average);
	let burst = num(input.packets_burst);
	ck.positive(en ? 'Max sessions' : 'セッションの上限', max);
	ck.positive(en ? 'Max sessions per source' : '送信元のセッションの上限', perSrc);
	ck.positive(en ? 'Datagrams per source' : '送信元ごとのデータグラム', avg);
	if (avg === undefined) burst = undefined;
	if (burst !== undefined && avg !== undefined && burst < avg) ck.say('一度に受けるデータグラム：平均以上にしてください', 'Datagram burst: at least the average');
	const servicePort = num(input.service_port);
	ck.port(en ? 'Service port' : 'Service のポート', servicePort);

	const perSource = perSrc !== undefined || avg !== undefined ? { max_connections: perSrc, packets: avg !== undefined ? { average: avg, period: '1s', burst } : undefined } : undefined;
	const limits =
		max !== undefined || perSource
			? {
					max_connections: max !== undefined ? c(max, 'このルールのセッション（既定の 16384 の代わり）', 'sessions of this rule (instead of the 16384 default)') : undefined,
					per_source: perSource,
				}
			: undefined;
	const rule = {
		protocol: 'udp',
		listen_addr: str(input.listen_addr),
		extra_listen_addrs: input.ipv6 ? ['::'] : undefined,
		listen_port: port,
		remote_addr: str(input.remote_addr),
		remote_port: rport,
		udp_idle_secs: idle !== undefined ? c(idle, '黙るプレイヤーを 30 秒で切らない', 'quiet players are not dropped after 30s') : undefined,
		limits,
	};
	const settings = { version: 1, rules: [rule] };
	const api = [{ method: 'POST', url: str(input.api_url) + RULES, body: plain(rule) }];

	const service = str(input.service);
	const docs = [
		{ doc: gatewayDoc(input, [{ name: 'game', port, protocol: 'UDP' }]) },
		{ doc: route('UDPRoute', service, input, { parentRefs: [parent(input, 'game')], rules: [{ backendRefs: [{ name: service, port: servicePort }] }] }) },
	];
	if (limits) {
		docs.push({
			note: t('セッションとデータグラムの上限は RproxyPolicy の limits で（rproxy-gateway GUIDE 8.1）', 'Session and datagram limits go in the RproxyPolicy\'s limits (rproxy-gateway GUIDE 8.1)'),
			doc: policyDoc(str(input.gateway), input, 'game', { limits: plain(limits) }),
		});
	}
	const gwNotes = [];
	if (idle !== undefined) gwNotes.push(t('udp_idle_secs は Gateway API からは決められません（rproxy の既定の 30 秒）', 'udp_idle_secs cannot be set from Gateway API (rproxy\'s 30 s default applies)'));
	if (input.ipv6) gwNotes.push(t('IPv6 で受けるかは Service（ipFamilyPolicy）とロードバランサが決めます', 'Whether IPv6 is served is up to the Service (ipFamilyPolicy) and the load balancer'));
	return { settings, api, apiNotes: [], docs, gwNotes };
}

// --- 17.4 --------------------------------------------------------------------

function sniSplit(input, lang, errors) {
	const ck = check(errors, lang);
	const en = lang === 'en';
	const listen = str(input.listen_addr);
	ck.required(en ? 'Certificate file' : '証明書のファイル', input.cert_file);
	ck.required(en ? 'Key file' : '鍵のファイル', input.key_file);
	const sites = list(String(input.sites ?? '').replace(/,/g, '\n'))
		.map((line) => {
			const [host, url] = line.split(/\s+/);
			if (!host || !url || !/^https?:\/\/\S+$/.test(url)) {
				ck.say(`終端するサイト：「名前 URL」で書いてください（${line}）`, `Terminated sites: write "name URL" (${line})`);
				return null;
			}
			return { host, url };
		})
		.filter(Boolean);
	const names = list(input.passthrough_names);
	const pt = names.length ? ck.target(en ? 'Passthrough target' : 'そのまま流す先', str(input.passthrough_target)) : null;
	const status = num(input.default_status);
	if (status !== undefined && (!Number.isInteger(status) || status < 100 || status > 599)) ck.say('当たらないとき：100〜599 の状態コード', 'Status for other names: 100 to 599');
	const sourceIp = ['proxy', 'proxy_v2', 'proxy_v1'].includes(str(input.source_ip)) ? str(input.source_ip) : 'proxy';

	const ptRoute = pt
		? {
				server_names: c(names, 'そのまま流す（証明書は向こう）', 'passed through (the backend has the certificate)'),
				passthrough: true,
				remote_addr: pt.addr,
				remote_port: pt.port,
				source_ip: sourceIp === 'proxy' ? undefined : sourceIp,
			}
		: undefined;
	const rule = {
		protocol: 'tcp',
		listen_addr: listen,
		listen_port: 443,
		tls: {
			mode: 'terminate',
			certificates: [{ cert_file: str(input.cert_file), key_file: str(input.key_file) }],
			routes: ptRoute ? [ptRoute] : undefined,
		},
		http: {
			routes: sites.map((s) => ({ name: label(s.host), match: `Host(\`${s.host}\`)`, to: s.url })),
			default: status !== undefined ? { status } : undefined,
		},
	};
	const settings = { version: 1, rules: [rule] };
	const api = [{ method: 'POST', url: str(input.api_url) + RULES, body: plain(rule) }];
	const apiNotes = [
		t(
			'API のルールは、証明書のストア・ACME の保存先の下のファイルを指せません（403 protected_file）。そこにあるなら PUT /certs で入れて {"cert": "<名前>"} で使います',
			'API rules cannot point at files under the certificate store or the ACME storage (403 protected_file); store those with PUT /certs and use {"cert": "<name>"}',
		),
	];

	// Gateway API: one HTTPS listener (terminated) and one TLS Passthrough listener on 443
	const secret = str(input.tls_secret);
	const listeners = [{ name: 'https', port: 443, protocol: 'HTTPS', tls: { certificateRefs: [{ name: secret }] } }];
	// Gateway API wildcards (*.x) match any depth, like rproxy's **.x
	const gwNames = [...new Set(names.map((n) => n.replace(/^\*\*\./, '*.')))];
	const docs = [];
	if (pt) {
		gwNames.forEach((n, i) => listeners.push({ name: gwNames.length > 1 ? `passthrough-${i + 1}` : 'passthrough', port: 443, protocol: 'TLS', hostname: n, tls: { mode: 'Passthrough' } }));
	}
	docs.push({
		note: t(
			`証明書の Secret は先に作ります：kubectl -n ${str(input.namespace)} create secret tls ${secret} --cert=<証明書> --key=<鍵>`,
			`Create the certificate Secret first: kubectl -n ${str(input.namespace)} create secret tls ${secret} --cert=<cert> --key=<key>`,
		),
		doc: gatewayDoc(input, listeners),
	});
	for (const s of sites) {
		const p = urlPort(s.url);
		docs.push({
			doc: route('HTTPRoute', label(s.host), input, {
				parentRefs: [parent(input, 'https')],
				hostnames: [s.host],
				rules: [{ backendRefs: [{ name: label(s.host), port: p }] }],
			}),
		});
	}
	if (pt) {
		docs.push({
			doc: route('TLSRoute', str(input.passthrough_service), input, {
				parentRefs: listeners.filter((l) => l.protocol === 'TLS').map((l) => parent(input, l.name)),
				hostnames: gwNames,
				rules: [{ backendRefs: [{ name: str(input.passthrough_service), port: pt.port }] }],
			}),
		});
	}
	const gwNotes = [
		t('Service の名前はサイトの名前の先頭（wiki など）にしています。自分の Service に合わせてください', 'The Service names are the sites\' first labels (wiki, ...); change them to your Services'),
	];
	if (pt && names.some((n) => !n.startsWith('**.') && n.startsWith('*.'))) {
		gwNotes.push(t('Gateway API の *.x は何階層下の名前にも当たります（rproxy の **.x と同じ）', 'In Gateway API, *.x matches any depth (like rproxy\'s **.x)'));
	}
	if (pt && sourceIp !== 'proxy') {
		gwNotes.push(
			t(
				'TLSRoute は送信元の IP を渡しません。渡すなら RproxyRule で rproxy のルールを書きます（rproxy-gateway GUIDE 8.3）',
				'A TLSRoute does not pass the client IP; to pass it, write the rproxy rule in an RproxyRule (rproxy-gateway GUIDE 8.3)',
			),
		);
	}
	if (status !== undefined && status !== 404) gwNotes.push(t(`当たらない名前は Gateway API では 404 です（${status} にはなりません）`, `Names nothing matches get 404 in Gateway API (not ${status})`));
	return { settings, api, apiNotes, docs, gwNotes };
}

const BUILDERS = { 'web-acme': webAcme, 'db-tcp': dbTcp, 'game-udp': gameUdp, 'sni-split': sniSplit };

/**
 * The three outputs of a recipe for an input (missing fields take the defaults).
 * Returns {settings, api, gateway} as text, {errors} (messages in `lang`) and
 * {data} (the same as objects: settings, api calls, gateway documents) for the checks.
 */
export function generate(recipeId, input = {}, lang = 'ja') {
	const r = recipe(recipeId);
	const full = { ...defaults(recipeId), ...input };
	const errors = [];
	const out = BUILDERS[r.id](full, lang, errors);
	const head = (ja, en) => comment(lang === 'en' ? en : ja);
	const settingsText =
		head(
			`rproxy の設定ファイル（RPROXY_CONFIG。GUIDE ${SECTIONS[r.guide][1]}）。使う前に rproxy-api --check-config で確かめます`,
			`rproxy settings file (RPROXY_CONFIG; GUIDE ${SECTIONS[r.guide][1]}). Check it with rproxy-api --check-config before use`,
		) +
		'\n' +
		toYaml(out.settings, lang);
	const gwHead = [
		lang === 'en'
			? `Gateway API (rproxy-gateway GUIDE ${SECTIONS[r.gwGuide][1]}). Needs the Gateway API v1.6 standard CRDs and rproxy-gateway`
			: `Gateway API（rproxy-gateway GUIDE ${SECTIONS[r.gwGuide][1]}）。Gateway API v1.6 の standard の CRD と rproxy-gateway が要ります`,
		...out.gwNotes.map((n) => n[lang]),
	];
	const gatewayText = comment(gwHead.join('\n')) + '\n' + yamlStream(out.docs, lang);
	return {
		settings: settingsText,
		api: apiText(out.api, out.apiNotes, lang),
		gateway: gatewayText,
		errors,
		data: {
			settings: dropUndefined(plain(out.settings)),
			api: out.api.map(({ method, url, body, socket }) => ({ method, url, body: dropUndefined(body), socket })),
			gateway: out.docs.map((d) => dropUndefined(plain(d.doc))),
		},
	};
}
