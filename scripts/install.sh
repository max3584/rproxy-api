#!/usr/bin/env bash
# rproxy-api を VM（systemd の Linux）に入れる。root で実行する。
#
#   curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | bash -s -- [オプション]
#
# Debian / Ubuntu は apt リポジトリ（https://max3584.github.io/rproxy-api）から入れる。
# それ以外は GitHub Release の静的リンクのバイナリを /usr/local/bin に置き、ユーザー・設定・ユニットを作る。
# もう一度実行するとアップグレードになる（設定とトークンは残し、指定したオプションだけを書き換える）。
set -euo pipefail

REPO=max3584/rproxy-api
APT_URL=https://max3584.github.io/rproxy-api
KEYRING=/usr/share/keyrings/rproxy-archive-keyring.gpg
ETC=/etc/rproxy
ENV_FILE=$ETC/rproxy.env
TOKENS=$ETC/tokens
LOG_DIR=/var/log/rproxy
UNIT=rproxy-api.service
ROUTING_UNIT=rproxy-transparent-routing.service
ROUTING_CONF=$ETC/transparent-routing.conf
ROUTING_BIN=/usr/local/sbin/rproxy-transparent-routing

usage() {
	cat <<'EOF'
使い方: install.sh [オプション]

  --api-addr ADDR        制御 API の待ち受けアドレス（既定 127.0.0.1。カンマ区切りで複数）
  --api-port PORT        制御 API のポート（既定 8080。初回で使用中なら 8081〜8099 の空きを選ぶ）
  --database-url URL     起動時にルールを復元する DB（mysql://user:pass@host:3306/db）
  --static-rules FILE    固定ルールの JSON ファイル
  --log-file PATH        ログファイル（既定 /var/log/rproxy/rproxy.log。- で標準出力 = journald）
  --transparent-clients CIDR[,CIDR...] | any
                         source_ip: transparent を使うクライアントのアドレス範囲（IPv4 / IPv6。戻りのパケットのポリシールーティングを入れる）。
                         any はクライアントの範囲を決めず、rproxy の transparent ソケット宛てだけを nftables で選ぶ（nft が要る）
  --transparent-iface IF[,IF...]
                         転送先側のインターフェース（--transparent-clients が範囲のとき、一緒に指定する）
  --transparent-table N  ポリシールーティングに使うテーブルの番号（既定 100）
  --no-transparent-routing
                         transparent 用のポリシールーティングを外す
  --version vX.Y.Z       入れるバージョン（バイナリで入れる場合。既定は最新のリリース）
  --method apt|binary    入れ方（既定は apt-get があれば apt、なければ binary）
  --binary PATH          ダウンロードせずに手元のバイナリを使う（--method binary と一緒に使う）
  --no-start             起動しない（有効化もしない）
  --uninstall            アンインストールする（設定・トークン・ログは残す）
  --purge                --uninstall と一緒に使うと、設定・トークン・ログも消す
  -h, --help             この説明
EOF
}

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m警告:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mエラー:\033[0m %s\n' "$*" >&2; exit 1; }

api_addr='' api_port='' database_url='' static_rules='' log_file='' version='' method='' binary=''
t_clients='' t_ifaces='' t_table=100 no_routing=false
no_start=false uninstall=false purge=false
while [ $# -gt 0 ]; do
	case $1 in
		--api-addr) api_addr=${2:?}; shift 2 ;;
		--api-port) api_port=${2:?}; shift 2 ;;
		--database-url) database_url=${2:?}; shift 2 ;;
		--static-rules) static_rules=${2:?}; shift 2 ;;
		--log-file) log_file=${2:?}; shift 2 ;;
		--transparent-clients) t_clients=${2:?}; shift 2 ;;
		--transparent-iface) t_ifaces=${2:?}; shift 2 ;;
		--transparent-table) t_table=${2:?}; shift 2 ;;
		--no-transparent-routing) no_routing=true; shift ;;
		--version) version=${2:?}; shift 2 ;;
		--method) method=${2:?}; shift 2 ;;
		--binary) binary=${2:?}; shift 2 ;;
		--no-start) no_start=true; shift ;;
		--uninstall) uninstall=true; shift ;;
		--purge) purge=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "不明なオプション: $1" ;;
	esac
done

[ "$(id -u)" = 0 ] || die "root で実行してください"
[ -d /run/systemd/system ] || die "systemd で起動した Linux が必要です"
if [ -n "$api_port" ]; then
	case $api_port in '' | *[!0-9]*) die "--api-port は数字で指定してください" ;; esac
	if [ "$api_port" -lt 1 ] || [ "$api_port" -gt 65535 ]; then die "--api-port は 1〜65535 です"; fi
fi
if [ -n "$static_rules" ] && [ ! -r "$static_rules" ]; then
	die "--static-rules のファイルが読めません: $static_rules"
fi
if [ -n "$version" ]; then
	case $version in v*) ;; *) version=v$version ;; esac
fi
if [ -n "$t_clients$t_ifaces" ]; then
	[ -n "$t_clients" ] || die "--transparent-iface は --transparent-clients と一緒に指定してください"
	$no_routing && die "--no-transparent-routing と --transparent-* は同時に使えません"
	t_clients=${t_clients//,/ } t_ifaces=${t_ifaces//,/ }
	if [ "$t_clients" = any ]; then
		command -v nft >/dev/null || die "--transparent-clients any には nft（nftables）が要ります（apt install nftables）"
	else
		[ -n "$t_ifaces" ] || die "--transparent-clients に範囲を書くときは --transparent-iface も指定してください（範囲を決めないなら any）"
		for c in $t_clients; do
			case $c in
				*/*) ;;
				*) die "--transparent-clients は CIDR（例 10.0.1.0/24、2001:db8::/32）か any で指定してください: $c" ;;
			esac
		done
	fi
	for i in $t_ifaces; do ip link show "$i" >/dev/null 2>&1 || die "インターフェースがありません: $i"; done
	case $t_table in '' | *[!0-9]*) die "--transparent-table は数字で指定してください" ;; esac
fi

installed_by_apt() { dpkg-query -W -f='${Status}' rproxy-api 2>/dev/null | grep -q 'install ok installed'; }

# ---------------------------------------------------------------- uninstall

remove_routing() {
	if [ -e "/etc/systemd/system/$ROUTING_UNIT" ]; then
		systemctl disable --now "$ROUTING_UNIT" 2>/dev/null || true
		rm -f "/etc/systemd/system/$ROUTING_UNIT" "$ROUTING_BIN" "$ROUTING_CONF"
		systemctl daemon-reload
	fi
}

if $uninstall; then
	remove_routing
	rm -rf "/etc/systemd/system/$UNIT.d/capabilities.conf"
	rmdir "/etc/systemd/system/$UNIT.d" 2>/dev/null || true
	if installed_by_apt; then
		log "apt で削除します"
		if $purge; then apt-get purge -y rproxy-api; else apt-get remove -y rproxy-api; fi
		rm -f /etc/apt/sources.list.d/rproxy-api.list "$KEYRING"
	else
		log "サービスとバイナリを削除します"
		systemctl disable --now "$UNIT" 2>/dev/null || true
		rm -f "/etc/systemd/system/$UNIT" /usr/local/bin/rproxy-api
		systemctl daemon-reload
	fi
	if $purge; then
		rm -rf "$ETC" "$LOG_DIR"
		log "設定・トークン・ログも削除しました（rproxy ユーザーは残しています）"
	else
		log "設定（$ETC）とログ（$LOG_DIR）は残しています。消すときは --uninstall --purge"
	fi
	exit 0
fi

# ---------------------------------------------------------------- install

if [ -z "$method" ]; then
	if [ -n "$binary" ]; then method=binary
	elif command -v apt-get >/dev/null; then method=apt
	else method=binary
	fi
fi
case $method in apt | binary) ;; *) die "--method は apt か binary です" ;; esac
[ -z "$binary" ] || [ "$method" = binary ] || die "--binary は --method binary と一緒に使います"
[ -z "$version" ] || [ "$method" = binary ] || die "--version は --method binary と一緒に使います（apt では常に最新が入ります）"

fresh=true
[ -e "$ENV_FILE" ] && fresh=false
was_active=false
systemctl is-active --quiet "$UNIT" && was_active=true

need() { command -v "$1" >/dev/null || die "$1 がありません（先にインストールしてください）"; }

# このスクリプトが git のチェックアウトから実行されていれば、同じチェックアウトの設定の雛形を使う
# （curl | bash のときはファイルがないので GitHub から取る）
here=
src=${BASH_SOURCE[0]:-}
if [ -n "$src" ] && [ -f "$src" ]; then
	here=$(cd "$(dirname "$src")" && pwd)
fi
template() { # template <リポジトリ内のパス> <出力先>
	if [ -n "$here" ] && [ -f "$here/../$1" ]; then
		cp "$here/../$1" "$2"
	else
		curl -fsSL "https://raw.githubusercontent.com/$REPO/${version:-master}/$1" -o "$2" || die "$1 を取得できませんでした"
	fi
}

install_apt() {
	need curl
	log "apt リポジトリを登録します（$APT_URL）"
	curl -fsSL "$APT_URL/rproxy-archive-keyring.gpg" -o "$KEYRING.tmp" || die "署名鍵を取得できませんでした"
	install -m 0644 "$KEYRING.tmp" "$KEYRING"
	rm -f "$KEYRING.tmp"
	echo "deb [signed-by=$KEYRING] $APT_URL stable main" > /etc/apt/sources.list.d/rproxy-api.list
	apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/rproxy-api.list \
		-o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
	log "rproxy-api をインストールします"
	DEBIAN_FRONTEND=noninteractive apt-get install -y rproxy-api
}

arch_target() {
	case $(uname -m) in
		x86_64 | amd64) echo x86_64-unknown-linux-musl ;;
		aarch64 | arm64) echo aarch64-unknown-linux-musl ;;
		armv7l | armv7*) echo armv7-unknown-linux-musleabihf ;;
		*) die "この CPU（$(uname -m)）向けのバイナリはありません" ;;
	esac
}

install_binary() {
	# スクリプトの終了時に消すので、関数の local にしない
	tmp=$(mktemp -d)
	trap 'rm -rf "${tmp:-}"' EXIT
	if [ -n "$binary" ]; then
		[ -f "$binary" ] || die "--binary のファイルがありません: $binary"
		cp "$binary" "$tmp/rproxy-api"
	else
		need curl
		if [ -z "$version" ]; then
			version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
			version=${version##*/}
			case $version in v*) ;; *) die "最新のリリースがわかりませんでした" ;; esac
		fi
		local target url
		target=$(arch_target)
		url="https://github.com/$REPO/releases/download/$version/rproxy-api-$version-$target"
		log "$version（$target）をダウンロードします"
		curl -fSL --progress-bar "$url" -o "$tmp/rproxy-api" || die "ダウンロードできませんでした: $url"
	fi
	chmod 0755 "$tmp/rproxy-api"
	"$tmp/rproxy-api" --version >/dev/null 2>&1 || die "このバイナリはこの環境で実行できません"

	if ! getent passwd rproxy >/dev/null; then
		log "rproxy ユーザーを作ります"
		useradd --system --user-group --no-create-home --home-dir /nonexistent \
			--shell "$(command -v nologin || echo /bin/false)" rproxy
	fi
	install -d -o root -g rproxy -m 0750 "$ETC"
	install -d -o rproxy -g rproxy -m 0750 "$LOG_DIR"
	if [ ! -e "$ENV_FILE" ]; then
		template debian/rproxy.env "$tmp/rproxy.env"
		install -o root -g root -m 0640 "$tmp/rproxy.env" "$ENV_FILE"
	fi
	if [ ! -e "$TOKENS" ]; then
		(umask 027; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$TOKENS"; echo >> "$TOKENS")
		chgrp rproxy "$TOKENS"
		log "API のトークンを $TOKENS に作りました"
	fi
	install -m 0755 "$tmp/rproxy-api" /usr/local/bin/rproxy-api
	template contrib/rproxy-api.service "$tmp/$UNIT"
	install -m 0644 "$tmp/$UNIT" "/etc/systemd/system/$UNIT"
	systemctl daemon-reload
}

# KEY=VALUE を設定する（あれば置き換え、コメントになっていれば外し、なければ末尾に足す）
set_env() {
	local key=$1 value=$2 tmp
	tmp=$(mktemp)
	awk -v k="$key" -v line="$key=$value" '
		!done && ($0 ~ "^" k "=" || $0 ~ "^# *" k "=") { print line; done = 1; next }
		{ print }
		END { if (!done) print line }
	' "$ENV_FILE" > "$tmp"
	cat "$tmp" > "$ENV_FILE"
	rm -f "$tmp"
}
unset_env() { # 行をコメントにする
	sed -i "s|^$1=|# $1=|" "$ENV_FILE"
}
get_env() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; }

port_in_use() {
	command -v ss >/dev/null || return 1
	[ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]
}

if [ "$method" = apt ]; then install_apt; else install_binary; fi
[ -e "$ENV_FILE" ] || die "$ENV_FILE がありません"

# ---------------------------------------------------------------- configure

[ -z "$api_addr" ] || set_env RPROXY_API_ADDR "$api_addr"
if [ -n "$api_port" ]; then
	set_env RPROXY_API_PORT "$api_port"
elif $fresh; then
	# 初回だけ: 既定のポートが使われていれば空いているポートにずらす
	port=$(get_env RPROXY_API_PORT)
	port=${port:-8080}
	if port_in_use "$port"; then
		for p in $(seq 8081 8099); do
			if ! port_in_use "$p"; then
				warn "ポート $port は使用中なので、制御 API は $p で待ち受けます（--api-port で変えられます）"
				set_env RPROXY_API_PORT "$p"
				break
			fi
		done
	fi
fi
[ -z "$database_url" ] || set_env RPROXY_DATABASE_URL "$database_url"

# transparent: 権限（古いパッケージのユニットには CAP_NET_ADMIN がないので drop-in で足す）
if ! systemctl cat "$UNIT" 2>/dev/null | grep -q '^AmbientCapabilities=.*CAP_NET_ADMIN'; then
	log "source_ip: transparent のために CAP_NET_ADMIN を与えます（$UNIT.d/capabilities.conf）"
	install -d "/etc/systemd/system/$UNIT.d"
	cat > "/etc/systemd/system/$UNIT.d/capabilities.conf" <<'CONF'
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CONF
	systemctl daemon-reload
fi

# transparent: 戻りのパケットのポリシールーティング
if $no_routing; then
	log "transparent 用のポリシールーティングを外します"
	remove_routing
elif [ -n "$t_clients" ]; then
	log "transparent 用のポリシールーティングを設定します（$t_clients${t_ifaces:+ ← $t_ifaces}、テーブル $t_table）"
	# 前の設定で入れたルールを先に外す
	systemctl stop "$ROUTING_UNIT" 2>/dev/null || true
	rtmp=$(mktemp -d)
	template contrib/rproxy-transparent-routing "$rtmp/routing"
	template contrib/rproxy-transparent-routing.service "$rtmp/routing.service"
	install -m 0755 "$rtmp/routing" "$ROUTING_BIN"
	install -m 0644 "$rtmp/routing.service" "/etc/systemd/system/$ROUTING_UNIT"
	rm -rf "$rtmp"
	cat > "$ROUTING_CONF" <<CONF
# rproxy-transparent-routing の設定（install.sh が書いた。変えたら systemctl restart $ROUTING_UNIT）
CLIENTS="$t_clients"
IFACES="$t_ifaces"
TABLE=$t_table
CONF
	chmod 0644 "$ROUTING_CONF"
	systemctl daemon-reload
	systemctl enable --now "$ROUTING_UNIT"
fi
if [ -n "$static_rules" ]; then
	static_rules=$(readlink -f "$static_rules")
	case $static_rules in
		/home/* | /root/* | /tmp/*) die "--static-rules は /etc/rproxy などに置いてください（サービスからは /home・/root・/tmp が見えません）" ;;
	esac
	runuser -u rproxy -- test -r "$static_rules" || die "rproxy ユーザーが $static_rules を読めません（chgrp rproxy と chmod g+r を）"
	set_env RPROXY_STATIC_RULES "$static_rules"
fi
case $log_file in
	'') ;;
	-) unset_env RPROXY_LOG_FILE ;;
	*)
		set_env RPROXY_LOG_FILE "$log_file"
		case $log_file in
			"$LOG_DIR"/*) ;;
			*) warn "$LOG_DIR 以外に書く場合は、rproxy ユーザーが書けるようにし、ユニットの ReadWritePaths にも足してください（systemctl edit rproxy-api）" ;;
		esac
		;;
esac
# 初回は、指定がなければファイルに出す（古い雛形ではこの行がコメントになっている）
if $fresh && [ -z "$log_file" ]; then
	set_env RPROXY_LOG_FILE "$LOG_DIR/rproxy.log"
fi

# ---------------------------------------------------------------- start

addr=$(get_env RPROXY_API_ADDR); addr=${addr:-127.0.0.1}; addr=${addr%%,*}
port=$(get_env RPROXY_API_PORT); port=${port:-8080}
case $addr in 0.0.0.0) host=127.0.0.1 ;; ::) host='[::1]' ;; *:*) host="[$addr]" ;; *) host=$addr ;; esac

if $no_start; then
	log "起動はしていません。sudo systemctl enable --now rproxy-api で起動します"
else
	start_failed() {
		journalctl -u "$UNIT" --no-pager -n 20 >&2 || true
		die "起動できませんでした（journalctl -u rproxy-api で確認してください）"
	}
	# 続けて何度も実行したときに systemd の起動回数の上限（StartLimitBurst）に当たらないようにする
	systemctl reset-failed "$UNIT" 2>/dev/null || true
	if $was_active; then
		log "再起動します"
		systemctl restart "$UNIT" || start_failed
	else
		log "有効にして起動します"
		systemctl enable --now "$UNIT" || start_failed
	fi
	scheme=http
	[ -z "$(get_env RPROXY_TLS_CERT)" ] || scheme=https
	ok=false
	for _ in $(seq 50); do
		if curl -fsk -o /dev/null "$scheme://$host:$port/healthz" 2>/dev/null; then ok=true; break; fi
		systemctl is-active --quiet "$UNIT" || break
		sleep 0.2
	done
	if $ok; then
		log "起動しました（$scheme://$host:$port）"
		caps=$(curl -fsk -H "Authorization: Bearer $(head -n1 "$TOKENS")" "$scheme://$host:$port/capabilities" 2>/dev/null || true)
		case $caps in
			*'"transparent":true'*) transparent=使える ;;
			*'"transparent":false'*) transparent=使えない; warn "source_ip: transparent が使えません（CAP_NET_ADMIN を確認してください）" ;;
			*) transparent=不明 ;;
		esac
		case $caps in
			*'"transparent_ipv6":true'*) transparent="$transparent（IPv6 も）" ;;
			*'"transparent_ipv6":false'*) transparent="$transparent（IPv6 は使えない）" ;;
		esac
	else
		journalctl -u "$UNIT" --no-pager -n 20 >&2 || true
		die "起動を確認できませんでした（journalctl -u rproxy-api で確認してください）"
	fi
fi

cat <<EOF

rproxy-api $(rproxy-api --version 2>/dev/null | awk '{print $2}') をインストールしました（$method）。

  設定        $ENV_FILE（変えたら systemctl restart rproxy-api）
  トークン    $TOKENS（変えたら systemctl reload rproxy-api）
  ログ        $(get_env RPROXY_LOG_FILE | sed 's/^$/journalctl -u rproxy-api/')
  状態        systemctl status rproxy-api
  transparent ${transparent:-未確認}$( [ -e "$ROUTING_CONF" ] && echo "（ルーティング: $ROUTING_BIN status）" )

UI（TCP-UDP-rproxy-ui）の .env.local に設定する値:
  RPROXY_API_URL=${scheme:-http}://$host:$port
  RPROXY_API_TOKEN=\$(cat $TOKENS)

EOF
