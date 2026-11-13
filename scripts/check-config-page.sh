#!/usr/bin/env bash
# Checks the config page (site/config, #406, https://max3584.github.io/rproxy-api/config/) against the code:
# every recipe's outputs, on its default input and a few variations, in Japanese and English.
#
#   scripts/check-config-page.sh <rproxy-api binary> [out-dir]
#
# out-dir: a new or empty directory (default: a new temporary one). A non-empty directory is refused unless an
# earlier run made it (it has .check-config-page); then only that run's files are replaced.
#
#   1. scripts/check-config-page.mjs: the generator's rules and global against docs/openapi.json, the guide
#      anchors against the headings of docs/GUIDE.md, docs/en/GUIDE.md and rproxy-gateway's guides;
#   2. the settings file YAML, and the JSON of the curl commands (as a settings file), with
#      `rproxy-api --check-config`;
#   3. the Gateway API YAML with kubeconform -strict against the CRD schemas of Gateway API (standard),
#      cert-manager and rproxy-gateway (`rproxy-gateway crds`);
#   4. the same YAML with `rproxy-gateway render` (with made-up Services, EndpointSlices and Secrets):
#      everything Accepted and resolved, and the rules it makes again with `rproxy-api --check-config`.
#
# Needs bash, curl, node, openssl, python3 with PyYAML (kubeconform's openapi2jsonschema.py) and tar.
# Downloads pinned versions (checked by SHA-256): kubeconform, the CRDs, and the rproxy-gateway binary
# from its image on ghcr.io (no docker). RPROXY_GATEWAY=<binary> uses a local rproxy-gateway instead,
# RPROXY_GATEWAY_GUIDES=<checkout> its docs instead of fetching them (the links on the live page point at
# rproxy-gateway's main; .github/workflows/config-page-links.yml checks them against main every week).
set -euo pipefail

if [ $# -lt 1 ]; then
	echo "usage: $0 <rproxy-api binary> [out-dir]" >&2
	exit 2
fi
api=$(realpath "$1")
if [ -n "${2:-}" ]; then
	out=$(realpath -m "$2")
else
	out=$(mktemp -d)
fi
here=$(cd "$(dirname "$0")/.." && pwd)

# pinned: bump together with the SHA-256 (Gateway API: the version rproxy-gateway's GUIDE 1.1 installs)
KUBECONFORM_VERSION=v0.8.0
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
OPENAPI2JSONSCHEMA_SHA256=d145babfbb765004030764e1b4e518bfb7a4bd7f111691a08fa57983b81881f3
GATEWAY_API_VERSION=v1.6.3
GATEWAY_API_SHA256=356c2b8e286a964dc20995435659ad1095386329974793af10bbfe3eff977fe5
CERT_MANAGER_VERSION=v1.21.3
CERT_MANAGER_SHA256=29810b2a84c8ee0731a79679ee1dfd7e93cd750eb0244542eec47fa8700f2749
# ghcr.io/max3584/rproxy-gateway:0.4.22 (the image index)
RPROXY_GATEWAY_IMAGE=max3584/rproxy-gateway
RPROXY_GATEWAY_DIGEST=sha256:12700de1f0ffc4560c773a18cdf95d3ef46ac9d11c4a659654238bce9e49c423
# rproxy-gateway's guides (the anchors the page links to), at a commit of its main
RPROXY_GATEWAY_REF=2fc51e8087d5666344aaa9e4d5648402d5e3421d
RPROXY_GATEWAY_GUIDE_SHA256=74dfb923ea27d4cf62cb64c09d80a093bc046b54e924cd990eaa4ed00d46b0da
RPROXY_GATEWAY_GUIDE_EN_SHA256=c637b3150ca862ce21393ef87a49276a434638f7623597419d9b4812502d74b3

# never remove a directory this script did not make
marker=.check-config-page
if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then
	if [ ! -f "$out/$marker" ]; then
		echo "$out is not empty and not from an earlier run; give a new or empty directory" >&2
		exit 2
	fi
	for d in settings api gateway world expect data tls dl schemas rendered; do rm -rf "${out:?}/$d"; done
fi
mkdir -p "$out"/{tls,dl,schemas,rendered}
touch "$out/$marker"

fetch() { # <url> <file> <sha256>
	curl -fsSL --retry 3 -o "$2" "$1"
	echo "$3  $2" | sha256sum -c --quiet - || {
		echo "$1: unexpected SHA-256" >&2
		exit 1
	}
}

# --- the test certificate (the sni-split recipe and the Secrets) ---------------------------------
(
	umask 077
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=example.com \
		-addext 'subjectAltName=DNS:example.com,DNS:*.example.com,DNS:*.example.org' \
		-keyout "$out/tls/example.key" -out "$out/tls/example.pem" 2>/dev/null
)
chmod 644 "$out/tls/example.pem"

# --- rproxy-gateway: the binary and its guides ---------------------------------------------------
if [ -n "${RPROXY_GATEWAY:-}" ]; then
	gw=$(realpath "$RPROXY_GATEWAY")
else
	# the linux/amd64 image of the pinned index; blobs are checked by their digests
	token=$(curl -fsSL "https://ghcr.io/token?scope=repository:$RPROXY_GATEWAY_IMAGE:pull" | node -e 'process.stdin.on("data",d=>process.stdout.write(JSON.parse(d).token))')
	registry() { # <path> <accept> <file>
		curl -fsSL --retry 3 -H "Authorization: Bearer $token" -H "Accept: $2" -o "$3" "https://ghcr.io/v2/$RPROXY_GATEWAY_IMAGE/$1"
	}
	digest_ok() { echo "${1#sha256:}  $2" | sha256sum -c --quiet -; }
	registry "manifests/$RPROXY_GATEWAY_DIGEST" 'application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json' "$out/dl/index.json"
	digest_ok "$RPROXY_GATEWAY_DIGEST" "$out/dl/index.json"
	manifest=$(node -e 'const i=require(process.argv[1]);process.stdout.write(i.manifests.find(m=>m.platform&&m.platform.architecture==="amd64"&&m.platform.os==="linux").digest)' "$out/dl/index.json")
	registry "manifests/$manifest" 'application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json' "$out/dl/manifest.json"
	digest_ok "$manifest" "$out/dl/manifest.json"
	mkdir -p "$out/dl/image"
	for layer in $(node -e 'for (const l of require(process.argv[1]).layers) console.log(l.digest)' "$out/dl/manifest.json"); do
		registry "blobs/$layer" '*/*' "$out/dl/layer.tgz"
		digest_ok "$layer" "$out/dl/layer.tgz"
		tar -xzf "$out/dl/layer.tgz" -C "$out/dl/image" usr/local/bin/rproxy-gateway 2>/dev/null || true
	done
	gw=$out/dl/image/usr/local/bin/rproxy-gateway
fi
"$gw" --version

if [ -n "${RPROXY_GATEWAY_GUIDES:-}" ]; then
	cp "$RPROXY_GATEWAY_GUIDES/docs/GUIDE.md" "$out/dl/gw-guide.md"
	cp "$RPROXY_GATEWAY_GUIDES/docs/en/GUIDE.md" "$out/dl/gw-guide-en.md"
else
	fetch "https://raw.githubusercontent.com/max3584/rproxy-gateway/$RPROXY_GATEWAY_REF/docs/GUIDE.md" "$out/dl/gw-guide.md" "$RPROXY_GATEWAY_GUIDE_SHA256"
	fetch "https://raw.githubusercontent.com/max3584/rproxy-gateway/$RPROXY_GATEWAY_REF/docs/en/GUIDE.md" "$out/dl/gw-guide-en.md" "$RPROXY_GATEWAY_GUIDE_EN_SHA256"
fi

# --- 1. the generator ----------------------------------------------------------------------------
node "$here/scripts/check-config-page.mjs" "$out" "$out/dl/gw-guide.md" "$out/dl/gw-guide-en.md"

failed=0

# --- the YAML on the page reads back as the generator's data (PyYAML, YAML 1.1: the stricter reading) ---
if ! python3 - "$out" << 'PY'; then
import glob, json, os, sys, yaml
out, bad = sys.argv[1], 0
for f in sorted(glob.glob(os.path.join(out, "data", "*.json"))):
    name = os.path.basename(f)[:-5]
    want = json.load(open(f))
    got = {
        "settings": yaml.safe_load(open(os.path.join(out, "settings", name + ".yaml"))),
        "gateway": [d for d in yaml.safe_load_all(open(os.path.join(out, "gateway", name + ".yaml"))) if d is not None],
    }
    for part in ("settings", "gateway"):
        if got[part] != want[part]:
            print(f"FAIL {name}: the {part} YAML does not read back as the generator's data", file=sys.stderr)
            bad = 1
sys.exit(bad)
PY
	failed=1
fi

check_config() { # <file> <what>
	if ! "$api" --check-config "$1" > "$out/check.log" 2>&1; then
		echo "FAIL $2: rproxy-api --check-config $1" >&2
		cat "$out/check.log" >&2
		failed=1
	fi
}

# --- 2. the settings file and the API JSON -------------------------------------------------------
for f in "$out"/settings/*.yaml; do check_config "$f" "settings file $(basename "$f")"; done
for f in "$out"/api/*.json; do check_config "$f" "API JSON $(basename "$f")"; done

# --- 3. Gateway API YAML against the CRD schemas -------------------------------------------------
fetch "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" "$out/dl/kubeconform.tar.gz" "$KUBECONFORM_SHA256"
tar -xzf "$out/dl/kubeconform.tar.gz" -C "$out/dl" kubeconform
fetch "https://raw.githubusercontent.com/yannh/kubeconform/$KUBECONFORM_VERSION/scripts/openapi2jsonschema.py" "$out/dl/openapi2jsonschema.py" "$OPENAPI2JSONSCHEMA_SHA256"
fetch "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" "$out/dl/gateway-api.yaml" "$GATEWAY_API_SHA256"
fetch "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.crds.yaml" "$out/dl/cert-manager.yaml" "$CERT_MANAGER_SHA256"
"$gw" crds > "$out/dl/rproxy-crds.yaml"
# one JSON Schema per kind and version; additionalProperties: false below the root (as kubectl validates)
(cd "$out/schemas" && FILENAME_FORMAT='{kind}_{version}' python3 "$out/dl/openapi2jsonschema.py" \
	"$out/dl/gateway-api.yaml" "$out/dl/cert-manager.yaml" "$out/dl/rproxy-crds.yaml" > /dev/null)
if ! "$out/dl/kubeconform" -strict -summary -schema-location "$out/schemas/{{ .ResourceKind }}_{{ .ResourceAPIVersion }}.json" "$out"/gateway/*.yaml; then
	echo "FAIL kubeconform" >&2
	failed=1
fi

# --- 4. rproxy-gateway render, and its rules with --check-config ---------------------------------
for f in "$out"/gateway/*.yaml; do
	name=$(basename "$f" .yaml)
	if ! "$gw" render -f "$f" -f "$out/world/$name.yaml" > "$out/rendered/$name.json" 2> "$out/check.log"; then
		echo "FAIL $name: rproxy-gateway render" >&2
		cat "$out/check.log" >&2
		failed=1
		continue
	fi
	node "$here/scripts/check-config-page-render.mjs" "$out" "$name" || failed=1
	check_config "$out/rendered/$name.settings.json" "rules rendered from $name"
done

if [ "$failed" != 0 ]; then
	echo "the config page's outputs do not pass; see FAIL above (outputs in $out)" >&2
	exit 1
fi
cases=("$out"/settings/*.yaml)
echo "OK: the config page's outputs pass (${#cases[@]} cases)"
