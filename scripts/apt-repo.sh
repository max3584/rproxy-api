#!/usr/bin/env bash
# Adds .deb files to a flat-pool apt repository and re-signs its index.
#
#   scripts/apt-repo.sh <repo-dir> <file.deb>...
#
# Layout (served as-is by GitHub Pages from the gh-pages branch):
#   pool/main/r/rproxy-api/*.deb
#   dists/stable/main/binary-<arch>/Packages{,.gz}
#   dists/stable/{Release,Release.gpg,InRelease}
#   rproxy-archive-keyring.gpg   (binary public key for signed-by=)
#
# Signs with the default secret key in the GnuPG keyring, or APT_GPG_KEY_ID.
# Needs dpkg-dev (dpkg-deb), apt-utils (apt-ftparchive) and gnupg.
set -euo pipefail

if [ $# -lt 2 ]; then
	echo "usage: $0 <repo-dir> <file.deb>..." >&2
	exit 2
fi
repo=$1
shift

SUITE=stable
COMPONENT=main
ARCHES="amd64 arm64 armhf"
pool="$repo/pool/$COMPONENT/r/rproxy-api"
dist="$repo/dists/$SUITE"
key=(${APT_GPG_KEY_ID:+--local-user "$APT_GPG_KEY_ID"})

mkdir -p "$pool"
for deb in "$@"; do
	name=$(dpkg-deb --field "$deb" Package)
	version=$(dpkg-deb --field "$deb" Version)
	arch=$(dpkg-deb --field "$deb" Architecture)
	dest="$pool/${name}_${version}_${arch}.deb"
	# a published version must never change under the same name (apt caches it by hash)
	if [ -e "$dest" ] && ! cmp -s "$deb" "$dest"; then
		echo "$dest already exists with different contents; bump the version" >&2
		exit 1
	fi
	cp "$deb" "$dest"
done

cd "$repo"
for arch in $ARCHES; do
	dir="dists/$SUITE/$COMPONENT/binary-$arch"
	mkdir -p "$dir"
	apt-ftparchive --arch "$arch" packages "pool/$COMPONENT" > "$dir/Packages"
	gzip -9nkf "$dir/Packages"
done

# the old index must not end up hashed into the new one
rm -f "dists/$SUITE/Release" "dists/$SUITE/InRelease" "dists/$SUITE/Release.gpg"
release=$(mktemp)
apt-ftparchive \
	-o APT::FTPArchive::Release::Origin=rproxy-api \
	-o APT::FTPArchive::Release::Label=rproxy-api \
	-o APT::FTPArchive::Release::Suite=$SUITE \
	-o APT::FTPArchive::Release::Codename=$SUITE \
	-o "APT::FTPArchive::Release::Architectures=$ARCHES" \
	-o APT::FTPArchive::Release::Components=$COMPONENT \
	release "dists/$SUITE" > "$release"
mv "$release" "dists/$SUITE/Release"
chmod 644 "dists/$SUITE/Release"

gpg --batch --yes "${key[@]}" --clearsign --digest-algo SHA512 -o "dists/$SUITE/InRelease" "dists/$SUITE/Release"
gpg --batch --yes "${key[@]}" --armor --detach-sign --digest-algo SHA512 -o "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"
gpg --batch --yes --export ${APT_GPG_KEY_ID:+"$APT_GPG_KEY_ID"} > rproxy-archive-keyring.gpg
# GitHub Pages must serve the files as they are (no Jekyll)
touch .nojekyll

echo "$(pwd): $(find pool -name '*.deb' | wc -l) package(s)"
