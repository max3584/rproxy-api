#!/bin/sh
# リリースのバイナリを 1 つのターゲット向けにビルドする（release.yml と cross.yml が使う。#191）。
# CI の Alpine（musl）のコンテナで動かす前提：
#
#   x86_64-unknown-linux-musl  ホストと同じなので cargo build（gcc・musl-dev）
#   それ以外                   cargo-zigbuild（zig cc がリンカと C コンパイラ。ring の C・アセンブリも zig でビルドする）
#                              gnu は glibc $GLIBC（既定 2.17）向けにリンクする（それより新しい glibc ならどこでも動く）
#
#   scripts/build-release.sh <target>
#   → target/<target>/release/rproxy-api と rproxy-traefik-convert（Traefik の設定の変換、.deb に入れる。crates/rproxy-traefik）
#
# 必要なもの: rustup の stable（<target> の rust-std）、zig と cargo-zigbuild 0.23 以降（apk add zig cargo-zigbuild。Alpine 3.24 以降。
# 古い cargo-zigbuild は aarch64 で rustc が渡す --fix-cortex-a53-843419 を zig に渡してしまい、リンクできない）
set -eu

# the server and the Traefik converter (both go into the .deb)
packages="-p rproxy-api -p rproxy-traefik"
target=${1:?usage: $0 <target>}
GLIBC=${GLIBC:-2.17}

case $target in
x86_64-unknown-linux-musl)
	# shellcheck disable=SC2086
	cargo build --locked --release --target "$target" $packages
	;;
*-gnu | *-gnueabihf)
	# shellcheck disable=SC2086
	cargo zigbuild --locked --release --target "$target.$GLIBC" $packages
	;;
*)
	# shellcheck disable=SC2086
	cargo zigbuild --locked --release --target "$target" $packages
	;;
esac
ls -l "target/$target/release/rproxy-api" "target/$target/release/rproxy-traefik-convert"
