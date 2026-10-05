#!/bin/sh
# リリースのバイナリを 1 つのターゲット向けにビルドする（release.yml と cross.yml が使う。#191）。
# CI の Alpine（musl）のコンテナで動かす前提：
#
#   x86_64-unknown-linux-musl  ホストと同じなので cargo build（gcc・musl-dev）
#   それ以外                   cargo-zigbuild（zig cc がリンカと C コンパイラ。ring の C・アセンブリも zig でビルドする）
#                              gnu は glibc $GLIBC（既定 2.17）向けにリンクする（それより新しい glibc ならどこでも動く）
#
#   scripts/build-release.sh <target>
#   → target/<target>/release/rproxy-api
#
# 必要なもの: rustup の stable（<target> の rust-std）、zig と cargo-zigbuild 0.23 以降（apk add zig cargo-zigbuild。Alpine 3.24 以降。
# 古い cargo-zigbuild は aarch64 で rustc が渡す --fix-cortex-a53-843419 を zig に渡してしまい、リンクできない）
set -eu

target=${1:?usage: $0 <target>}
GLIBC=${GLIBC:-2.17}

case $target in
x86_64-unknown-linux-musl)
	cargo build --locked --release --target "$target"
	;;
*-gnu | *-gnueabihf)
	cargo zigbuild --locked --release --target "$target.$GLIBC"
	;;
*)
	cargo zigbuild --locked --release --target "$target"
	;;
esac
ls -l "target/$target/release/rproxy-api"
