#!/usr/bin/env bash
# docs/architecture/*.puml から SVG を作り直す。次の順で使えるものを使う：
#   1. PLANTUML_SERVER（PlantUML サーバの URL。例 http://plantuml.example:8080）… POST /svg で描く
#   2. plantuml コマンド
#   3. PLANTUML_JAR（plantuml.jar のパス）と java
# Graphviz は不要（図は PlantUML に入っているレイアウト smetana を使う）。
set -euo pipefail
cd "$(dirname "$0")/../docs/architecture"
if [ -n "${PLANTUML_SERVER:-}" ]; then
	for f in ./*.puml; do
		out="${f%.puml}.svg"
		curl -fsS -X POST -H 'Content-Type: text/plain; charset=utf-8' --data-binary "@$f" "${PLANTUML_SERVER%/}/svg" -o "$out.tmp"
		if grep -q 'Syntax Error' "$out.tmp"; then
			echo "$f: PlantUML の構文の誤り" >&2
			rm -f "$out.tmp"
			exit 1
		fi
		mv "$out.tmp" "$out"
	done
elif command -v plantuml >/dev/null; then
	plantuml -tsvg -charset UTF-8 ./*.puml
elif [ -n "${PLANTUML_JAR:-}" ]; then
	"${JAVA:-java}" -Djava.awt.headless=true -jar "$PLANTUML_JAR" -tsvg -charset UTF-8 ./*.puml
else
	echo "PLANTUML_SERVER（PlantUML サーバの URL）、plantuml コマンド、PLANTUML_JAR のどれかが要ります" >&2
	exit 1
fi
ls -1 ./*.svg
