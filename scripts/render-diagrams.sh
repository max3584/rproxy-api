#!/usr/bin/env bash
# docs/architecture/*.puml から SVG を作り直す。
# plantuml コマンドがあればそれを、なければ PLANTUML_JAR（と java）を使う。
# Graphviz は不要（図は PlantUML に入っているレイアウト smetana を使う）。
set -euo pipefail
cd "$(dirname "$0")/../docs/architecture"
if command -v plantuml >/dev/null; then
	plantuml -tsvg -charset UTF-8 ./*.puml
elif [ -n "${PLANTUML_JAR:-}" ]; then
	"${JAVA:-java}" -Djava.awt.headless=true -jar "$PLANTUML_JAR" -tsvg -charset UTF-8 ./*.puml
else
	echo "plantuml コマンドか PLANTUML_JAR（plantuml.jar のパス）が要ります" >&2
	exit 1
fi
ls -1 ./*.svg
