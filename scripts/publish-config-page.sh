#!/usr/bin/env bash
# Publishes the config page (site/config, #406) to the gh-pages branch under config/ only:
# https://max3584.github.io/rproxy-api/config/. Used by .github/workflows/pages.yml.
#
#   scripts/publish-config-page.sh [remote]      # remote: a name or URL, default origin
#   DRY_RUN=1 scripts/publish-config-page.sh     # commit in a temporary worktree, show it, do not push
#
# The apt repository on the same branch (dists/, pool/, rproxy-archive-keyring.gpg, index.html, written by
# the apt job of release.yml) is never touched: only config/ is staged, and anything else staged stops it.
# What keeps the two writers safe is that both push without --force: a push only fast-forwards the gh-pages
# it was built on (FETCH_HEAD here), so git refuses it when the other one pushed in between. Then this starts
# again from the new gh-pages (and the apt job puts its commit on top of it): neither loses the other's files.
# The concurrency groups only keep each workflow from racing itself.
set -euo pipefail

remote=${1:-origin}
here=$(cd "$(dirname "$0")/.." && pwd)
src=$here/site/config
rev=$(git -C "$here" rev-parse --short HEAD)
work=$(mktemp -d)
# a shallow checkout (CI) fetches only the tip; a full clone stays full (--depth would make it shallow)
depth=()
if [ "$(git -C "$here" rev-parse --is-shallow-repository)" = true ]; then depth=(--depth 1); fi
trap 'git -C "$here" worktree remove --force "$work/pages" 2> /dev/null || true; rm -rf "$work"' EXIT

for attempt in 1 2 3 4 5; do
	git -C "$here" worktree remove --force "$work/pages" 2> /dev/null || true
	# gh-pages is made by the first release (docs/APT.md); this never creates it
	git -C "$here" fetch --quiet "${depth[@]}" "$remote" gh-pages
	git -C "$here" worktree add --quiet --detach "$work/pages" FETCH_HEAD
	pages=$work/pages

	rm -rf "$pages/config"
	mkdir "$pages/config"
	# the whole directory, as it is in the repository
	cp -R "$src"/. "$pages/config/"
	git -C "$pages" add --all -- config
	others=$(git -C "$pages" diff --cached --name-only | grep -v '^config/' || true)
	if [ -n "$others" ]; then
		echo "refusing: files outside config/ are staged:" >&2
		echo "$others" >&2
		exit 1
	fi
	if git -C "$pages" diff --cached --quiet; then
		echo "gh-pages config/ is already up to date"
		exit 0
	fi
	git -C "$pages" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
		commit --quiet -m "pages: config/ from $rev"
	git -C "$pages" show --stat --format='%h %s' HEAD
	if [ "${DRY_RUN:-0}" = 1 ]; then
		echo "dry run: not pushed"
		exit 0
	fi
	if git -C "$pages" push --quiet "$remote" HEAD:refs/heads/gh-pages; then
		echo "published config/ to gh-pages"
		exit 0
	fi
	echo "push refused (gh-pages moved, attempt $attempt)" >&2
	if [ "$attempt" -lt 5 ]; then sleep $((attempt * 5)); fi
done
echo "could not push gh-pages" >&2
exit 1
