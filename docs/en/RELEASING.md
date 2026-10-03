日本語: [RELEASING.md](../RELEASING.md)

# Versioning and releases

rproxy-api ([max3584/rproxy-api](https://github.com/max3584/rproxy-api)) and the UI ([max3584/TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)) **share one sequence of version numbers**.
When what runs changes in both, release them together under the same number (UI vX.Y.Z pairs with rproxy-api vX.Y.Z). **When what runs changes in only one of them, release only that one** (the other skips the number; e.g. after a UI-only v0.3.16, rproxy-api's next release is v0.3.17). A release pairs with the newest release of the other at or below its number (UI v0.3.16 pairs with rproxy-api v0.3.15).

## How to bump the version

To avoid bumping the minor version too often, **decide the shape (interface) collectively in a minor release, and make the contents usable step by step in patch releases**.

| Change | Component to bump | Example |
|---|---|---|
| Adding to or changing the shape of the config file, control API, or DB (`options`, etc.) (until 1.0, breaking changes also go here) | Minor | 0.2.x → 0.3.0 |
| Making the contents of a feature whose shape is already decided usable (`GET /capabilities` reports whether it is available) | Patch | 0.3.0 → 0.3.1 |
| Bug fixes, dependency updates (they change what gets built), improvements to packaging and installers | Patch | 0.3.1 → 0.3.2 |
| Changes only to the README, docs, CI or tests | No bump | Ship them with the next release that changes code |

- **Bump the version only when what runs changes** (the rproxy-api binary or source code, the UI code, the package contents). Changes only to the README, docs, badges, CI or tests don't get a release of their own; they stay in the milestone and go out with the next release.
- In a minor release, decide together the config and API shape for the features that will land over the following period, and write it in docs/API.md. Items whose contents are not ready yet are reported as unavailable by `GET /capabilities` and rejected with `unsupported` when specified.
- If a change cannot be made without changing the shape, bundle it into the next minor release.

## Milestones

- Keep "next patch" (e.g. v0.2.3), "next minor" (e.g. v0.3.0; the work of deciding the shape), and "implementation" (e.g. v0.3.x; the work of making the contents usable) open.
- When creating a PR or issue, attach the milestone determined by the table above. For PRs where it was forgotten, `.github/workflows/milestone.yml` attaches the milestone of the nearest version (the same applies to Renovate PRs).
- When releasing a patch, move the completed items in "implementation" to that patch's milestone (e.g. v0.3.1) and release.
- Verification tasks that wait on the environment or on an administrator's action (testing on real hardware, installing an app, etc.) get no milestone, so that they do not block releases.
- Release when everything in the milestone is closed. Move anything not finished to the next milestone.

## Release procedure

1. **A version bump PR** (branch `release/vX.Y.Z`, with the same name in both repositories; the UI's e2e tests run against the rproxy-api branch with the same name)
   - rproxy-api: `version` in `Cargo.toml` and the rproxy-api entry in `Cargo.lock` (`cargo update -p rproxy-api --offline`). If `Cargo.lock` is not updated, CI and the release, which build with `--locked`, stop
   - UI: `npm version X.Y.Z --no-git-tag-version` (`package.json` and `package-lock.json`)
2. **Once merged, release the UI first, then rproxy-api** (because rproxy-api's apt publishing takes the `rproxy-ui` .deb from the UI release with the same number) (`vX.Y.Z`. Tags cannot be deleted or moved because of the ruleset, so verify the commit before tagging)
   - rproxy-api: pushing the tag makes `release.yml` build the binaries and .deb files, attach them to the GitHub Release, and update the apt repository. It stops if the tag and `version` in `Cargo.toml` differ
   - UI: create the tag and release with `gh release create vX.Y.Z --target <full ID of the merge commit>`. On publishing, `release.yml` builds and attaches `rproxy-ui_X.Y.Z-1_all.deb`, so wait for it to finish
   - rproxy-api: push the tag after the UI .deb above has been attached (if it is missing, the apt job emits a warning and publishes only rproxy-api; to add it later, rerun the apt job)
   - **UI-only release**: once the UI release has its .deb attached, run rproxy-api's `release.yml` by hand to publish it to apt (`gh workflow run release.yml -R max3584/rproxy-api -f ui_tag=vX.Y.Z`; rproxy-api is not built). Don't open a version bump PR or push a tag in rproxy-api
3. **Release notes**: write "Main changes" in Japanese from the PRs merged in that milestone, and add a link to the release of the counterpart it is paired with (for a one-sided release, link the previous release of the other)
4. **Close the milestone** and create the milestone for the next patch
5. Confirm that it has been published via apt (the new version is visible with `apt-cache policy rproxy-api`)
