日本語: [RELEASING.md](../RELEASING.md)

# Versioning and releases

rproxy-api ([max3584/rproxy-api](https://github.com/max3584/rproxy-api)) and the UI ([max3584/TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)) are **released together under the same version number**.
UI vX.Y.Z is used together with rproxy-api vX.Y.Z. Even when only one of them has changes, create a tag and a release with the same number in both.

## How to bump the version

To avoid bumping the minor version too often, **decide the shape (interface) collectively in a minor release, and make the contents usable step by step in patch releases**.

| Change | Component to bump | Example |
|---|---|---|
| Adding to or changing the shape of the config file, control API, or DB (`options`, etc.) (until 1.0, breaking changes also go here) | Minor | 0.2.x → 0.3.0 |
| Making the contents of a feature whose shape is already decided usable (`GET /capabilities` reports whether it is available) | Patch | 0.3.0 → 0.3.1 |
| Bug fixes, documentation, dependency updates, packaging/installer improvements, tests | Patch | 0.3.1 → 0.3.2 |

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
3. **Release notes**: write "Main changes" in Japanese from the PRs merged in that milestone, and add a link to the release of the counterpart it is paired with
4. **Close the milestone** and create the milestone for the next patch
5. Confirm that it has been published via apt (the new version is visible with `apt-cache policy rproxy-api`)
