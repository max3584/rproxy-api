日本語: [RELEASING.md](../RELEASING.md)

# Versioning and releases

rproxy-api ([max3584/rproxy-api](https://github.com/max3584/rproxy-api)) and the UI ([max3584/TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)) **advance their version numbers independently** (their release tags may diverge).
Each repository bumps its own number and releases only when what runs in it changes.

The UI checks the combination. It knows the oldest rproxy-api it needs and compares it with each node's rproxy-api version (`version` in `GET /capabilities`, since v0.3.18); when a node is older, its version is unknown, or it is a newer minor than the UI knows about, the UI shows a notice. Fine-grained decisions per feature still use `features` in `GET /capabilities`. The UI's release notes state the minimum rproxy-api version it needs.

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

Done only in the repository being released (the other one's version is not bumped).

1. **A version bump PR** (branch `release/vX.Y.Z`)
   - rproxy-api: `version` in `Cargo.toml` and the rproxy-api entry in `Cargo.lock` (`cargo update -p rproxy-api --offline`). If `Cargo.lock` is not updated, CI and the release, which build with `--locked`, stop
   - UI: `npm version X.Y.Z --no-git-tag-version` (`package.json` and `package-lock.json`). When the UI starts to need a newer rproxy-api feature, also raise the minimum rproxy-api version (`components/version.ts` in the UI)
   - For a change spanning both repositories, use the same branch name in both (the UI's e2e tests run against the rproxy-api branch with the same name if there is one, otherwise the default branch)
2. **Once merged, release** (`vX.Y.Z`. Tags cannot be deleted or moved because of the ruleset, so verify the commit before tagging)
   - rproxy-api: pushing the tag makes `release.yml` build the binaries and .deb files, attach them to the GitHub Release, and publish rproxy-api to the apt repository. It stops if the tag and `version` in `Cargo.toml` differ
   - UI: create the tag and release with `gh release create vX.Y.Z --target <full ID of the merge commit>`. On publishing, `release.yml` builds and attaches `rproxy-ui_X.Y.Z-1_all.deb`. Once it is attached, run rproxy-api's `release.yml` by hand to publish it to apt (`gh workflow run release.yml -R max3584/rproxy-api -f ui_tag=vX.Y.Z`; rproxy-api is not built)
3. **Release notes**: write "Main changes" in Japanese from the PRs merged in that milestone. The UI's release notes state the minimum rproxy-api version it needs (e.g. "rproxy-api v0.3.18 or later")
4. **Close the milestone** and create the milestone for the next patch
5. Confirm that it has been published via apt (the new version is visible with `apt-cache policy rproxy-api` / `apt-cache policy rproxy-ui`)

## Live upgrades and patches (#174, from v0.4)

- **Patches within one minor (X.Y) are guaranteed to be swappable while running** (docs/en/UPGRADE.md). A .deb upgrade hands over (SIGUSR2) when major.minor is the same and restarts otherwise. The container self-update follows the same X.Y only.
- What a handoff passes (the kinds of sockets, the shape of `State` in `handoff.rs`, the messages) **does not change within a minor** (additions only in a form older versions can skip). Changing it means a new minor. Within a minor, going back to an older patch uses the same handoff.
- **Exception patches** (a fix that needs a restart): commit `debian/restart-required` (an empty file) and add `["debian/restart-required", "usr/share/rproxy-api/", "644"]` to `assets` in `Cargo.toml`. The `sign` job of `release.yml` then writes `"handoff": false` into `manifest.json` (the self-update does not swap it in and uses it at the next start), and the .deb's `postinst` restarts. Say "restart needed" in the release notes too. Remove both in the next patch.

## Release signatures (minisign, #174)

The `sign` job of `release.yml` writes the index `releases.json` (every release's version; the self-update reads the latest release's) and attaches minisign signatures (`.minisig`) of every binary, `manifest.json`, `SHA256SUMS` and `releases.json` to the release. The self-update runs nothing it cannot verify. The key is separate from the apt GPG key (the owner's decision).

Creating the key (once, locally; the secret key never goes into the repository):

```bash
minisign -G -W -p minisign.pub -s minisign.key   # -W: no password (CI signs with it; the secret store protects it)
```

- **Secret key**: the whole content of `minisign.key` goes into the repository secret **`MINISIGN_SECRET_KEY`** (`gh secret set MINISIGN_SECRET_KEY -R max3584/rproxy-api < minisign.key`). Keep the local `minisign.key` offline.
- **Public key**: the second line (base64) of `minisign.pub` goes into the repository variable **`MINISIGN_PUBLIC_KEY`** (`gh variable set MINISIGN_PUBLIC_KEY -R max3584/rproxy-api --body "$(tail -n1 minisign.pub)"`). The release build puts it into the binary (`RPROXY_RELEASE_PUBKEY`) as the default of `RPROXY_UPDATE_PUBKEY`. Publish `minisign.pub` in the README and release notes too.
- Without the secret, `manifest.json` and `SHA256SUMS` are attached unsigned with a warning (the self-update skips that release). Without the variable, binaries have no key built in and the self-update needs `RPROXY_UPDATE_PUBKEY`.
- Rotating the key: versions with the old key built in cannot self-update to releases signed with a new key (they cannot verify it). Rotate together with a minor upgrade (a restart), or have users pass the new key with `RPROXY_UPDATE_PUBKEY`.
