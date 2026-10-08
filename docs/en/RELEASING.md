日本語: [RELEASING.md](../RELEASING.md)

# Versioning and releases

rproxy-api ([max3584/rproxy-api](https://github.com/max3584/rproxy-api)) and the UI ([max3584/TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)) **advance their version numbers independently** (their release tags may diverge).
Each repository bumps its own number and releases only when what runs in it changes.

The UI checks the combination. It knows the oldest rproxy-api it needs and compares it with each node's rproxy-api version (`version` in `GET /capabilities`, since v0.3.18); when a node is older, its version is unknown, or it is a newer minor than the UI knows about, the UI shows a notice. Fine-grained decisions per feature still use `features` in `GET /capabilities`. The UI's release notes state the minimum rproxy-api version it needs.

## How to bump the version

To avoid bumping the minor version too often, **decide the shape (interface) collectively in a minor release, and make the contents usable step by step in patch releases**.

| Change | Component to bump | Example |
|---|---|---|
| Adding to or changing the shape of the config file, control API, or DB (`options`, etc.) (until 1.0, breaking changes also go here; after v0.4.0, additions alone are a patch: "After v0.4.0" below) | Minor | 0.2.x → 0.3.0 |
| Making the contents of a feature whose shape is already decided usable (`GET /capabilities` reports whether it is available) | Patch | 0.3.0 → 0.3.1 |
| Bug fixes, dependency updates (they change what gets built), improvements to packaging and installers | Patch | 0.3.1 → 0.3.2 |
| Changes only to the README, docs, CI or tests | No bump | Ship them with the next release that changes code |

- **Bump the version only when what runs changes** (the rproxy-api binary or source code, the UI code, the package contents). Changes only to the README, docs, badges, CI or tests don't get a release of their own; they stay in the milestone and go out with the next release.
- In a minor release, decide together the config and API shape for the features that will land over the following period, and write it in docs/API.md. Items whose contents are not ready yet are reported as unavailable by `GET /capabilities` and rejected with `unsupported` when specified.
- If a change cannot be made without changing the shape, bundle it into the next minor release.
- **v0.4.0 is an exception** (owner's decision, #215): instead of settling the shape and shipping the contents in patches, every content lands first and v0.4.0 ships once (no intermediate releases before v0.4.0). In v0.4.0 every v0.4 flag in `GET /capabilities` `features` is true (`features.performance` lists every key) and no v0.4 setting is refused with `unsupported`.

### After v0.4.0: additive shapes ship in patches (owner's decision)

After v0.4.0, **changes that only add shape (new settings, API endpoints, fields, scopes, `features` flags, new DB tables) also ship in patches** (v0.4.1, v0.4.2, ...). The minor version goes up only for **breaking changes** (changing or removing the shape or behaviour of existing settings, API or DB). "Adding shape" in the table above becomes a patch instead of a minor.

- Everything added is optional, and leaving it out behaves as the previous patch (existing settings, .deb and VM setups keep their behaviour). To change a default, make the new behaviour selectable with a flag or environment variable, and leave switching the default to the next minor.
- A new feature lands its shape and its implementation in the same PR, and adds a new flag to `features` in `GET /capabilities` set to true (no shipping a shape first with the flag false). The UI and rproxy-gateway tell features apart by these flags, so they keep working with an older patch of rproxy.
- **Live upgrades (`handoff`) within one minor are still guaranteed** ("Live upgrades and patches" below). The state handed over only grows (in a shape an older version can skip what it does not know), so rolling back to an older patch still hands over.
- Once you use settings a newer patch added (token file fields or scopes, `RPROXY_*`), an older patch that does not know them may treat them as an error (for example, the token file rejects unknown fields). Remove those settings before rolling back. The "Added" section of the release notes says which version a setting needs.
- The design is in docs/en/DESIGN-v0.4.x.md (from v0.4.1).

### Before releasing v0.4.0

- The release signing key ("Release signatures" below): set the secret `MINISIGN_SECRET_KEY` and the variable `MINISIGN_PUBLIC_KEY`. Tagging without them makes v0.4.0 unsigned and built without a key (the self-update of v0.4.0 binaries then always needs `RPROXY_UPDATE_PUBKEY`).
- Live upgrades (`handoff`) work only within a minor, so upgrading the .deb from v0.3.x to v0.4.0 restarts the service (`postinst`). Say so in the release notes too.

## Milestones

- Keep "next patch" (e.g. v0.2.3), "next minor" (e.g. v0.3.0; the work of deciding the shape), and "implementation" (e.g. v0.3.x; the work of making the contents usable) open. After v0.4.0, new features also go to patch milestones (v0.4.1, v0.4.2, ...); "next minor" is only for breaking changes.
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
minisign -G -p minisign.pub -s minisign.key      # with a password (protects the key file you keep)
# minisign -G -W -p minisign.pub -s minisign.key # -W for no password
```

- **Secret key**: the whole content of `minisign.key` goes into the repository secret **`MINISIGN_SECRET_KEY`** (`gh secret set MINISIGN_SECRET_KEY -R max3584/rproxy-api < minisign.key`). Keep the local `minisign.key` offline.
- **Password**: if the key has a password, put it in the repository secret **`MINISIGN_PASSWORD`** (`gh secret set MINISIGN_PASSWORD -R max3584/rproxy-api`, typed interactively). `sign` passes it on stdin.
- **Public key**: the second line (base64) of `minisign.pub` goes into the repository variable **`MINISIGN_PUBLIC_KEY`** (`gh variable set MINISIGN_PUBLIC_KEY -R max3584/rproxy-api --body "$(tail -n1 minisign.pub)"`). The release build puts it into the binary (`RPROXY_RELEASE_PUBKEY`) as the default of `RPROXY_UPDATE_PUBKEY`. Publish `minisign.pub` in the README and release notes too.
- When `sign` fails on the tag push (a missing password, say), fix it and run `gh workflow run release.yml -R max3584/rproxy-api -f sign_tag=vX.Y.Z` to attach the signatures and self-update files to the published tag (nothing is built).
- Without the secret, `manifest.json` and `SHA256SUMS` are attached unsigned with a warning (the self-update skips that release). Without the variable, binaries have no key built in and the self-update needs `RPROXY_UPDATE_PUBKEY`.
- Rotating the key: versions with the old key built in cannot self-update to releases signed with a new key (they cannot verify it). Rotate together with a minor upgrade (a restart), or have users pass the new key with `RPROXY_UPDATE_PUBKEY`.
