日本語: [APT.md](../APT.md)

# Debian package and apt repository

## Package contents

Built with `cargo deb` (configuration in `[package.metadata.deb]` of `Cargo.toml`; scripts and units in `debian/`).
Releases use a statically linked musl binary, so the same package works on any Debian / Ubuntu release.

| Path | Contents |
|---|---|
| `/usr/bin/rproxy-api` | The binary |
| `/usr/lib/systemd/system/rproxy-api.service` | Unit (same contents as `contrib/rproxy-api.service`, except that `ExecStart` uses `/usr/bin`) |
| `/etc/rproxy/rproxy.env` | Configuration (conffile; your edits are preserved across upgrades) |
| `/etc/rproxy/tokens` | API tokens. One is generated on first install (`root:rproxy`, 640) |
| `/var/log/rproxy/` | Logs (`rproxy.<date>.log`, JSON Lines). rproxy splits them daily and deletes old ones beyond `RPROXY_LOG_KEEP`, so logrotate is not needed |
| `/usr/share/doc/rproxy-api/` | README, API.md, PROFILES.md, examples of static rules |

- Installation creates the `rproxy` system user. The service runs as this user, and the unit grants `CAP_NET_BIND_SERVICE` (ports below 1024) and `CAP_NET_ADMIN` (`source_ip: transparent`) (docs/PERMISSIONS.md).
- Installing alone neither enables nor starts the service (so that the API does not come up before configuration). Start it with `systemctl enable --now rproxy-api`.
- On upgrade, the service is restarted if it is running (`try-restart`). Tokens and configuration are left unchanged.
- `apt purge` removes `/etc/rproxy/tokens`, `/etc/rproxy/`, and `/var/log/rproxy/`. The `rproxy` user is kept.
- To send logs to journald (`journalctl -u rproxy-api`), comment out the `RPROXY_LOG_FILE` line in `rproxy.env`.
- Policy routing for the return packets of `source_ip: transparent` can be installed with `scripts/install.sh --transparent-clients ... --transparent-iface ...` (see "Passing the source IP" in the README).

The CI `Debian package` job (`scripts/test-deb.sh`) actually verifies installation, startup, reinstallation from the signed repository, and purge.

## Repository

Pushing a `v*` tag makes `.github/workflows/release.yml` do the following.

1. Build the binaries for each target and the amd64 / arm64 / armhf `.deb` files, and attach them to the GitHub Release (it stops if the tag and `version` in `Cargo.toml` differ)
2. Add the `.deb` files to the apt repository on the `gh-pages` branch with `scripts/apt-repo.sh`, re-sign the index (`dists/stable/`), and push

GitHub Pages serves `https://max3584.github.io/rproxy-api/`. The management UI `rproxy-ui` (Architecture: all) is published in the same repository. rproxy-ui advances its version independently of rproxy-api (docs/RELEASING.md), so a tag push does not publish it. Once a UI release has `rproxy-ui_X.Y.Z-1_all.deb` attached, running `release.yml` by hand (`gh workflow run release.yml -R max3584/rproxy-api -f ui_tag=vX.Y.Z`) fetches it from the [TCP-UDP-rproxy-ui release](https://github.com/max3584/TCP-UDP-rproxy-ui/releases) and publishes just rproxy-ui. The layout is as follows.

```
pool/main/r/<package>/<package>_<version>_<arch>.deb   rproxy-api and rproxy-ui. Past versions are kept too
dists/stable/main/binary-{amd64,arm64,armhf}/Packages{,.gz}
dists/stable/{Release,InRelease,Release.gpg}
rproxy-archive-keyring.gpg                                public key used for signed-by=
```

A package with the same version cannot be republished with different contents (`apt-repo.sh` stops it). To fix something, bump the version.


## Initial setup (once, by the repository administrator)

### 1. Create a signing key and register it in GitHub Secrets

Create a signing-only key without a passphrase (so that CI can sign non-interactively). Do not keep the private key anywhere other than Secrets.

```shell
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key 'rproxy-api apt repository <max3584.work@gmail.com>' ed25519 sign never
KEY_ID=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --armor --export-secret-keys "$KEY_ID" | gh secret set APT_GPG_PRIVATE_KEY -R max3584/rproxy-api
gh secret set APT_GPG_KEY_ID -R max3584/rproxy-api --body "$KEY_ID"
# So that losing it is not a problem, store the private key offline before deleting
gpg --armor --export-secret-keys "$KEY_ID" > rproxy-apt-signing-key.asc
rm -rf "$GNUPGHOME"
```

If the Secrets are not set, release.yml skips only the apt repository update (with a warning).

### 2. Enable GitHub Pages after the first release

The `gh-pages` branch is created by the first release. Run this once after that.

```shell
gh api -X POST repos/max3584/rproxy-api/pages -f 'source[branch]=gh-pages' -f 'source[path]=/'
```

### Rotating the key

When you register a new key in Secrets and push a tag, the index and `rproxy-archive-keyring.gpg` switch to the new key.
Users get signature errors from `apt update` until they re-fetch `rproxy-archive-keyring.gpg`.

## Trying it locally

```shell
cargo deb                                   # target/debian/rproxy-api_<version>-1_amd64.deb
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key 'test <test@example.invalid>' ed25519 sign never
scripts/apt-repo.sh /tmp/apt-repo target/debian/*.deb
python3 -m http.server 8000 -d /tmp/apt-repo
```

`scripts/test-deb.sh` actually installs and uninstalls the package, so do not run it on a machine where rproxy-api is running in production.
