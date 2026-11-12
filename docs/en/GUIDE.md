日本語: [GUIDE.md](../GUIDE.md)

# Configuration and operations guide

This guide shows how to install rproxy-api, set up TCP, UDP and HTTP forwarding, and run it day to day. It is written for operators who know the basics of Linux and networking (systemd, ports, TLS certificates, CIDR) but have not used rproxy before. For each task it gives a configuration you can paste as is and a command to check that it worked.

rproxy-api is a proxy that relays the connections and datagrams it receives to fixed targets. What to relay and where is described by a **rule**. You can write rules in a settings file, or send them to a running rproxy over its HTTP **control API**. The difference between these two ways matters more than anything else in this guide, so the [map of this guide](#map-of-this-guide) explains it first.

Related documents:

- [API.md](API.md) is the authority on the exact meaning and behaviour of every field. When a topic would take long to explain, this guide links to the section in API.md.
- Examples by use case are in [PROFILES.md](PROFILES.md), passing the client's address to the target in [SOURCE-IP.md](SOURCE-IP.md), file permissions in [PERMISSIONS.md](PERMISSIONS.md), ACME in [ACME.md](ACME.md), upgrades without a restart in [UPGRADE.md](UPGRADE.md), and backups in [BACKUP.md](BACKUP.md).

Replace the addresses, names and paths in the examples with your own. The example addresses are reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) or private (`10.0.0.0/8` and so on). The example YAML passes `rproxy-api --check-config`.

## Map of this guide

### Two ways to add rules

There are two ways to add rules to rproxy-api. Either way, a rule has the same shape (the same fields with the same meaning). What differs is who owns the rule, how you change it, and what happens to it after a restart.

| | Writing a settings file | Creating through the control API |
|---|---|---|
| Where | The YAML / JSON file that `RPROXY_CONFIG` points to | The running rproxy's HTTP API (`POST /rules` and so on) |
| Name of the resulting rule | **Static rule** (the rule's `origin` shows `static`) | **Dynamic rule** (`origin` is `dynamic` or `api`) |
| How to change it | Edit the file. rproxy re-reads it on its own | `PATCH` or `DELETE` through the API, or `PUT` a rule set |
| After a restart | Built again from the file | Depends on how it was stored ([10.1](#101-keeping-api-created-rules)) |
| Suited to | A setup the operator decides by hand that rarely changes | Automation: the admin UI, CI, a Kubernetes controller |

Think of the settings file the way you think of an nginx or HAProxy configuration file: the file is the source of truth, and the API cannot change it. The control API is how other programs operate rproxy. The admin UI ([TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)) also creates its rules through this API.

You can use both in the same rproxy. For example, you might put the rule that publishes the admin UI itself in the settings file, because it must never disappear, and create everyday rules from the UI. However, a given listener (protocol, address and port) can belong to only one of them. To add HTTP routes or similar from the API to the listener of a settings-file rule, use a separate mechanism called an **overlay** ([2.4](#24-settings-file-versus-api)).

### Where to start, by reader

You do not need to read everything in order. Start with the row that matches how you use rproxy.

| Reader | Read first | Read when you need it |
|---|---|---|
| Runs everything from the settings file | [1.](#1-install-and-start), [2.1–2.2](#21-in-the-settings-file), [3.–6.](#3-l4-forwarding-udp-port-ranges-several-targets) (what goes in a rule), [9.1](#91-re-reading-the-settings-file) | [7.](#7-security-tokens-crowdsec-geoip-files), [8.](#8-global-settings), [11.–18.](#11-observing-logs-metrics-stats) (operations) |
| Uses the control API (CI, scripts, controllers) | [1.](#1-install-and-start), [2.](#2-the-first-rule), [7.1](#71-tokens) (tokens), [10.](#10-persistence-rule-sets-and-dry-run) (persistence, rule sets, dry run) | [9.](#9-changing-things-while-running), [18.1](#181-api-errors) (API errors). For what goes in a rule, [3.–6.](#3-l4-forwarding-udp-port-ranges-several-targets) |
| Runs the admin UI | [1.](#1-install-and-start) (especially [1.5](#15-opening-the-control-apis-unix-socket)), [2.4](#24-settings-file-versus-api), [7.1](#71-tokens) (the UI's token is `admin`), [12.1](#121-upgrading-with-apt) (a note for v0.4.23) | [10.1](#101-keeping-api-created-rules) (why the UI's token has no `persist`), [13.](#13-backup-and-restore) (backing up the database) |

### Terms used in this guide

These terms come up often. Each is explained in detail where it first appears.

| Term | Meaning | Explained in |
|---|---|---|
| Rule key | What identifies a rule: protocol, listen address and port. API paths use it too | [2.3](#23-through-the-control-api) |
| Static rule / dynamic rule | A rule from the settings file / a rule created through the control API | [2.4](#24-settings-file-versus-api) |
| Overlay | HTTP routes or TLS names added from the API to a static rule's listener | [2.4](#24-settings-file-versus-api) |
| Scope | The set of operations a token is allowed (`rules:write`, `admin` and so on) | [7.1](#71-tokens) |
| Owner | The name of the token that created a rule or similar. A token without `admin` may change only what it owns | [7.1](#71-tokens) |
| persist | Writing API-created rules to the database so they come back after a restart | [10.1](#101-keeping-api-created-rules) |
| Rule set | A named group of rules. You `PUT` the whole group each time and rproxy applies the difference | [10.2](#102-rule-sets-for-automation) |
| Dry run | A trial that changes nothing and only reports what a change would do | [10.3](#103-dry-run) |
| `in_place` / `recreate` | A change that keeps current connections / a change that rebuilds the listener and cuts them | [9.2](#92-changes-that-keep-connections-in_place-and-changes-that-cut-them-recreate) |
| Drain | When stopping, refusing new connections and waiting for the current ones to finish | [9.3](#93-waiting-when-stopping-drain) |
| Handoff (SIGUSR2) | Replacing the binary with a new one while running | [9.4](#94-replacing-the-binary-no-restart) |
| `degraded` | A notice that rproxy stopped only some parts, because of a problem in the environment such as permissions or the database, and kept running | [1.4](#14-checking-that-it-runs) |
| Connection and session budget (fd budget) | The share of the process's file descriptors that connections and UDP sessions may use | [16.](#16-capacity-limits) |

## Contents

**Part 1: Getting started**

1. [Install and start](#1-install-and-start)
2. [The first rule](#2-the-first-rule)

**Part 2: What goes in a rule** (the same in the settings file and in the API)

3. [L4 forwarding (UDP, port ranges, several targets)](#3-l4-forwarding-udp-port-ranges-several-targets)
4. [TLS](#4-tls)
5. [L7 (`http` rules)](#5-l7-http-rules)
6. [Source IP](#6-source-ip)

**Part 3: Protection and process-wide settings**

7. [Security (tokens, CrowdSec, GeoIP, files)](#7-security-tokens-crowdsec-geoip-files)
8. [`global` settings](#8-global-settings)

**Part 4: Changing things while running, and automating with the API**

9. [Changing things while running](#9-changing-things-while-running)
10. [Persistence, rule sets and dry run](#10-persistence-rule-sets-and-dry-run)

**Part 5: Operations**

11. [Observing (logs, `/metrics`, stats)](#11-observing-logs-metrics-stats)
12. [Upgrades and going back](#12-upgrades-and-going-back)
13. [Backup and restore](#13-backup-and-restore)
14. [Monitoring and alerts](#14-monitoring-and-alerts)
15. [Handling logs](#15-handling-logs)
16. [Capacity limits](#16-capacity-limits)
17. [Recipes](#17-recipes)
18. [Troubleshooting](#18-troubleshooting)

## Part 1: Getting started

Part 1 installs and starts rproxy-api (1.) and creates a first rule both in the settings file and through the control API (2.). It also explains how the two ways differ.

## 1. Install and start

This chapter takes you from installing rproxy-api to talking to its control API. On Debian or Ubuntu, install with apt; on other Linux distributions with systemd, use install.sh. Either way, rproxy-api's settings are passed as environment variables in `/etc/rproxy/rproxy.env`.

### 1.1 Installing with apt (Debian / Ubuntu)

These commands put the signing key of the rproxy-api apt repository in place, add the repository, and install the package.

```shell
sudo curl -fsSLo /usr/share/keyrings/rproxy-archive-keyring.gpg https://max3584.github.io/rproxy-api/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] https://max3584.github.io/rproxy-api stable main" \
  | sudo tee /etc/apt/sources.list.d/rproxy-api.list
sudo apt update && sudo apt install rproxy-api
```

The package creates the service user `rproxy-api` (primary group `rproxy`), the environment file `/etc/rproxy/rproxy.env`, the token file `/etc/rproxy/tokens` holding one control API token, and the systemd unit `rproxy-api.service`.

Installing does not start the service. Edit `/etc/rproxy/rproxy.env` for your environment, then enable and start the service. [1.3](#13-main-environment-variables) explains which variables to change.

```shell
sudoedit /etc/rproxy/rproxy.env
sudo systemctl enable --now rproxy-api
```

### 1.2 Installing with install.sh (Linux with systemd, for VMs)

install.sh installs everything on a VM in one go. On Debian and Ubuntu it installs from apt; on other distributions it installs the release binary. It then creates the user, the settings and the unit, and starts the service.

```shell
curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | sudo bash -s -- --api-addr 127.0.0.1
```

`--api-addr 127.0.0.1` makes the control API listen only inside the host (loopback), which is also the default. `install.sh --help` lists the other options (port, database, log location, routing for transparent mode and so on).

Running the same command again upgrades. The settings and tokens are kept.

### 1.3 Main environment variables

The rproxy-api process takes its settings from environment variables. With the package, systemd reads `/etc/rproxy/rproxy.env` and passes them, so edit that file and apply it with `sudo systemctl restart rproxy-api`. This section covers only the variables you usually decide first. The table in [the README's "Running"](../../README.en.md#running) lists all of them.

| Variable | Default | What it decides |
|---|---|---|
| `RPROXY_API_ADDR` / `RPROXY_API_PORT` | `127.0.0.1` / `8080` | Address and port the control API listens on |
| `RPROXY_API_SOCKET` | none | Path of the control API's Unix socket |
| `RPROXY_TOKEN_FILE` | none (`/etc/rproxy/tokens` with the package) | The control API's token file |
| `RPROXY_CONFIG` | none | Location of the settings file (static rules) |
| `RPROXY_DATABASE_URL` | none | MariaDB from which rules are restored |
| `RPROXY_LOG_FILE` / `RPROXY_LOG_LEVEL` | standard output / `info` | Where logs go and how detailed they are |
| `RPROXY_NODE_NAME` | host name | The name that identifies this rproxy in the database |

- **`RPROXY_API_ADDR` / `RPROXY_API_PORT`**: The address and port on which the control API listens over TCP. With the default `127.0.0.1`, only the same host can reach the API. You can list several addresses separated by commas (for example `127.0.0.1,10.0.0.2`). If you include an address other than loopback, a token file (`RPROXY_TOKEN_FILE`) and a TLS certificate and key (`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`) are required, and rproxy refuses to start if any of them is missing. This keeps tokens off the network in plain text. Setting the port to `0` turns off TCP, leaving only the Unix socket (below).
- **`RPROXY_API_SOCKET`**: Also serves the control API on a Unix socket in the file system (for example `/run/rproxy/api.sock`). It is not opened by default. Operations with a wide effect, such as re-reading the settings file (`POST /config/reload`), are accepted only from this socket by default, so open it if you want to use them from the API ([1.5](#15-opening-the-control-apis-unix-socket)). For an admin UI on the same host, connecting over the socket is also safer than TCP.
- **`RPROXY_TOKEN_FILE`**: The file with the control API's tokens. When set, every endpoint except `/healthz` and `/readyz` requires `Authorization: Bearer <token>`. When not set, there is no authentication (and the API can then listen only on loopback). The package creates `/etc/rproxy/tokens` and sets this, so authentication is on from the moment you install. [7.1](#71-tokens) explains how to write tokens.
- **`RPROXY_CONFIG`**: The path of a settings file (YAML or JSON) or of a directory holding such files. The rules written here become static rules ([2.1](#21-in-the-settings-file)). If you do not use a settings file and create every rule through the API or the UI, leave it unset.
- **`RPROXY_DATABASE_URL`**: The MariaDB to connect to (`mysql://user:pass@host:port/db`). When set, rproxy restores at start the rules the admin UI saved in the database and the rules stored through the API ([10.1](#101-keeping-api-created-rules)). When not set, rules created through the API exist only in rproxy's memory and are lost on restart. Set it when you use the admin UI or want to keep API rules.
- **`RPROXY_LOG_FILE` / `RPROXY_LOG_LEVEL`**: Logs are one JSON object per line (JSON Lines). By default they go to standard output, which systemd puts in the journal. The package sets `RPROXY_LOG_FILE=/var/log/rproxy/rproxy.log`, so logs are written to `/var/log/rproxy/rproxy.<date>.log`, one file per day ([15.](#15-handling-logs)). Leave `RPROXY_LOG_LEVEL` at `info` and raise the detail only while investigating.
- **`RPROXY_NODE_NAME`**: The name that identifies this rproxy in the database; the host name by default. When several rproxy instances share one database, give each node a different name. If a live process with the same name is already running, the one that starts later waits about 40 seconds, logs a `persist.duplicate_node` error and exits.

### 1.4 Checking that it runs

After starting, check the service status and that the control API answers. The example reads the token the package created into the shell variable `TOKEN` before calling the API.

```shell
systemctl status rproxy-api
TOKEN=$(sudo head -1 /etc/rproxy/tokens)     # the one-line token the package created (all permissions); /etc/rproxy is root:rproxy 750
curl -s http://127.0.0.1:8080/healthz          # ok (no authentication)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/capabilities | jq '{version, features: (.features | keys | length)}'
```

- `/healthz` answers `ok` without authentication. It tells you whether the process is alive.
- `/capabilities` returns the version of the running rproxy (`version`) and the list of settings this version supports (`features`). Use it to check versions and supported features. `/etc/rproxy` is `root:rproxy` mode 750, so reading the token needs `sudo`.

If it does not start, read the log with `journalctl -u rproxy-api`. rproxy reacts differently depending on the kind of problem.

- **Configuration errors** (a wrong value, a path that does not exist, wrong file contents) stop it from starting. It will not run until you fix them, so read the error in the log and correct it.
- **Problems in the environment** (no permission, a port used by another process, an unreachable database and so on) stop only the parts that cannot work, and rproxy starts with the rest. It then logs `"event":"degraded"` with `part` naming what was stopped. This guide calls this state "`degraded`". See [the README's "When some parts cannot start"](../../README.en.md#when-some-parts-cannot-start) for details.

### 1.5 Opening the control API's Unix socket

The control API's strong operations, which affect the whole process, are accepted only from the Unix socket by default. They are re-reading the settings file (`POST /config/reload`), changing some items of the `global` settings (`PATCH /config/global`, [8.](#8-global-settings)), `/admin/*` (upgrades and so on), and the strong ACME operations. The socket's file permissions decide which OS users may use them. Open the socket when you use these operations, or when an admin UI on the same host connects over the socket.

The package keeps the socket closed by default, so uncomment two lines in `/etc/rproxy/rproxy.env` and restart. The last line checks that the API answers on the new socket.

```shell
sudoedit /etc/rproxy/rproxy.env
#   RPROXY_API_SOCKET=/run/rproxy/api.sock      <- uncomment
#   RPROXY_API_SOCKET_GROUP=rproxy              <- uncomment
sudo systemctl restart rproxy-api
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/capabilities | jq .version
```

- `RPROXY_API_SOCKET` is the socket's path and `RPROXY_API_SOCKET_GROUP` the group of the socket file. The socket belongs to `rproxy-api` with mode 660 (`RPROXY_API_SOCKET_MODE`), so root and members of the group `rproxy` can use it.
- Use it with `sudo` as above, or add the user to the group `rproxy` (`sudo usermod -aG rproxy $USER`, then log in again).
- The host name in the `curl` URL (`localhost`) is only a placeholder; the request goes to the socket given with `--unix-socket`.
- A token is required on the Unix socket too. Strong operations need the `admin` scope (every permission), and the one-line token the package created is `admin`.

Every example in this guide that uses the socket assumes this setup, with an `admin` token in `$TOKEN`.

## 2. The first rule

This chapter creates a first forwarding rule both in the settings file and through the control API. As an example, it relays TCP connections that arrive at `0.0.0.0:8888` to `192.168.1.2:8080`. At the end it explains how the two ways differ and the rules for mixing them.

### 2.1 In the settings file

The settings file is how an operator decides rules by hand and keeps them. A rule written in the file becomes a **static rule**: the API cannot change it, and it is built again from the file after a restart.

This YAML is a settings file with only the forwarding above.

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8888
    remote_addr: 192.168.1.2
    remote_port: 8080
```

- `version: 1` is the version of the settings file's shape. Only `1` exists today.
- Under `rules`, write one rule per item. `protocol` (`tcp` or `udp`), `listen_addr` and `listen_port` describe the listener, and together they form the rule's **key** (what identifies the rule).
- `remote_addr` and `remote_port` are the target. The target may also be a host name.

To make rproxy read this file, add `RPROXY_CONFIG=/etc/rproxy/rproxy.yaml` to `/etc/rproxy/rproxy.env`. Because this changes an environment variable, this one time needs a restart.

```shell
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/rproxy.yaml   # 0: fine, 1: a mistake
sudo systemctl restart rproxy-api
```

`--check-config` runs the same checks as starting and re-reading (syntax, values, overlapping listeners, certificate and key files and so on) and exits with code 0 if there is no problem or 1 if there is an error. It opens no listeners and no database, so it does not affect a running rproxy. It is the equivalent of nginx's `nginx -t`; run it first every time you edit the settings file. Running it as `sudo -u rproxy-api` also checks that the service user can read the files.

After that, no restart is needed. rproxy checks the settings file every `RPROXY_CONFIG_CHECK_SECS` (10 seconds by default), re-reads it when it changed, and applies only the differences. To apply a change right away, use `sudo systemctl reload rproxy-api`. The package's unit runs `--check-config` first on reload and sends nothing to rproxy if there is an error. [9.1](#91-re-reading-the-settings-file) explains re-reading in detail.

### 2.2 Checking that the rule runs

Use the control API to check that a rule runs. The first command prints the main fields from the list of rules; the second prints the state of the settings file.

```shell
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq '.[] | {protocol, listen_addr, listen_port, origin, state, error}'
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/config | jq '{files, rules, last_reload, error}'
```

- A rule whose `state` is `running` is working. With `failed` it is not, and the reason is in `error` and `conditions` (a list of states such as `BindFailed` and `ResolveFailed`).
- `origin` is where the rule came from. Rules from the settings file show `static` ([2.4](#24-settings-file-versus-api)).
- In `GET /config`, `files` lists the files read, `rules` is the number of rules in them, and `last_reload` gives how many rules the last re-read added, removed and changed. If `error` is not `null`, the latest file could not be applied and the previous version keeps running.

Two things to watch with YAML and file layout:

- YAML is read as YAML 1.2. Unlike YAML 1.1, `yes` and `on` are strings, not booleans. Something that looks like a number, such as `010`, becomes a number, so quote it if you want a string.
- If `RPROXY_CONFIG` names a directory, rproxy reads every `*.yaml`, `*.yml` and `*.json` file in it in name order as one configuration. This helps when you want one file per purpose, or want to mount a Kubernetes ConfigMap as is. However, only one file may contain `global` (the process-wide settings, [8.](#8-global-settings)) ([API.md, "Config file"](API.md#config-file-fixed-rules)).

### 2.3 Through the control API

The control API is how other programs (the admin UI, CI, scripts) have a running rproxy create rules. A rule created through the API becomes a **dynamic rule**, which you can create, change and delete on the spot.

The following example creates the same forwarding through the API, on listen port 8889, changes its target and finally deletes it. The JSON body has the same shape as one item of `rules` in the settings file.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":8889,"remote_addr":"192.168.1.2","remote_port":8080}'

# change the target (new connections use it)
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889 \
  -d '{"remote_addr":"192.168.1.3","remote_port":8080}'

# delete (current connections are cut; ?drain_secs=30 waits up to 30 seconds for them to end)
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889
```

- `POST /rules` answers only after it has resolved names and started listening. When the answer arrives, forwarding has already begun.
- The path of `PATCH` and `DELETE` is `/rules/{protocol}/{listen_addr}/{listen_port}`, which is the rule's key itself. URL-encode an IPv6 address in the path (`::` becomes `%3A%3A`).
- When `PATCH` changes the target, TCP connections that are already open keep talking to the old target; new connections go to the new one.
- By default `DELETE` cuts current connections at once. With `?drain_secs=30` it stops accepting new connections and waits up to 30 seconds for the current ones to end before cutting them (drain, [9.3](#93-waiting-when-stopping-drain)).

### 2.4 Settings file versus API

The two rules above look alike in `GET /rules`, but their origin (`origin`) and handling differ. This table sums up the differences.

| | Settings file | API |
|---|---|---|
| `origin` shown | `static` | `dynamic` (`api` with a token that has `persist: true`) |
| How to change | Edit the file (applied automatically) | `PATCH` / `DELETE`. Static rules give `409 static` |
| After a restart | Built again from the file | `dynamic` rules are gone. UI rules come back from the database, `api` rules from `rproxy_rules` |
| Suited to | Rules that must not disappear (such as the rule publishing the UI) | Rules changed by the UI, CI or a controller |

Some notes on the terms in the table:

- **`dynamic`** is a rule created through the API that exists only in rproxy's memory. Rules created in the admin UI are also `dynamic`, but the UI writes them to its own database (the table `forward_rules`) too, so they come back from there after rproxy restarts. A `dynamic` rule created by calling the API directly is lost on restart.
- **`api`** is a rule created with a token marked `persist: true` (store). rproxy writes it to its own table `rproxy_rules` and restores it after a restart. [10.1](#101-keeping-api-created-rules) explains which tokens should get `persist` and how storing works.

A rule with a given key can exist in only one of the two places.

- `POST /rules` with a key that is in the settings file gives `409 already_exists`.
- `PATCH` or `DELETE` on a rule from the settings file gives `409 static`. Change it by editing the file.
- If you later write the key of an API-created rule into the file, the API rule stays, and the file's rule does not run and logs `rule.failed`.

Sometimes you want to **add** HTTP routes or `tls.routes` names from the API to the listener of a static rule. For example, port 443 is terminated by the settings file and you want to add a new site from the UI. Use an **overlay** for this (v0.4.23, #397), not the rule itself. An overlay is kept separately from the static rule, so the file's rule does not change.

This example adds a route to `wiki.example.com` and its service as an overlay on the static rule `tcp/0.0.0.0:443`.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H 'If-None-Match: *' \
  http://127.0.0.1:8080/rules/tcp/0.0.0.0/443/overlay \
  -d '{"http":{"routes":[{"name":"wiki","match":"Host(`wiki.example.com`)","service":"wiki"}],
       "services":{"wiki":{"servers":[{"url":"http://10.0.0.5:8080"}]}}}}'
```

- `PUT .../overlay` replaces the rule's overlay as a whole with the body.
- `If-None-Match: *` means "create only if there is no overlay yet". If someone created one first, rproxy refuses with `412 precondition_failed` instead of overwriting it. To edit an existing overlay, `PUT` with the `ETag` you got from `GET` in `If-Match`.
- The body's `http` has the same shape as `routes`, `services` and `middlewares` in a rule's `http` ([5.](#5-l7-http-rules)). An `http` overlay is possible only when the static rule has `http`. You can also overlay `tls.routes` names.

An overlay's routes see only requests that match none of the file's routes. An overlay therefore cannot take over a site from the file or bypass the authentication on the file's routes. Using a name that already exists in the file (a route, service or middleware) is refused with `409 overlay_conflict`. The detailed rules are in [API.md, "Overlays on a static rule's listener"](API.md#overlays-on-a-static-rules-listener-v0423-397-featuresstatic_overlay).

## Part 2: What goes in a rule

Part 2 describes the fields you can write in a rule, by task: L4 forwarding (3.), TLS (4.), L7 forwarding that understands HTTP (5.), and how to pass the client's IP to the target (6.). These fields mean the same whether you write them in the settings file or send them through the API.

## 3. L4 forwarding (UDP, port ranges, several targets)

This chapter covers L4 forwarding, which relays bytes as they are without interpreting them: UDP, port ranges, several listen addresses, several targets with balancing, and limits on the number and lifetime of connections.

Each example in this chapter is one rule (or part of one) to add under `rules:` in the settings file. To create it through the API, send the same shape as JSON to `POST /rules`.

### 3.1 UDP

UDP has no connections, so rproxy remembers "the datagrams coming from one client" as a **session** and sends the target's replies back to that client. Use it to relay DNS, games, VoIP and similar.

This rule relays UDP port 53 to the DNS server at `10.0.0.53`.

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 53
    remote_addr: 10.0.0.53
    remote_port: 53
    udp_idle_secs: 30        # seconds before a quiet session is dropped (default 30)
```

`udp_idle_secs` is how many seconds a session may stay silent before it is dropped. The default is 30 seconds. Raise it when sessions should survive clients that go quiet for a while, as in games ([17.3](#173-a-udp-game-server) uses 120 seconds).

More things to know about UDP rules:

- Even when listening on `0.0.0.0` or `::`, replies are sent from the address the client sent to. Clients get the reply from the address they talked to, even on a host with several addresses.
- A session that is not established, meaning it has not yet seen both a reply from the target and a second datagram from the client, ends after 5 seconds. This keeps spoofed datagrams from filling the session table ([API.md, "Against spoofed UDP sources"](API.md#against-spoofed-udp-sources-v0420-354)). A client that sends one datagram and then only listens is cut by these 5 seconds, so have it keep sending something.
- By default one rule can hold up to `RPROXY_UDP_MAX_SESSIONS` (16384) sessions at once. To accept many clients, raise the rule's `limits.max_connections` ([3.5](#35-connection-limits-for-the-whole-rule)) or this environment variable.

### 3.2 Port ranges

When you want to relay many consecutive ports at once, as for game servers or RTP, one rule can describe a range of ports.

This rule relays UDP ports 10000–10100 to ports 20000–20100 on `10.0.0.40`.

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 10000
    listen_port_end: 10100     # 10000-10100
    remote_addr: 10.0.0.40
    remote_port: 20000         # go to 20000-20100, shifted by the same amount
```

- The listener covers `listen_port` through `listen_port_end`.
- Target ports are shifted by the same amount as the listen ports. In the example, traffic to 10005 goes to 20005.
- One rule may have up to `RPROXY_MAX_RANGE_PORTS` (20000 by default) ports.
- Each port uses one socket, so a large range uses many file descriptors ([16.](#16-capacity-limits)).
- A port range cannot be changed after the rule is created. To change it, recreate the rule.

### 3.3 Several listen addresses

To accept the same forwarding on both IPv4 and IPv6, or on several fixed addresses, put the extra listen addresses in `extra_listen_addrs`.

This rule accepts port 443 on both `203.0.113.5` and `2001:db8::5` with one rule.

```yaml
  - protocol: tcp
    listen_addr: 203.0.113.5
    extra_listen_addrs: ['2001:db8::5']   # IPv4 and IPv6 in one rule
    listen_port: 443
    remote_addr: 10.0.0.20
    remote_port: 443
```

You can list up to 16 extra addresses. The rule's key stays `listen_addr`, and the stats are kept together for the one rule. This keeps configuration and monitoring in one place, rather than two rules.

### 3.4 Several targets (balancing and failover)

Giving a rule several targets lets it spread connections across them, or switch away from a target that has failed. Write `targets` instead of `remote_addr` / `remote_port`.

This rule spreads PostgreSQL connections across two servers and uses a spare only when both have failed.

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 5432
    targets:
      - {addr: 10.0.0.11, port: 5432, weight: 2, max_connections: 200}
      - {addr: 10.0.0.12, port: 5432, max_connections: 200}
      - {addr: db-backup.internal, port: 5432, backup: true}
    balance: least_conn        # round_robin (default) / least_conn / failover
    health_check: {interval: 10s, timeout: 3s}
    connect_timeout: 3s
```

The fields mean the following:

| Field | What it decides |
|---|---|
| `targets[].weight` | The balancing weight. The default is 1; in the example the first server gets twice the share |
| `targets[].max_connections` | The maximum number of connections open to that target at once (v0.4.19) |
| `targets[].backup` | A target with `true` is used only when every other target is down |
| `balance` | How a target is chosen |
| `health_check` | Checks regularly whether the targets are alive |
| `connect_timeout` | How long to wait when connecting to a target |

Choose `balance` from three methods:

- `round_robin` (default): take turns in proportion to `weight`. Use it when the targets are about equally capable.
- `least_conn`: pick the target with the fewest open connections (sessions for UDP) divided by `weight`. Suits long-lived connections that easily end up uneven, such as database connections.
- `failover`: use only the first live target, from the top. Use it when there is a clear primary and spare.

Whether a target is alive (up or down) is decided like this:

- With `health_check`, rproxy tries a TCP connection every `interval`, and counts the target as up if it connects within `timeout`. A UDP rule must give the TCP port to check in `port`.
- Even without `health_check`, a target that fails a connection is taken out for 10 seconds and the connection is retried on the next target. `outlier_detection` changes how often and for how long ([API.md, "Passive health checks"](API.md#passive-health-checks-170)).

A target that has reached its `max_connections` is skipped for the next one, and when every target is full the connection is refused. The log shows this as `conn.limited` with `reason: target_full`.

Without `connect_timeout`, rproxy waits 5 seconds if there are other targets, or 30 seconds if there is only one. Shorten it to move on faster when a target fails. It applies only to `tcp` rules.

You can see each target's state in `stats.targets` of `GET /rules/tcp/0.0.0.0/5432` (`up` and `connections` per target) and in `rproxy_target_up` in `/metrics`.

### 3.5 Connection limits for the whole rule

Limiting how many connections a rule accepts, or how many one source may open, protects the targets and keeps a single client from using up resources.

This example is the `limits` to add to a rule.

```yaml
    limits:
      max_connections: 2000          # the whole rule (UDP: sessions)
      per_source:
        max_connections: 50          # one source (by default per IPv4 /32 and IPv6 /64)
        new_connections: {average: 10, period: 1s, burst: 20}
```

- `max_connections` is the number of connections the whole rule may have open at once. For a UDP rule it is the number of sessions.
- `per_source` holds limits per source. By default, a source is one address for IPv4 (/32) and a /64 for IPv6 (change this with `prefix_v4` and `prefix_v6`).
- `per_source.max_connections` is how many connections one source may have open at once.
- `per_source.new_connections` is how fast new connections may be opened. The example allows 10 per second on average, with bursts of up to 20.

Connections over a limit are closed without sending anything for TCP, and the datagrams are dropped for UDP. The number refused shows in the rule's `stats.limited`, in `rproxy_rule_limited_total{reason}` in `/metrics`, and as `conn.limited` in the log ([API.md, "How L4 limits and bandwidth behave"](API.md#how-l4-limits-and-bandwidth-165-166-behave)).

To limit bandwidth, write `upload` and `download` (for example `"10Mbps"`) in the rule's `bandwidth`. TCP is slowed by waiting before reading, and UDP drops what goes over.

### 3.6 Connections that stay quiet for long

A TCP rule cuts a connection on which nothing flows in either direction after `idle_timeout` (`1h` by default), so that unused connections do not hold resources forever. Raise it when you relay connections that should survive long silences, such as a database connection pool. `0s` removes the limit.

```yaml
    idle_timeout: 8h
    half_close_timeout: 1m           # after one side has closed (default 1m)
```

- Only bytes flowing on the connection count. TCP keepalive probes do not, so a connection that sends keepalives is still cut by `idle_timeout`.
- `half_close_timeout` is how long to wait for the other side after one side has closed its sending direction (sent FIN). The default is 1 minute. With `0s` this limit is not used and only `idle_timeout` applies.
- It does not apply to `http` rules. Time limits for `http` rules are set in `global.http.timeouts` ([5.5](#55-time-limits-globalhttptimeouts)).

## 4. TLS

This chapter explains how TLS connections are handled. Choose with the rule's `tls.mode` whether to pass them through encrypted, route them by name, or decrypt (terminate) them in rproxy. [PROFILES.md](PROFILES.md) has more examples by use case.

| `tls.mode` | Behaviour | Where the certificate lives |
|---|---|---|
| `passthrough` (default) | Passes the traffic through encrypted | The target |
| `sni` | Reads the server name in the ClientHello, without decrypting, and picks the target | The target |
| `terminate` | rproxy terminates TLS and sends to the target in plain text or over new TLS | rproxy |

- **`passthrough`**: What happens when you write no `tls`. rproxy does not care that the traffic is TLS and passes the bytes through.
- **`sni`**: The first TLS message (the ClientHello) contains, in plain text, the server name the client wants (SNI). rproxy reads just that and picks a target per name. Nothing is decrypted, so the target holds the certificate. For tcp it reads TLS names, for udp DTLS and QUIC (HTTP/3 and others) names.
- **`terminate`**: rproxy holds the certificate and ends TLS. For tcp this is TLS, for udp DTLS. Choose it to use `http` rules, which interpret HTTP ([5.](#5-l7-http-rules)), or to keep certificates in one place.

### 4.1 Routing by name (`sni`)

When one port 443 serves several sites and each server holds its own certificate, use `sni` to split targets by name.

This rule sends `git.example.com` to `10.0.0.11`, `apps.example.com` and names one level below it to `10.0.0.12`, and cuts every other name.

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.10           # when no name matches
    remote_port: 443
    tls:
      mode: sni
      routes:
        - {server_name: git.example.com, remote_addr: 10.0.0.11, remote_port: 443}
        - {server_names: ['*.apps.example.com', 'apps.example.com'], remote_addr: 10.0.0.12, remote_port: 8443}
      unmatched: reject              # cut unmatched names and connections without SNI
```

- Each item in `routes` is one set of names and a target. Use `server_name` for one name and `server_names` for several.
- Names come in three forms. `git.example.com` matches exactly, `*.example.com` matches names exactly one level below, and `**.example.com` matches any depth below. When several routes match, rproxy prefers an exact match, then `*.`, then the longer `**.`, then the order written.
- `unmatched` decides what happens to names that match no route and to connections without SNI. The default `default` sends them to the rule's `remote_addr` / `remote_port`; `reject` cuts them.

Routing by name is not access control, because a client can write any name in the ClientHello. To restrict who may connect, combine it with `allow_from` (a range of source addresses) or client certificates (mTLS).

### 4.2 Terminating (`terminate`)

This example ends TLS in rproxy and sends plain text to the target. Use it, for instance, to put HTTPS in front of an internal application.

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8443
    remote_addr: 10.0.0.30
    remote_port: 8080                # plain text to the target
    allow_from: [10.0.0.0/8]         # outside the range, cut before TLS
    tls:
      mode: terminate
      certificates:
        - cert_file: /etc/rproxy/tls/site.pem
          chain_file: /etc/rproxy/tls/intermediates.pem
          key_file: /etc/rproxy/tls/site.key
      options: {min_version: '1.2'}
```

- `certificates` lists the server certificate (`cert_file`), the intermediate CA certificates (`chain_file`) and the private key (`key_file`). With several entries, rproxy picks the certificate that matches the name the client asks for.
- `allow_from` is the range of sources from which connections are accepted. Connections from outside it are cut before the TLS handshake.
- `options.min_version` is the oldest TLS version accepted.

Things to keep in mind about certificate files in operation:

- Certificates and keys must be owned by the service user `rproxy-api`, and keys must have mode 600 or 640. rproxy does not use files that others can change, or keys that others can read ([PERMISSIONS.md](PERMISSIONS.md), [7.4](#74-files-that-rules-point-to)). If certbot or similar creates files owned by root, copy them in a deploy hook.
- When a file changes, rproxy re-reads it within `RPROXY_CERT_CHECK_SECS` (60 seconds by default). Current connections are not cut. Renewals by certbot are picked up as they are.
- Certificates close to expiry show up as `cert.expiring` in the log and in `rproxy_cert_expiry_seconds` in `/metrics`.

### 4.3 TLS to the target too (re-encryption, mTLS)

After terminating in rproxy, you can also connect to the target over TLS. Use this when the path to the target must be encrypted too, or when the target asks for a client certificate.

This example adds `upstream` to the rule's `tls`.

```yaml
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
      upstream:
        tls: true
        server_name: backend.internal
        ca_file: /etc/rproxy/tls/internal-ca.pem
        cert_file: /etc/rproxy/tls/client.pem        # client certificate towards the target (mTLS)
        key_file: /etc/rproxy/tls/client.key
```

- `upstream.tls: true` connects to the target over TLS.
- `server_name` is the SNI sent to the target and the name used to check the target's certificate.
- `ca_file` is the CA that checks the target's certificate. Set it when the certificate comes from an internal CA.
- `cert_file` / `key_file` are the client certificate and key rproxy presents to the target. Set them only when the target requires mTLS.

The other way round, to ask clients for a certificate, write `client_auth` in `tls`. For example, `client_auth: {mode: required, ca_file: /etc/rproxy/tls/clients-ca.pem}` lets through only clients whose certificate was issued by the CA in `clients-ca.pem`. `mode` is one of `none` (default), `optional` (check a certificate if one is presented), `required`, and `optional_no_verify` (ask for one, but let the client through even without one or if it does not verify).

### 4.4 DTLS

DTLS is TLS over UDP. In a `protocol: udp` rule, `mode: terminate` makes rproxy terminate DTLS and send plain UDP to the target. It is used with IoT protocols such as CoAP.

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 5684
    remote_addr: 10.0.0.60
    remote_port: 5683
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/coap.pem, key_file: /etc/rproxy/tls/coap.key}
```

DTLS keys must be PKCS#8 (the file starts with `-----BEGIN PRIVATE KEY-----`). WebRTC media (DTLS-SRTP) cannot be terminated, because its certificate is tied to the fingerprint in the SDP. Pass it through as is.

### 4.5 STARTTLS (mail)

SMTP, IMAP and POP3 start in plain text and switch to TLS with the `STARTTLS` command. With `starttls`, rproxy carries out this exchange with the client and terminates TLS.

This rule terminates mail submission (port 587) and hands it to the MTA behind it.

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 587
    remote_addr: 10.0.0.20
    remote_port: 587
    source_ip: proxy_v2              # pass the source IP and TLS details to the target
    starttls: smtp                   # smtp / imap / pop3
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/mail.pem, key_file: /etc/rproxy/tls/mail.key}
```

- `starttls` is one of `smtp`, `imap` and `pop3`.
- `source_ip: proxy_v2` passes the client's IP and the TLS details to the target with the PROXY protocol ([6.](#6-source-ip)). Mail servers need it when they judge by the sender.

By default (`starttls_required: true`), clients that do not use STARTTLS are refused. On port 25, where MTAs talk to each other, some peers do not use TLS, so set `starttls_required: false` to accept plain text too. `false` applies only to SMTP; IMAP and POP3 always require STARTTLS.

### 4.6 Automatic certificates (ACME)

ACME is the protocol for getting certificates automatically from a CA such as Let's Encrypt and renewing them before they expire. rproxy-api has a built-in ACME client, so you can get certificates without certbot.

It takes two steps. First, write the CA account and how to get certificates (a resolver) in `global.acme` (the process-wide settings). Then replace a rule's certificate `cert_file` with `{acme: <resolver name>, domains: [...]}`.

This example gets a certificate for `example.com` and `www.example.com` from Let's Encrypt, proving control through TLS on port 443 (`tls-alpn-01`).

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [example.com, '*.example.com']    # required: the names it may get
    resolvers:
      le-alpn: {account: letsencrypt, challenge: tls-alpn-01}
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.30
    remote_port: 8080
    tls:
      mode: terminate
      certificates:
        - acme: le-alpn
          domains: [example.com, www.example.com]
```

- `accounts` are CA accounts. `contact` is where the CA writes to, and `allowed_names` is the list of names this account may get certificates for. It is required, so that rules and the API cannot get certificates for other names.
- `resolvers` pair an account with a method (challenge); rules refer to them by this name.
- In the rule's `certificates`, `acme` names the resolver and `domains` lists the names to put in the certificate.

Choose the challenge by how you prove to the CA that you control the domain:

- `tls-alpn-01`: a `terminate` rule on port 443 answers the CA's check.
- `http-01`: an `http` rule on port 80 (or `http01_listen` in `global.acme`) answers.
- Wildcard certificates (`*.example.com`) are available only with `dns-01`, which needs a DNS provider configured.

Operational notes:

- Until the certificate arrives, rproxy serves a temporary self-signed one. When the rule's `acme` `state` becomes `valid`, the certificate is in place. `GET /acme` also shows the state.
- For trials, use the Let's Encrypt staging environment (`directory: https://acme-staging-v02.api.letsencrypt.org/directory`) so you do not hit the production rate limits.
- Creating a rule that uses an ACME certificate through the API needs the `acme:write` scope on the token.
- DNS-01 providers, the helper process that holds secrets, and changes while running are covered in [ACME.md](ACME.md).

## 5. L7 (`http` rules)

This chapter covers L7 forwarding, which interprets HTTP and picks a target by host name or path. It corresponds to `server` / `location` in Traefik or nginx. Use it to serve several sites on one port 443, or to add processing (middlewares) such as authentication, redirects and compression.

Writing `http` in a `tcp` rule makes it an L7 rule. TLS is either `terminate` (HTTPS) or none (plain HTTP). The targets are written in `http.services`, so you do not write `remote_addr` / `remote_port`.

### 5.1 Routes, services and middlewares

An `http` rule is built from three parts:

- **Routes** (`routes`): which requests go to which service. A `match` expression selects the requests.
- **Services** (`services`): groups of target servers. Balancing, health checks and time limits are set here.
- **Middlewares** (`middlewares`): processing inserted into requests and responses. You define them with a name and use them from routes by that name.

The following example serves two sites, `app.example.com` and `api.example.com`, on one port 443. `/admin` is let through only from the office network and with a login, and `api` gets a per-source rate limit.

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
    http:
      http3: true                    # HTTP/3 on UDP on the same port too
      pre_routing: [secure-headers]  # applied to every request before a route is chosen
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [compress, cache]
        - name: admin
          match: Host(`app.example.com`) && PathPrefix(`/admin`)
          service: app
          middlewares: [office-only, login]
        - name: api
          match: Host(`api.example.com`)
          service: api
          middlewares: [per-ip]
      default: {status: 404}
      services:
        app:
          servers:
            - {url: 'http://10.0.0.10:3000'}
            - {url: 'http://10.0.0.11:3000'}
          health_check: {path: /healthz, interval: 10s}
          timeouts: {connect: 5s, response: 60s}
        api:
          servers:
            - {url: 'http://10.0.0.12:8080', max_connections: 500}
      middlewares:
        secure-headers:
          headers:
            hsts: {max_age: 31536000, include_subdomains: true}
            frame_deny: true
            content_type_nosniff: true
        compress: {compress: {}}
        cache: {cache: {ttl: 60s}}
        office-only: {ip_allow: {source_range: [10.0.0.0/8, '2001:db8:10::/48']}}
        login: {basic_auth: {users_file: /etc/rproxy/auth/htpasswd, realm: admin}}
        per-ip: {rate_limit: {average: 50, period: 1s, burst: 100}}
```

The main lines:

- `http3: true` also accepts HTTP/3 over UDP on the same address and port ([5.4](#54-http3)).
- `pre_routing` lists middlewares applied to every request before a route is chosen. In the example they add security headers to every response.
- The route `admin` selects requests for `app.example.com` whose path starts with `/admin`, passes them through `office-only` (office ranges only) and `login` (Basic authentication), then sends them to `app`.
- `default` is the answer for requests that match no route. In the example it returns 404.
- The service `app` spreads requests over two servers and checks `/healthz` every 10 seconds. `timeouts` means waiting up to 5 seconds to connect to a server and up to 60 seconds for its response.
- `max_connections` on the `api` server limits the connections open to that server at once.

How routes are chosen, and the order of middlewares:

- Routes are tried in descending `priority`. Without `priority`, the length of the `match` expression is used, so longer (more specific) expressions come first. In the example, the longer `admin` is tried before `app`. If nothing matches, `default` answers.
- `match` uses the same expressions as Traefik. Combine `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `Query`, `ClientIP` and others with `&&` (and), `||` (or) and `!` (not).
- Middlewares apply to the request in the order written, and to the response in reverse order.
- To send to a single URL without defining a service, write `to: 'http://10.0.0.10:3000'` in the route.
- Paths and Host are normalised before matching. For example `/%61dmin` and `/x/../admin` are matched as `/admin`, so such spellings cannot slip past `PathPrefix(`/admin`)`.

### 5.2 Common middlewares

Middlewares are defined under `http.middlewares` as `name: {kind: {settings}}`. This example lists some commonly used kinds.

```yaml
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
        old-docs: {redirect_regex: {regex: '^https://old\.example\.com/(.*)', replacement: 'https://docs.example.com/$1'}}
        sso:
          forward_auth:
            address: 'http://127.0.0.1:9091/api/verify'
            response_headers: [Remote-User, Remote-Groups]
        no-index: {headers: {response: {set: {X-Robots-Tag: noindex}}}}
        api-cache: {cache: {ttl: 30s, stale_on_error: 5m, vary: [Accept-Language]}}
        maintenance: {respond: {status: 503, body: 'maintenance'}}
```

- `to-https` redirects HTTP requests to HTTPS permanently.
- `old-docs` redirects URLs on the old host to the same path on the new host, using a regular expression.
- `sso` asks an authentication server (Authelia in the example) and lets through only requests for which it answers 2xx. The headers listed in `response_headers` (user name, groups) are copied from its answer to the target.
- `no-index` adds `X-Robots-Tag: noindex` to responses.
- `api-cache` keeps GET responses for 30 seconds. `stale_on_error: 5m` means that when the target returns a 5xx, an old answer may be served for up to 5 minutes. A separate answer is kept for each value of the headers listed in `vary`.
- `maintenance` returns 503 with a body without sending anything to the target. Attach it to a route only during maintenance.

What each kind does:

| Kind | What it does |
|---|---|
| `basic_auth` | Lets through only users listed in an htpasswd file. bcrypt hashes from `htpasswd -B` are recommended. `user_header` passes the user name to the target |
| `forward_auth` | Asks an authentication server (Authelia, oauth2-proxy and others) and lets the request through on 2xx |
| `oidc` | rproxy itself does the OpenID Connect sign-in (Keycloak and others; no oauth2-proxy needed) |
| `headers` | `set`, `add` and `remove` for request and response headers, and security headers such as `hsts`, `frame_deny` and `csp` |
| `redirect_scheme` / `redirect_regex` | Redirects to HTTPS, or to another URL |
| `rate_limit` / `in_flight` | Limits the rate / the number in flight of requests per source. Over the limit, it returns 429 |
| `cache` | Keeps GET responses in memory for `ttl`. Placed after an authentication middleware, it needs `share_after_auth` |
| `compress` | Compresses responses with br, zstd or gzip |
| `ip_allow` | Returns 403 when the source address is outside the ranges |

The other kinds (`crowdsec`, `geoip`, `cors`, `mirror`, `retry`, `circuit_breaker`, `errors`, path rewriting and so on) and the details of each are in [API.md, "HTTP forwarding semantics"](API.md#http-forwarding-semantics) and "L7 and TLS features for the Gateway API".

### 5.3 From port 80 to HTTPS

Once you have an HTTPS site, plain HTTP arriving on port 80 is normally redirected to HTTPS. This rule sends every request on port 80 to HTTPS.

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
```

The route's `match: 'PathPrefix(`/`)'` matches every path. The route has no service, and the middleware answers with the redirect, so nothing is sent to a target.

Answers to ACME `http-01` checks are given before routing. You can therefore keep this rule in place and still get certificates with `http-01`.

### 5.4 HTTP/3

With `http.http3: true`, the rule also accepts HTTP/3 over UDP on the same address and port as TCP. It works only with `terminate` rules. Open the UDP port in the firewall as well as TCP.

If HTTP/3 cannot be served, for example because the UDP port cannot be opened, the rule keeps running on TCP only. The reason is in `stats.http.http3` of `GET /rules`.

### 5.5 Time limits (`global.http.timeouts`)

For `http` rules, how long to wait on client connections is set once for the whole process in `global` (the process-wide settings), not per rule. These limits keep idle connections and clients that never send their body from holding resources.

This example is what to add to `global` in your current settings file. New values apply from new connections.

```yaml
global:
  http:
    timeouts:
      idle: 5m                 # a connection with no request in progress (default 180s)
      request_body_idle: 2m    # silence while sending a body (default 60s)
      upgraded_idle: 4h        # nothing flowing on WebSocket and similar (default 1h)
```

- `idle` is how long a keep-alive connection with no request in progress stays open.
- `request_body_idle` is how long a client may stay silent while sending a request body. It counts silence, not total time. Raise it if clients upload large files slowly.
- `upgraded_idle` is how long a connection switched (upgraded) to WebSocket or similar may go with nothing flowing. Raise it for WebSockets that stay quiet for long, such as chat.

The other fields and their defaults are in [API.md, "HTTP forwarding semantics", `global.http.timeouts`](API.md#http-forwarding-semantics). Time limits on the target side (waiting to connect and for the response) are set in the service's `timeouts` (`connect`, `response`).

## 6. Source IP

This chapter explains how to tell the target the client's real IP address. rproxy opens its own connection to the target, so unless you do something, the target sees rproxy's IP as the source. When the target's access log or access control needs to tell clients apart, choose how to pass it with the rule's `source_ip`. [SOURCE-IP.md](SOURCE-IP.md) explains in detail how to choose and how to set up the target.

| `source_ip` | Behaviour | What the target needs |
|---|---|---|
| `proxy` (default) | Does not pass the client's IP | Nothing |
| `proxy_v2` / `proxy_v1` | Adds a PROXY protocol header at the start of the connection | A setting to accept the PROXY protocol |
| `transparent` | Connects to the target using the client's IP | Routing for the return path ([TRANSPARENT.md](TRANSPARENT.md)) |

- **`proxy`** is the default. The target sees rproxy's IP.
- **`proxy_v2` / `proxy_v1`** send a PROXY protocol header (client and listener addresses and ports) at the start of the connection. The format comes from HAProxy, and nginx, Postfix and many other servers can read it. v2 is binary and can also carry TLS details. UDP uses only v2, with a header on every datagram. If the target is not set up to accept the PROXY protocol, it will mistake the header for data and stop working, so switch both sides together.
- **`transparent`** makes rproxy connect to the target with the client's IP as the source. The target needs no change, but the routing must send the target's replies back through rproxy, and the `CAP_NET_ADMIN` capability is required.

Also note:

- In `http` rules, the client's IP is passed in the `X-Forwarded-For` and `X-Real-IP` headers. Only `proxy` and `transparent` can be used as `source_ip`.
- `source_ip` cannot be changed after the rule is created. To change it, recreate the rule.

### 6.1 Accepting PROXY protocol from a front proxy

If a load balancer in front of rproxy adds PROXY protocol headers, rproxy needs to read them. Otherwise rproxy sees the load balancer as the client. The rule's `proxy_protocol` names the peers whose headers are read.

```yaml
    proxy_protocol:
      from: [10.2.0.0/16]          # only the front proxies whose header is trusted (required, no /0)
      required: true               # refuse connections from `from` without a header (default)
```

- `from` is the range of front proxies whose headers may be trusted. It is required, and `/0` (everyone) is not allowed, because trusting headers from anyone would let clients claim any IP.
- With `required: true` (the default), connections from the `from` range without a header are refused.

Once the header is read, `allow_from`, `limits`, the logs and `source_ip` all work with the client address written in the header. The front load balancer's address appears in the log as `proxy_peer`.

### 6.2 Front proxies whose `X-Forwarded-For` is trusted

If a CDN or load balancer sits in front of an `http` rule, the client's IP is in the `X-Forwarded-For` header the front adds. Write the ranges whose headers are trusted in `global.trusted_proxies`.

This example is what to add to `global` in your current settings file.

```yaml
global:
  trusted_proxies: [10.2.0.0/16]
```

For connections from these ranges, `X-Forwarded-For` is trusted and the real client IP is used for `ClientIP` matching, `ip_allow`, `rate_limit` and the logs. `X-Forwarded-For` on connections from outside the ranges is not trusted. A range that is too wide lets clients forge the header and get past address-based restrictions, so list only the front proxies' addresses.

## Part 3: Protection and process-wide settings

Part 3 covers settings that live outside the rules. Chapter 7 covers who may use the control API (tokens) and the mechanisms that protect a rule's traffic (CrowdSec, GeoIP, file checks). Chapter 8 covers the `global` settings, which apply to the whole process, and whether to set them in the settings file or through the API.

## 7. Security (tokens, CrowdSec, GeoIP, files)

This chapter covers four mechanisms that protect rproxy: tokens, which limit who may use the control API and for what (7.1); CrowdSec, which stops IPs that misbehave (7.2); GeoIP, which decides by country or ASN whom to let through (7.3); and the checks on files that rules point to (7.4).

### 7.1 Tokens

A token is a shared secret that identifies a person or program using the control API and limits what each may do. Every setup that uses the control API uses tokens. When the API has several users, such as the admin UI, CI, monitoring and a Kubernetes controller, create one token per user and give each only the permissions it needs.

#### Two ways to write the token file

Tokens go in the token file that `RPROXY_TOKEN_FILE` points to. There are two ways to write it.

- **One per line**: write each token string itself on its own line. Every token has every permission (`admin`), and the log names them `token-1`, `token-2` and so on. The `/etc/rproxy/tokens` the package creates is in this format. It is enough when only you, or only the admin UI, use the API.
- **YAML**: under `tokens:`, write each token's name, SHA-256 hash, permissions (scopes) and restrictions. The token string itself is not stored in the file, only its hash. Use this format when you want different permissions for different users.

With YAML, first create a token and compute its hash. In these commands, the first line is the token (what you give to the client) and the second prints the hash to write in the file.

```shell
TOKEN=$(openssl rand -hex 32)
printf %s "$TOKEN" | sha256sum      # write this value as sha256
```

This token file gives four users, the admin UI, CI, a Kubernetes controller and monitoring, different permissions each.

```yaml
# /etc/rproxy/tokens (root:rproxy 640)
tokens:
  - name: ui
    sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    scopes: [admin]                     # make the UI's token admin (v0.4.23)
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    allow_listen_ports: 20000-29999     # listen ports it may create, change or delete
    max_rules: 200
    expires: 2027-03-31
  - name: k8s-controller
    sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
    scopes: [rules:read, rules:write]
    allow_rulesets: [k8s/]              # name prefixes of the rule sets it may PUT / DELETE
  - name: monitoring
    sha256: baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096
    scopes: [metrics:read]
```

The four tokens are used like this:

- `ui` is the admin UI's token and has every permission (`admin`). Why it needs `admin` is explained under "Only the owner may change or delete" below.
- `ci-deploy` is the CI token. It may read and write rules, but only for listen ports 20000–29999, it may own up to 200 rules, and it works until 31 March 2027.
- `k8s-controller` is the Kubernetes controller's token. It may handle only the rule sets ([10.2](#102-rule-sets-for-automation)) whose names start with `k8s/`.
- `monitoring` is Prometheus's token. It can only read `/metrics`.

Give the file `root:rproxy` mode 640, so that rproxy's service user can read it and nobody else can.

#### Token fields

These are the main fields of a YAML token. `name`, `scopes`, and `sha256` (or `client_cert`, below) are required. Leaving out any other field means no restriction.

| Field | When left out | What it decides |
|---|---|---|
| `name` | (required) | The token's name. Used in the log and as the owner of what it creates |
| `sha256` | (required) | The SHA-256 of the token string |
| `scopes` | (required, may not be empty) | The operations allowed |
| `allow_listen_ports` | every port | Listen ports of the rules it may create, change and delete |
| `allow_rulesets` | every name | Name prefixes of the rule sets it may `PUT` / `DELETE` |
| `max_rules` | no limit (only the process's limit) | How many rules this token may own |
| `expires` | no expiry | The last day the token may be used |
| `allow_restored` | `false` | Whether it may change rules whose creator is unknown (v0.4.23) |
| `persist` | `false` | Whether rules created with this token are stored in the database ([10.1](#101-keeping-api-created-rules)) |

- **`name`**: A name unique within the file. It appears as `token` in the audit log (`event: "audit"`), so you can tell who did what. It also becomes the **owner** of the rules and rule sets created with this token (explained below).
- **`sha256`**: The SHA-256 of the token string the client sends, in hex. rproxy compares the hash of the token it receives with this. Even if the file leaks, the token itself stays unknown.
- **`scopes`**: The operations this token may perform. List only the ones needed from the table below.
- **`allow_listen_ports`**: The listen ports of rules this token may create, change and delete, as a range such as `20000-29999` or a single number. A rule with a port range must fit entirely inside. Use it so that temporary rules made by CI cannot touch production ports (443 and so on). Ports outside give `403 forbidden`.
- **`allow_rulesets`**: Name prefixes of the rule sets this token may `PUT` / `DELETE`. Give a controller something like `[k8s/]`, and give other `rules:write` tokens names that do not overlap, so that after an rproxy restart no other token can create a set with the same name first.
- **`max_rules`**: The limit on rules created by this token plus the rules in this token's rule sets. Creating more is refused with `409 limit`. It keeps one token from using up the process's resources. `max_rulesets` sets the limit on the number of rule sets.
- **`expires`**: The token works until the end of this day (UTC). From `RPROXY_TOKEN_WARN_DAYS` (14 by default) days before, the log shows `token.expiring`; once expired, the log shows `token.expired` and the token is no longer accepted. Use it on tokens you want to rotate regularly, such as CI tokens.
- **`allow_restored`** and **`persist`**: Explained below and in [10.1](#101-keeping-api-created-rules).

There are also prefixes of stored certificate names it may use (`allow_certs`), whether it may listen on addresses the host does not have (`allow_freebind`), and the name of a client certificate (`client_cert`). [API.md, "Basics"](API.md#basics) and "Control API hardening" explain them.

#### Scopes

There are seven scopes. `admin` includes all the others. Operations without the needed scope are refused with `403 forbidden`.

| Scope | Operations allowed |
|---|---|
| `rules:read` | Reading rules, rule sets, overlays and the settings file's state (`GET /rules`, `GET /interfaces` and so on) |
| `rules:write` | Creating, changing and deleting rules; putting and deleting rule sets and overlays |
| `metrics:read` | Reading `GET /metrics` |
| `acme:write` | Creating and changing rules that use ACME certificates; `POST /acme/...` |
| `certs:read` | Reading the list and contents (without keys) of stored certificates |
| `certs:write` | Storing and deleting certificates (`PUT` / `DELETE /certs/{name}`) |
| `admin` | Everything. Only this scope can use strong operations such as re-reading the settings file, the `global` settings and upgrades |

Any token can read `GET /capabilities`, whatever its scopes.

#### Only the owner may change or delete (v0.4.23, #401)

From v0.4.23, a token without `admin` may change or delete only the rules, overlays and rule sets it **created itself**. Trying to change something created by another token is refused with `403 not_owner`. This keeps, for example, a CI token from deleting another team's rules.

- The owner is the **name** of the token that created it. Replacing `sha256` with a new token's hash while keeping the name does not change the owner.
- An `admin` token may change or delete anything, whoever owns it. The owner stays the same when `admin` changes it.
- Reading (`GET`) depends only on scopes, not on ownership.

The tricky case is **rules whose creator is unknown**: rules restored from the admin UI's database (`forward_rules`), and `dynamic` rules after a restart. Only `admin` and tokens with `allow_restored: true` may change these.

The admin UI changes rules it did not create, on its screen for rules created by other tokens ("API rules") and when it resends rules to several nodes. **Make the UI's token `admin`**, as with `ui` in the example above.

If you do not want `admin` and the UI only needs to change the rules it restored, give the UI's token `rules:read` and `rules:write` plus `allow_restored: true`. Put `allow_restored` only on the UI's token, never on CI or similar tokens.

`allow_restored` was added in v0.4.23. rproxy v0.4.22 and earlier refuse a whole token file that contains a field they do not know, so every token stops working. Remove this line before going back to an older version ([12.4](#124-going-back-to-an-earlier-version)).

#### Changing and rotating tokens

After editing the token file, have rproxy re-read it with `sudo systemctl reload rproxy-api` (SIGHUP). Even without a reload, rproxy checks the file every `RPROXY_TOKENS_CHECK_SECS` (10 seconds by default) and re-reads it when it changed. If the new file has an error, rproxy keeps using the previous tokens and logs a `reload.tokens` warning.

To replace a token without downtime, go in this order:

1. Add the new token to the file. In the meantime both old and new are accepted.
2. Switch the clients (UI, CI and so on) to the new token.
3. Remove the old token from the file.

Because the name decides the owner, take care with names. Do not reuse the name of a deleted token for a new token for another person or purpose: it could then change everything the old token created. Conversely, renaming a token means that what was created under the old name can be changed only by `admin`. See [API.md, "Rotating tokens and certificates"](API.md#control-api-hardening-v04-167) for details.

#### Locking out sources that keep failing

The TCP control API temporarily locks out sources that keep failing authentication. By default, a source (a /64 for IPv6) that fails 20 times within 1 minute is locked out for 5 minutes, during which its requests are refused with `429 locked_out` without looking at the token. This protects against guessing tokens by brute force.

- Change the count and times with `RPROXY_API_LOCKOUT_FAILURES`, `_WINDOW` and `_DURATION`. `RPROXY_API_LOCKOUT_FAILURES=0` turns the lockout off.
- Legitimate clients behind the same IP are locked out too. Put sources you never want locked out, such as a controller behind NAT, in `RPROXY_API_LOCKOUT_EXEMPT` as CIDRs.
- Requests over the Unix socket are not counted and never locked out.

#### Opening the control API beyond the host

To open the control API beyond loopback (to other hosts), a token file and TLS (`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`) are required. Without either, rproxy does not start. This keeps tokens from travelling in plain text.

An admin UI on the same host is safer connected over the Unix socket ([1.5](#15-opening-the-control-apis-unix-socket)) than over TCP. The API need not be opened on the network, and the UI is not caught by the lockout above. To check client certificates (mTLS) in addition to tokens, see [API.md, "Control API hardening"](API.md#control-api-hardening-v04-167).

### 7.2 CrowdSec

CrowdSec is an open-source system that finds attacks in logs and distributes decisions (bans) that block the offending IPs. rproxy can act as a bouncer: it receives decisions from CrowdSec's LAPI (the API that distributes decisions) and stops connections and requests from banned IPs. Use it if you already run CrowdSec, or when you publish services that attract many attacks (SSH, mail and so on).

There are two places to block. In an L4 rule, write `crowdsec: true` in the rule. In an `http` rule, use the `crowdsec` middleware.

First, create a bouncer key for rproxy on the CrowdSec side and put it in a file only the service user can read.

```shell
sudo cscli bouncers add rproxy -o raw | sudo tee /etc/rproxy/crowdsec.key >/dev/null
sudo chown rproxy-api:rproxy /etc/rproxy/crowdsec.key && sudo chmod 640 /etc/rproxy/crowdsec.key
```

Next, write the LAPI's location and the key file in `global.crowdsec` in the settings file, and add `crowdsec: true` to the rules to protect. This example cuts banned IPs on mail port 25.

```yaml
version: 1
global:
  crowdsec:
    lapi_url: 'http://127.0.0.1:8081'     # not the control API's port
    api_key_file: /etc/rproxy/crowdsec.key
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 25
    remote_addr: 10.0.0.30
    remote_port: 25
    crowdsec: true                        # banned IPs are cut before TLS
```

- `lapi_url` is the URL of CrowdSec's LAPI. The LAPI's default port is 8080, the same as rproxy's control API, so on the same host change one of them (the example moves the LAPI to 8081).
- `api_key_file` is the key file created above.
- rproxy fetches decisions from the LAPI regularly and keeps them in memory; it does not ask the LAPI for every connection. While the LAPI is unreachable, it keeps using the decisions it already has.

Whether rproxy is connected to the LAPI shows in `crowdsec` (`connected`, `decisions`) of `GET /config`. For the opposite direction, having CrowdSec read rproxy's logs to find attacks, see [CROWDSEC.md](CROWDSEC.md).

### 7.3 GeoIP

GeoIP decides whether to let a connection through by the country or the ASN (network operator) its source IP belongs to. Use it for coarse filtering, such as keeping an SSH server used only from Japan out of reach from abroad.

Write a database in mmdb format, such as GeoLite2, in `global.geoip`, and choose the countries to let through in the rule's `geoip`. No database is bundled; create a MaxMind account and fetch it with `geoipupdate` or similar.

This example limits SSH on port 22 to connections from Japan.

```yaml
version: 1
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 22
    remote_addr: 10.0.0.70
    remote_port: 22
    geoip: {allow_countries: [JP], unknown: deny}
```

- `country_db` is the country database and `asn_db` the ASN database. If you do not filter by ASN, `asn_db` is not needed.
- `allow_countries` lists the countries to let through. With this list, only connections from those countries are allowed.
- `unknown` decides what to do with connections whose country is not known: private addresses, addresses not in the database, and the time when the database cannot be read. The default `allow` lets them through, so set `deny` as in the example when you need a strict filter.

The checks run in the order `allow_from` → `geoip` → `crowdsec` ([API.md, "GeoIP"](API.md#geoip-168)).

### 7.4 Files that rules point to

Rules point to many files: certificates, keys, htpasswd files, OIDC secrets and more. Before using such a file, rproxy checks its owner and permissions so that it cannot be tampered with or stolen. Keep this in mind when placing certificates, and when you let others create rules through the API.

- Certificates, keys and secret files are used only if they are owned by the service user `rproxy-api` and cannot be written by the group or others. Keys and secrets must also not be readable by others. This check is `global.files.owner_check: strict` (the default). Places where files are owned by root, such as Kubernetes Secret volumes, can be used by listing them in `global.files.trusted_dirs`.
- Rules created through the API cannot point to the certificate store, the ACME storage, rproxy's own secrets (the token file and so on), `/proc` and similar (`403 protected_file`). This keeps API users from reading rproxy's secrets.
- A token without `admin` cannot point to a key or secret file used by a rule of another owner (`409 file_in_use`). This keeps one team from terminating TLS with another team's key and impersonating that site.
- Why a file could not be used is not put in the API answer but logged as `config.file`, so that the answer cannot be used to probe whether a file exists ([PERMISSIONS.md](PERMISSIONS.md)).

## 8. `global` settings

This chapter covers `global`, the settings that apply to the whole process rather than to a rule. They include the trusted front proxies ([6.2](#62-front-proxies-whose-x-forwarded-for-is-trusted)), the access log, CrowdSec ([7.2](#72-crowdsec)), GeoIP ([7.3](#73-geoip)), ACME ([4.6](#46-automatic-certificates-acme)) and HTTP time limits ([5.5](#55-time-limits-globalhttptimeouts)).

Set `global` either in `global` in the settings file, or through the control API with `PATCH /config/global` (needs `admin`). As with rules, **items written in the file (and environment variables) win**. Trying to change through the API an item that the file sets is refused with `409 static`. Put fixed values in the file and values you want to change, for example from the admin UI's settings screen, in the API.

Items differ in how they can be changed and where their value is decided.

| Item | How it changes | Where the value is decided |
|---|---|---|
| `trusted_proxies`, `access_log`, `crowdsec`, `geoip`, `acme` | While running (only from the Unix socket) | File / API |
| `http.timeouts` | While running (from new connections) | File / API |
| `udp_max_sessions`, `cache_max_memory` | While running | Environment variable / API |
| `performance`, `files` | Needs a restart | File / environment variable |

- Items that change "while running" are swapped without a restart. Changing the items in the first row can weaken protection (widening the trusted front proxies, writing or reading files and so on), so by default they can be changed only over the API's Unix socket.
- `udp_max_sessions` ([3.1](#31-udp)) and `cache_max_memory` (the total memory limit for all `cache` middlewares) are set by environment variable (`RPROXY_UDP_MAX_SESSIONS`, `RPROXY_CACHE_MAX_MEMORY`) or the API, not in the file.
- `performance` (the number of workers and so on) and `files` ([7.4](#74-files-that-rules-point-to)) are read only at start, so changing them needs a restart.

This example looks at the current values over the Unix socket, then checks with a dry run before changing `http.timeouts` and `udp_max_sessions`.

```shell
SOCK=/run/rproxy/api.sock                    # see "Opening the control API's Unix socket" in chapter 1
sudo curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" http://localhost/config/global | jq '.items | map_values({value, source, apply})'

sudo curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" -X PATCH 'http://localhost/config/global?dry_run=true' \
  -d '{"http":{"timeouts":{"idle":"5m"}},"udp_max_sessions":32768}'
# if it looks right, send it again without ?dry_run=true; null removes the item's API value
```

- `items` in `GET /config/global` shows, for each item, the value in effect (`value`), where the value came from (`source`: `file`, `env`, `api` or `default`), and how it changes (`apply`: `live` or `restart`).
- The body of `PATCH` has the same shape as `global` in the settings file. With `?dry_run=true` nothing changes and only the items that would change are returned.
- Sending `null` for an item removes its API value and returns it to the default.

Things to know about how `PATCH` behaves:

- Each item named is replaced as a whole. For `http.timeouts` too, sending only one field inside resets the fields you did not send to their defaults.
- If there is a database (`RPROXY_DATABASE_URL`), values set through the API are stored in the table `rproxy_global` and restored after a restart. Without a database the values live only in this process and are lost on restart.
- If you change in the settings file an item that is read only at start, it does not apply until a restart. `restart_needed` in `GET /config` shows this ([API.md, "The global settings API"](API.md#the-global-settings-api-v0419-342-featuresglobal_api)).

## Part 4: Changing things while running, and automating with the API

Part 4 explains how to change a running rproxy without stopping it (9.), and, for rules created through the control API, persistence, rule sets and dry runs (10.). Chapter 10 is written for people who use the API from automation such as CI or controllers.

## 9. Changing things while running

This chapter explains how to change settings or the binary while cutting as few current connections as possible. It covers re-reading the settings file, telling changes that cut connections from those that do not, draining (waiting for connections to end when stopping), and handoff, which replaces the binary without a restart.

### 9.1 Re-reading the settings file

When you edit the settings file, rproxy notices at its check every 10 seconds (`RPROXY_CONFIG_CHECK_SECS`) and applies only the differences. It starts the rules that were added, stops the ones that were removed, changes only the ones that changed, and does not touch the ones that stayed the same.

To get the result of a re-read on the spot instead of waiting for the automatic check, use `POST /config/reload`. It is a strong operation affecting the whole process, so it needs an `admin` token and, by default, is accepted only on the Unix socket. The example first uses `?dry_run=true` to see only what would change, then re-reads for real.

```shell
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" -X POST 'http://localhost/config/reload?dry_run=true' | jq
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" -X POST http://localhost/config/reload
# {"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0,"restart_needed":[],...}
```

The numbers in the answer count the rules that were added (`added`), removed (`removed`), changed (`changed`), left as they were (`unchanged`), and created but not running (`failed`). `restart_needed` lists the `global` items that do not apply until a restart.

If the file has an error, nothing changes: the answer is `400` with the reasons, and rproxy keeps running with the previous settings. The same happens when the automatic check finds an error, and the log shows `config.error`. `rproxy-api --check-config --diff` also shows the differences between the edited file and the running rproxy.

### 9.2 Changes that keep connections (`in_place`) and changes that cut them (`recreate`)

When you change a rule, what happens to current connections depends on the fields you change. rproxy treats changes in two kinds:

- **`in_place`**: The rule's listener stays and only its contents are swapped. Current connections are not cut.
- **`recreate`**: The listener is closed and built again. The rule's current connections are cut.

| What changes | Effect |
|---|---|
| Targets (`remote_*`, `targets`, `balance`, `health_check`), `tls`, `starttls`, `allow_from`, `http`, `extra_listen_addrs`, times, `limits`, `bandwidth`, `geoip`, `labels` and so on | `in_place` |
| `listen_port_end` (port range), `source_ip`, `listen_freebind`, whether there is `http`, whether a rule listening on `::` has extra addresses (switching between dual-stack and IPv6 only) | `recreate` |

How an `in_place` change affects current traffic depends on the protocol:

- For TCP, current connections continue with the old settings and new connections get the new ones.
- For UDP, current sessions move to the new targets too. However, UDP sessions on an address removed from `extra_listen_addrs` end.

A `PATCH` through the API does not accept a change that needs `recreate`; it refuses with `400 unsupported`. To make such a change, delete the rule and create it again. When the settings file is re-read or a rule set is `PUT`, rproxy recreates the rule by itself.

You can tell which kind a change is before sending it, from `change` in the answer to `?dry_run=true` ([10.3](#103-dry-run)).

### 9.3 Waiting when stopping (drain)

Draining means that before stopping, rproxy stops accepting new connections and waits a while for the current ones to end on their own. Use it so that downloads or database transactions are not cut off midway.

- **When deleting a rule**: add the number of seconds to wait, as in `DELETE /rules/...?drain_secs=30` (up to 3600 seconds). Without it, current connections are cut at once.
- **When stopping the process** (SIGTERM from `systemctl stop`): by default it stops at once. Two environment variables turn the shutdown into stages:
  - `RPROXY_SHUTDOWN_DELAY`: first `/readyz` returns 503 to tell the front "about to stop", and connections are still accepted as usual for this long. This is the time for a load balancer in front to move traffic to other rproxy instances.
  - `RPROXY_SHUTDOWN_DRAIN`: then the listeners close and rproxy waits up to this long for current connections to end. Connections still open after that are cut.

How to choose these values with a load balancer in front is explained in [the README's "Shutting down on SIGTERM"](../../README.en.md#shutting-down-on-sigterm-v041).

### 9.4 Replacing the binary (no restart)

rproxy-api can replace itself with a new binary while running. This is called a **handoff**. `systemctl restart` cuts every current connection, but a handoff does not cut TCP or HTTP connections. It works for patches within the same minor version (X.Y), for example 0.4.22 → 0.4.23.

A handoff starts when you send the SIGUSR2 signal to the running rproxy.

```shell
sudo systemctl kill -s USR2 --kill-whom=main rproxy-api    # hand over to the binary on disk
journalctl -u rproxy-api | grep -E '"handoff\.(done|failed|refused)"'
```

The first line sends SIGUSR2 only to the service's main process. The second searches the log for the handoff's result.

A handoff goes like this:

1. The old process starts the new binary on disk as its child.
2. The old process hands its listening sockets, and state such as API-created rules and rule sets, to the new process. Because the same sockets stay in use, no new connection is missed during the switch.
3. Once the new process is ready, it accepts new connections. The old process waits for the connections it holds to end, then exits (`RPROXY_HANDOFF_DRAIN`, 5 minutes by default).

The result is in the log. `handoff.done` means success. `handoff.refused` means the minor versions differ so the handoff was refused, and `handoff.failed` means the new process did not become ready. On either failure, the old process keeps running.

UDP sessions are not handed over; the new process creates them again, so UDP may pause briefly. Package upgrades use this handoff automatically within the same minor version ([12.](#12-upgrades-and-going-back), [UPGRADE.md](UPGRADE.md)).

## 10. Persistence, rule sets and dry run

This chapter is for people who create rules through the control API. It covers how to keep API-created rules across restarts (10.1), rule sets, which manage many rules together declaratively (10.2), and dry runs, which check the result before you send a change (10.3).

### 10.1 Keeping API-created rules

A rule created through the API with a token that does not store (`origin: dynamic`) exists only in rproxy's memory and is lost on restart. That is fine for temporary rules, such as CI preview environments. For rules you want to keep, there are three ways:

1. Write them in the settings file (they become static rules).
2. Create them in the admin UI. The UI writes them to its own database, and rproxy restores them when it starts.
3. Add `persist: true` to a token and create them through the API. Rules created with this token become `origin: api`; rproxy writes them to the table `rproxy_rules` in the `RPROXY_DATABASE_URL` database and restores them when it starts.

For the third way, add `persist: true` in the token file's YAML to the token whose rules should be stored.

```yaml
tokens:
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    persist: true
```

Storing works like this:

- rproxy writes to the database before answering a rule's creation, change or deletion. `persisted: true` in the answer means the database has committed it.
- If the database is unreachable, the rule still runs and the answer says `persisted: false`. What could not be written is written later by the periodic reconciliation (`RPROXY_PERSIST_CHECK_SECS`, 60 seconds by default).
- Only the rows of rproxy's own node (`RPROXY_NODE_NAME`) in `rproxy_rules` are restored. The table definition is in [API.md, "Storing API-created rules"](API.md#storing-api-created-rules-144).

**Do not give the UI's token `persist`.** The UI writes the rules it creates to its own database (`forward_rules`), so with `persist` the same rule would be stored in two places.

### 10.2 Rule sets (for automation)

A rule set is a named group of rules. Use it when a program manages many rules, as a Kubernetes controller or CI does.

Instead of sending `POST`, `PATCH` and `DELETE` for each rule, you `PUT` the whole list each time: "this is how the rules of this set should look". rproxy works out the difference from the current rules, creates the missing ones, changes the ones that differ, and stops the ones that left the list. Even if something fails midway, the next `PUT` brings everything to the right state, so the caller does not need to remember the differences.

This example puts one rule in the rule set named `ci/preview-42`.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PUT http://127.0.0.1:8080/rulesets/ci/preview-42 -d '{
  "generation": 1,
  "rules": [
    {"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":20042,"remote_addr":"10.0.5.42","remote_port":8080}
  ]}' | jq '.results'
```

- `ci/preview-42` in the path is the set's name. Names may contain `/`.
- `generation` is a version number chosen by the caller. Increase it with every change.
- `rules` is the whole of the set's rules. Each has the same shape as the body of `POST /rules`.
- `results` in the answer lists, per rule, what was done (`action`: `create`, `update`, `delete`, `none`) and whether connections were cut (`change`: `in_place`, `recreate`, [9.2](#92-changes-that-keep-connections-in_place-and-changes-that-cut-them-recreate)).

The rules for sets:

- If even one of the rules sent fails validation, nothing changes.
- A `generation` smaller than the last one received is refused with `409 stale_generation`. This keeps an old `PUT` that arrives late from overwriting a newer state.
- If you put the `etag` from the answer in the `If-Match` header of the next `PUT`, the `PUT` is refused with `412 precondition_failed` when someone else changed the set in the meantime. This keeps you from overwriting someone else's change without noticing.
- `PATCH` or `DELETE` on a single rule of a set gives `409 owned`. Change a set's rules by `PUT`ting the set.
- A set belongs to the token that created it. Other tokens without `admin` can neither `PUT` nor `DELETE` it (`403 not_owner`).

Sets live only in rproxy's memory and are lost on restart. Only sets of a `persist: true` token are stored in the table `rproxy_rule_sets` and restored. In a setup that does not store them, after a restart the caller waits until `GET /readyz` returns 200 (the restore at start has finished), then `PUT`s the sets again ([API.md, "Rule sets, conditions and readiness"](API.md#rule-sets-conditions-and-readiness-for-the-kubernetes-controller-28)).

### 10.3 Dry run

A dry run runs the same checks as a change but changes nothing; it only reports what the change would do. Use it before changing production rules, to check for errors and whether current connections would be cut.

You can add `?dry_run=true` to `POST` / `PATCH` / `DELETE /rules`, `PUT /rulesets/{name}`, `POST /config/reload`, `PATCH /config/global`, and `PUT` / `DELETE` of an overlay. A dry run opens no listener and resolves no names.

This example checks what would happen if the target of the rule on port 8889 changed.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH 'http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889?dry_run=true' \
  -d '{"remote_addr":"10.0.0.13","remote_port":8080}' | jq '{action, change, diff}'
```

- `action` is what would be done (`create`, `update`, `delete`, `none`).
- `change` says, for an `update`, whether the rule changes without cutting connections (`in_place`) or with cutting them (`recreate`).
- `diff` gives the old and new value of each field that changes.

One thing to watch with `PATCH`: it replaces the target fields (`remote_addr` / `remote_port` or `targets`, `balance`, `health_check`) together every time. A `balance` left out becomes `round_robin`, and a `health_check` left out becomes none. So when you change the targets of a rule with `targets`, send `balance` and `health_check` along with them. The dry run's `diff` shows what would be lost.

## Part 5: Operations

Part 5 collects the procedures for watching a running rproxy, upgrading it, and fixing it when something goes wrong: reading logs, metrics and stats (11.), upgrading and going back (12.), backups (13.), monitoring (14.), handling logs (15.), capacity limits (16.), examples of common setups (17.), and troubleshooting (18.).

## 11. Observing (logs, `/metrics`, stats)

This chapter covers three ways to see what rproxy is doing: logs, which follow what happened over time; `/metrics`, which Prometheus collects to show trends; and stats, which give each rule's current numbers.

### 11.1 Logs

The log is JSON with one event per line. The `event` in each line is the kind of event. [The README's "Logs"](../../README.en.md#logs) lists the kinds.

This example follows the log and uses `jq` to show only the events worth attention. The first command is for logging to a file, the second for logging to journald.

```shell
# when logging to a file (the package default; file dates are UTC)
tail -F /var/log/rproxy/rproxy.$(date -u +%F).log | jq -c 'select(.event == "degraded" or .event == "rule.failed" or .event == "audit")'
# when logging to journald
journalctl -u rproxy-api -o cat | jq -c 'select(.event == "conn.denied" or .event == "degraded")'
```

Log files are split by day, and the date in the file name is in UTC. That is why the example builds today's file name with `date -u`.

The events worth looking at first:

| `event` | Meaning |
|---|---|
| `degraded` | rproxy stopped some parts because of a problem in the environment and kept running (`part` says where) |
| `rule.failed` | A rule is not running |
| `config.error` | The settings file could not be re-read, and the previous version is running |
| `audit` | A record of changes made through the control API and of refused requests |
| `conn.denied`, `conn.limited` | A connection was refused by access control or a limit |
| `tls.error` | A TLS handshake failed |
| `target.down` | A target was judged to be down |
| `cert.expiring` | A certificate is close to expiry |

### 11.2 `/metrics`

`/metrics` provides numbers in Prometheus format: the number of rules, connections and bytes per rule, the state of targets, refusals and more. Use it to collect time series, watch trends and build alerts. Reading it needs a `metrics:read` (or `admin`) token.

This example extracts only the lines with the number of rules and each rule's state and connections.

```shell
curl -s -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:8080/metrics | grep -E '^rproxy_(rules|rule_up|connections) '
```

[14.](#14-monitoring-and-alerts) explains how to collect it with Prometheus and which values to watch.

### 11.3 A rule's stats

To see the current state of one rule, look at `stats` and `conditions` in `GET /rules/{protocol}/{addr}/{port}`.

- `stats` includes the number of open connections (`connections`), bytes received and sent (`rx_bytes`, `tx_bytes`), refusals by access control (`denied`) and by limits (`limited`), per-target details (`targets`), and per-route numbers for `http` rules (`http`).
- `conditions` gives four states: whether the rule was accepted, whether it is listening, whether its references (certificates, target names) resolved, and whether its targets are alive ([API.md, "Rule sets, conditions and readiness"](API.md#rule-sets-conditions-and-readiness-for-the-kubernetes-controller-28)).

The numbers live only in memory, so they start again from 0 after a restart. A handoff ([9.4](#94-replacing-the-binary-no-restart)) carries over the old process's numbers, so they do not go down.

## 12. Upgrades and going back

This chapter explains how to move rproxy-api to a new version, and how to go back to the previous one if there is a problem. VMs installed with apt are upgraded with apt; containers with self-update. Either way, within the same minor version the switch is a handoff ([9.4](#94-replacing-the-binary-no-restart)) that does not cut connections.

### 12.1 Upgrading with apt

An rproxy installed with apt is upgraded like any other package. The second line checks in the log how the switch ended.

```shell
sudo apt update && sudo apt install rproxy-api
journalctl -u rproxy-api -n 50 | grep -E '"handoff\.|"start"'
```

If the major.minor version is the same as before, the package hands over with SIGUSR2 (connections are not cut); if it differs, the package restarts the service (connections are cut). `handoff.done` in the log means a handoff happened; only `start` means a restart. A patch whose release notes say "restart required" restarts even within the same minor version.

When upgrading to v0.4.23, watch the tokens' permissions:

- From v0.4.23, a token without `admin` may change only the rules it created ("Only the owner may change or delete" in [7.1](#71-tokens), #401).
- If a YAML token file gives the UI's token `rules:read` and `rules:write`, the UI's "API rules" screen and its synchronisation across several nodes stop with `403 not_owner`.
- Before upgrading, make the UI's token `admin`, or add `allow_restored: true`. A token in the one-per-line format is `admin` already, so nothing is needed.

### 12.2 Self-update (containers)

In a container, rproxy-api can fetch new patches by itself. Make the image's entrypoint `rproxy-api launch` and pass the environment variable `RPROXY_UPDATE=auto`. To only be told that a new version exists, use `check`.

- Self-update installs only newer patches of the same X.Y, checks their signatures first, and switches with a handoff.
- If a new version fails before `RPROXY_UPDATE_HEALTHY` (60 seconds by default), it is remembered as a bad version and the previous version is restored.
- Leave it `off` (the default) on apt VMs and in Kubernetes: on VMs so that apt and self-update do not both upgrade, in Kubernetes because upgrades happen by replacing replicas ([UPGRADE.md, "Self-update"](UPGRADE.md#self-update-containers)).

This command shows the current state of self-update (the running version, a newer version found, the list of bad versions and so on).

```shell
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/admin/update | jq
```

### 12.3 Handing over by hand

If you replaced the binary without the package, start the handoff yourself. After replacing the binary, run `systemctl kill -s USR2 --kill-whom=main rproxy-api`, or call `POST /admin/upgrade` (`admin`, from the Unix socket).

It is done when the log shows `handoff.done`. If the new process is not ready within 30 seconds (`RPROXY_HANDOFF_TIMEOUT`), the old process keeps running and the log shows `handoff.failed`.

### 12.4 Going back to an earlier version

If a new version causes problems, reinstall the previous version with apt by naming it. The repository keeps past versions too.

```shell
apt-cache policy rproxy-api                 # versions you can install (the repository keeps old ones)
sudo apt install rproxy-api=0.4.22-1        # versions look like <number>-1; within the same minor, going back also hands over
```

The first line lists the versions you can install, and the second installs a given one. Package versions have the form `<number>-1`. Going back within the same minor version also uses a handoff and does not cut connections.

An older version does not know the settings added in newer versions. Before going back, check the following:

- **Remove settings added by the newer version first.** An older version treats fields it does not know as errors. For example, going back to v0.4.22 with `allow_restored` (v0.4.23) still in the token file means the whole token file is not read and no token works. The "Added" section of the release notes says from which version each field is available.
- **The same applies to the settings file.** Run `--check-config` with the binary of the version you go back to before switching.
- **Values set with `PATCH /config/global`** (from v0.4.19) are not handed over to versions before that. The database rows remain, so they are read again when you return to v0.4.19 or later.
- **Going back across minor versions** needs a restart; a handoff is not possible.
- **Going back to v0.4.22 or earlier** removes the protection that only the owner may change or delete (#401, v0.4.23). Every `rules:write` token can then change or delete other tokens' rules.

## 13. Backup and restore

This chapter explains what to save, and in which order to restore it, so that a broken rproxy-api host can be brought back to the same state. [BACKUP.md](BACKUP.md) describes what to save and how to restore in detail; here are the essentials.

| What to save | Where |
|---|---|
| Environment file and tokens | `/etc/rproxy/rproxy.env`, `/etc/rproxy/tokens` |
| Settings file | The path in `RPROXY_CONFIG` |
| Certificates, keys and secret files | The paths written in settings and rules, `/var/lib/rproxy/certs/`, `/var/lib/rproxy/acme/` |
| Database | `forward_rules`, `rproxy_rules`, `rproxy_rule_sets`, `rproxy_global`, `rproxy_rule_overlays` |

- The settings file is the only place static rules exist. There is no copy anywhere else, so always save it.
- `/var/lib/rproxy/certs/` holds certificates stored with the control API's `PUT /certs`, and `/var/lib/rproxy/acme/` holds certificates obtained with ACME and the account keys.
- In the database, `forward_rules` holds the admin UI's rules, and the tables starting with `rproxy_` are written by rproxy (stored API rules, rule sets, API values of `global`, and overlays; `rproxy_rule_overlays` from v0.4.23).

Restore in this order. rproxy reads the settings and the database when it starts, so put those back first.

1. Install the package (do not start it yet).
2. Restore `/etc/rproxy` and the key files.
3. Restore the database.
4. Check the settings file with `--check-config`.
5. Start rproxy-api.
6. Start the admin UI.
7. Check with `GET /rules` and similar that the rules are back.

Rules created through the API with a token that does not store (`origin: dynamic`) are not in the database, so they do not come back. If you want to keep them as well, save the output of `GET /rules` as a record.

## 14. Monitoring and alerts

This chapter explains how to collect rproxy's `/metrics` with Prometheus and set up alerts that tell you about problems. At the end it shows how to catch `degraded`, which does not appear in `/metrics`.

### 14.1 Collecting

This `prometheus.yml` collects `/metrics` from a control API opened with TLS, from Prometheus on another host.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rproxy
    scheme: https                                       # the control API off loopback requires TLS
    tls_config:
      ca_file: /etc/prometheus/rproxy-api-ca.pem        # if self-signed, that certificate or its CA
    authorization:
      credentials_file: /etc/prometheus/rproxy.token     # a metrics:read token (plain text)
    static_configs:
      - targets: ['10.0.0.2:8080']
```

- `scheme: https` and `tls_config.ca_file` let Prometheus check the control API's TLS certificate.
- `authorization.credentials_file` points to a file with the `metrics:read` token string (not its hash).

On the rproxy side, open the control API to the monitoring network. Opening it beyond loopback requires a token file and TLS (`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`); without any of them rproxy does not start. Then add the monitoring network's address to `RPROXY_API_ADDR` (for example `127.0.0.1,10.0.0.2`).

To keep the control API on loopback only, run Prometheus on the same host with `scheme: http` and `targets: ['127.0.0.1:8080']`. `tls_config` is then not needed.

### 14.2 What to watch

The values in `/metrics` worth watching in operation, by what you want to know:

| What you want to know | Value |
|---|---|
| Rules that are not running | `rproxy_rules{state="failed"}`, `rproxy_rule_up == 0` |
| All targets down | `rproxy_rule_all_targets_down`, `rproxy_http_service_down`, `rproxy_target_up` |
| Refusals by limits | `rproxy_rule_limited_total{reason}`, `rproxy_http_limited_total` |
| Connection and session budget | `rproxy_session_budget_in_use` / `rproxy_session_budget_limit` |
| Certificate expiry | `rproxy_cert_expiry_seconds` |
| Connection to CrowdSec | `rproxy_crowdsec_connected` |
| Background tasks that crashed | `rproxy_task_restarts_total{part}` |
| Lost log lines | `rproxy_log_dropped_total` |
| Handoffs | `rproxy_handoffs_total{outcome}`, `rproxy_build_info` |

Some notes on these values:

- The `reason` of `rproxy_rule_limited_total` is why a connection was refused. `max_connections`, `source_connections`, `new_connections` and `packets` come from the rule's `limits` ([3.5](#35-connection-limits-for-the-whole-rule)), `target_full` from the targets' `max_connections` ([3.4](#34-several-targets-balancing-and-failover)), and `fd_budget` from the process's connection and session budget ([16.](#16-capacity-limits)).
- The ratio of the budget in use (`in_use`) to its limit (`limit`) shows how full it is.
- Background tasks (watching the settings file, ACME, the database and so on) restart on their own when they crash. If `rproxy_task_restarts_total` grows, look at `part` in the log's `degraded` to see what crashed.
- `rproxy_log_dropped_total` is the number of log lines dropped because writing could not keep up.
- `rproxy_build_info` is the version of the running binary. It shows whether the version changed after a handoff.

### 14.3 Example alerts

This file is an example of Prometheus alerts built on the values above.

```yaml
# rproxy-alerts.yml
groups:
  - name: rproxy
    rules:
      - alert: RproxyRuleFailed
        expr: rproxy_rules{state="failed"} > 0
        for: 5m
        annotations: {summary: 'A rule is not running (state and error in GET /rules)'}
      - alert: RproxyAllTargetsDown
        expr: rproxy_rule_all_targets_down == 1 or rproxy_http_service_down == 1
        for: 2m
      - alert: RproxyLimited
        expr: sum by (protocol, listen, reason) (rate(rproxy_rule_limited_total{reason!="fd_budget"}[5m])) > 1
        for: 10m
        annotations: {summary: '{{ $labels.listen }} keeps refusing by {{ $labels.reason }}'}
      - alert: RproxyFdBudgetRefusing
        expr: sum(rate(rproxy_rule_limited_total{reason="fd_budget"}[5m])) > 0
        annotations: {summary: 'The descriptor budget is full and connections or sessions are refused (raise LimitNOFILE)'}
      - alert: RproxyFdBudgetHigh
        expr: rproxy_session_budget_limit > 0 and rproxy_session_budget_in_use / rproxy_session_budget_limit > 0.8
        for: 10m
      - alert: RproxyCertExpiring
        expr: rproxy_cert_expiry_seconds < 7 * 86400
      - alert: RproxyCrowdsecDisconnected
        expr: rproxy_crowdsec_connected == 0
        for: 5m
      - alert: RproxyTaskRestarted
        expr: increase(rproxy_task_restarts_total[15m]) > 0
        annotations: {summary: 'A background task crashed and was restarted (part in the degraded log)'}
      - alert: RproxyLogDropped
        expr: increase(rproxy_log_dropped_total[5m]) > 0
```

Each alert fires when:

- `RproxyRuleFailed`: a rule has not been running for 5 minutes. Look at `state` and `error` in `GET /rules` for the reason.
- `RproxyAllTargetsDown`: every target of a rule, or every server of an `http` service, has been down for 2 minutes.
- `RproxyLimited`: a rule's limits have kept refusing more than once per second for 10 minutes. Either the limit is too small or there is an attack. Refusals by the budget (`fd_budget`) are handled by the next alert.
- `RproxyFdBudgetRefusing`: the process's connection and session budget is full and connections are being refused. Raise `LimitNOFILE` ([16.](#16-capacity-limits)).
- `RproxyFdBudgetHigh`: more than 80% of the budget has been in use for 10 minutes. This warns you before it fills up.
- `RproxyCertExpiring`: a certificate expires within 7 days.
- `RproxyCrowdsecDisconnected`: the CrowdSec LAPI has been unreachable for 5 minutes.
- `RproxyTaskRestarted`, `RproxyLogDropped`: a background task crashed, or log lines were lost.

### 14.4 Catching `degraded`

`degraded` (some parts stopped because of a problem in the environment, [1.4](#14-checking-that-it-runs)) has no value in `/metrics` and appears only in the log. Catch it with whatever collects your logs.

This command lists the `degraded` events of the last hour with only the time, the part and the reason.

```shell
journalctl -u rproxy-api --since -1h -o cat | jq -c 'select(.event == "degraded") | {timestamp, part, error}'
```

With Loki, a query such as `{unit="rproxy-api.service"} | json | event="degraded"` can drive an alert.

## 15. Handling logs

This chapter covers where logs go, how much there is, and how to treat the information in them. Read it when you decide how long to keep logs and who may read them.

- **Location**: with the package defaults, logs are written to `/var/log/rproxy/rproxy.<date>.log` (`RPROXY_LOG_FILE`). rproxy splits the files by day and removes old files beyond `RPROXY_LOG_KEEP` (14 by default), so logrotate is not needed. Removing the `RPROXY_LOG_FILE` line from `/etc/rproxy/rproxy.env` sends the log to standard output, which systemd puts in the journal.
- **Access log**: each request of an `http` rule becomes an `http.access` event. Because there are many, `global.access_log: /var/log/rproxy/access.log` can split them into a separate file. When you set this through the API (`PATCH /config/global`), it can only be placed under the directory `RPROXY_API_ACCESS_LOG_DIR`. rproxy deletes old files in that directory, so keep it for rproxy's access logs only.
- **Volume**: so that the same line does not flood the log during an attack, `conn.denied`, `conn.limited`, `tls.error` and similar are thinned out per source. The number of lines left out goes in `suppressed` on the next line written. Long fields chosen by the client (header values and so on) are cut at 2,048 bytes.
- **Secrets**: values such as `token`, `code` and `password` in URL queries are written as `REDACTED`. Even so, logs contain client IPs, SNI and certificate CNs, so limit who can read them (`/var/log/rproxy` is mode 750).
- **CrowdSec**: with the bundled parser and scenarios, CrowdSec can read rproxy's logs and find attacks ([CROWDSEC.md](CROWDSEC.md)). The file name changes every day, so write a glob (`/var/log/rproxy/*.log`) in CrowdSec's `acquis`.

## 16. Capacity limits

This chapter covers the limits that decide how many connections and listeners rproxy can handle at once, and what to do when they run short. Read it when you prepare a host that will take many connections, or when an `fd_budget` alert fires.

On Linux every socket uses a file descriptor (fd). A process may open only so many file descriptors (`RLIMIT_NOFILE`), and rproxy raises this to the hard limit when it starts. The package's unit sets `LimitNOFILE=65536`.

rproxy splits this limit between listening sockets and connections and sessions. 1024 are kept back for everything else, such as log files and database connections.

| Limit | Default | What it counts |
|---|---|---|
| `LimitNOFILE` (unit) | `65536` | All of the process's file descriptors |
| `RPROXY_MAX_LISTENERS` | `0` (automatic) | Listening sockets that can be opened through the control API |
| Connection and session budget | limit − 1024 − `RPROXY_MAX_LISTENERS` | File descriptors used by connections and UDP sessions |
| `RPROXY_MAX_RANGE_PORTS` | `20000` | Ports in one rule |
| `RPROXY_MAX_RULES` / `RPROXY_MAX_RULESETS` | `10000` / `1000` | Rules and rule sets that can be created through the API |
| `RPROXY_UDP_MAX_SESSIONS` | `16384` | Sessions of one UDP rule |

- **`RPROXY_MAX_LISTENERS`**: The limit on listening sockets. It counts the number of listen addresses times the number of ports, doubled for `http3` rules (TCP and UDP). The default `0` means automatic: half of (limit − 1024), which is 32256 with `LimitNOFILE=65536`.
- **Connection and session budget** (fd budget): the remaining file descriptors that connections and sessions may use; 32256 with 65536. A TCP relay uses 2 (the accepted socket and the socket to the target), an `http` connection 1 plus 1 per connection to a target, a UDP session 1, and a splice pipe 2.
- **`RPROXY_MAX_RANGE_PORTS`**: How large a port range one rule may have ([3.2](#32-port-ranges)).
- **`RPROXY_MAX_RULES` / `RPROXY_MAX_RULESETS`**: Limits on the rules and rule sets that can be created through the API. `0` means no limit.
- **`RPROXY_UDP_MAX_SESSIONS`**: How many sessions one UDP rule may hold at once. If the rule has `limits.max_connections`, that is used instead ([3.1](#31-udp)).

When the connection and session budget is full, new TCP connections are closed at once, and UDP sessions are refused or room is made by ending old sessions that are not established. This shows as `reason: fd_budget` on `conn.limited` in the log and as `rproxy_rule_limited_total{reason="fd_budget"}` in `/metrics`. With 65536, about 16000 TCP relays can run at once. If that is not enough, raise `LimitNOFILE` like this:

```shell
sudo systemctl edit rproxy-api
# [Service]
# LimitNOFILE=262144
sudo systemctl restart rproxy-api
```

In the editor that `systemctl edit` opens, write the two commented lines (`[Service]` and `LimitNOFILE=262144`) and save. The unit's limit takes effect on restart.

More to know about the limits:

- The `start` line logged at start shows the size of the budget (`session_budget`), `max_listeners`, and the number kept back (`fd_reserve`). The number currently in use is `rproxy_session_budget_in_use` in `/metrics`.
- Rules restored from the settings file or the database count towards the limits, but are not refused even when over them. Only API changes that increase the count are refused (`409 limit`).
- **Source ports of connections to targets** (an OS rule): every TCP connection and UDP session from rproxy to a target uses one ephemeral port on the rproxy host. With Linux's default (`net.ipv4.ip_local_port_range`, 32768–60999), that allows about 28000 per pair of source address and target (address and port). To connect more than that to one target, widen the range or split the target with `targets`. With `source_ip: transparent`, connections leave with the client's address, so these pairs are separate.

## 17. Recipes

This chapter presents common setups as settings files you can use as they are. Replace the certificate paths and addresses with your own and run `--check-config` before using them.

### 17.1 A web app over HTTPS (ACME)

Publish a web app running on port 3000 on the same host over HTTPS, with a Let's Encrypt certificate. Port 80 answers ACME checks and redirects other requests to HTTPS.

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [app.example.com]
    resolvers:
      le-http: {account: letsencrypt, challenge: http-01}
rules:
  - protocol: tcp                  # 80: answers ACME http-01, sends the rest to HTTPS
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
  - protocol: tcp                  # 443: terminates and forwards to the web app
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: le-http
          domains: [app.example.com]
    http:
      http3: true
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [secure, compress]
      services:
        app:
          servers: [{url: 'http://127.0.0.1:3000'}]
          health_check: {path: /, interval: 10s}
      middlewares:
        secure: {headers: {hsts: {max_age: 31536000}, content_type_nosniff: true}}
        compress: {compress: {}}
```

- `global.acme` is the account and resolver that get a certificate for `app.example.com` with `http-01` ([4.6](#46-automatic-certificates-acme)).
- The first rule (port 80) answers ACME checks and redirects everything else to HTTPS ([5.3](#53-from-port-80-to-https)).
- The second rule (port 443) terminates with the ACME certificate, adds headers such as HSTS and compression, and sends to the web app. `http3: true` also accepts HTTP/3.

Open TCP ports 80 and 443 and, for HTTP/3, UDP port 443 in the firewall. Check the certificate's state with `GET /acme`.

### 17.2 A TCP proxy for a database (long-idle connections)

Put rproxy in front of a PostgreSQL primary and spare so that applications connect to a single address. When the primary fails, traffic switches to the spare.

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 10.0.0.2
    listen_port: 5432
    targets:
      - {addr: 10.0.1.11, port: 5432}
      - {addr: 10.0.1.12, port: 5432}
    balance: failover              # send to the primary, the next one if it fails
    health_check: {interval: 5s, timeout: 2s}
    connect_timeout: 3s
    idle_timeout: 12h              # do not cut pooled connections after 1h
    allow_from: [10.0.0.0/16]
    limits: {max_connections: 1000}
```

- `balance: failover` with `health_check` checks the primary every 5 seconds and uses the next target if it is down ([3.4](#34-several-targets-balancing-and-failover)).
- `idle_timeout: 12h` keeps connections that an application's pool holds silently for long from being cut after the default 1 hour ([3.6](#36-connections-that-stay-quiet-for-long)).
- `allow_from` accepts only the office network, and `limits` caps connections at 1000.

### 17.3 A UDP game server

Publish a UDP game server on both IPv4 and IPv6, while keeping each player from using too many resources.

```yaml
version: 1
rules:
  - protocol: udp
    listen_addr: 0.0.0.0
    extra_listen_addrs: ['::']
    listen_port: 27015
    remote_addr: 10.0.0.80
    remote_port: 27015
    udp_idle_secs: 120             # do not drop quiet players after 30 seconds
    limits:
      max_connections: 4000        # this rule's sessions (instead of the default 16384)
      per_source:
        max_connections: 4
        packets: {average: 200, period: 1s, burst: 400}
```

- `extra_listen_addrs: ['::']` also accepts IPv6 on the same port ([3.3](#33-several-listen-addresses)).
- `udp_idle_secs: 120` keeps sessions of players who go quiet for a while from being dropped after the default 30 seconds ([3.1](#31-udp)).
- `limits` caps the whole rule at 4000 sessions, one source at 4 sessions, and datagrams at 200 per second on average ([3.5](#35-connection-limits-for-the-whole-rule)).

### 17.4 Splitting one 443 by name

On one port 443, split by name between sites that rproxy terminates and relays, and sites passed as they are to a target that holds the certificate.

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/example.pem, key_file: /etc/rproxy/tls/example.key}
      routes:
        - server_names: ['**.k8s.example.com']    # straight to Kubernetes (it holds the certificates)
          passthrough: true
          remote_addr: 10.2.255.131
          remote_port: 443
          source_ip: proxy_v2
    http:
      routes:
        - {name: wiki, match: Host(`wiki.example.com`), to: 'http://10.0.0.5:8080'}
        - {name: git, match: Host(`git.example.com`), to: 'http://10.0.0.6:3000'}
      default: {status: 404}
```

- The route in `tls.routes` with `passthrough: true` does not terminate connections for names under `**.k8s.example.com`; it passes them, ClientHello and all, to the Kubernetes load balancer. The certificate is held there, and `source_ip: proxy_v2` passes the client's IP with the PROXY protocol.
- Other names are terminated by rproxy with `example.pem` and routed by the `http` routes to `wiki` or `git`. Anything else gets 404.

If the targets hold the certificates of every site, rproxy does not need to terminate at all. Use the `tls.mode: sni` example ([4.1](#41-routing-by-name-sni)).

## 18. Troubleshooting

This chapter explains where to look when things do not work, and the common causes: when the API returns an error (18.1), when a rule does not run (18.2), and when connections are refused (18.3).

### 18.1 API errors

When it fails, the control API returns JSON of the form `{"error": "...", "code": "..."}`. `error` is a sentence for people; `code` is a short name for programs. [API.md, "Errors"](API.md#errors) lists every `code`.

Common codes and what to do:

| `code` (HTTP) | Meaning | What to do |
|---|---|---|
| `static` (409) | You tried to `PATCH` / `DELETE` a rule from the settings file. Also when a rule set `PUT` tries to take the same key, and when `PATCH /config/global` tries to change an item set by the file or an environment variable | Edit the file. To add to a static rule's listener from the API, use an overlay ([2.4](#24-settings-file-versus-api)) |
| `already_exists` (409) | A rule with the same key, or with an overlapping listener, already exists. Also a `POST` with a key that is in the settings file | Find it with `GET /rules` and change the address or port |
| `reserved` (409) | It overlaps the address and port of the control API (or `http01_listen`) | Use another port. The addresses rproxy uses are in `reserved` of `GET /interfaces` |
| `bind_failed` (409) | The port cannot be opened: another process uses it, or permission is missing | Find the user with `ss -lntup`. Ports below 1024 need `CAP_NET_BIND_SERVICE` |
| `not_owner` (403) | A token without `admin` tried to change something another token created | Change it with the token that created it, or with an `admin` token. Make the UI's token `admin` (or give it `allow_restored`) ([7.1](#71-tokens)) |
| `forbidden` (403) | Outside the scopes or `allow_listen_ports`. Also when an operation allowed only on the Unix socket is called over TCP | Review the token. Call strong operations through `RPROXY_API_SOCKET` |
| `file_in_use` (409) | You pointed to a key or secret file used by another owner's rule | Prepare your own file (or create the rule as `admin`) |
| `protected_file` (403) | You pointed to the certificate store, the ACME storage, rproxy's secrets or similar | Put the file somewhere else |
| `file_not_allowed` (403) | A token with `allow_certs` wrote a file path | Refer to a stored certificate with `{cert: <name>}` |
| `tls_config` / `invalid` (400) | A shape error, or a file that cannot be used | See the explanation below |
| `unsupported` (400) | A setting this version or environment cannot run, or a field `PATCH` cannot change | Check `features` in `GET /capabilities`. For fields that cannot change, recreate the rule ([9.2](#92-changes-that-keep-connections-in_place-and-changes-that-cut-them-recreate)) |
| `limit` (409) | Over `RPROXY_MAX_*` or the token's `max_rules` / `max_rulesets` | Delete what you do not use, or raise the limit ([16.](#16-capacity-limits)) |
| `owned` (409) | You tried to change a single rule of a rule set | `PUT` the set ([10.2](#102-rule-sets-for-automation)) |
| `stale_generation` (409) / `precondition_failed` (412) | You sent an old `generation`, or `If-Match` does not match the current state | Read the current state again, then send |
| `resolve_failed` (502) | The target's name cannot be resolved | Check DNS. Once it resolves, the rule starts on its own |
| `locked_out` (429) | This source is locked out after repeated authentication failures | Wait the number of seconds in `Retry-After` and fix the token |
| `upgrading` / `shutting_down` (503) | A handoff or shutdown is in progress | Wait a little and send again |
| `no_config` (409) | `POST /config/reload` was called without a settings file | Set `RPROXY_CONFIG` |
| `restart_only` (409) | You tried to change through the API a `global` item that needs a restart | Change it in the file and restart |
| `in_use` (409) | You tried to remove something a rule uses (a `global` item, a stored certificate and so on) | Change the rule first |

For `tls_config` / `invalid`, where the reason appears depends on the cause:

- For a shape error (a wrong field name or value), the reason is in the answer's `error`.
- When a file cannot be used (wrong owner or mode, missing, unreadable contents), the reason is not put in the answer but logged as `config.file` ([7.4](#74-files-that-rules-point-to)). For the settings file, `--check-config` prints the reason, so use it to check.

### 18.2 A rule is `failed` or does not work

When a rule's `state` is `failed`, or a rule that should work lets nothing through, look in this order:

1. Look at the rule's `error` and `conditions` in `GET /rules`. The reason in `conditions` (`BindFailed`, `ResolveFailed`, `CertificateUnreadable` and so on) tells you whether the listener, name resolution or a certificate is the cause.
2. Look at `rule.failed`, `config.error` and `config.file` in the log.
3. For a rule from the settings file, run `--check-config`. The result of the re-read is in `error` of `GET /config`.
4. If an API rule shows `persisted: false`, the rule is running but could not be written to the database. Look at `degraded` with `part: db` in the log and check the connection to the database.

### 18.3 Connections are refused

When a client's connections are refused, look at `conn.denied`, `conn.limited` and similar in the log, and at their reason (`reason`).

| Log | Reason | What to do |
|---|---|---|
| `conn.denied` (`allow_from`, `geoip`, `crowdsec`, `unmatched`) | Refused by access control | Check the source ranges, countries and bans. `unmatched` means a name that matched no `tls.routes` |
| `conn.denied` (`proxy_protocol*`) | No PROXY protocol header, or the front proxy is outside `from` | Write the front proxy's address in `from` ([6.1](#61-accepting-proxy-protocol-from-a-front-proxy)) |
| `conn.limited` (`max_connections` and others) | Over the rule's `limits` | Raise the limit ([3.5](#35-connection-limits-for-the-whole-rule)) |
| `conn.limited` (`target_full`) | Every target has reached `max_connections` | Add targets or raise the limit |
| `conn.limited` (`fd_budget`) | The process's connection and session budget is full | Raise `LimitNOFILE` ([16.](#16-capacity-limits)) |
| `tls.error` | A TLS handshake failed | Check the certificate, the name, `min_version`, and the versions the client supports |
| `target.down` | A target failed the liveness check | Check that the target is running and that `health_check`'s `port` is right |
