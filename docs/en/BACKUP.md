日本語: [BACKUP.md](../BACKUP.md)

# Backup and restore

What to back up for rproxy-api and the management UI ([TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)), how to take it, and how to restore it.
Paths are the defaults of the .deb (apt) and of `scripts/install.sh`. Adjust them if you use other locations.

## What to back up

| Item | Location | Contents and notes |
|---|---|---|
| rproxy environment file | `/etc/rproxy/rproxy.env` | The `RPROXY_*` settings. Contains the database password if `RPROXY_DATABASE_URL` is set |
| Token file | `/etc/rproxy/tokens` (`RPROXY_TOKEN_FILE`) | One token per line (plain text), or YAML with names, SHA-256 and scopes (docs/en/API.md). In the plain format the file holds the API keys themselves |
| Configuration file (static rules) | The file or directory of `RPROXY_CONFIG` (e.g. `/etc/rproxy/rproxy.yaml`) | `version`, `global`, `rules`. Static rules are not in the database, so this is their only copy |
| Files the configuration refers to | Paths written in the configuration file and in rules | Certificates, keys and CAs (`cert_file`, `chain_file`, `key_file`, `ca_file`), `basic_auth` `users_file`, secret files of `oidc` and others, CrowdSec `api_key_file` |
| Control API certificate and key | `RPROXY_TLS_CERT` / `RPROXY_TLS_KEY` (e.g. `/etc/rproxy/tls/`) | Only when the control API uses TLS |
| TLS certificates of rules made in the UI | Paths written in the database `options` | The database holds only the paths. Back up the files separately |
| Certificates from certbot and similar | e.g. `/etc/letsencrypt/` | Can be issued again, but when moving hosts take them with their renewal configuration |
| Policy routing for transparent | `/etc/rproxy/transparent-routing.conf`, `/usr/local/sbin/rproxy-transparent-routing`, `/etc/systemd/system/rproxy-transparent-routing.service` | Only when installed with `install.sh --transparent-*` |
| systemd overrides | `/etc/systemd/system/rproxy-api.service.d/` (drop-ins from `systemctl edit`), plus `/etc/systemd/system/rproxy-api.service` when installed with `install.sh` | Needed if you changed the permissions (capabilities) |
| UI database | MariaDB `forward_rules` (rules) and `forward_rules_log` (change history) | The source of truth for rules made in the UI. The table definitions are `db/schema.sql` in the UI repository |
| UI environment file | `/etc/rproxy-ui/rproxy-ui.env` (600) | Contains `NEXTAUTH_SECRET`, `KEYCLOAK_CLIENT_SECRET`, `DB_PASSWORD`, `RPROXY_API_TOKEN` |
| Logs (optional) | `/var/log/rproxy/` (`RPROXY_LOG_FILE`; split daily into `rproxy.<date>.log`, files beyond `RPROXY_LOG_KEEP` are deleted), the `global.access_log` file | Not needed to run. Back them up if you keep them for investigation or auditing |

Not needed:

- `/run/rproxy/` (the Unix socket of `RPROXY_API_SOCKET`). The unit's `RuntimeDirectory=rproxy` recreates it at every start
- The binaries and package contents (`/usr/bin/rproxy-api`, `/usr/lib/rproxy-ui`, ...). Install them again, with the same or a newer version
- Rules made by calling the API directly (`origin: dynamic` but not in the database). They live only in rproxy's memory and disappear on restart; they are temporary ("Relationship between the API, config file and UI (DB)" in docs/en/API.md). To keep them, save them with "A copy of `GET /rules`" below

## Taking backups

### Database

`--single-transaction` takes a consistent snapshot without locking the tables (both tables are InnoDB).

```bash
mariadb-dump --single-transaction --default-character-set=utf8mb4 \
  -h 127.0.0.1 -u rproxy_backup -p rproxy forward_rules forward_rules_log \
  | gzip > rproxy-db-$(date +%Y%m%d-%H%M%S).sql.gz
```

- Use the database name of the UI's `DB_DATABASE` (default `rproxy`)
- The output contains `DROP TABLE IF EXISTS` and `CREATE TABLE`, so you do not need to create the tables before restoring
- The backup user only needs to read. Keep it separate from the UI user (`rproxy_ui`) and the rproxy DB user (`rproxy`, `SELECT` on `forward_rules` only)

```sql
CREATE USER 'rproxy_backup'@'localhost' IDENTIFIED BY '<password>';
GRANT SELECT, LOCK TABLES ON rproxy.* TO 'rproxy_backup'@'localhost';
```

Do not put the password on the command line; keep it in a file only root can read.

```ini
# /etc/rproxy-backup/my.cnf (root:root 600)
[client]
host=127.0.0.1
user=rproxy_backup
password=<password>
```

### Configuration, keys and tokens

```bash
sudo tar -C / -czpf rproxy-etc-$(date +%Y%m%d-%H%M%S).tar.gz \
  etc/rproxy etc/rproxy-ui etc/systemd/system/rproxy-api.service.d
```

Leave out `etc/rproxy-ui` or the drop-in directory on hosts that do not have them (`tar` fails on a missing path).
Add certificates and secret files kept outside `/etc/rproxy` (`/etc/letsencrypt` and so on) to the same `tar`.

### A copy of `GET /rules` (optional)

The list of rules rproxy is running now. It is useful for comparing after a restore, and for running rproxy without the database (below).

```bash
TOKEN=$(grep -v -e '^#' -e '^[[:space:]]*$' /etc/rproxy/tokens | head -n1 | tr -d '[:space:]')
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules > rproxy-rules-$(date +%Y%m%d-%H%M%S).json
# over the Unix socket (RPROXY_API_SOCKET)
curl -fsS --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/rules > rules.json
```

- Taking the first line of the token file works only for the plain format. The YAML format (`tokens:`) stores only SHA-256, so use a token with the `rules:read` scope (such as the UI's `RPROXY_API_TOKEN`)
- The port is `RPROXY_API_PORT` (moved to 8081-8099 if 8080 was in use at install time)

The UI's "Export (JSON)" ("Export and import" in the UI README) also works as a copy of the rules. It includes paused rules and can be restored as is with the UI's "Import".

### Daily backups with a systemd timer

An example. Adjust the paths, the database name and the retention.

```sh
#!/bin/sh
# /usr/local/sbin/rproxy-backup (root:root 700)
set -eu
umask 077
dest=/var/backups/rproxy
stamp=$(date +%Y%m%d-%H%M%S)
install -d -m 0700 "$dest"

# database (UI rules and change history)
mariadb-dump --defaults-extra-file=/etc/rproxy-backup/my.cnf \
  --single-transaction --default-character-set=utf8mb4 \
  rproxy forward_rules forward_rules_log | gzip > "$dest/db-$stamp.sql.gz"

# configuration, tokens and keys (only what exists)
set --
for p in etc/rproxy etc/rproxy-ui etc/systemd/system/rproxy-api.service.d etc/letsencrypt; do
  [ -e "/$p" ] && set -- "$@" "$p"
done
tar -C / -czpf "$dest/etc-$stamp.tar.gz" "$@"

# delete files older than 30 days
find "$dest" -type f -mtime +30 -delete
```

```ini
# /etc/systemd/system/rproxy-backup.service
[Unit]
Description=Back up rproxy-api and rproxy-ui
After=mariadb.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rproxy-backup
```

```ini
# /etc/systemd/system/rproxy-backup.timer
[Unit]
Description=Daily backup of rproxy-api and rproxy-ui

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rproxy-backup.timer
sudo systemctl start rproxy-backup.service   # run it once to check
journalctl -u rproxy-backup.service
```

Backups kept only on the same host are lost with the host. Encrypt them ("Security" below) and send them elsewhere.

## Restore order

The order for restoring onto a freshly installed host (or the same host).

1. **Install the packages**: rproxy-api and rproxy-ui ("Installation" in the README), the same or a newer version. Installing creates the `rproxy` / `rproxy-ui` users (`tar` restores owners by name, so the users must exist first). Do not start them yet
2. **Restore the configuration, tokens and keys**:

   ```bash
   sudo systemctl stop rproxy-api rproxy-ui 2>/dev/null || true
   sudo tar -C / -xzpf rproxy-etc-<timestamp>.tar.gz
   sudo chgrp rproxy /etc/rproxy /etc/rproxy/tokens && sudo chmod 0750 /etc/rproxy && sudo chmod 0640 /etc/rproxy/tokens
   sudo systemctl daemon-reload
   ```

   The token and environment file created at install time are overwritten by the restored ones (so the UI's `RPROXY_API_TOKEN` matches rproxy's token again).
   Certificates, keys and secret files must be readable by the `rproxy` user (for example through the `rproxy` group)
3. **Restore the database**:

   ```bash
   sudo mariadb -e "CREATE DATABASE IF NOT EXISTS rproxy CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
   gunzip -c rproxy-db-<timestamp>.sql.gz | sudo mariadb rproxy
   ```

   The database users (the UI's `rproxy_ui`, rproxy's `rproxy`) and their grants are not in the dump; create them again ("DB users" in `db/README.en.md` of the UI repository).
   When restoring an older dump under a newer UI, apply the missing migrations in order (`/usr/share/rproxy-ui/db/migrations/`, `db/README.en.md`)
4. **Check the rproxy configuration**: `sudo -u rproxy-api rproxy-api --check-config` ("Checks after restoring" below)
5. **Start rproxy-api**: `sudo systemctl enable --now rproxy-api`. At startup it restores the rules from the database's `forward_rules`
6. **Start rproxy-ui**: `sudo systemctl enable --now rproxy-ui`
7. **Check** (below)

rproxy-api does not stop if it starts before the database is back (it starts without the database rules and logs `restore.error`). In that case restore the database, then `sudo systemctl restart rproxy-api` to read it again.

## Checks after restoring

### Configuration file

```bash
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/rproxy.yaml
```

Runs the same checks as startup and reloads (syntax, rule values, overlapping listeners, certificate, key and CA files and their expiry, secret files) and exits with 0 when everything is fine.
Running it as the `rproxy` user also shows files that user cannot read (run as root, it warns about files that may be unreadable judging by owner and mode).
Without an argument it checks the file of `RPROXY_CONFIG` (`/etc/rproxy/rproxy.env` is read by systemd, so when running by hand, passing the path to `--check-config` is the reliable way).

### Logs

```bash
journalctl -u rproxy-api -b | grep -E '"event":"(restore\.[a-z_]+|degraded)"'
# with RPROXY_LOG_FILE
grep -hE '"event":"(restore\.[a-z_]+|degraded)"' /var/log/rproxy/rproxy.*.log
```

- `restore.start` is there (`rules` is the number read from the database)
- There is no `restore.error` (cannot connect to the database), `restore.skip` (a row that could not be read), `restore.legacy_schema` (an old table missing columns), or `degraded` (a part that cannot be used; `part` says which)
- `restore.paused` is the number of rules paused in the UI (not starting them is correct)

### Compare `GET /rules` with the database

Check that the UI rules rproxy is running (`origin: dynamic`) and the database's `forward_rules` (minus paused rules) have the same set of keys.

```bash
TOKEN=...   # as in "A copy of GET /rules" above
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq -r '.[] | select(.origin == "dynamic") | "\(.protocol)\t\(.listen_addr)\t\(.listen_port)"' | sort > api.tsv
sudo mariadb -N -B rproxy -e "SELECT protocol, src_addr, src_port FROM forward_rules
  WHERE COALESCE(JSON_VALUE(options, '$.enabled'), 'true') <> 'false'" | sort > db.tsv
diff db.tsv api.tsv && echo "match"

# rules that are not running (with the reason)
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq -r '.[] | select(.state == "failed") | "\(.protocol) \(.listen_addr):\(.listen_port) \(.error)"'
```

- Lines only in `db.tsv`: rules in the database that rproxy does not have. If they are not even listed as `failed`, look at the `restore.skip` log. The UI shows them as "missing"
- Lines only in `api.tsv`: rules made by calling the API directly (not in the database)
- A `failed` reason of `bind_failed` means the listen address is not on this host or the port is in use (see below when moving hosts)
- In the UI too, check that the list's states and the "Change history" are back

## Moving to a new host

1. Take a fresh backup on the old host (stop changes in the UI first so nothing is missed)
2. Restore on the new host following "Restore order" above
3. Fix what changes with the host:
   - **Listen addresses**: rules whose `listen_addr` is an IP of the old host become `bind_failed`. Look up usable addresses with `GET /interfaces` and fix them in the UI (database rules) and in the configuration file (static rules). Rules on `0.0.0.0` / `::` keep working
   - **Database location**: `RPROXY_DATABASE_URL` (`/etc/rproxy/rproxy.env`) and the UI's `DB_HOST`. The host part of the database users (`'rproxy'@'127.0.0.1'` and so on)
   - **Control API**: fix `RPROXY_API_ADDR` if it names an old IP, and the UI's `RPROXY_API_URL`
   - **UI URL**: if it changes, `NEXTAUTH_URL` and Keycloak's Valid redirect URIs (`${NEXTAUTH_URL}/api/auth/callback/keycloak`)
   - **transparent**: policy routing is per host. Reinstall it with `install.sh --transparent-*`, or check the interface names in the restored `transparent-routing.conf` (docs/en/TRANSPARENT.md). The return path from the targets must also go through the new host
   - **Certificates**: move them with the certbot (or similar) renewal configuration, or issue them again on the new host. http-01 cannot succeed until DNS points at the new host
   - **Firewall and DNS**: open the listen ports and point the names at the new host
4. If the new host takes over the same listen IPs (moving the IP), stop rproxy-api on the old host before starting it on the new one (only one of them can listen on the same address)
5. Run "Checks after restoring"

## Running rproxy without the database

- **A running rproxy keeps running.** rproxy reads the database only at startup, so a broken database does not stop the current rules. Not restarting rproxy-api until the database is fixed is the safest option (changes from the UI are not possible meanwhile)
- Started while the database is unreachable, rproxy starts without the database rules (`restore.error`; static rules and the control API work)

If you must restart, write the current rules (or a saved copy of `GET /rules`) to a configuration file and run them as static rules.

```bash
TOKEN=...
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules > rules.json
jq '{version: 1, rules: [.[] | select(.origin == "dynamic")
      | del(.origin, .state, .error, .resolved, .connections, .stats, .started_at, .cert_status)
      | if has("targets") or has("http") then del(.remote_addr, .remote_port) else . end]}' \
  rules.json > from-db.json
sudo install -o root -g rproxy -m 0640 from-db.json /etc/rproxy/from-db.json
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/from-db.json
```

- The `jq` drops the runtime fields (`state`, `stats`, ...), and for rules with several targets and L7 (`http`) rules drops the listing's `remote_addr` / `remote_port` (they are not accepted together with `targets`)
- Set `RPROXY_CONFIG=/etc/rproxy/from-db.json` in `/etc/rproxy/rproxy.env`, comment out `RPROXY_DATABASE_URL`, and `sudo systemctl restart rproxy-api`
- If you already use static rules through `RPROXY_CONFIG`, make it a directory (e.g. `/etc/rproxy/conf.d/`, whose files are read in name order) and put `from-db.json` there. Rules with overlapping keys are errors
- You can also build it from the `rules` of the UI's Export (JSON) (drop paused rules and `enabled`; "Export and import" in the UI README)
- Meanwhile these rules are static (`origin: static`), so the API and the UI cannot change them (`409 static`). Edit the file to change them (applied automatically)

When the database is fixed, restore `RPROXY_CONFIG` (remove `from-db.json`), restore `RPROXY_DATABASE_URL`, and `sudo systemctl restart rproxy-api`.
If a rule with the same key is in both the configuration file and the database, the database one cannot start, so always remove `from-db.json` first. Then check with "Compare `GET /rules` with the database".

## Security

- Backups contain the API tokens (in the plain format, the API keys themselves), TLS private keys, database and Keycloak passwords, and `NEXTAUTH_SECRET`. Treat them like production
- Make the storage location readable only by root (the script above uses `umask 077` and a 0700 directory)
- Encrypt before sending off the host. For example (with an [age](https://github.com/FiloSottile/age) public key; keep the private key away from the backups):

  ```bash
  age -R /etc/rproxy-backup/recipients.txt -o etc-<timestamp>.tar.gz.age etc-<timestamp>.tar.gz
  # with gpg
  gpg --encrypt --recipient backup@example.com etc-<timestamp>.tar.gz
  ```

- Permissions after restoring: `/etc/rproxy` `root:rproxy` 0750, `/etc/rproxy/tokens` `root:rproxy` 0640, `/etc/rproxy/rproxy.env` 0640, `/etc/rproxy-ui/rproxy-ui.env` `root:root` 0600 (the same as at package installation). Private keys with the least permission that lets `rproxy` read them (e.g. `root:rproxy` 0640)
- With the YAML token format (only SHA-256 is written), a leaked backup of the token file does not give API keys (docs/en/API.md). The UI's `RPROXY_API_TOKEN` is plain text, so protect the UI environment file separately
- If a backup may have leaked, replace the tokens (edit the file and `systemctl reload rproxy-api`), the database passwords, the Keycloak client secret and the TLS keys
- Rehearse the restore on another host (backups you think you have are sometimes not there)
