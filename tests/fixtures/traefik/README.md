# Traefik configurations for the converter's tests

Each directory is one Traefik setup that `rproxy-traefik-convert` (crates/rproxy-traefik)
converts:

- the input files (static configuration, dynamic configuration, `docker inspect` output, …);
- `README.md`: where the setup comes from and what was changed or redacted (one `source:` line
  is enough);
- `cases`: one case per line, `<name> <arguments…>` (paths relative to the directory);
- the expected output of each case, byte for byte: `expected.yaml` (or `.json` with `--json`)
  and the notes on stderr `expected.notes` for the case `default`, `expected.<name>.yaml` /
  `.notes` for the others.

`crates/rproxy-traefik/tests/fixtures.rs` compares the output with the expected files, and
`tests/traefik_convert.rs` checks that rproxy accepts every case (and looks at some of them in
detail). The expected files of the directories here were first written by the Python
converter that the Rust one replaced (contrib/traefik2rproxy.py, v0.4.7; only the header line
naming the converter differs), so they also show that the two behave the same.

## Adding a setup (also from a real project)

1. Make a directory and copy the Traefik files into it.
2. Redact: no secrets (API keys, bouncer keys, EAB keys, password hashes, DNS credentials:
   replace them with `not-a-real-…`), no real names or addresses. Use documentation names and
   addresses only: `example.com` / `example.net` / `example.org`, `192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`.
3. Write `README.md` (`source:` where it came from, what was changed) and `cases`.
4. Write the expected files with the converter and read them:
   `RPROXY_TRAEFIK_BLESS=1 cargo test -p rproxy-traefik --test fixtures`, then
   `cargo test --test traefik_convert` (rproxy has to accept the result).
5. A difference later is either a bug or a change of the conversion: change the expected files
   only on purpose (and say so in the PR).
