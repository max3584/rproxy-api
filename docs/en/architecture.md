日本語: [architecture/README.md](../architecture/README.md)

# Architecture diagrams

Diagrams of the current architecture (SVG).

| Diagram | Content |
|---|---|
| [overview.svg](../architecture/overview.svg) | Overall (UI, DB, rproxy, configuration files, certificates, targets, CrowdSec, OIDC, the ACME CA and DNS) |
| [internals.svg](../architecture/internals.svg) | Module structure of rproxy-api (control plane, Registry, L4 / L7 data plane, common (certificate store, ACME)) |
| [connection.svg](../architecture/connection.svg) | Flow of a single TCP connection (allow_from, CrowdSec -> TLS -> L4 / L7 -> target) |
| [rule_state.svg](../architecture/rule_state.svg) | Rule states (rproxy's running / failed, the UI's paused / missing / unknown; includes failed due to certificate expiry) |

![Overall](../architecture/overview.svg)
![Modules](../architecture/internals.svg)
![Connection flow](../architecture/connection.svg)
![Rule states](../architecture/rule_state.svg)
