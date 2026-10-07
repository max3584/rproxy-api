日本語: [architecture/README.md](../architecture/README.md)

# Architecture diagrams

Diagrams of the current architecture (v0.4.0, SVG). The diagrams are edited as SVG directly (no PlantUML sources are kept in the repository). Update them when modules or states change. The labels in the diagrams are in Japanese.

| Diagram | Content |
|---|---|
| [overview.svg](../architecture/overview.svg) | Overall (UI, DB (`forward_rules`, `rproxy_rules`), rproxy, the Kubernetes controller (rproxy-gateway), the release source (self-update), configuration files, certificates, the GeoIP database, targets, CrowdSec, OIDC, the ACME CA and DNS) |
| [internals.svg](../architecture/internals.svg) | Module structure of rproxy-api (startup and `global.performance`; control plane (API hardening, the ruleset API, handoff and self-update); configuration (reload, `--check-config`, dry-run diffs, DB restore and persistence); Registry (rulesets, conditions, readiness); admission checks and targets (allow_from, GeoIP, limits, bandwidth, balance, outlier); L4 / L7 data plane; common (certificate store, ACME, helper process, logging)) |
| [connection.svg](../architecture/connection.svg) | Flow of a single TCP connection (allow_from -> GeoIP -> CrowdSec -> limits -> TLS -> L4 / L7 -> target; ejecting targets on connection failures with outlier_detection; relaying with bandwidth limits) |
| [rule_state.svg](../architecture/rule_state.svg) | Rule states (rproxy's running / failed, the UI's paused / missing / unknown; includes failed due to certificate expiry) and how rulesets, restoring `rproxy_rules`, conditions, dry run and handoff relate to them |

![Overall](../architecture/overview.svg)
![Modules](../architecture/internals.svg)
![Connection flow](../architecture/connection.svg)
![Rule states](../architecture/rule_state.svg)
