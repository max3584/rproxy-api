日本語: [TRANSPARENT.md](../TRANSPARENT.md)

# transparent (connecting to the target with the client's IP)

In a rule with `source_ip: transparent`, rproxy connects to the target using the client's address as the source (`IP_TRANSPARENT` / `IPV6_TRANSPARENT`).
The target's logs and access control see the client's address instead of rproxy's. TCP and UDP, IPv4 and IPv6 are supported.

If the target supports PROXY protocol, `source_ip: proxy_v2` is simpler (it passes the client's address in a header without changing routing).
Use transparent when the target does not support PROXY protocol and the source address is needed (see [SOURCE-IP.md](SOURCE-IP.md) for how to choose).

## Requirements

| Where | What | How |
|---|---|---|
| rproxy | `CAP_NET_ADMIN` | Granted by the unit installed by apt or install.sh (docs/PERMISSIONS.md). Check with `transparent` / `transparent_ipv6` in `GET /capabilities` |
| rproxy | Receive return packets from the target as addressed to itself | "rproxy routing" below |
| Target | Send responses addressed to clients back to rproxy | Nothing to do if the default gateway is rproxy. If there is another exit, see "Target return path" below |

- The listen address, the client, and the target must be in the same address family (an IPv6 client cannot be passed to an IPv4 target with transparent). IPv4 clients accepted on a `[::]` listener (`::ffff:a.b.c.d`) are treated as IPv4. When listening on IPv4 and IPv6 at the same time with `extra_listen_addrs`, a target for each family is needed (if no target written as an IP is in the same family as the extra address, the rule is `invalid`; if `targets` lists both IPv4 and IPv6 targets, traffic goes to the target in the client's family).
- CI verifies IPv4 / IPv6 x 3 ways of receiving x 2 ways of return from the target, over real routes inside namespaces (`scripts/test-transparent.sh`).

## Example: GUA at the entrance, ULA internally, going out via a shared public IP

```
Internet ── GUA ──▶ rproxy ── ULA ──▶ target
                                         │ when going out (updates, etc.)
                                         └──▶ exit router (NAT to the shared public IP)
```

- `proxy` (default): the target sees rproxy's ULA.
- `transparent`: the target sees the client's GUA. However, the target's responses are addressed to the client's GUA, so as-is they go out to the exit router. **The target needs a setting that "returns only the responses to connections from rproxy to rproxy"** ("Target return path" below). Other traffic keeps going out through the exit router with the shared public IP as before.

## rproxy routing

The rproxy host itself receives the return packets from the target that are addressed to clients. Install this with install.sh (`rproxy-transparent-routing.service` sets it up at boot).

```shell
# When the client range is known (IPv4 / IPv6 may be mixed)
install.sh --transparent-clients 10.0.1.0/24,2001:db8:1::/64 --transparent-iface eth1

# When the range cannot be determined, such as clients on the Internet (requires nftables)
install.sh --transparent-clients any

rproxy-transparent-routing status
```

- When a range is given, only packets addressed to that range that arrive from the target-side interface (`--transparent-iface`) are treated as addressed to itself (`ip rule iif` + a `local` route).
- `any` marks only packets addressed to rproxy's transparent sockets with nftables (`socket transparent`) and treats them as addressed to itself. Even if rproxy is also the target's gateway, other traffic is not affected.
- For manual setup, see "Passing the source IP" in the [README](../../README.en.md#passing-the-source-ip) (iptables / nftables examples).

## Target return path

If the target's default gateway is rproxy, nothing needs to be done.
If there is another exit (such as a router with the shared public IP), add the following settings on the target (Linux). It puts a conntrack mark on connections from rproxy and sends only the responses to those connections to rproxy.

```shell
# On the target. eth0 is the interface connected to rproxy; fd00:2::1 / 10.0.2.1 are rproxy's addresses
nft -f - <<'EOF'
table inet rproxy_return {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "eth0" ip6 saddr != fd00::/8 ct mark set 0x52
    iifname "eth0" ip saddr != 10.0.0.0/8 ct mark set 0x52
  }
  chain output {
    type route hook output priority mangle; policy accept;
    ct mark 0x52 meta mark set 0x52
  }
}
EOF
ip -6 rule add fwmark 0x52 lookup 200
ip -6 route add default via fd00:2::1 table 200
ip -4 rule add fwmark 0x52 lookup 200
ip -4 route add default via 10.0.2.1 table 200
```

- `saddr != <internal range>` is there so that internal traffic (connections from internal hosts other than rproxy) is not marked. If there is an interface dedicated to rproxy, `iifname` alone is enough.
- To persist across reboots, put the nftables rules in `/etc/nftables.conf`, and `ip rule` / `ip route` in the network configuration (such as systemd-networkd's `[RoutingPolicyRule]`).
- CI (`RETURN=gateway`) verifies that, in a setup where the target's default gateway is a different exit, transparent works with these settings.

## How to verify

1. `curl -H "Authorization: Bearer $(sudo cat /etc/rproxy/tokens)" http://127.0.0.1:8080/capabilities` shows `"transparent": true` / `"transparent_ipv6": true`
2. Create a rule with `source_ip: transparent` and check that the client's address appears in the target's log
3. If it does not connect, check where the target sends its responses (`tcpdump -ni any host <client>`). If they go out to the exit router, see "Target return path"; if they reach rproxy but are not received, see "rproxy routing"
