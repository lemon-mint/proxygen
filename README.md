# proxygen

Userspace WireGuard proxy built with wireguard-go and gVisor Netstack. It keeps up to four independent egress WireGuard devices, races every healthy edge for each new TCP flow, and relays payload only through the first completed TCP handshake. Internally, UDP is keyed by the literal full 5-tuple and every active tuple receives an explicitly unique overlay source port until the mapping expires. The public Internet mapping still depends on the remote edge's routing or SNAT policy.

No host TUN device or `CAP_NET_ADMIN` is required. The outer WireGuard UDP sockets use the host network normally.

## Build

Requires Go 1.26.3 or newer.

```sh
go build -o proxygen ./cmd/proxygen
```

The project pins the synthetic gVisor `go` branch revision that reflects master. Raw `gvisor@master` is Bazel-oriented and is not a valid replacement for standard Go builds.

## Configuration

Configuration is strict JSON. Unknown fields, noncanonical or zero WireGuard keys, hostnames, zoned addresses, mixed address families, and non-full-tunnel egress routes are rejected.

```json
{
  "mtu": 1420,
  "geo_database": "/var/lib/GeoIP/GeoLite2-City.mmdb",
  "metrics_listen": "127.0.0.1:9090",
  "ingress": {
    "private_key": "REPLACE_WITH_BASE64_32_BYTE_PRIVATE_KEY",
    "listen_port": 51820,
    "overlay_address": "10.77.0.1/24",
    "peers": [
      {
        "public_key": "REPLACE_WITH_BASE64_32_BYTE_CLIENT_PUBLIC_KEY",
        "overlay_address": "10.77.0.2"
      }
    ]
  },
  "edges": [
    {
      "id": "edge-us-east",
      "private_key": "REPLACE_WITH_BASE64_32_BYTE_PRIVATE_KEY",
      "overlay_address": "10.88.1.2/24",
      "peer_public_key": "REPLACE_WITH_BASE64_32_BYTE_EDGE_PUBLIC_KEY",
      "endpoint": "192.0.2.10:51820",
      "health_check_address": "198.51.100.10:443",
      "allowed_ips": ["0.0.0.0/0"],
      "persistent_keepalive": "25s",
      "geo": {"country_code": "US", "region": "Virginia", "city": "Ashburn", "latitude": 39.0438, "longitude": -77.4874}
    },
    {
      "id": "edge-eu-west",
      "private_key": "REPLACE_WITH_BASE64_32_BYTE_PRIVATE_KEY",
      "overlay_address": "10.88.2.2/24",
      "peer_public_key": "REPLACE_WITH_BASE64_32_BYTE_EDGE_PUBLIC_KEY",
      "endpoint": "192.0.2.20:51820",
      "health_check_address": "198.51.100.20:443",
      "allowed_ips": ["0.0.0.0/0"],
      "persistent_keepalive": "25s",
      "geo": {"country_code": "DE", "region": "Hesse", "city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821}
    },
    {
      "id": "edge-ap-northeast",
      "private_key": "REPLACE_WITH_BASE64_32_BYTE_PRIVATE_KEY",
      "overlay_address": "10.88.3.2/24",
      "peer_public_key": "REPLACE_WITH_BASE64_32_BYTE_EDGE_PUBLIC_KEY",
      "endpoint": "192.0.2.30:51820",
      "health_check_address": "198.51.100.30:443",
      "allowed_ips": ["0.0.0.0/0"],
      "persistent_keepalive": "25s",
      "geo": {"country_code": "JP", "region": "Tokyo", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503}
    }
  ],
  "timeouts": {
    "tcp_connect": "10s",
    "tcp_idle": "5m",
    "udp_idle": "2m",
    "health_check_interval": "10s",
    "shutdown": "10s"
  },
  "limits": {
    "tcp_race_workers": 256,
    "tcp_race_queue_depth": 1024,
    "max_udp_flows": 512,
    "relay_buffer_bytes": 32768
  }
}
```

Replace every key placeholder. `endpoint`, `health_check_address`, and `metrics_listen` must contain numeric IP addresses. Each health target must be covered by the edge's `allowed_ips` and must complete TCP handshakes through that tunnel.

A configuration is single-stack: ingress, every egress overlay, every health target, and every `allowed_ips` entry must use the same address family. IPv4 requires `0.0.0.0/0`; an IPv6 deployment uses `::/0`.

When `geo_database` is set, proxygen opens that local MaxMind City-compatible MMDB without modifying it. When omitted, proxygen conditionally downloads `https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb` into `${TMPDIR}/proxygen/GeoLite2-City.mmdb`. It sends cached `ETag`/`Last-Modified` validators every 24 hours, compares SHA-256 content, validates a new MMDB before atomic replacement, and reloads only when the file changed. A failed refresh keeps a valid cached database. TCP selection always uses live full-edge connection racing; Geo data is a fallback for UDP and cold destinations.

The UDP NAT table uses one shared idle reaper rather than one timer goroutine per mapping. Each active mapping still holds two maximum-size datagram buffers and two blocking packet pumps, so `max_udp_flows` defaults to 512 and is capped at 2048. The buffer-only ceiling is about 64 MiB by default and 256 MiB at the maximum; larger scale requires a readiness-driven multiplexer.

### Client destination ACL

When `destination_acl` is omitted, proxygen installs an Internet-exit policy that denies loopback, private/ULA, link-local, CGNAT, multicast, benchmark, documentation, and reserved address ranges. TCP is rejected before the ingress endpoint is created; UDP is rejected before a mapping or egress source port is allocated.

Custom policies use ordered first-match rules:

```json
{
  "destination_acl": {
    "default_action": "deny",
    "rules": [
      {
        "action": "allow",
        "protocol": "tcp",
        "prefix": "0.0.0.0/0",
        "ports": [{"from": 80, "to": 80}, {"from": 443, "to": 443}]
      },
      {
        "action": "allow",
        "protocol": "udp",
        "prefix": "0.0.0.0/0",
        "ports": [{"from": 53, "to": 53}, {"from": 443, "to": 443}]
      }
    ]
  }
}
```

`protocol` is `any`, `tcp`, or `udp`. An empty `ports` list matches every non-zero destination port. Rule order is authoritative; place narrow exceptions before broad rules.

### WireGuard directory import

Egress edges may be provided as inline JSON, `.conf` files, or a mixture. The merged total must be between one and four.

```json
{
  "wireguard_directory": "/etc/wireguard/proxygen.d",
  "wireguard_health_check_address": "1.1.1.1:443",
  "edges": []
}
```

At startup, proxygen reads regular `*.conf` files in lexical filename order. The filename without `.conf` becomes the edge ID. Directory changes take effect after a process restart.

```ini
[Interface]
PrivateKey = BASE64_PRIVATE_KEY
Address = 10.88.1.2/24
ListenPort = 42001

[Peer]
PublicKey = BASE64_EDGE_PUBLIC_KEY
PresharedKey = OPTIONAL_BASE64_PRESHARED_KEY
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Exactly one `Interface` address and one `Peer` are supported per file. `Endpoint` must be numeric. `DNS`, `MTU`, `Table`, `FwMark`, `SaveConfig`, and wg-quick shell-hook keys are not applied; shell hooks are never executed. The JSON-level MTU and userspace routing remain authoritative.

Egress `ListenPort` should normally be omitted so the host selects an ephemeral port. If specified, every non-zero egress listen port must be unique and must not equal the ingress listen port; duplicate wildcard UDP4/UDP6 binds are rejected during configuration validation.

All imported edges use `wireguard_health_check_address`. With `geo_database`, an imported edge location is derived from its endpoint IP; otherwise selection falls back to measured probe RTT and TCP winner history.

Validate without opening sockets:

```sh
./proxygen -config /etc/proxygen.json -check
```

Run in the foreground:

```sh
./proxygen -config /etc/proxygen.json
```

`SIGINT` and `SIGTERM` trigger ordered shutdown: ingress admission, TCP and UDP flows, egress devices, Geo DB, then the metrics listener.

## Edge NAT requirement

proxygen guarantees full-5-tuple separation and unique UDP source ports only on the WireGuard overlay side. It cannot force an independently administered edge NAT to preserve those mappings.

To expose literal address-and-port-dependent mappings on the public Internet, every edge must use one of:

- A public address routed directly to that WireGuard overlay address, without another NAPT layer.
- A dedicated public IP with deterministic 1:1 SNAT that preserves proxygen's unique overlay UDP source port independently of the remote destination.

Ordinary `MASQUERADE` is insufficient as a guarantee. It may preserve ports in common cases, but it remains free to remap or reuse an external port according to its conntrack tuple and collision state. A deployment using generic `MASQUERADE` must not claim literal symmetric NAT based on proxygen's internal mapping alone.

Validate every edge after deployment and after firewall/NAT changes:

1. Isolate the edge under test so both probes use that same egress.
2. Bind one client UDP socket to a fixed source address and port.
3. Send STUN Binding requests from that socket to two different STUN destination IP:port pairs.
4. Record `XOR-MAPPED-ADDRESS` for each destination. The two public mapped endpoints must differ.
5. Repeat each request during the UDP idle window. Requests to the same destination must retain their prior mapped endpoint.
6. Repeat the procedure for every configured edge.

Failure at step 4 means the edge SNAT does not provide literal address-and-port-dependent mapping, regardless of the unique overlay ports reported by proxygen.

## Health and metrics

When `metrics_listen` is configured, it must use `127.0.0.0/8` or `::1`. Host-local processes can access it; WireGuard clients cannot reach it through the userspace data plane because the listener is outside gVisor and the built-in destination ACL rejects loopback.

- `GET /healthz` returns HTTP 200 when at least one edge is healthy; otherwise 503.
- `GET /metrics` returns JSON edge states, probe RTT/failure counts, TCP race/ACL counters, and UDP mapping/ACL counters.

For remote collection, keep the listener on loopback and use an authenticated host-side reverse proxy or SSH tunnel.

Edge health is based on TCP probes sent through each independent egress Netstack. Configuring or bringing up a WireGuard device alone does not mark it healthy.

## Protocol support

The current data plane terminates and relays TCP and UDP only. Ingress ICMPv4/ICMPv6, echo requests, ICMP errors, and arbitrary non-TCP/UDP IP protocols are not forwarded through an edge. Supporting them requires a separate ICMP/raw-packet relay with checksum rewriting, response correlation, ACL semantics, and edge-side source translation; the TCP/UDP L4 relay cannot transparently provide that path.


## Data-plane invariants

- Each egress owns a separate WireGuard device, UDP bind, gVisor stack, key, overlay address, and UDP port allocator.
- TCP sends a connect attempt through every currently healthy edge. The first successful handshake wins; successful losers are closed before relay, and losers never receive application payload.
- TCP activity refreshes one shared bidirectional idle deadline.
- UDP mappings are keyed by IP version, protocol, source address/port, and destination address/port. Payload is never duplicated across edges.
- Existing TCP and UDP flows never migrate between edges. An edge failure requires the client application to reconnect or create a new mapping.
