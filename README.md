# proxygen

Userspace WireGuard proxy built with wireguard-go and gVisor Netstack. It keeps three or four independent egress WireGuard devices, races every healthy edge for each new TCP flow, and relays payload only through the first completed TCP handshake. UDP uses literal full-5-tuple mappings: every tuple receives one edge and an explicitly unique egress source port until the mapping expires.

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
    "max_udp_flows": 16384,
    "relay_buffer_bytes": 32768
  }
}
```

Replace every key placeholder. `endpoint`, `health_check_address`, and `metrics_listen` must contain numeric IP addresses. Each health target must be covered by the edge's `allowed_ips` and must complete TCP handshakes through that tunnel.

A configuration is single-stack: ingress, every egress overlay, every health target, and every `allowed_ips` entry must use the same address family. IPv4 requires `0.0.0.0/0`; an IPv6 deployment uses `::/0`.

`geo_database` is optional. When present, it must be a MaxMind City-compatible MMDB. TCP selection always uses live full-edge connection racing; Geo data is a fallback for UDP and cold destinations. A recent TCP winner for the exact destination takes priority for UDP selection.

Validate without opening sockets:

```sh
./proxygen -config /etc/proxygen.json -check
```

Run in the foreground:

```sh
./proxygen -config /etc/proxygen.json
```

`SIGINT` and `SIGTERM` trigger ordered shutdown: ingress admission, TCP and UDP flows, egress devices, Geo DB, then the metrics listener.

## Health and metrics

When `metrics_listen` is configured:

- `GET /healthz` returns HTTP 200 only when at least three edges are healthy; otherwise 503.
- `GET /metrics` returns JSON edge states, probe RTT/failure counts, TCP race counters, and UDP mapping counters.

Edge health is based on TCP probes sent through each independent egress Netstack. Configuring or bringing up a WireGuard device alone does not mark it healthy.

## Data-plane invariants

- Each egress owns a separate WireGuard device, UDP bind, gVisor stack, key, overlay address, and UDP port allocator.
- TCP sends a connect attempt through every currently healthy edge. The first successful handshake wins; successful losers are closed before relay, and losers never receive application payload.
- TCP activity refreshes one shared bidirectional idle deadline.
- UDP mappings are keyed by IP version, protocol, source address/port, and destination address/port. Payload is never duplicated across edges.
- Existing TCP and UDP flows never migrate between edges. An edge failure requires the client application to reconnect or create a new mapping.
