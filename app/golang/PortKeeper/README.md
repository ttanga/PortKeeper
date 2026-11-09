# PortKeeper

PortKeeper temporarily allows TCP access to configured VPS ports for the source IP that calls a configured GUID endpoint.

## Configuration

Edit config.yaml:

    listen_addr: "127.0.0.1:8787"
    default_ttl: "24h"
    state_file: "/var/lib/portkeeper/state.json"
    access:
      - guid: "your-secret-guid"
        port: 8080

Each port may be mapped to one or more GUIDs. The service supports IPv4 and IPv6 source addresses.

## Run

Requires Go 1.23+, ipset, iptables, and ip6tables. Run as root (or with equivalent network-administration capabilities):

    go build -o portkeeper .
    ./portkeeper -config config.yaml

Call GET /<GUID> to allow the caller's source IP to reach the mapped TCP port for 24 hours. Repeating the request refreshes the 24-hour timeout. The service persists expiration timestamps in the configured state file and restores unexpired entries after restart.

The service manages the PORTKEEPER chains in iptables and ip6tables, plus one ipset per configured port and address family.

## Nginx reverse proxy

The default listener is bound to localhost. When running behind Nginx, pass the source address:

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header X-Real-IP $remote_addr;
    }
