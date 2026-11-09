# PortKeeper

PortKeeper temporarily allows TCP access to configured VPS ports for the source IP that calls a configured GUID endpoint.

## Project layout

- `cmd/portkeeper` — application entry point
- `internal/portkeeper` — configuration, HTTP handler, ipset/firewall integration, and state persistence
- `configs/config.example.yaml` — example runtime configuration
- `deploy/systemd` — systemd unit

## Requirements

Go 1.23+, `ipset`, `iptables`, and `ip6tables`. The service must run as root (or with equivalent network-administration capabilities).

## Build and test

From the repository root:

```sh
go test ./...
go build -o ./portkeeper ./cmd/portkeeper
```

## Deploy on the VPS

The repository layout is independent of the deployment directory. The systemd unit expects the binary and runtime configuration under `/app/golang/PortKeeper`.

```sh
sudo mkdir -p /app/golang/PortKeeper
sudo cp ./portkeeper /app/golang/PortKeeper/portkeeper
sudo cp configs/config.example.yaml /app/golang/PortKeeper/config.yaml
```

Edit `/app/golang/PortKeeper/config.yaml`, replacing the example GUID values. Install and start the systemd unit:

```sh
sudo cp deploy/systemd/portkeeper.service /etc/systemd/system/portkeeper.service
sudo systemctl daemon-reload
sudo systemctl enable --now portkeeper
```

The default listener is `127.0.0.1:8787`, the default TTL is 24 hours, and the default state file is `/var/lib/portkeeper/state.json`.

## API

Call `GET /<GUID>` to allow the caller's source IP to reach the TCP port mapped to that GUID. Repeating the request refreshes the timeout. IPv4 and IPv6 are supported.

The service persists expiration timestamps and restores unexpired entries after restart. It manages the `PORTKEEPER` chains in iptables and ip6tables, plus one ipset per configured port and address family.

## Nginx reverse proxy

When running behind Nginx, pass the actual client address:

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header X-Real-IP $remote_addr;
}
```
