# PortKeeper

PortKeeper temporarily allows TCP access to configured VPS ports for the source IP that calls a configured GUID endpoint.

## Project layout

- `cmd/portkeeper` — application entry point
- `internal/portkeeper` — configuration, HTTP handler, ipset/firewall integration, rate limiting, and state persistence
- `configs/config.example.yaml` — example runtime configuration
- `deploy/systemd` — systemd unit

## Requirements

Go 1.23+, `ipset`, `iptables`, and `ip6tables`. The service must run as root (or with equivalent network-administration capabilities).

## Configuration

The example configuration includes a per-IP sliding-window rate limit:

```yaml
rate_limit_requests: 10
rate_limit_window: "1m"
```

This allows at most 10 HTTP requests from each client IP in any rolling one-minute window. The 11th request receives HTTP `429 Too Many Requests` and a `Retry-After` header. Requests are counted per source IP, including requests with an unknown GUID and unsupported HTTP methods. The limiter is in-memory and resets when the service restarts.

Both values are configurable. `rate_limit_requests` must be at least 1; `rate_limit_window` must be a positive Go duration such as `30s`, `1m`, or `5m`. If omitted, they default to 10 requests and 1 minute.

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

## GitHub Actions deployment

The `.github/workflows/deploy.yml` workflow tests the project, builds a Linux amd64 binary, and deploys it to the VPS over SSH when changes are pushed to `main`. It can also be started manually with `workflow_dispatch`.

Configure these values in **Settings → Secrets and variables → Actions**:

Repository variables:
- `VPS_HOST` — VPS hostname or IP address
- `VPS_USER` — SSH deployment account (for example, `deploy`)
- `VPS_KNOWN_HOSTS` — verified SSH host-key line for the VPS

Repository secret:
- `VPS_SSH_PRIVATE_KEY` — private key matching the public key installed in `/home/deploy/.ssh/authorized_keys`

The host key is public information, so it belongs in a variable rather than a secret. It is nevertheless security-sensitive: verify its fingerprint against the VPS console before saving it. Do not disable SSH host-key checking.

The VPS must be bootstrapped once with `deploy/scripts/setup-vps.sh`, and `/app/golang/PortKeeper/config.yaml` must be configured before the first deployment. Subsequent application deployments do not require pulling the repository on the VPS: GitHub Actions builds the binary and uploads it over SSH.
