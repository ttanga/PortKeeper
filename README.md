# PortKeeper

PortKeeper temporarily allows TCP access to configured VPS ports for the source IP that calls a configured GUID endpoint.

This README describes a clean installation on a new Ubuntu VPS, GitHub Actions deployment, and recovery/migration to another server.

## 1. How deployment works

- GitHub Actions runs tests and builds the Linux amd64 binary.
- The workflow uploads **only the binary** to the VPS over SSH.
- A root-owned deployment script installs the binary, restarts the systemd service, checks that it became active, and rolls back the previous binary if startup fails.
- The runtime configuration stays on the VPS and is **not** stored in or deployed from GitHub.
- The systemd service runs as the unprivileged `portkeeper` user with only the required `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities.

The VPS does not need Go installed for the normal GitHub Actions deployment. Go 1.23+ is needed only to build or test the project manually.

## 2. Requirements

- Ubuntu 24.04 (or a compatible recent Ubuntu/Debian release).
- A public hostname or IP address for SSH access.
- GitHub repository access and permission to configure Actions variables/secrets.
- An SSH key pair dedicated to GitHub Actions deployment.
- The ability to configure the VPS provider firewall/security group.

The setup script installs `ipset`, `iptables`, and `sudo`. It creates the `portkeeper` service account and the `deploy` SSH account.

## 3. Prepare the deployment SSH key

Generate a dedicated key pair on your trusted workstation (not on the VPS):

```sh
ssh-keygen -t ed25519 -C "github-actions-portkeeper" -f ./portkeeper_deploy
```

This creates:

- `portkeeper_deploy` — private key. Keep it secret; it will be stored as a GitHub Actions secret.
- `portkeeper_deploy.pub` — public key. This will be installed for the `deploy` account on the VPS.

Do not use your personal SSH key or another service's key for this deployment.

## 4. Bootstrap a new VPS

Connect to the new VPS as root (or use an account with sudo). Install Git and clone the repository:

```sh
apt-get update
apt-get install -y git
git clone https://github.com/ttanga/PortKeeper.git
cd PortKeeper
```

Run the bootstrap script, passing the contents of `portkeeper_deploy.pub` as its single argument:

```sh
sudo bash deploy/scripts/setup-vps.sh 'ssh-ed25519 AAAA... github-actions-portkeeper'
```

Replace the example key with the complete, actual one-line public key. If already logged in as root, the `sudo` prefix is optional.

The script:

- installs `ipset`, `iptables`, and `sudo`;
- creates the `portkeeper` system user and `deploy` SSH user if missing;
- installs the public key in `/home/deploy/.ssh/authorized_keys`;
- creates `/app/golang/PortKeeper` and `/var/lib/portkeeper`;
- installs the systemd unit at `/etc/systemd/system/portkeeper.service`;
- installs `/usr/local/sbin/deploy-portkeeper`;
- grants the `deploy` user passwordless sudo permission for that deployment script only;
- enables the service, but does not start it yet.

The script does not overwrite an existing `config.yaml`.

## 5. Create and configure the runtime config

Create the runtime configuration from the example:

```sh
sudo cp configs/config.example.yaml /app/golang/PortKeeper/config.yaml
sudo chown root:portkeeper /app/golang/PortKeeper/config.yaml
sudo chmod 0640 /app/golang/PortKeeper/config.yaml
sudo nano /app/golang/PortKeeper/config.yaml
```

Example:

```yaml
listen_addr: "0.0.0.0:8787"
default_ttl: "24h"
state_file: "/var/lib/portkeeper/state.json"

rate_limit_requests: 10
rate_limit_window: "1m"

access:
  - guid: "REPLACE-WITH-A-UNIQUE-GUID"
    port: 8080
  - guid: "REPLACE-WITH-ANOTHER-UNIQUE-GUID"
    port: 8090
```

Configure the following:

- `listen_addr` — HTTP address and port for the API. Use `0.0.0.0:8787` to listen on all IPv4 interfaces. If the API should only be reached through a local reverse proxy, use `127.0.0.1:8787` instead.
- `default_ttl` — how long an IP remains allowed after a successful request.
- `state_file` — persistent state file. Keep it under `/var/lib/portkeeper`.
- `rate_limit_requests` and `rate_limit_window` — per-source-IP sliding-window rate limit.
- `access` — each GUID maps to the TCP port that should be temporarily opened. Replace every example GUID with a unique, unguessable value.

Do not commit the real `config.yaml` or its GUIDs to Git. The repository contains only the example configuration.

The setup script installs the service unit and enables it. Start PortKeeper after the runtime config is ready:

```sh
sudo systemctl start portkeeper
sudo systemctl status portkeeper --no-pager
sudo journalctl -u portkeeper -n 50 --no-pager
```

To verify the installed unit has the required capabilities:

```sh
sudo systemctl show portkeeper -p User -p AmbientCapabilities -p CapabilityBoundingSet
```

It should show user `portkeeper` and both `CAP_NET_ADMIN` and `CAP_NET_RAW`.

## 6. Network and firewall configuration

At the VPS provider level, allow inbound SSH (normally TCP 22) and the configured PortKeeper API listener port (TCP 8787 in the example) if the API is intended to be reachable directly from the Internet.

If UFW is enabled, check its current rules before changing them. For a directly exposed API listener on port 8787, the corresponding UFW rule is:

```sh
sudo ufw allow 8787/tcp
```

If using Nginx as a reverse proxy, the application can listen on `127.0.0.1:8787`; expose the Nginx listener instead.

PortKeeper manages its own `PORTKEEPER` iptables/ip6tables chains and ipset sets for the configured target ports. Do not add permanent broad allow rules for those target ports: that could defeat the purpose of temporary access. If UFW or another firewall manager is active, verify the actual packet path and rules on the new VPS before relying on the service.

## 7. Configure GitHub Actions

In the GitHub repository, open **Settings → Secrets and variables → Actions**.

Create these **repository variables**:

| Name | Value |
| --- | --- |
| `VPS_HOST` | Public hostname or IP of the new VPS |
| `VPS_USER` | `deploy` |
| `VPS_KNOWN_HOSTS` | Verified SSH host-key line for this VPS |

Create this **repository secret**:

| Name | Value |
| --- | --- |
| `VPS_SSH_PRIVATE_KEY` | Full contents of the private key file `portkeeper_deploy` (not the `.pub` file) |

### Obtain and verify the VPS host key

From a trusted workstation, obtain the host-key line:

```sh
ssh-keyscan -H YOUR_VPS_HOST
```

Before saving it in `VPS_KNOWN_HOSTS`, verify its fingerprint through the VPS provider console or another trusted channel. You can calculate the fingerprint of a key line saved to a file with:

```sh
ssh-keygen -lf known_hosts_entry
```

Do not disable SSH host-key checking and do not blindly trust an unverified `ssh-keyscan` result.

The public key supplied to `setup-vps.sh` must match the private key stored in `VPS_SSH_PRIVATE_KEY`.

## 8. Deploy and update

The workflow `.github/workflows/deploy.yml` runs on pushes to `main` and can also be started manually with **Actions → PortKeeper CI/CD → Run workflow**.

A normal deployment:

1. runs `go test ./...`;
2. builds a Linux amd64 binary;
3. uploads the binary to `/tmp/portkeeper-upload`;
4. runs `sudo /usr/local/sbin/deploy-portkeeper` over SSH;
5. installs the new binary and restarts the service;
6. rolls back to the previous binary if the new version does not start.

The workflow deliberately does not copy `config.yaml` or the systemd unit on every application deployment.

### Applying a changed systemd unit

If `deploy/systemd/portkeeper.service` changes, apply it on the VPS explicitly:

```sh
sudo install -o root -g root -m 0644 \
  deploy/systemd/portkeeper.service \
  /etc/systemd/system/portkeeper.service
sudo systemctl daemon-reload
sudo systemctl restart portkeeper
sudo systemctl status portkeeper --no-pager
```

Run these commands from a checkout containing the updated repository files. The current unit grants `CAP_NET_ADMIN` and `CAP_NET_RAW`; both are needed by the iptables/ipset integration on the tested Ubuntu host.

## 9. Backup and restore / move to another VPS

Keep secure backups of at least:

- `/app/golang/PortKeeper/config.yaml` — contains the GUIDs and port mappings;
- `/var/lib/portkeeper/state.json` — contains persisted temporary-access expiration state.

The config contains credentials in the form of access GUIDs. Store backups encrypted and restrict access.

Create a backup archive on the current VPS:

```sh
sudo tar -czf /root/portkeeper-backup.tar.gz \
  /app/golang/PortKeeper/config.yaml \
  /var/lib/portkeeper/state.json
sudo chmod 0600 /root/portkeeper-backup.tar.gz
```

Copy the archive securely to the new VPS or a trusted backup location. After running the bootstrap script on the new VPS, restore the files and fix ownership/permissions:

```sh
sudo tar -xzf /root/portkeeper-backup.tar.gz -C /
sudo chown root:portkeeper /app/golang/PortKeeper/config.yaml
sudo chmod 0640 /app/golang/PortKeeper/config.yaml
sudo chown -R portkeeper:portkeeper /var/lib/portkeeper
sudo systemctl start portkeeper
sudo systemctl status portkeeper --no-pager
```

Only restore `state.json` if its unexpired access entries should remain valid on the new server. Otherwise, restore only `config.yaml` and let PortKeeper create a fresh state file. After migration, update `VPS_HOST` and `VPS_KNOWN_HOSTS` in GitHub Actions. If the new VPS uses a different deployment key, also update `VPS_SSH_PRIVATE_KEY` and install the matching public key with the bootstrap script.

## 10. API

Call:

```http
GET /<GUID>
```

The caller's source IP is temporarily allowed to reach the TCP port mapped to that GUID. Repeating the request refreshes the timeout. IPv4 and IPv6 are supported.

The service persists expiration timestamps and restores unexpired entries after restart. It manages the `PORTKEEPER` chains in iptables and ip6tables, plus one ipset per configured port and address family.

## 11. Nginx reverse proxy

When running behind Nginx, pass the actual client address:

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header X-Real-IP $remote_addr;
}
```

The application listener can then be bound to `127.0.0.1:8787`, rather than exposed directly.

## 12. Build and test manually

From the repository root:

```sh
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o portkeeper ./cmd/portkeeper
```
