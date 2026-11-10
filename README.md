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

The script does not overwrite an existing `config.yaml`. If one already exists, it sets ownership to `root:portkeeper` and mode `0660` so the service can update it from the admin UI.

## 5. Create and configure the runtime config

Create the runtime configuration from the example:

```sh
sudo cp configs/config.example.yaml /app/golang/PortKeeper/config.yaml
sudo chown root:portkeeper /app/golang/PortKeeper/config.yaml
sudo chmod 0660 /app/golang/PortKeeper/config.yaml
sudo nano /app/golang/PortKeeper/config.yaml
```

Example:

```yaml
listen_addr: "0.0.0.0:8787"
public_base_url: "https://portkeeper.example.com:8787"
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
- `public_base_url` — externally reachable API base URL used by the admin UI to generate `GET /<GUID>` links. Include the public scheme, hostname and external port if non-standard, e.g. `https://portkeeper.example.com:8787`. Do not include a path, query, fragment or trailing slash. If omitted, the copy-link buttons remain unavailable.
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

The workflow `.github/workflows/deploy.yml` runs tests and builds on pushes to `main` and `feature/**`; production deployment runs only for `main`. It can also be started manually with **Actions → PortKeeper CI/CD → Run workflow**.

A normal deployment:

1. runs `go test ./...`;
2. builds a Linux amd64 binary;
3. uploads the binary to `/tmp/portkeeper-upload`;
4. runs `sudo /usr/local/sbin/deploy-portkeeper` over SSH;
5. installs the new binary and restarts the service;
6. rolls back to the previous binary if the new version does not start.

The workflow deliberately does not copy `config.yaml` or the systemd unit on every application deployment.

### Update the application and set/reset the admin password

Push changes to `main` (or run the workflow manually) to deploy the new binary. After the deployment succeeds, create or reset the local administrator account on the VPS:

```sh
sudo /app/golang/PortKeeper/portkeeper -admin-create -admin-user admin
```

Enter the password when prompted and press Enter. **The password is hidden while typing**; the terminal restores its normal input mode afterward. The password is not placed in shell history or process arguments. Any non-empty password is accepted; there are no complexity or minimum-length requirements.

Restart the service so it reloads the new credentials:

```sh
sudo systemctl restart portkeeper
sudo systemctl status portkeeper --no-pager
```

Run the account-creation command again whenever you need to replace the password. Replacing credentials invalidates existing admin sessions.

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
- `/var/lib/portkeeper/state.json` — contains persisted temporary-access expiration state;\n- `/var/lib/portkeeper/admin.json` — contains the password hash and session-signing secret for the admin UI.

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
sudo chmod 0660 /app/golang/PortKeeper/config.yaml
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


## 13. Local React administration UI

PortKeeper can serve a React administration UI from the same Go binary. It manages only the local instance; there is no central controller or remote-server connection.

The admin listener defaults to TCP **8083** and is configured separately from the public GUID API listener:

```yaml
admin:
  enabled: true
  listen_addr: "0.0.0.0:8083"
  https: false
  tls_cert_file: ""
  tls_key_file: ""
```

The example config enables the admin listener. Existing runtime configs are not overwritten by deployment; add this section manually to an existing `config.yaml` to enable it. The admin account must be created before starting the service with admin enabled.

### Create or reset the administrator

Run on the VPS as root:

```sh
sudo /app/golang/PortKeeper/portkeeper -admin-create -admin-user admin
```

Enter the password at the prompt and press Enter. Terminal echo is disabled while you type, so neither characters nor asterisks are displayed. The original terminal settings are restored after input. Any non-empty password is accepted; PortKeeper does not enforce password length or complexity.

The password is read directly from the terminal and is not passed as a command-line argument. The command stores a PBKDF2-HMAC-SHA256 password hash and a random session-signing secret in `/var/lib/portkeeper/admin.json`, owned by `root:portkeeper` with mode `0640`. Running it again replaces the credentials. Restart PortKeeper afterward; the new credentials are loaded at startup and all existing sessions are invalidated.

### Enable and expose the admin UI

Make sure the runtime config is writable by the service group (the setup script does this for an existing config):

```sh
sudo chown root:portkeeper /app/golang/PortKeeper/config.yaml
sudo chmod 0660 /app/golang/PortKeeper/config.yaml
```

Open TCP 8083 in the VPS provider firewall and, if enabled, UFW:

```sh
sudo ufw allow 8083/tcp
```

Then install the updated systemd unit and restart:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/portkeeper.service /etc/systemd/system/portkeeper.service
sudo systemctl daemon-reload
sudo systemctl restart portkeeper
sudo systemctl status portkeeper --no-pager
```

Open `http://YOUR_VPS_HOST:8083/` in a browser. **Plain HTTP is not safe for an admin interface exposed to the Internet:** credentials and session cookies can be intercepted. Use HTTPS as soon as possible.

### Enable HTTPS

Install a certificate and private key readable by the `portkeeper` group. For Let's Encrypt, copy the current files into a dedicated directory (renewal automation must refresh these copies):

```sh
sudo install -d -o root -g portkeeper -m 0750 /etc/portkeeper/tls
sudo install -o root -g portkeeper -m 0640 /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem /etc/portkeeper/tls/fullchain.pem
sudo install -o root -g portkeeper -m 0640 /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem /etc/portkeeper/tls/privkey.pem
```

Set the admin section in `config.yaml`:

```yaml
admin:
  enabled: true
  listen_addr: "0.0.0.0:8083"
  https: true
  tls_cert_file: "/etc/portkeeper/tls/fullchain.pem"
  tls_key_file: "/etc/portkeeper/tls/privkey.pem"
```

Restart PortKeeper. If HTTPS is enabled and the certificate or key is missing/invalid, PortKeeper fails to start the admin listener rather than silently falling back to HTTP. The admin UI will then be available at `https://YOUR_DOMAIN:8083/`.

### What the admin UI can do

- Log in using the local admin account; the browser receives an HttpOnly, SameSite=Strict session cookie.
- View and edit TTL, rate-limit settings and GUID-to-port access rules.
- Generate GUIDs and add/remove access rules.
- Copy a complete public `GET /<GUID>` URL for each access rule. Configure `public_base_url` to the externally reachable API address; it is separate from the admin UI address/port.
- Save config changes with a backup of the previous config.
- Apply/rebuild the PortKeeper iptables/ip6tables and ipset rules with **Apply firewall rules**.

The firewall action does **not** expose configured target ports to every Internet address. It reapplies the PortKeeper allowlist: only source IPs that have successfully called the corresponding GUID endpoint are accepted for the configured TCP port; other source IPs are dropped by the PortKeeper chain.

The admin UI keeps the main API listener, state-file path and admin listener address read-only. The HTTPS toggle and certificate/key paths are editable in the UI; saving a TLS change validates the certificate and marks that a service restart is required. The main API listener, state-file path and admin listener address remain configurable in `config.yaml`. Saving access rules, TTL and rate limits updates the live service without restarting it.

The React source is in `web/admin`. The CI workflow installs Node.js dependencies, builds the frontend into the embedded assets directory, and then builds the single Go binary. Build locally with:

```sh
cd web/admin
npm install
npm run build
cd ../..
go test ./...
go build -o portkeeper ./cmd/portkeeper
```
