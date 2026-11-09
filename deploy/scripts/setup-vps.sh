#!/usr/bin/env bash
set -euo pipefail

# Run as root, passing the public SSH key for the dedicated deploy account:
# sudo bash setup-vps.sh 'ssh-ed25519 AAAA... github-actions-portkeeper'

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root (sudo)." >&2
  exit 1
fi

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "Usage: sudo bash $0 '<SSH_PUBLIC_KEY>'" >&2
  exit 1
fi

DEPLOY_PUBLIC_KEY=$1
if [[ ! "$DEPLOY_PUBLIC_KEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
  echo "The supplied value does not look like a supported SSH public key." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ipset iptables sudo

if ! id portkeeper >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin portkeeper
fi

if ! id deploy >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash deploy
fi

install -d -o deploy -g deploy -m 0700 /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys
chmod 0600 /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
if ! grep -qxF "$DEPLOY_PUBLIC_KEY" /home/deploy/.ssh/authorized_keys; then
  printf '%s\n' "$DEPLOY_PUBLIC_KEY" >> /home/deploy/.ssh/authorized_keys
fi

install -d -o root -g portkeeper -m 0750 /app/golang/PortKeeper
install -d -o root -g portkeeper -m 0750 /var/lib/portkeeper
install -o root -g portkeeper -m 0640 \
  "$PROJECT_ROOT/configs/config.example.yaml" \
  /app/golang/PortKeeper/config.example.yaml

if [[ -f /app/golang/PortKeeper/config.yaml ]]; then
  chown root:portkeeper /app/golang/PortKeeper/config.yaml
  chmod 0640 /app/golang/PortKeeper/config.yaml
fi

install -o root -g root -m 0644 \
  "$PROJECT_ROOT/deploy/systemd/portkeeper.service" \
  /etc/systemd/system/portkeeper.service

install -o root -g root -m 0755 \
  "$SCRIPT_DIR/deploy-portkeeper.sh" \
  /usr/local/sbin/deploy-portkeeper

cat > /etc/sudoers.d/portkeeper-deploy <<'SUDOERS'
deploy ALL=(root) NOPASSWD: /usr/local/sbin/deploy-portkeeper
SUDOERS
chmod 0440 /etc/sudoers.d/portkeeper-deploy
visudo -cf /etc/sudoers.d/portkeeper-deploy

systemctl daemon-reload
systemctl enable portkeeper

echo
echo "Initial VPS setup completed."
echo "Create /app/golang/PortKeeper/config.yaml using config.example.yaml as a template."
echo "IMPORTANT: replace the example GUIDs and choose ports carefully before starting PortKeeper."
echo "PortKeeper installs INPUT firewall rules for every configured port."
echo "Then add GitHub Actions variables: VPS_HOST, VPS_USER, VPS_KNOWN_HOSTS; add secret: VPS_SSH_PRIVATE_KEY."
echo "The service is enabled but has not been started."
