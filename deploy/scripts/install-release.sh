#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo "Run as root"; exit 1; }
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Unsupported architecture"; exit 1 ;;
esac
app=/apps/golang/PortKeeper
if [[ -e /etc/systemd/system/portkeeper.service || -e /app/golang/PortKeeper ]]; then
  echo "Existing installation detected; remove or migrate it first."
  exit 1
fi
apt-get update
apt-get install -y curl ca-certificates iptables ipset openssl
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
base=https://github.com/ttanga/PortKeeper/releases/latest/download
asset=portkeeper-linux-$arch.tar.gz
cd "$tmp"
curl -fsSL "$base/$asset" -o "$asset"
curl -fsSL "$base/checksums.txt" -o checksums.txt
grep -F "  $asset" checksums.txt | sha256sum -c -
tar -xzf "$asset"
id portkeeper >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin portkeeper
install -d -o root -g portkeeper -m 0750 "$app"
install -d -o portkeeper -g portkeeper -m 0750 /var/lib/portkeeper
install -o root -g portkeeper -m 0755 portkeeper "$app/portkeeper"
install -o root -g portkeeper -m 0640 config.example.yaml "$app/config.example.yaml"
if [[ ! -e "$app/config.yaml" ]]; then
  umask 077
  cat > "$app/config.yaml" <<EOF
listen_addr: "127.0.0.1:8787"
default_ttl: "24h"
state_file: "/var/lib/portkeeper/state.json"
rate_limit_requests: 10
rate_limit_window: "1m"
admin:
  enabled: true
  listen_addr: "127.0.0.1:8083"
  https: false
access:
  - guid: "$(openssl rand -hex 16)"
    port: 8090
firewall:
  protected_interfaces: []
EOF
fi
chown root:portkeeper "$app/config.yaml"
chmod 0660 "$app/config.yaml"
sed 's|/app/golang/PortKeeper|/apps/golang/PortKeeper|g' portkeeper.service > unit
install -m 0644 unit /etc/systemd/system/portkeeper.service
systemctl daemon-reload
echo "Installed. Review $app/config.yaml before starting."
echo "Create administrator: $app/portkeeper -config $app/config.yaml -admin-create -admin-user admin"
echo "Then: systemctl enable --now portkeeper"
echo "Listeners are loopback-only by default; configure secure external access explicitly."
