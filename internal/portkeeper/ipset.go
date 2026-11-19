package portkeeper

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Firewall struct { runCommand func(string, ...string) error }

func (f Firewall) run(name string, args ...string) error {
	if f.runCommand != nil { return f.runCommand(name, args...) }
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func setName(port uint16, ip net.IP) string {
	family := "v4"
	if ip.To4() == nil {
		family = "v6"
	}
	return fmt.Sprintf("pk_%d_%s", port, family)
}

// Ensure retains the original temporary-only firewall behavior for legacy callers.
func (f Firewall) Ensure(ports []uint16) error {
	return f.ensure(ports, nil)
}

// EnsureRules installs permanent CIDR allowances ahead of temporary ipset
// allowances and the final DROP. Multiple GUID rules for one port are merged.
func (f Firewall) EnsureRules(rules []AccessRule) error {
	ports := make([]uint16, 0, len(rules))
	seenPorts := make(map[uint16]bool)
	permanent := make(map[uint16][]string)
	seenNetworks := make(map[uint16]map[string]bool)
	for _, rule := range rules {
		if !seenPorts[rule.Port] {
			ports = append(ports, rule.Port)
			seenPorts[rule.Port] = true
		}
		if seenNetworks[rule.Port] == nil { seenNetworks[rule.Port] = make(map[string]bool) }
		for _, cidr := range rule.AllowedNetworks {
			if !seenNetworks[rule.Port][cidr] {
				permanent[rule.Port] = append(permanent[rule.Port], cidr)
				seenNetworks[rule.Port][cidr] = true
			}
		}
	}
	return f.ensure(ports, permanent)
}

func (f Firewall) ensure(ports []uint16, permanent map[uint16][]string) error {
	for _, port := range ports {
		for _, family := range []string{"inet", "inet6"} {
			name := fmt.Sprintf("pk_%d_%s", port, map[string]string{"inet": "v4", "inet6": "v6"}[family])
			if err := f.run("ipset", "create", name, "hash:ip", "family", family, "timeout", "86400", "-exist"); err != nil {
				return err
			}
		}
	}

	if err := f.run("iptables", "-N", "PORTKEEPER"); err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return err
	}
	if err := f.run("ip6tables", "-N", "PORTKEEPER"); err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return err
	}
	if err := f.run("iptables", "-F", "PORTKEEPER"); err != nil {
		return err
	}
	if err := f.run("ip6tables", "-F", "PORTKEEPER"); err != nil {
		return err
	}

	// Loopback traffic must reach the host's ordinary firewall rules (UFW).
	// PortKeeper runs before UFW in INPUT; without RETURN, per-port DROP
	// rules also block connections to 127.0.0.1 and ::1 from this host.
	for _, command := range []string{"iptables", "ip6tables"} {
		if err := f.run(command, "-A", "PORTKEEPER", "-i", "lo", "-j", "RETURN"); err != nil {
			return err
		}
	}

	for _, port := range ports {
		p := strconv.Itoa(int(port))
		for _, cidr := range permanent[port] {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil { return fmt.Errorf("invalid permanent CIDR %q for port %d: %w", cidr, port, err) }
			command := "iptables"
			if ip.To4() == nil { command = "ip6tables" }
			if err := f.run(command, "-A", "PORTKEEPER", "-p", "tcp", "--dport", p,
				"-s", cidr, "-j", "ACCEPT"); err != nil { return err }
		}
		if err := f.run("iptables", "-A", "PORTKEEPER", "-p", "tcp", "--dport", p, "-m", "set", "--match-set", fmt.Sprintf("pk_%d_v4", port), "src", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := f.run("iptables", "-A", "PORTKEEPER", "-p", "tcp", "--dport", p, "-j", "DROP"); err != nil {
			return err
		}
		if err := f.run("ip6tables", "-A", "PORTKEEPER", "-p", "tcp", "--dport", p, "-m", "set", "--match-set", fmt.Sprintf("pk_%d_v6", port), "src", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := f.run("ip6tables", "-A", "PORTKEEPER", "-p", "tcp", "--dport", p, "-j", "DROP"); err != nil {
			return err
		}
	}

	if err := f.ensureJump("iptables"); err != nil {
		return err
	}
	return f.ensureJump("ip6tables")
}

func (f Firewall) ensureJump(command string) error {
	if err := f.run(command, "-C", "INPUT", "-j", "PORTKEEPER"); err == nil {
		return nil
	}
	return f.run(command, "-I", "INPUT", "1", "-j", "PORTKEEPER")
}

func (f Firewall) Refresh(port uint16, ip net.IP, ttl time.Duration) error {
	name := setName(port, ip)
	address := ip.String()
	// Delete first so the timeout is refreshed for an existing element too.
	_ = f.run("ipset", "del", name, address)
	seconds := int(ttl / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return f.run("ipset", "add", name, address, "timeout", strconv.Itoa(seconds))
}

func (f Firewall) FlushPort(port uint16) error {
	for _, family := range []string{"v4", "v6"} {
		name := fmt.Sprintf("pk_%d_%s", port, family)
		if err := f.run("ipset", "flush", name); err != nil {
			return err
		}
	}
	return nil
}
