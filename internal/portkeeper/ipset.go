package portkeeper

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Firewall struct{}

func (Firewall) run(name string, args ...string) error {
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

func (f Firewall) Ensure(ports []uint16) error {
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

	for _, port := range ports {
		p := strconv.Itoa(int(port))
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
