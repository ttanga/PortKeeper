package portkeeper

import (
    "fmt"
    "strings"
    "testing"
)

func TestValidateCIDRNetworks(t *testing.T) {
    cfg := Config{Access: []AccessRule{{GUID: "test", Port: 443, AllowedNetworks: []string{"160.79.104.1/21", "2001:db8::1/32"}}}}
    got, _, err := ValidateConfig(cfg)
    if err != nil { t.Fatal(err) }
    if got.Access[0].AllowedNetworks[0] != "160.79.104.0/21" || got.Access[0].AllowedNetworks[1] != "2001:db8::/32" {
        t.Fatalf("noncanonical networks: %#v", got.Access[0].AllowedNetworks)
    }
    for _, cidrs := range [][]string{{"not-a-network"}, {"0.0.0.0/0", "0.0.0.0/0"}} {
        _, _, err := ValidateConfig(Config{Access: []AccessRule{{GUID:"test", Port:443, AllowedNetworks:cidrs}}})
        if err == nil { t.Fatalf("expected invalid CIDRs %#v to fail", cidrs) }
    }
}

func TestFirewallCIDRsPrecedeTemporarySetsAndDrop(t *testing.T) {
    var calls []string
    fw := Firewall{runCommand: func(name string, args ...string) error {
        command := name + " " + strings.Join(args, " ")
        calls = append(calls, command)
        if strings.Contains(command, "-C INPUT -j PORTKEEPER") { return nil }
        return nil
    }}
    rules := []AccessRule{
        {GUID:"first", Port:443, AllowedNetworks: []string{"160.79.104.0/21", "2001:db8::/32"}},
        {GUID:"second", Port:443, AllowedNetworks: []string{"160.79.104.0/21", "153.61.208.0/20"}},
    }
    if err := fw.EnsureRules(rules); err != nil { t.Fatal(err) }
    index := func(fragment string) int {
        for i, call := range calls {
            if strings.Contains(call, fragment) { return i }
        }
        t.Fatalf("missing command %q in: %v", fragment, calls)
        return -1
    }
    ipv4Loopback := index("iptables -A PORTKEEPER -i lo -j RETURN")
    ipv6Loopback := index("ip6tables -A PORTKEEPER -i lo -j RETURN")
    ipv4Flush := index("iptables -F PORTKEEPER")
    ipv6Flush := index("ip6tables -F PORTKEEPER")
    if ipv4Flush >= ipv4Loopback || ipv6Flush >= ipv6Loopback {
        t.Fatal("loopback exception must be installed after flushing the chains")
    }
    ipv4CIDR := index("iptables -A PORTKEEPER -p tcp --dport 443 -s 160.79.104.0/21 -j ACCEPT")
    secondCIDR := index("iptables -A PORTKEEPER -p tcp --dport 443 -s 153.61.208.0/20 -j ACCEPT")
    ipsetRule := index("iptables -A PORTKEEPER -p tcp --dport 443 -m set --match-set pk_443_v4 src -j ACCEPT")
    dropRule := index("iptables -A PORTKEEPER -p tcp --dport 443 -j DROP")
    if !(ipv4Loopback < ipv4CIDR && ipv4Loopback < secondCIDR && ipv4Loopback < ipsetRule && ipv4Loopback < dropRule) {
        t.Fatal("IPv4 loopback RETURN must precede every access and DROP rule")
    }
    if !(ipv4CIDR < ipsetRule && secondCIDR < ipsetRule && ipsetRule < dropRule) {
        t.Fatal("incorrect IPv4 firewall rule order")
    }
    ipv6CIDR := index("ip6tables -A PORTKEEPER -p tcp --dport 443 -s 2001:db8::/32 -j ACCEPT")
    ipv6Set := index("ip6tables -A PORTKEEPER -p tcp --dport 443 -m set --match-set pk_443_v6 src -j ACCEPT")
    ipv6Drop := index("ip6tables -A PORTKEEPER -p tcp --dport 443 -j DROP")
    if !(ipv6Loopback < ipv6CIDR && ipv6Loopback < ipv6Set && ipv6Loopback < ipv6Drop) {
        t.Fatal("IPv6 loopback RETURN must precede every access and DROP rule")
    }
    if !(ipv6CIDR < ipv6Set && ipv6Set < ipv6Drop) { t.Fatal("incorrect IPv6 firewall rule order") }
    seen := 0
    for _, command := range calls {
        if strings.Contains(command, "-s 160.79.104.0/21") { seen++ }
        if strings.HasPrefix(command, "ip6tables ") && strings.Contains(command, "160.79.104.0/21") { t.Fatal("IPv4 CIDR used in IPv6 firewall") }
    }
    if seen != 1 { t.Fatal(fmt.Sprintf("duplicate network rules: %d", seen)) }
}
