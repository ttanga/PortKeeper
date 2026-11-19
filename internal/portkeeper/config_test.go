package portkeeper

import (
    "strings"
    "testing"
)

func TestServiceNameOptionalAndPreserved(t *testing.T) {
    cfg, _, err := ParseConfig([]byte(`access:
  - guid: AABBCCDD00112233445566778899AABB
    port: 443
    service_name: "  Claude MCP  "
    allowed_networks: ["160.79.104.0/21"]
  - guid: LEGACY-UUID-WITH-HYPHENS
    port: 8443
`))
    if err != nil { t.Fatal(err) }
    if cfg.Access[0].ServiceName != "Claude MCP" { t.Fatalf("service name: %q", cfg.Access[0].ServiceName) }
    if cfg.Access[1].ServiceName != "" { t.Fatalf("unexpected default service name: %q", cfg.Access[1].ServiceName) }
    if cfg.Access[1].GUID != "LEGACY-UUID-WITH-HYPHENS" { t.Fatal("existing GUID format was modified") }
}

func TestServiceNameTooLongRejected(t *testing.T) {
    _, _, err := ValidateConfig(Config{Access: []AccessRule{{GUID: "test", Port: 443, ServiceName: strings.Repeat("я", 121)}}})
    if err == nil { t.Fatal("expected service name length validation error") }
}
