package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML configuration")
	flag.Parse()

	cfg, ttl, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	ports := make([]uint16, 0, len(cfg.Access))
	for _, rule := range cfg.Access {
		ports = append(ports, rule.Port)
	}

	fw := Firewall{}
	if err := fw.Ensure(ports); err != nil {
		log.Fatalf("firewall initialization failed: %v", err)
	}

	store := StateStore{Path: cfg.StateFile}
	entries, err := store.Load()
	if err != nil {
		log.Fatalf("state loading failed: %v", err)
	}
	configuredPorts := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		configuredPorts[port] = struct{}{}
	}
	filtered := make([]AccessState, 0, len(entries))
	for _, entry := range entries {
		if _, ok := configuredPorts[entry.Port]; ok {
			filtered = append(filtered, entry)
		}
	}
	entries, err = restoreState(fw, filtered)
	if err != nil {
		log.Fatalf("state restoration failed: %v", err)
	}
	if err := store.Save(entries); err != nil {
		log.Fatalf("state initialization failed: %v", err)
	}

	server := NewServer(cfg, ttl, fw, store, entries)
	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: server, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("PortKeeper listening on %s", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("HTTP server stopped: %v", err)
		os.Exit(1)
	}
}
