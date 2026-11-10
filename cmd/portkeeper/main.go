package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ttanga/PortKeeper/internal/portkeeper"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML configuration")
	createAdmin := flag.Bool("admin-create", false, "create or replace the local admin account; read password from stdin")
	adminUser := flag.String("admin-user", "admin", "username for -admin-create")
	flag.Parse()

	if *createAdmin {
		password, err := readPassword()
		if err != nil {
			log.Fatalf("read admin password: %v", err)
		}
		if err := portkeeper.CreateAdminCredentials(*adminUser, password); err != nil {
			log.Fatalf("create admin account: %v", err)
		}
		fmt.Println("Admin account created. Keep the password safe.")
		return
	}

	cfg, ttl, err := portkeeper.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	ports := make([]uint16, 0, len(cfg.Access))
	for _, rule := range cfg.Access {
		ports = append(ports, rule.Port)
	}

	fw := portkeeper.Firewall{}
	if err := fw.Ensure(ports); err != nil {
		log.Fatalf("firewall initialization failed: %v", err)
	}

	store := portkeeper.StateStore{Path: cfg.StateFile}
	entries, err := store.Load()
	if err != nil {
		log.Fatalf("state loading failed: %v", err)
	}
	configuredPorts := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		configuredPorts[port] = struct{}{}
	}
	filtered := make([]portkeeper.AccessState, 0, len(entries))
	for _, entry := range entries {
		if _, ok := configuredPorts[entry.Port]; ok {
			filtered = append(filtered, entry)
		}
	}
	entries, err = portkeeper.RestoreState(fw, filtered)
	if err != nil {
		log.Fatalf("state restoration failed: %v", err)
	}
	if err := store.Save(entries); err != nil {
		log.Fatalf("state initialization failed: %v", err)
	}

	server := portkeeper.NewServer(cfg, ttl, fw, store, entries)
	if cfg.Admin.Enabled {
		adminHandler, err := portkeeper.NewAdminHandler(*configPath, server)
		if err != nil {
			log.Fatalf("admin initialization failed: %v", err)
		}
		listener, err := net.Listen("tcp", cfg.Admin.ListenAddr)
		if err != nil {
			log.Fatalf("admin listener failed on %s: %v", cfg.Admin.ListenAddr, err)
		}
		adminHTTP := &http.Server{Handler: adminHandler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
		if cfg.Admin.HTTPS {
			cert, err := tls.LoadX509KeyPair(cfg.Admin.TLSCertFile, cfg.Admin.TLSKeyFile)
			if err != nil {
				_ = listener.Close()
				log.Fatalf("load admin TLS certificate/key: %v", err)
			}
			tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			go func() {
				log.Printf("PortKeeper Admin listening with HTTPS on %s", cfg.Admin.ListenAddr)
				if err := adminHTTP.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
					log.Fatalf("admin HTTPS server stopped: %v", err)
				}
			}()
		} else {
			log.Printf("WARNING: PortKeeper Admin is exposed over plain HTTP on %s; credentials and session cookies are not encrypted", cfg.Admin.ListenAddr)
			go func() {
				log.Printf("PortKeeper Admin listening with HTTP on %s", cfg.Admin.ListenAddr)
				if err := adminHTTP.Serve(listener); err != nil && err != http.ErrServerClosed {
					log.Fatalf("admin HTTP server stopped: %v", err)
				}
			}()
		}
	}

	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: server, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("PortKeeper listening on %s", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("HTTP server stopped: %v", err)
		os.Exit(1)
	}
}

func readPassword() (string, error) {
	data, err := os.ReadFile("/dev/stdin")
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", fmt.Errorf("password was empty; pipe it through stdin")
	}
	return password, nil
}
