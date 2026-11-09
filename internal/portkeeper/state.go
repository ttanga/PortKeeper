package portkeeper

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

type AccessState struct {
	Port      uint16    `json:"port"`
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

type StateStore struct {
	Path string
}

func (s StateStore) Load() ([]AccessState, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var entries []AccessState
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return entries, nil
}

func (s StateStore) Save(entries []AccessState) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

func RestoreState(fw Firewall, entries []AccessState) ([]AccessState, error) {
	now := time.Now()
	restored := make([]AccessState, 0, len(entries))
	for _, entry := range entries {
		ip := net.ParseIP(entry.IP)
		if ip == nil || entry.ExpiresAt.IsZero() || !entry.ExpiresAt.After(now) {
			continue
		}
		if err := fw.Refresh(entry.Port, ip, time.Until(entry.ExpiresAt)); err != nil {
			return nil, err
		}
		restored = append(restored, entry)
	}
	return restored, nil
}
