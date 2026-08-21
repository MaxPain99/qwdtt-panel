package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

func socksStoreCreate(p SocksProfile) error {
	if p.Port == 0 {
		p.Port = 45000
	}
	if p.Host == "" {
		p.Host = "127.0.0.1"
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	p.ID = hex.EncodeToString(b)
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore == nil {
		return errors.New("нет panel.json")
	}
	if len(panelStore.SocksProfiles) >= 20 {
		return fmt.Errorf("лимит 20 SOCKS-профилей")
	}
	panelStore.SocksProfiles = append(panelStore.SocksProfiles, p)
	return persistPanelStoreLocked()
}

func socksCreateProfile(p SocksProfile) error {
	return socksStoreCreate(p)
}

func socksFindProfileLocked(id string) *SocksProfile {
	if panelStore == nil {
		return nil
	}
	for i := range panelStore.SocksProfiles {
		if panelStore.SocksProfiles[i].ID == id {
			return &panelStore.SocksProfiles[i]
		}
	}
	return nil
}

func socksStoreDelete(id string) error {
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore == nil {
		return errors.New("нет panel.json")
	}
	next := make([]SocksProfile, 0, len(panelStore.SocksProfiles))
	found := false
	for _, p := range panelStore.SocksProfiles {
		if p.ID == id {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		return errors.New("профиль не найден")
	}
	panelStore.SocksProfiles = next
	if panelStore.ActiveSocksID == id {
		panelStore.ActiveSocksID = ""
	}
	return persistPanelStoreLocked()
}

func socksDeleteProfile(id string) error {
	panelStoreMu.Lock()
	active := panelStore != nil && panelStore.ActiveSocksID == id
	panelStoreMu.Unlock()
	if active {
		socksDeactivate()
	}
	return socksStoreDelete(id)
}

func socksPanelState() map[string]interface{} {
	on, tcp, udp, health := socksSnapshot()
	panelStoreMu.Lock()
	profiles := []SocksProfile{}
	activeID := ""
	var probe *SocksProfile
	if panelStore != nil {
		profiles = append(profiles, panelStore.SocksProfiles...)
		activeID = panelStore.ActiveSocksID
		if p := socksFindProfileLocked(activeID); p != nil {
			cp := *p
			probe = &cp
		}
	}
	for i := range profiles {
		profiles[i].Password = ""
	}
	panelStoreMu.Unlock()
	listening := false
	if probe != nil {
		listening = socksPortOpen(*probe)
	}
	return map[string]interface{}{
		"profiles":  profiles,
		"active_id": activeID,
		"on":        on,
		"tcp":       tcp,
		"udp":       udp,
		"health":    health,
		"listening": listening,
	}
}
