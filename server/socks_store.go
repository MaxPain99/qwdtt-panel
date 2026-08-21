package main

import "errors"

func migratePanelSocks(st *panelFileStore) {
	if st == nil {
		return
	}
	if st.Socks != nil && st.Socks.Port != 0 {
		if st.Socks.Host == "" {
			st.Socks.Host = "127.0.0.1"
		}
		st.SocksProfiles = nil
		st.ActiveSocksID = ""
		return
	}
	if len(st.SocksProfiles) > 0 {
		p := st.SocksProfiles[0]
		if p.Host == "" {
			p.Host = "127.0.0.1"
		}
		st.Socks = &p
		if st.ActiveSocksID != "" {
			st.SocksOn = true
		}
	}
	st.SocksProfiles = nil
	st.ActiveSocksID = ""
}

func socksFormProfile(host, user, pass string, port uint16) SocksProfile {
	if host == "" {
		host = "127.0.0.1"
	}
	if pass == "" {
		panelStoreMu.Lock()
		if panelStore != nil && panelStore.Socks != nil {
			pass = panelStore.Socks.Password
		}
		panelStoreMu.Unlock()
	}
	return SocksProfile{Host: host, Port: port, Username: user, Password: pass}
}

func socksSaveAndEnable(p SocksProfile) error {
	if p.Host == "" {
		p.Host = "127.0.0.1"
	}
	if p.Port == 0 {
		return errors.New("укажите порт SOCKS5")
	}
	chk := socksInspect(p)
	if !chk.Allow {
		return errors.New(chk.Message)
	}
	if err := socksActivate(p); err != nil {
		return err
	}
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore == nil {
		return errors.New("нет panel.json")
	}
	cp := p
	panelStore.Socks = &cp
	panelStore.SocksOn = true
	panelStore.SocksProfiles = nil
	panelStore.ActiveSocksID = ""
	return persistPanelStoreLocked()
}

func socksTurnOff() {
	socksDeactivate()
	panelStoreMu.Lock()
	if panelStore != nil {
		panelStore.SocksOn = false
		panelStore.ActiveSocksID = ""
	}
	_ = persistPanelStoreLocked()
	panelStoreMu.Unlock()
}

func socksPanelState() map[string]interface{} {
	on, tcp, udp, health := socksSnapshot()
	panelStoreMu.Lock()
	host := "127.0.0.1"
	var port uint16
	user := ""
	hasPass := false
	if panelStore != nil && panelStore.Socks != nil {
		if panelStore.Socks.Host != "" {
			host = panelStore.Socks.Host
		}
		port = panelStore.Socks.Port
		user = panelStore.Socks.Username
		hasPass = panelStore.Socks.Password != ""
	}
	panelStoreMu.Unlock()
	listening := false
	if port != 0 {
		listening = socksPortOpen(SocksProfile{Host: host, Port: port})
	}
	return map[string]interface{}{
		"host":         host,
		"port":         port,
		"username":     user,
		"has_password": hasPass,
		"on":           on,
		"tcp":          tcp,
		"udp":          udp,
		"health":       health,
		"listening":    listening,
	}
}
