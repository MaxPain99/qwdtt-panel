package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "embed"
)

//go:embed login.html
var loginHTML string

//go:embed panel.html
var panelHTML string

//go:embed update-server.sh
var updateServerScript string

const (
	panelCookieName = "qwdtt_session"
	panelCertFile   = "panel.crt"
	panelKeyFile    = "panel.key"
	panelStoreFile  = "panel.json"
)

type SocksProfile struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type panelFileStore struct {
	WebUser       string         `json:"web_user"`
	PassHash      string         `json:"pass_hash"`
	LoggingActive *bool          `json:"logging_active,omitempty"`
	Socks         *SocksProfile  `json:"socks,omitempty"`
	SocksOn       bool           `json:"socks_on,omitempty"`
	SocksProfiles []SocksProfile `json:"socks_profiles,omitempty"`
	ActiveSocksID string `json:"active_socks_id,omitempty"`
	TLSCertFile   string `json:"tls_cert_file,omitempty"`
	TLSKeyFile    string            `json:"tls_key_file,omitempty"`
}

var (
	panelUser     string
	panelPassHash [32]byte
	panelDir      string
	panelSessMu   sync.Mutex
	panelSessions = map[string]time.Time{}
	panelStoreMu  sync.Mutex
	panelStore    *panelFileStore
)

func hashPanelPass(user, pass string) [32]byte {
	sum := sha256.Sum256([]byte("qwdtt-panel-v1\x00" + user + "\x00" + pass))
	return sum
}

func startWebPanel(configDir string, port uint16, user, pass string) {
	if port == 0 {
		log.Println("[WEB] панель выключена (-web-port 0)")
		return
	}
	if serverStartTime.IsZero() {
		serverStartTime = time.Now()
	}
	panelDir = configDir
	if user == "" {
		user = "admin"
	}
	storePath := filepath.Join(configDir, panelStoreFile)
	st, _ := loadPanelStore(storePath)
	if st == nil {
		st = &panelFileStore{}
	}
	if pass == "" {
		if st.PassHash != "" {
			user = st.WebUser
			if decoded, err := hex.DecodeString(st.PassHash); err == nil && len(decoded) == 32 {
				copy(panelPassHash[:], decoded)
			}
		} else {
			pass = randomPanelPass()
			log.Printf("[WEB] пароль панели сгенерирован: %s", pass)
		}
	}
	if pass != "" {
		panelPassHash = hashPanelPass(user, pass)
		_ = os.WriteFile(filepath.Join(configDir, "web.password"), []byte(pass+"\n"), 0600)
	}
	panelUser = user
	st.WebUser = user
	st.PassHash = hex.EncodeToString(panelPassHash[:])
	if st.LoggingActive == nil {
		on := true
		st.LoggingActive = &on
	}
	migratePanelSocks(st)
	panelStoreMu.Lock()
	panelStore = st
	panelStoreMu.Unlock()
	initPanelLogging(configDir, *st.LoggingActive)
	_ = persistPanelStore()
	startPanelBackgroundTasks()

	certPath, keyPath := resolvePanelTLSPaths()
	if isDefaultPanelTLS(certPath, keyPath) {
		if err := ensurePanelTLS(certPath, keyPath); err != nil {
			log.Printf("[WEB] TLS: %v", err)
			return
		}
	} else if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		log.Printf("[WEB] TLS пути: %v — fallback на локальный сертификат", err)
		certPath = filepath.Join(configDir, panelCertFile)
		keyPath = filepath.Join(configDir, panelKeyFile)
		if err := ensurePanelTLS(certPath, keyPath); err != nil {
			log.Printf("[WEB] TLS: %v", err)
			return
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handlePanelLogin)
	mux.HandleFunc("/logout", handlePanelLogout)
	mux.HandleFunc("/api/health", handlePanelHealth)
	mux.HandleFunc("/api/metrics", handlePanelMetrics)
	mux.HandleFunc("/", handlePanelIndex)
	mux.HandleFunc("/api/status", handlePanelStatus)
	mux.HandleFunc("/api/clients", handlePanelClients)
	mux.HandleFunc("/api/clients/delete", handlePanelDeleteClient)
	mux.HandleFunc("/api/clients/update", handlePanelUpdateClient)
	mux.HandleFunc("/api/clients/activate", handlePanelActivateClient)
	mux.HandleFunc("/api/clients/deactivate", handlePanelDeactivateClient)
	mux.HandleFunc("/api/clients/unbind", handlePanelUnbindDevice)
	mux.HandleFunc("/api/clients/export", handlePanelClientsExport)
	mux.HandleFunc("/api/clients/import", handlePanelClientsImport)
	mux.HandleFunc("/api/clients/bulk", handlePanelClientsBulk)
	mux.HandleFunc("/api/clients/reset-traffic", handlePanelResetTraffic)
	mux.HandleFunc("/api/csqtt/unbind", handlePanelCsqttUnbind)
	mux.HandleFunc("/api/account/password", handlePanelChangePassword)
	mux.HandleFunc("/api/audit", handlePanelAudit)
	mux.HandleFunc("/api/qr", handlePanelQR)
	mux.HandleFunc("/api/tls", handlePanelTLS)
	mux.HandleFunc("/api/tls/renew", handlePanelTLSRenew)
	mux.HandleFunc("/api/journal", handlePanelJournal)
	mux.HandleFunc("/api/logs", handlePanelLogs)
	mux.HandleFunc("/api/update-log", handlePanelUpdateLog)
	mux.HandleFunc("/api/logs/clear", handlePanelLogsClear)
	mux.HandleFunc("/api/logs/toggle", handlePanelLogsToggle)
	mux.HandleFunc("/api/socks", handlePanelSocks)
	mux.HandleFunc("/api/socks/check", handlePanelSocksCheck)
	mux.HandleFunc("/api/socks/deactivate", handlePanelSocksDeactivate)
	mux.HandleFunc("/api/csqtt", handlePanelCsqtt)
	mux.HandleFunc("/api/csqtt/clients", handlePanelCsqttClients)
	mux.HandleFunc("/api/csqtt/clients/delete", handlePanelCsqttDelete)
	mux.HandleFunc("/api/csqtt/clients/toggle", handlePanelCsqttToggle)
	mux.HandleFunc("/api/csqtt/clients/update", handlePanelCsqttUpdate)
	mux.HandleFunc("/api/reboot", handlePanelReboot) // legacy no-op redirect
	mux.HandleFunc("/api/services", handlePanelServices)
	mux.HandleFunc("/api/restart", handlePanelRestart)
	mux.HandleFunc("/api/update-server", handlePanelUpdate)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	tlsCert, tlsKey := certPath, keyPath
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 8 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				c, k := resolvePanelTLSPaths()
				if !isDefaultPanelTLS(c, k) {
					if cert, err := tls.LoadX509KeyPair(c, k); err == nil {
						return &cert, nil
					}
				}
				cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
				if err != nil {
					return nil, err
				}
				return &cert, nil
			},
		},
	}
	go func() {
		log.Printf("[WEB] HTTPS панель https://0.0.0.0:%d логин %s cert=%s", port, user, tlsCert)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Printf("[WEB] %v", err)
		}
	}()
}

func loadPanelStore(path string) (*panelFileStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st panelFileStore
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func persistPanelStore() error {
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	return persistPanelStoreLocked()
}

func persistPanelStoreLocked() error {
	if panelStore == nil || panelDir == "" {
		return nil
	}
	panelStore.WebUser = panelUser
	panelStore.PassHash = hex.EncodeToString(panelPassHash[:])
	b, err := json.MarshalIndent(panelStore, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(panelDir, panelStoreFile), b, 0600)
}

func randomPanelPass() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "changeme"
	}
	out := make([]byte, 16)
	for i := range out {
		out[i] = chars[int(b[i])%len(chars)]
	}
	return string(out)
}

func ensurePanelTLS(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "qwdtt-panel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	if ip := net.ParseIP(getPublicIP()); ip != nil {
		tmpl.IPAddresses = []net.IP{ip, net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0600)
}

func panelAuthed(r *http.Request) bool {
	c, err := r.Cookie(panelCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	panelSessMu.Lock()
	defer panelSessMu.Unlock()
	exp, ok := panelSessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(panelSessions, c.Value)
		return false
	}
	return true
}

func requirePanelAuth(w http.ResponseWriter, r *http.Request) bool {
	if panelAuthed(r) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	http.Redirect(w, r, "/login", http.StatusFound)
	return false
}

func handlePanelLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginHTML))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	host := panelLoginHost(r)
	if panelLoginBlocked(host) {
		http.Redirect(w, r, "/login?bad=1&locked=1", http.StatusFound)
		return
	}
	_ = r.ParseForm()
	user := strings.TrimSpace(r.FormValue("user"))
	pass := r.FormValue("pass")
	got := hashPanelPass(user, pass)
	if subtle.ConstantTimeCompare(got[:], panelPassHash[:]) != 1 || user != panelUser {
		recordPanelLoginFailure(host, time.Now())
		http.Redirect(w, r, "/login?bad=1", http.StatusFound)
		return
	}
	clearPanelLoginFailure(host)
	tok := randomPanelPass() + randomPanelPass()
	panelSessMu.Lock()
	panelSessions[tok] = time.Now().Add(12 * time.Hour)
	panelSessMu.Unlock()
	savePanelSessions()
	panelAudit("login", user)
	http.SetCookie(w, &http.Cookie{
		Name:     panelCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   12 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func handlePanelLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(panelCookieName); err == nil {
		panelSessMu.Lock()
		delete(panelSessions, c.Value)
		panelSessMu.Unlock()
		savePanelSessions()
	}
	http.SetCookie(w, &http.Cookie{Name: panelCookieName, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func handlePanelIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !requirePanelAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(panelHTML))
}

func parsePanelForm(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		return r.ParseMultipartForm(1 << 20)
	}
	return r.ParseForm()
}

func writePanelError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writePanelJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func handlePanelStatus(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	upStr := formatUptime(time.Since(serverStartTime))
	if serverStartTime.IsZero() {
		upStr = "—"
	}
	socksOn, socksTCP, socksUDP, socksHealth := socksSnapshot()
	csqtt := csqttCachedStatus()
	var csqttStats map[string]interface{}
	if stats, ok := csqtt["stats"].(map[string]interface{}); ok {
		csqttStats = stats
	}
	csqttActive := csqttStatNumber(csqttStats, "hot_sessions")
	if csqttActive == 0 {
		csqttActive = csqttStatNumber(csqttStats, "active")
	}
	csqttTotal := csqttStatNumber(csqttStats, "total")
	csqttUp := csqttStatNumber(csqttStats, "up")
	csqttDown := csqttStatNumber(csqttStats, "down")

	wdttActive := int64(atomic.LoadInt32(&activeConns))
	wdttTotal := atomic.LoadInt64(&totalConns)
	wdttUp := atomic.LoadInt64(&totalBytesFromClient)
	wdttDown := atomic.LoadInt64(&totalBytesToClient)
	nat := natType
	wdttOK, wdttState := panelUnitActive("wdtt")
	wdttAdminOK := false
	if panelWdttAdminEnabled() {
		if st := panelAdminStatus(); st != nil {
			wdttActive = csqttStatNumber(st, "active")
			wdttTotal = csqttStatNumber(st, "total")
			wdttUp = csqttStatNumber(st, "up_bytes")
			wdttDown = csqttStatNumber(st, "down_bytes")
			if s, ok := st["nat"].(string); ok && s != "" {
				nat = s
			}
			if s, ok := st["uptime"].(string); ok && s != "" {
				upStr = s
			}
			wdttAdminOK = true
		}
	}
	writePanelJSON(w, map[string]interface{}{
		"active":         wdttActive + csqttActive,
		"total":          wdttTotal + csqttTotal,
		"up_bytes":       wdttUp + csqttUp,
		"down_bytes":     wdttDown + csqttDown,
		"wdtt_active":    wdttActive,
		"wdtt_total":     wdttTotal,
		"wdtt_up":        wdttUp,
		"wdtt_down":      wdttDown,
		"uptime":         upStr,
		"nat":            nat,
		"wdtt_ok":        wdttOK,
		"wdtt_state":     wdttState,
		"wdtt_admin_ok":  wdttAdminOK,
		"logs_active":    panelLogsEnabled(),
		"socks_on":       socksOn,
		"socks_tcp":      socksTCP,
		"socks_udp":      socksUDP,
		"socks_health":   socksHealth,
		"socks_ifaces":   socksIfaceNames(),
		"csqtt_ok":       csqtt["connected"],
		"csqtt_active":   csqttActive,
		"csqtt_total":    csqttTotal,
		"csqtt_up":       csqttUp,
		"csqtt_down":     csqttDown,
		"csqtt_error":    csqtt["error"],
		"csqtt_iface_up": csqtt["iface_up"],
	})
}

func csqttStatNumber(stats map[string]interface{}, key string) int64 {
	if stats == nil {
		return 0
	}
	switch n := stats[key].(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		v, _ := n.Int64()
		return v
	default:
		return 0
	}
}

func panelClientLink(pass, hash string) (wdtt string, qwdtt string) {
	ip := getPublicIP()
	if hash == "" {
		hash = "-"
	}
	wdtt = fmt.Sprintf("wdtt://%s:56000:56001:56002:%s:%s", ip, pass, hash)
	name := url.QueryEscape(fmt.Sprintf("qWDTT (%s)", ip))
	qwdtt = fmt.Sprintf("qwdtt://config?name=%s&peer=%s&hashes=%s&workers=9&port=9000&pass=%s",
		name, url.QueryEscape(ip), url.QueryEscape(hash), url.QueryEscape(pass))
	return
}

func parsePanelVkHashes(r *http.Request) (string, error) {
	raw := make([]string, 0, 5)
	if v := strings.TrimSpace(r.FormValue("vk_hash")); v != "" {
		raw = append(raw, v)
	}
	for i := 1; i <= 4; i++ {
		if v := strings.TrimSpace(r.FormValue("vk_hash" + strconv.Itoa(i))); v != "" {
			raw = append(raw, v)
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, chunk := range raw {
		for _, p := range strings.FieldsFunc(chunk, func(ru rune) bool {
			return ru == ',' || ru == ';' || ru == '\n' || ru == '\r' || ru == '\t' || ru == ' '
		}) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			if len(out) >= 4 {
				return "", fmt.Errorf("максимум 4 VK hash")
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "", fmt.Errorf("укажите VK hash")
	}
	return strings.Join(out, ","), nil
}

func handlePanelClientsViaAdmin(w http.ResponseWriter, r *http.Request) {
	type row struct {
		Label         string   `json:"label"`
		Password      string   `json:"password"`
		Owner         bool     `json:"owner"`
		Up            int64    `json:"up"`
		Down          int64    `json:"down"`
		MaxDevices    int      `json:"max_devices"`
		ActiveDevices int      `json:"active_devices"`
		DeviceIDs     []string `json:"device_ids"`
		Expires       string   `json:"expires"`
		Deactivated   bool     `json:"deactivated"`
		Hashes        string   `json:"hashes"`
		QWDTTLink     string   `json:"qwdtt_link"`
		WDTTLink      string   `json:"wdtt_link"`
	}
	if r.Method == http.MethodGet {
		out := []row{}
		if owner := panelOwnerPassword(panelDir); owner != "" {
			wd, q := panelClientLink(owner, "")
			out = append(out, row{Label: "владелец", Password: owner, Owner: true, QWDTTLink: q, WDTTLink: wd})
		}
		list, err := panelAdminListPasswords()
		if err != nil {
			writePanelError(w, http.StatusBadGateway, "wdtt admin: "+err.Error())
			return
		}
		for _, e := range list {
			exp := ""
			if e.ExpiresAt > 0 {
				exp = time.Unix(e.ExpiresAt, 0).Format("2006-01-02")
			}
			wdtt, qwdtt := panelClientLink(e.Password, e.VkHash)
			out = append(out, row{
				Label:         e.Label,
				Password:      e.Password,
				Up:            e.UpBytes,
				Down:          e.DownBytes,
				MaxDevices:    e.MaxDevices,
				ActiveDevices: e.ActiveDevices,
				DeviceIDs:     e.DeviceIDs,
				Expires:       exp,
				Deactivated:   e.IsDeactivated,
				Hashes:        e.VkHash,
				QWDTTLink:     qwdtt,
				WDTTLink:      wdtt,
			})
		}
		writePanelJSON(w, map[string]interface{}{"clients": out})
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	vkHash, err := parsePanelVkHashes(r)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	days := 30
	if v := r.FormValue("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 365 {
			writePanelError(w, http.StatusBadRequest, "days")
			return
		}
		days = n
	}
	label := strings.TrimSpace(r.FormValue("label"))
	maxDevices, err := parsePanelMaxDevices(r, 1)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, "max_devices")
		return
	}
	view, err := panelAdminCreatePassword(label, vkHash, days, maxDevices)
	if err != nil {
		writePanelError(w, http.StatusBadGateway, err.Error())
		return
	}
	wdtt, qwdtt := panelClientLink(view.Password, view.VkHash)
	writePanelJSON(w, map[string]string{
		"password":   view.Password,
		"qwdtt_link": qwdtt,
		"wdtt_link":  wdtt,
		"label":      view.Label,
	})
}

func handlePanelClients(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if panelWdttAdminEnabled() {
		handlePanelClientsViaAdmin(w, r)
		return
	}
	if r.Method == http.MethodGet {
		type row struct {
			Label         string   `json:"label"`
			Password      string   `json:"password"`
			Owner         bool     `json:"owner"`
			Up            int64    `json:"up"`
			Down          int64    `json:"down"`
			MaxDevices    int      `json:"max_devices"`
			ActiveDevices int      `json:"active_devices"`
			DeviceIDs     []string `json:"device_ids"`
			Expires       string   `json:"expires"`
			Deactivated   bool     `json:"deactivated"`
			Hashes        string   `json:"hashes"`
			QWDTTLink     string   `json:"qwdtt_link"`
			WDTTLink      string   `json:"wdtt_link"`
		}
		out := []row{}
		dbMutex.Lock()
		if db != nil {
			wd, q := panelClientLink(db.MainPassword, "")
			out = append(out, row{
				Label:     "владелец",
				Password:  db.MainPassword,
				Owner:     true,
				QWDTTLink: q,
				WDTTLink:  wd,
			})
			for pass, e := range db.Passwords {
				if e == nil {
					continue
				}
				exp := ""
				if e.ExpiresAt > 0 {
					exp = time.Unix(e.ExpiresAt, 0).Format("2006-01-02")
				}
				active := 0
				ids := e.DeviceIDs
				if len(ids) == 0 && e.DeviceID != "" {
					ids = []string{e.DeviceID}
				}
				activeDevicesMu.Lock()
				for _, id := range ids {
					if activeDevices[id] > 0 {
						active++
					}
				}
				activeDevicesMu.Unlock()
				wdtt, qwdtt := panelClientLink(pass, e.VkHash)
				out = append(out, row{
					Label:         e.Label,
					Password:      pass,
					Up:            e.UpBytes,
					Down:          e.DownBytes,
					MaxDevices:    e.MaxDevices,
					ActiveDevices: active,
					DeviceIDs:     ids,
					Expires:       exp,
					Deactivated:   e.IsDeactivated,
					Hashes:        e.VkHash,
					QWDTTLink:     qwdtt,
					WDTTLink:      wdtt,
				})
			}
		}
		dbMutex.Unlock()
		writePanelJSON(w, map[string]interface{}{"clients": out})
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	vkHash, err := parsePanelVkHashes(r)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	days := 30
	if v := r.FormValue("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 365 {
			writePanelError(w, http.StatusBadRequest, "days")
			return
		}
		days = n
	}
	label := strings.TrimSpace(r.FormValue("label"))
	maxDevices, err := parsePanelMaxDevices(r, 1)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, "max_devices")
		return
	}
	dbMutex.Lock()
	if db == nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "db")
		return
	}
	if cleanupExpiredPasswordsLocked(globalWgDev) > 0 {
		saveDB()
	}
	const panelMaxPasswords = 256
	if len(db.Passwords) >= panelMaxPasswords {
		dbMutex.Unlock()
		writePanelError(w, http.StatusConflict, "лимит клиентов")
		return
	}
	newPass := ""
	for i := 0; i < 10; i++ {
		c, err := generatePassword()
		if err != nil {
			break
		}
		if _, exists := db.Passwords[c]; !exists {
			newPass = c
			break
		}
	}
	if newPass == "" {
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "не удалось сгенерировать пароль")
		return
	}
	if err := serverWrapKeys.AddPassword(newPass); err != nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "wrap: "+err.Error())
		return
	}
	if label == "" {
		label = nextPasswordLabel()
	}
	expiresAt := int64(0)
	if days > 0 {
		expiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	}
	db.Passwords[newPass] = &PasswordEntry{
		Label:      label,
		ExpiresAt:  expiresAt,
		MaxDevices: maxDevices,
		VkHash:     vkHash,
		Ports:      "56000,56001,56002",
	}
	if err := saveDB(); err != nil {
		delete(db.Passwords, newPass)
		serverWrapKeys.RemovePassword(newPass)
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	if err := refreshWrapKeysFromDBLocked(); err != nil {
		log.Printf("[WEB] wrap keys после создания клиента: %v", err)
	}
	dbMutex.Unlock()
	log.Printf("[WEB] создан клиент %s (%s)", label, maskPassword(newPass))
	wdtt, qwdtt := panelClientLink(newPass, vkHash)
	writePanelJSON(w, map[string]string{
		"password":   newPass,
		"qwdtt_link": qwdtt,
		"wdtt_link":  wdtt,
		"label":      label,
	})
}

func handlePanelDeleteClient(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	pass := r.FormValue("password")
	if panelWdttAdminEnabled() {
		if err := panelAdminDeletePassword(pass); err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
		writePanelJSON(w, map[string]bool{"ok": true})
		return
	}
	dbMutex.Lock()
	entry, ok := db.Passwords[pass]
	if !ok || entry == nil {
		dbMutex.Unlock()
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	ids := entry.DeviceIDs
	if len(ids) == 0 && entry.DeviceID != "" {
		ids = []string{entry.DeviceID}
	}
	for _, id := range ids {
		if dev, exists := db.Devices[id]; exists {
			if globalWgDev != nil {
				if pubHex, err := b64ToHex(dev.PubKey); err == nil {
					globalWgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
				}
			}
			delete(db.Devices, id)
		}
	}
	delete(db.Passwords, pass)
	disconnectCredentialConnections(pass)
	serverWrapKeys.RemovePassword(pass)
	saveDB()
	dbMutex.Unlock()
	writePanelJSON(w, map[string]bool{"ok": true})
}

func handlePanelUpdateClient(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	pass := strings.TrimSpace(r.FormValue("password"))
	if pass == "" {
		writePanelError(w, http.StatusBadRequest, "password")
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	vkHash, err := parsePanelVkHashes(r)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	days := 30
	setDays := false
	if v := r.FormValue("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 365 {
			writePanelError(w, http.StatusBadRequest, "days")
			return
		}
		days = n
		setDays = true
	}
	maxDevices := 0
	setMax := false
	if v := strings.TrimSpace(r.FormValue("max_devices")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writePanelError(w, http.StatusBadRequest, "max_devices")
			return
		}
		maxDevices = n
		setMax = true
	}

	if panelWdttAdminEnabled() {
		if err := panelAdminUpdatePassword(pass, label, vkHash, days, setDays, maxDevices, setMax); err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
		_, qwdtt := panelClientLink(pass, vkHash)
		writePanelJSON(w, map[string]interface{}{"ok": true, "qwdtt_link": qwdtt, "label": label})
		return
	}

	dbMutex.Lock()
	entry, ok := db.Passwords[pass]
	if !ok || entry == nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusNotFound, "not found")
		return
	}
	entry.Label = label
	entry.VkHash = vkHash
	if setDays {
		if days == 0 {
			entry.ExpiresAt = 0
		} else {
			entry.ExpiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
		}
	}
	if setMax {
		entry.MaxDevices = maxDevices
	}
	if err := saveDB(); err != nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	dbMutex.Unlock()
	_, qwdtt := panelClientLink(pass, vkHash)
	writePanelJSON(w, map[string]interface{}{"ok": true, "qwdtt_link": qwdtt, "label": label})
}

func parsePanelMaxDevices(r *http.Request, def int) (int, error) {
	v := strings.TrimSpace(r.FormValue("max_devices"))
	if v == "" {
		if def < 1 {
			def = 1
		}
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 64 {
		return 0, fmt.Errorf("max_devices")
	}
	return n, nil
}

func handlePanelActivateClient(w http.ResponseWriter, r *http.Request) {
	handlePanelSetClientActive(w, r, true)
}

func handlePanelDeactivateClient(w http.ResponseWriter, r *http.Request) {
	handlePanelSetClientActive(w, r, false)
}

func handlePanelSetClientActive(w http.ResponseWriter, r *http.Request, active bool) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	pass := strings.TrimSpace(r.FormValue("password"))
	if pass == "" {
		writePanelError(w, http.StatusBadRequest, "password")
		return
	}
	if panelWdttAdminEnabled() {
		if err := panelAdminSetActive(pass, active); err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
		writePanelJSON(w, map[string]bool{"ok": true, "active": active})
		return
	}
	dbMutex.Lock()
	entry, ok := db.Passwords[pass]
	if !ok || entry == nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusNotFound, "not found")
		return
	}
	if active {
		if err := serverWrapKeys.AddPassword(pass); err != nil {
			dbMutex.Unlock()
			writePanelError(w, http.StatusInternalServerError, "activate: "+err.Error())
			return
		}
		entry.IsDeactivated = false
	} else {
		entry.IsDeactivated = true
		disconnectCredentialConnections(pass)
		serverWrapKeys.RemovePassword(pass)
		disconnectPasswordDevicesLocked(entry)
	}
	if err := saveDB(); err != nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	dbMutex.Unlock()
	writePanelJSON(w, map[string]bool{"ok": true, "active": active})
}

func handlePanelUnbindDevice(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	pass := strings.TrimSpace(r.FormValue("password"))
	deviceID := strings.TrimSpace(r.FormValue("device_id"))
	if pass == "" || deviceID == "" {
		writePanelError(w, http.StatusBadRequest, "password and device_id")
		return
	}
	if panelWdttAdminEnabled() {
		if err := panelAdminUnbindDevice(pass, deviceID); err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
		writePanelJSON(w, map[string]bool{"ok": true})
		return
	}
	dbMutex.Lock()
	entry, ok := db.Passwords[pass]
	if !ok || entry == nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusNotFound, "not found")
		return
	}
	disconnectCredentialDeviceConnections(pass, deviceID)
	unbindDevices(entry, deviceID)
	if err := saveDB(); err != nil {
		dbMutex.Unlock()
		writePanelError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	dbMutex.Unlock()
	writePanelJSON(w, map[string]bool{"ok": true})
}

const panelUpdateLogPath = "/var/log/qwdtt-panel-update.log"

func handlePanelUpdateLog(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	const maxTail = 96 << 10
	text, size, modTime, err := tailFile(panelUpdateLogPath, maxTail)
	if err != nil {
		writePanelJSON(w, map[string]interface{}{
			"path":   panelUpdateLogPath,
			"text":   "",
			"empty":  true,
			"status": "idle",
			"error":  "лог ещё не создан",
		})
		return
	}
	status := parseUpdateLogStatus(text, modTime)
	writePanelJSON(w, map[string]interface{}{
		"path":   panelUpdateLogPath,
		"text":   text,
		"size":   size,
		"mtime":  modTime.Local().Format("2006-01-02 15:04:05"),
		"empty":  len(strings.TrimSpace(text)) == 0,
		"status": status,
	})
}

func handlePanelLogs(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	active := panelLogsEnabled()
	text := panelLogText()
	if !active && text == "" {
		text = "логи выключены"
	}
	writePanelJSON(w, map[string]interface{}{
		"text":   text,
		"active": active,
	})
}

func handlePanelLogsClear(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := panelLogsClear(); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true})
}

func handlePanelLogsToggle(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	v := strings.TrimSpace(r.FormValue("active"))
	on := v == "1" || strings.EqualFold(v, "true") || v == "on"
	if v == "" {
		on = !panelLogsEnabled()
	}
	if err := panelLogsSet(on); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true, "active": on})
}

func handlePanelSocks(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		writePanelJSON(w, socksPanelState())
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if host == "" {
		host = "127.0.0.1"
	}
	port := uint16(0)
	if v := r.FormValue("port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			writePanelError(w, http.StatusBadRequest, "порт")
			return
		}
		port = uint16(n)
	}
	if port == 0 {
		writePanelError(w, http.StatusBadRequest, "укажите порт SOCKS5")
		return
	}
	p := socksFormProfile(host, strings.TrimSpace(r.FormValue("username")), r.FormValue("password"), port)
	if err := socksSaveAndEnable(p); err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	writePanelJSON(w, socksPanelState())
}

func handlePanelSocksCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := r.ParseForm(); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	n, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || n < 1 || n > 65535 {
		writePanelError(w, http.StatusBadRequest, "укажите порт")
		return
	}
	p := socksFormProfile(host, strings.TrimSpace(r.FormValue("username")), r.FormValue("password"), uint16(n))
	writePanelJSON(w, socksInspect(p))
}

func handlePanelSocksDeactivate(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	socksTurnOff()
	writePanelJSON(w, socksPanelState())
}

func panelUnitActive(unit string) (active bool, state string) {
	out, err := runCmdTimeout(2*time.Second, "systemctl", "is-active", unit)
	state = strings.TrimSpace(out)
	if state == "" {
		if err != nil {
			state = "unknown"
		} else {
			state = "unknown"
		}
	}
	// systemctl may append newline noise; take first token
	if i := strings.IndexAny(state, "\r\n"); i >= 0 {
		state = state[:i]
	}
	if state == "active" {
		return true, state
	}
	return false, state
}

func panelServiceSnapshot() map[string]interface{} {
	wdttOK, wdttState := panelUnitActive("wdtt")
	csqttOK, csqttState := panelUnitActive("csqtt")
	panelOK, panelState := panelUnitActive("qwdtt-panel")
	csqttAPI := false
	csqttVer := ""
	if st := csqttCachedStatus(); st != nil {
		if v, ok := st["connected"].(bool); ok {
			csqttAPI = v
		}
		if stats, ok := st["stats"].(map[string]interface{}); ok {
			csqttVer = csqttVersionFromAPI(stats)
		}
	}
	if csqttVer == "" {
		// CSQTT — Rust: stamp/buildinfo обычно нет, останется mtime.
		csqttVer = binaryVersion(envOr(os.Getenv("CSQTT_BIN_PATH"), csqttDefaultBin))
	}
	adminOK := false
	if panelWdttAdminEnabled() {
		if st := panelAdminStatus(); st != nil {
			adminOK = true
		}
	}
	// Версия с диска (stamp/buildinfo), не через exec и не из live API —
	// так видно именно установленный бинарник.
	qwdttVer := binaryVersion(envOr(os.Getenv("QWDTT_BIN"), wdttDefaultBin))
	return map[string]interface{}{
		"qwdtt": map[string]interface{}{
			"unit":     "wdtt",
			"active":   wdttOK,
			"state":    wdttState,
			"admin_ok": adminOK,
			"version":  qwdttVer,
			"tun":      qwdttTunCIDR,
			"iface":    wgIfaceName,
			"iface_up": ifaceUp(wgIfaceName),
		},
		"csqtt": map[string]interface{}{
			"unit":     "csqtt",
			"active":   csqttOK,
			"state":    csqttState,
			"api_ok":   csqttAPI,
			"version":  csqttVer,
			"tun":      csqttTunCIDR,
			"iface":    csqttTunIface,
			"iface_up": ifaceUp(csqttTunIface),
		},
		"panel": map[string]interface{}{
			"unit":    "qwdtt-panel",
			"active":  panelOK,
			"state":   panelState,
			"version": panelDisplayVersion(),
		},
	}
}

func handlePanelServices(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	writePanelJSON(w, panelServiceSnapshot())
}

func handlePanelRestart(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	_ = r.ParseForm()
	target := strings.ToLower(strings.TrimSpace(r.FormValue("target")))
	unit := ""
	switch target {
	case "qwdtt", "wdtt":
		unit = "wdtt"
		target = "qwdtt"
	case "csqtt":
		unit = "csqtt"
	case "panel", "qwdtt-panel":
		unit = "qwdtt-panel"
		target = "panel"
	default:
		writePanelError(w, http.StatusBadRequest, "target: qwdtt | csqtt | panel")
		return
	}
	cmd := exec.Command("systemctl", "restart", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		writePanelError(w, http.StatusBadGateway, msg)
		return
	}
	// Invalidate CSQTT status cache so Settings refresh is not stale.
	csqttStatMu.Lock()
	csqttStatVal = nil
	csqttStatAt = time.Time{}
	csqttStatMu.Unlock()
	invalidateBinaryVersionCache()
	time.Sleep(1200 * time.Millisecond)
	snap := panelServiceSnapshot()
	writePanelJSON(w, map[string]interface{}{
		"ok":       true,
		"target":   target,
		"unit":     unit,
		"services": snap,
	})
}

func handlePanelReboot(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	// VPS reboot removed — use /api/restart
	writePanelError(w, http.StatusGone, "используйте перезапуск сервисов")
}

func handlePanelUpdate(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	target := strings.ToLower(strings.TrimSpace(r.FormValue("target")))
	switch target {
	case "qwdtt", "panel", "csqtt", "all":
	default:
		target = "all"
	}
	mode := strings.ToLower(strings.TrimSpace(r.FormValue("mode")))
	switch mode {
	case "app", "source":
	default:
		mode = "source"
	}
	helper := "/usr/local/lib/qwdtt/update-server.sh"
	if err := os.MkdirAll(filepath.Dir(helper), 0755); err == nil && updateServerScript != "" {
		_ = os.WriteFile(helper, []byte(updateServerScript), 0755)
	}
	cmd := exec.Command("systemd-run", "--collect", "--no-block", helper, target, mode)
	if err := cmd.Start(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writePanelJSON(w, map[string]interface{}{"ok": true, "target": target, "mode": mode})
}
