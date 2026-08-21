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
	ActiveSocksID string         `json:"active_socks_id,omitempty"`
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

	certPath := filepath.Join(configDir, panelCertFile)
	keyPath := filepath.Join(configDir, panelKeyFile)
	if err := ensurePanelTLS(certPath, keyPath); err != nil {
		log.Printf("[WEB] TLS: %v", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handlePanelLogin)
	mux.HandleFunc("/logout", handlePanelLogout)
	mux.HandleFunc("/", handlePanelIndex)
	mux.HandleFunc("/api/status", handlePanelStatus)
	mux.HandleFunc("/api/clients", handlePanelClients)
	mux.HandleFunc("/api/clients/delete", handlePanelDeleteClient)
	mux.HandleFunc("/api/logs", handlePanelLogs)
	mux.HandleFunc("/api/logs/clear", handlePanelLogsClear)
	mux.HandleFunc("/api/logs/toggle", handlePanelLogsToggle)
	mux.HandleFunc("/api/socks", handlePanelSocks)
	mux.HandleFunc("/api/socks/check", handlePanelSocksCheck)
	mux.HandleFunc("/api/socks/deactivate", handlePanelSocksDeactivate)
	mux.HandleFunc("/api/reboot", handlePanelReboot)
	mux.HandleFunc("/api/update-server", handlePanelUpdate)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 8 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		log.Printf("[WEB] HTTPS панель https://0.0.0.0:%d логин %s", port, user)
		if err := server.ListenAndServeTLS(certPath, keyPath); err != nil {
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
	_ = r.ParseForm()
	user := strings.TrimSpace(r.FormValue("user"))
	pass := r.FormValue("pass")
	got := hashPanelPass(user, pass)
	if subtle.ConstantTimeCompare(got[:], panelPassHash[:]) != 1 || user != panelUser {
		http.Redirect(w, r, "/login?bad=1", http.StatusFound)
		return
	}
	tok := randomPanelPass() + randomPanelPass()
	panelSessMu.Lock()
	panelSessions[tok] = time.Now().Add(12 * time.Hour)
	panelSessMu.Unlock()
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
	up := time.Since(serverStartTime)
	if serverStartTime.IsZero() {
		up = 0
	}
	socksOn, socksTCP, socksUDP, socksHealth := socksSnapshot()
	writePanelJSON(w, map[string]interface{}{
		"active":       atomic.LoadInt32(&activeConns),
		"total":        atomic.LoadInt64(&totalConns),
		"up_bytes":     atomic.LoadInt64(&totalBytesFromClient),
		"down_bytes":   atomic.LoadInt64(&totalBytesToClient),
		"uptime":       formatUptime(up),
		"nat":          natType,
		"logs_active":  panelLogsEnabled(),
		"socks_on":     socksOn,
		"socks_tcp":    socksTCP,
		"socks_udp":    socksUDP,
		"socks_health": socksHealth,
	})
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

func handlePanelClients(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		type row struct {
			Label         string `json:"label"`
			Password      string `json:"password"`
			Owner         bool   `json:"owner"`
			Up            int64  `json:"up"`
			Down          int64  `json:"down"`
			MaxDevices    int    `json:"max_devices"`
			ActiveDevices int    `json:"active_devices"`
			Expires       string `json:"expires"`
			Deactivated   bool   `json:"deactivated"`
			Hashes        string `json:"hashes"`
			QWDTTLink     string `json:"qwdtt_link"`
			WDTTLink      string `json:"wdtt_link"`
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
		if err != nil || n < 1 || n > 365 {
			writePanelError(w, http.StatusBadRequest, "days")
			return
		}
		days = n
	}
	label := strings.TrimSpace(r.FormValue("label"))
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
	db.Passwords[newPass] = &PasswordEntry{
		Label:      label,
		ExpiresAt:  time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix(),
		MaxDevices: 1,
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
	_, qwdtt := panelClientLink(newPass, vkHash)
	writePanelJSON(w, map[string]string{
		"password":   newPass,
		"qwdtt_link": qwdtt,
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

func handlePanelReboot(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true})
	go func() {
		time.Sleep(time.Second)
		exec.Command("systemctl", "reboot").Run()
	}()
}

func handlePanelUpdate(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	helper := "/usr/local/lib/qwdtt/update-server.sh"
	if err := os.MkdirAll(filepath.Dir(helper), 0755); err == nil && updateServerScript != "" {
		_ = os.WriteFile(helper, []byte(updateServerScript), 0755)
	}
	cmd := exec.Command("systemd-run", "--collect", "--no-block", helper)
	if err := cmd.Start(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true})
}
