package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type panelLoginAttempt struct {
	count       int
	windowStart time.Time
	blockedTill time.Time
}

var (
	panelLoginMu       sync.Mutex
	panelLoginAttempts = map[string]panelLoginAttempt{}
)

func panelLoginHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func panelLoginBlocked(host string) bool {
	panelLoginMu.Lock()
	defer panelLoginMu.Unlock()
	a := panelLoginAttempts[host]
	return time.Now().Before(a.blockedTill)
}

func recordPanelLoginFailure(host string, now time.Time) {
	panelLoginMu.Lock()
	defer panelLoginMu.Unlock()
	for h, a := range panelLoginAttempts {
		if now.Sub(a.windowStart) > 10*time.Minute && now.After(a.blockedTill) {
			delete(panelLoginAttempts, h)
		}
	}
	a := panelLoginAttempts[host]
	if a.windowStart.IsZero() || now.Sub(a.windowStart) > time.Minute {
		a = panelLoginAttempt{windowStart: now}
	}
	a.count++
	if a.count >= 5 {
		a.blockedTill = now.Add(5 * time.Minute)
		a.count = 0
		a.windowStart = now
	}
	panelLoginAttempts[host] = a
}

func clearPanelLoginFailure(host string) {
	panelLoginMu.Lock()
	delete(panelLoginAttempts, host)
	panelLoginMu.Unlock()
}

func handlePanelHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	writePanelJSON(w, enrichHealthResponse())
}

func handlePanelJournal(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	unit := strings.TrimSpace(r.URL.Query().Get("unit"))
	switch unit {
	case "wdtt", "csqtt", "panel", "qwdtt-panel":
	default:
		unit = "panel"
	}
	systemdUnit := unit
	if unit == "panel" {
		systemdUnit = "qwdtt-panel"
	}
	lines := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("lines")); err == nil && n > 0 && n <= 2000 {
		lines = n
	}
	out, err := runCmdTimeout(8*time.Second, "journalctl", "-u", systemdUnit, "-n", fmt.Sprintf("%d", lines), "--no-pager", "-o", "short-iso")
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		writePanelJSON(w, map[string]interface{}{
			"unit":  systemdUnit,
			"text":  msg,
			"error": "journalctl недоступен (нужен Linux + systemd)",
		})
		return
	}
	writePanelJSON(w, map[string]interface{}{
		"unit": systemdUnit,
		"text": out,
	})
}

func handlePanelChangePassword(w http.ResponseWriter, r *http.Request) {
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
	cur := r.FormValue("current")
	newPass := r.FormValue("new")
	if cur == "" || newPass == "" {
		writePanelError(w, http.StatusBadRequest, "укажите текущий и новый пароль")
		return
	}
	if len(newPass) < 8 {
		writePanelError(w, http.StatusBadRequest, "новый пароль: минимум 8 символов")
		return
	}
	got := hashPanelPass(panelUser, cur)
	if subtle.ConstantTimeCompare(got[:], panelPassHash[:]) != 1 {
		writePanelError(w, http.StatusForbidden, "неверный текущий пароль")
		return
	}
	panelPassHash = hashPanelPass(panelUser, newPass)
	_ = os.WriteFile(filepath.Join(panelDir, "web.password"), []byte(newPass+"\n"), 0600)
	if err := persistPanelStore(); err != nil {
		writePanelError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true})
}

func resolvePanelTLSPaths() (certPath, keyPath string) {
	defCert := filepath.Join(panelDir, panelCertFile)
	defKey := filepath.Join(panelDir, panelKeyFile)
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore == nil {
		return defCert, defKey
	}
	c := strings.TrimSpace(panelStore.TLSCertFile)
	k := strings.TrimSpace(panelStore.TLSKeyFile)
	if c != "" && k != "" {
		return c, k
	}
	return defCert, defKey
}

func isDefaultPanelTLS(certPath, keyPath string) bool {
	defCert := filepath.Join(panelDir, panelCertFile)
	defKey := filepath.Join(panelDir, panelKeyFile)
	return filepath.Clean(certPath) == filepath.Clean(defCert) && filepath.Clean(keyPath) == filepath.Clean(defKey)
}

func panelCertInfo() map[string]interface{} {
	certPath, _ := resolvePanelTLSPaths()
	b, err := os.ReadFile(certPath)
	if err != nil {
		return map[string]interface{}{"error": "сертификат не найден"}
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return map[string]interface{}{"error": "неверный PEM"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	selfSigned := cert.Issuer.String() == cert.Subject.String()
	return map[string]interface{}{
		"subject":     cert.Subject.CommonName,
		"issuer":      cert.Issuer.CommonName,
		"not_before":  cert.NotBefore.Local().Format("2006-01-02"),
		"not_after":   cert.NotAfter.Local().Format("2006-01-02"),
		"self_signed": selfSigned,
		"dns_names":   cert.DNSNames,
	}
}

func handlePanelTLS(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		certPath, keyPath := resolvePanelTLSPaths()
		info := panelCertInfo()
		info["path"] = certPath
		info["cert_file"] = certPath
		info["key_file"] = keyPath
		info["custom_paths"] = !isDefaultPanelTLS(certPath, keyPath)
		panelStoreMu.Lock()
		linkHost := ""
		if panelStore != nil {
			info["cert_file_setting"] = panelStore.TLSCertFile
			info["key_file_setting"] = panelStore.TLSKeyFile
			linkHost = strings.TrimSpace(panelStore.LinkHost)
		}
		panelStoreMu.Unlock()
		info["link_host"] = linkHost
		info["peer_host"] = panelLinkHost()
		writePanelJSON(w, info)
	case http.MethodPost:
		if err := parsePanelForm(r); err != nil {
			writePanelError(w, http.StatusBadRequest, "form")
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		switch action {
		case "upload":
			panelTLSUpload(w, r)
		case "letsencrypt":
			panelTLSLetsencrypt(w, r)
		case "paths":
			panelTLSSetPaths(w, r)
		case "link_host":
			panelTLSSetLinkHost(w, r)
		case "clear_paths":
			panelTLSClearPaths(w, r)
		default:
			writePanelError(w, http.StatusBadRequest, "action: paths | link_host | upload | letsencrypt | clear_paths")
		}
	default:
		writePanelError(w, http.StatusMethodNotAllowed, "method")
	}
}

func panelTLSSetLinkHost(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		writePanelError(w, http.StatusBadRequest, "укажите домен")
		return
	}
	setPanelLinkHost(domain)
	if err := persistPanelStore(); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	panelAudit("link_host", panelLinkHost())
	writePanelJSON(w, map[string]interface{}{
		"ok":        true,
		"message":   "домен для ссылок: " + panelLinkHost(),
		"link_host": panelLinkHost(),
	})
}

func panelTLSSetPaths(w http.ResponseWriter, r *http.Request) {
	certFile := strings.TrimSpace(r.FormValue("cert_file"))
	keyFile := strings.TrimSpace(r.FormValue("key_file"))
	if certFile == "" || keyFile == "" {
		writePanelError(w, http.StatusBadRequest, "укажите пути к cert и key")
		return
	}
	if !filepath.IsAbs(certFile) || !filepath.IsAbs(keyFile) {
		writePanelError(w, http.StatusBadRequest, "нужны абсолютные пути (например /etc/letsencrypt/live/.../fullchain.pem)")
		return
	}
	certFile = filepath.Clean(certFile)
	keyFile = filepath.Clean(keyFile)
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		writePanelError(w, http.StatusBadRequest, "не удалось прочитать пару: "+err.Error())
		return
	}
	panelStoreMu.Lock()
	if panelStore == nil {
		panelStore = &panelFileStore{}
	}
	panelStore.TLSCertFile = certFile
	panelStore.TLSKeyFile = keyFile
	panelStoreMu.Unlock()
	if h := linkHostFromCertPath(certFile); h != "" {
		setPanelLinkHost(h)
	}
	if err := persistPanelStore(); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	panelAudit("tls_paths", certFile)
	writePanelJSON(w, map[string]interface{}{
		"ok":      true,
		"message": "пути сохранены — сертификат подхватится сразу (без перезапуска)",
		"cert":    panelCertInfo(),
		"cert_file": certFile,
		"key_file":  keyFile,
	})
}

func panelTLSClearPaths(w http.ResponseWriter, r *http.Request) {
	panelStoreMu.Lock()
	if panelStore != nil {
		panelStore.TLSCertFile = ""
		panelStore.TLSKeyFile = ""
	}
	panelStoreMu.Unlock()
	if err := persistPanelStore(); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	certPath := filepath.Join(panelDir, panelCertFile)
	keyPath := filepath.Join(panelDir, panelKeyFile)
	_ = ensurePanelTLS(certPath, keyPath)
	panelAudit("tls_paths", "cleared")
	writePanelJSON(w, map[string]interface{}{
		"ok":      true,
		"message": "вернулись к локальному panel.crt / panel.key",
		"cert":    panelCertInfo(),
	})
}

func panelTLSUpload(w http.ResponseWriter, r *http.Request) {
	certPEM := strings.TrimSpace(r.FormValue("cert"))
	keyPEM := strings.TrimSpace(r.FormValue("key"))
	if certPEM == "" || keyPEM == "" {
		writePanelError(w, http.StatusBadRequest, "cert и key (PEM) обязательны")
		return
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		writePanelError(w, http.StatusBadRequest, "неверная пара cert/key: "+err.Error())
		return
	}
	certPath := filepath.Join(panelDir, panelCertFile)
	keyPath := filepath.Join(panelDir, panelKeyFile)
	ts := time.Now().Format("20060102-150405")
	_ = os.Rename(certPath, certPath+".bak."+ts)
	_ = os.Rename(keyPath, keyPath+".bak."+ts)
	if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// после ручной загрузки PEM — используем локальные файлы
	panelStoreMu.Lock()
	if panelStore != nil {
		panelStore.TLSCertFile = ""
		panelStore.TLSKeyFile = ""
	}
	panelStoreMu.Unlock()
	_ = persistPanelStore()
	writePanelJSON(w, map[string]interface{}{
		"ok":      true,
		"message": "сертификат сохранён",
		"cert":    panelCertInfo(),
	})
}

func panelTLSLetsencrypt(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.FormValue("domain"))
	email := strings.TrimSpace(r.FormValue("email"))
	if domain == "" || email == "" {
		writePanelError(w, http.StatusBadRequest, "domain и email обязательны")
		return
	}
	setPanelLinkHost(domain)
	_ = persistPanelStore()
	if _, err := exec.LookPath("certbot"); err != nil {
		writePanelError(w, http.StatusBadRequest, "certbot не установлен на сервере")
		return
	}
	cmd := exec.Command("certbot", "certonly", "--standalone",
		"-d", domain, "--email", email, "--agree-tos", "--non-interactive")
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Run(); err != nil {
		_ = os.WriteFile(filepath.Join(panelDir, "letsencrypt.log"), outBuf.Bytes(), 0600)
		writePanelError(w, http.StatusBadGateway, strings.TrimSpace(outBuf.String()))
		return
	}
	chain := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	key := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")
	if _, err := tls.LoadX509KeyPair(chain, key); err != nil {
		writePanelError(w, http.StatusBadGateway, "certbot OK, но файлы нечитаемы: "+err.Error())
		return
	}
	panelStoreMu.Lock()
	if panelStore == nil {
		panelStore = &panelFileStore{}
	}
	panelStore.TLSCertFile = chain
	panelStore.TLSKeyFile = key
	panelStoreMu.Unlock()
	setPanelLinkHost(domain)
	if err := persistPanelStore(); err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	panelAudit("tls_letsencrypt", domain)
	writePanelJSON(w, map[string]interface{}{
		"ok":        true,
		"message":   "Let's Encrypt OK — ссылки клиентов будут с доменом " + domain,
		"cert":      panelCertInfo(),
		"cert_file": chain,
		"key_file":  key,
		"link_host": panelLinkHost(),
	})
}

func parseUpdateLogStatus(text string, modTime time.Time) string {
	if st := readUpdateJobStatus(); st != "" {
		return st
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "exit code") {
		return "error"
	}
	if strings.Contains(lower, "обновлён") || strings.Contains(lower, "updated") {
		return "success"
	}
	if time.Since(modTime) < 2*time.Minute && strings.TrimSpace(text) != "" {
		return "running"
	}
	if strings.TrimSpace(text) == "" {
		return "idle"
	}
	return "idle"
}

func handlePanelClientsExport(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	type exportRow map[string]interface{}
	rows := []exportRow{}
	if kind == "" || kind == "qwdtt" || kind == "all" {
		if panelWdttAdminEnabled() {
			list, err := panelAdminListPasswords()
			if err == nil {
				for _, e := range list {
					exp := ""
					if e.ExpiresAt > 0 {
						exp = time.Unix(e.ExpiresAt, 0).Format("2006-01-02")
					}
					_, q := panelClientLink(e.Password, e.VkHash)
					rows = append(rows, exportRow{
						"kind": "qwdtt", "label": e.Label, "password": e.Password,
						"expires": exp, "max_devices": e.MaxDevices, "deactivated": e.IsDeactivated,
						"link": q, "hashes": e.VkHash,
					})
				}
			}
		} else if db != nil {
			dbMutex.Lock()
			for pass, e := range db.Passwords {
				if e == nil {
					continue
				}
				exp := ""
				if e.ExpiresAt > 0 {
					exp = time.Unix(e.ExpiresAt, 0).Format("2006-01-02")
				}
				_, q := panelClientLink(pass, e.VkHash)
				rows = append(rows, exportRow{
					"kind": "qwdtt", "label": e.Label, "password": pass,
					"expires": exp, "max_devices": e.MaxDevices, "deactivated": e.IsDeactivated,
					"link": q, "hashes": e.VkHash,
				})
			}
			dbMutex.Unlock()
		}
	}
	if kind == "" || kind == "csqtt" || kind == "all" {
		if list, err := csqttListClients(); err == nil {
			for _, c := range list {
				if owner, _ := c["owner"].(bool); owner {
					continue
				}
				rows = append(rows, exportRow{
					"kind": "csqtt", "label": c["label"], "password": c["password"],
					"expires": c["expires"], "deactivated": c["deactivated"],
					"link": c["csqtt_link"], "hashes": c["hashes"],
				})
			}
		}
	}
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="qwdtt-clients.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"kind", "label", "password", "expires", "hashes", "link", "deactivated"})
		for _, row := range rows {
			_ = cw.Write([]string{
				fmt.Sprint(row["kind"]), fmt.Sprint(row["label"]), fmt.Sprint(row["password"]),
				fmt.Sprint(row["expires"]), fmt.Sprint(row["hashes"]), fmt.Sprint(row["link"]),
				fmt.Sprint(row["deactivated"]),
			})
		}
		cw.Flush()
	default:
		writePanelJSON(w, map[string]interface{}{"clients": rows, "count": len(rows)})
	}
}

func tailFile(path string, maxBytes int64) (text string, size int64, modTime time.Time, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	defer f.Close()
	size = st.Size()
	modTime = st.ModTime()
	start := int64(0)
	if size > maxBytes {
		start = size - maxBytes
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return "", size, modTime, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", size, modTime, err
	}
	text = string(b)
	if start > 0 {
		if i := strings.IndexByte(text, '\n'); i >= 0 && i+1 < len(text) {
			text = text[i+1:]
		}
		text = "…\n" + text
	}
	return text, size, modTime, nil
}
