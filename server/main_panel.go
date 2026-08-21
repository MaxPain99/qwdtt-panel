//go:build qwdtt_panel

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Отдельный бинарь панели: HTTPS UI + SOCKS5 TPROXY + мост CSQTT.
// qWDTT CRUD — через admin API wdtt-server (можно обновлять сервер с APK).
func main() {
	listen := flag.String("listen", "0.0.0.0:46102", "HTTPS адрес панели")
	configDir := flag.String("config-dir", "/etc/wdtt", "каталог конфигурации (panel.json, web.password)")
	webUser := flag.String("web-user", "admin", "логин панели")
	webPass := flag.String("web-pass", "", "пароль панели")
	webPassFile := flag.String("web-pass-file", "", "файл пароля панели")
	adminURL := flag.String("wdtt-admin", "https://127.0.0.1:56002", "admin API wdtt-server")
	adminTokenFile := flag.String("wdtt-admin-token-file", "", "токен admin API (по умолчанию config-dir/admin.token)")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("══════════════════════════════════════════")
	log.Println("   qWDTT Panel (standalone) + SOCKS5")
	log.Println("══════════════════════════════════════════")

	tokenPath := *adminTokenFile
	if tokenPath == "" {
		tokenPath = filepath.Join(*configDir, "admin.token")
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil || strings.TrimSpace(string(tokenBytes)) == "" {
		log.Fatalf("[PANEL] admin token (%s): %v — нужен admin API wdtt-server", tokenPath, err)
	}
	panelSetWdttAdmin(*adminURL, strings.TrimSpace(string(tokenBytes)))

	webPassValue, err := loadOptionalSecret(*webPass, *webPassFile)
	if err != nil {
		log.Fatalf("[PANEL] пароль: %v", err)
	}
	if webPassValue == "" {
		if b, e := os.ReadFile(filepath.Join(*configDir, "web.password")); e == nil {
			webPassValue = strings.TrimSpace(string(b))
		}
	}

	_, portStr, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatalf("[PANEL] listen: %v", err)
	}
	p64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || p64 == 0 {
		log.Fatalf("[PANEL] порт: %v", err)
	}
	startWebPanel(*configDir, uint16(p64), *webUser, webPassValue)
	socksRestore()
	log.Printf("[PANEL] SOCKS5 TPROXY готов (если включён в panel.json)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Println("[PANEL] остановка…")
	socksDeactivate()
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
}
