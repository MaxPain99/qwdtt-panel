//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	socksTproxyPort = 11662
	socksMarkHex    = "0x62"
	socksMarkSpec   = "0x62/0x62"
	socksTable      = "162"
	socksRulePref   = "162"
	socksComment    = "QWDTT_SOCKS"
	socksUDPIdle    = 60 * time.Second
	socksMaxTCP     = 2048
	socksMaxUDP     = 2048
)

type socksEngine struct {
	mu      sync.Mutex
	profile SocksProfile
	cancel  chan struct{}
	ln      net.Listener
	pc      net.PacketConn
	tcpN    atomic.Int32
	udpN    atomic.Int32
	health  string
	alive   atomic.Bool
	rulesOn atomic.Bool
}

var socksEng *socksEngine

func socksSnapshot() (active bool, tcp, udp int, health string) {
	e := socksEng
	if e == nil {
		return false, 0, 0, ""
	}
	return e.alive.Load(), int(e.tcpN.Load()), int(e.udpN.Load()), e.health
}

func socksRestore() {
	panelStoreMu.Lock()
	on := false
	var p *SocksProfile
	if panelStore != nil && panelStore.SocksOn && panelStore.Socks != nil && panelStore.Socks.Port != 0 {
		on = true
		cp := *panelStore.Socks
		p = &cp
	}
	panelStoreMu.Unlock()
	if !on || p == nil {
		return
	}
	if err := socksActivate(*p); err != nil {
		log.Printf("[SOCKS] не удалось восстановить: %v — прямой выход", err)
	}
}

func socksActivate(p SocksProfile) error {
	if p.Port == 0 {
		return errors.New("укажите порт SOCKS5")
	}
	chk := socksInspect(p)
	if !chk.Allow {
		return errors.New(chk.Message)
	}
	socksDeactivate()
	e := &socksEngine{
		profile: p,
		cancel:  make(chan struct{}),
		health:  "ok",
	}
	csqttPrepareSharedSocks()
	if err := e.startListeners(); err != nil {
		return err
	}
	if err := socksInstallNet(); err != nil {
		close(e.cancel)
		if e.ln != nil {
			e.ln.Close()
		}
		if e.pc != nil {
			e.pc.Close()
		}
		return err
	}
	e.alive.Store(true)
	e.rulesOn.Store(true)
	socksEng = e
	go e.healthLoop()
	log.Printf("[SOCKS] активен %s — трафик с %s на SOCKS5", socksDialAddr(p), strings.Join(socksIfaces(), ", "))
	return nil
}

func socksDeactivate() {
	e := socksEng
	socksEng = nil
	socksRemoveNet()
	if e == nil {
		return
	}
	if e.ln != nil {
		e.ln.Close()
	}
	if e.pc != nil {
		e.pc.Close()
	}
	e.alive.Store(false)
	e.rulesOn.Store(false)
	select {
	case <-e.cancel:
	default:
		close(e.cancel)
	}
	e.health = "выкл"
	log.Println("[SOCKS] выключен, выход с VPS напрямую")
}

func socksRefreshIfaces() {
	e := socksEng
	if e == nil || !e.alive.Load() {
		return
	}
	_ = socksInstallIptables()
}

func (e *socksEngine) healthLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.cancel:
			return
		case <-t.C:
			if socksEng != e {
				return
			}
			if socksPortOpen(e.profile) {
				if !e.rulesOn.Load() {
					if err := socksInstallIptables(); err == nil {
						e.rulesOn.Store(true)
						e.health = "ok"
						log.Println("[SOCKS] прокси снова доступен")
					}
				} else {
					e.health = "ok"
					socksEnsureIfaces()
				}
				continue
			}
			if e.rulesOn.Load() {
				socksRemoveIptables()
				e.rulesOn.Store(false)
				e.health = "SOCKS не отвечает — выход напрямую"
				log.Println("[SOCKS] прокси молчит, TPROXY снят")
			}
		}
	}
}

func (e *socksEngine) startListeners() error {
	ln, err := listenTransparentTCP("0.0.0.0:" + strconv.Itoa(socksTproxyPort))
	if err != nil {
		return fmt.Errorf("TPROXY tcp: %w", err)
	}
	pc, err := listenTransparentUDP("0.0.0.0:" + strconv.Itoa(socksTproxyPort))
	if err != nil {
		ln.Close()
		return fmt.Errorf("TPROXY udp: %w", err)
	}
	e.ln = ln
	e.pc = pc
	go e.serveTCP(ln)
	go e.serveUDP(pc)
	return nil
}

func listenTransparentTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				if sockErr == nil {
					sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp4", addr)
}

func listenTransparentUDP(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				if sockErr == nil {
					sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
				}
				if sockErr == nil {
					sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

type socksUDPFlow struct {
	assoc  *socksUDPAssoc
	udp    *net.UDPConn
	src    *net.UDPAddr
	dst    *net.UDPAddr
	expire time.Time
}

func (e *socksEngine) serveTCP(ln net.Listener) {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-e.cancel:
				return
			default:
				return
			}
		}
		if e.tcpN.Load() >= socksMaxTCP {
			c.Close()
			continue
		}
		go e.handleTCP(c)
	}
}

func (e *socksEngine) handleTCP(client net.Conn) {
	defer client.Close()
	host, portStr, err := net.SplitHostPort(client.LocalAddr().String())
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	port, _ := strconv.Atoi(portStr)
	if ip == nil || port <= 0 {
		return
	}
	e.tcpN.Add(1)
	defer e.tcpN.Add(-1)
	up, err := socks5Connect(e.profile, ip, uint16(port))
	if err != nil {
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, client) }()
	_, _ = io.Copy(client, up)
}

func (e *socksEngine) serveUDP(pc net.PacketConn) {
	defer pc.Close()
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	var mu sync.Mutex
	flows := map[string]*socksUDPFlow{}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-e.cancel:
				return
			case <-t.C:
				now := time.Now()
				mu.Lock()
				for k, f := range flows {
					if now.After(f.expire) {
						if f.assoc != nil && f.assoc.ctrl != nil {
							f.assoc.ctrl.Close()
						}
						if f.udp != nil {
							f.udp.Close()
						}
						delete(flows, k)
						e.udpN.Add(-1)
					}
				}
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, 2048)
	oob := make([]byte, 256)
	for {
		select {
		case <-e.cancel:
			return
		default:
		}
		_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, oobn, _, src, err := uc.ReadMsgUDP(buf, oob)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-e.cancel:
				return
			default:
				return
			}
		}
		dst, err := parseOrigDst(oob[:oobn])
		if err != nil || dst == nil || src == nil {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		key := src.String()
		mu.Lock()
		f := flows[key]
		if f == nil {
			if e.udpN.Load() >= socksMaxUDP {
				mu.Unlock()
				continue
			}
			assoc, aerr := socks5UDPAssociate(e.profile)
			if aerr != nil {
				mu.Unlock()
				continue
			}
			uconn, uerr := net.DialUDP("udp4", nil, assoc.relay)
			if uerr != nil {
				assoc.ctrl.Close()
				mu.Unlock()
				continue
			}
			f = &socksUDPFlow{assoc: assoc, udp: uconn, src: src, dst: dst, expire: time.Now().Add(socksUDPIdle)}
			flows[key] = f
			e.udpN.Add(1)
			go e.udpDown(f, src)
		}
		f.dst = dst
		f.expire = time.Now().Add(socksUDPIdle)
		pkt := socksUDPEncode(dst, payload)
		mu.Unlock()
		if pkt != nil && f.udp != nil {
			_, _ = f.udp.Write(pkt)
		}
	}
}

func (e *socksEngine) udpDown(f *socksUDPFlow, client *net.UDPAddr) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-e.cancel:
			return
		default:
		}
		if f.udp == nil {
			return
		}
		_ = f.udp.SetReadDeadline(time.Now().Add(socksUDPIdle))
		n, err := f.udp.Read(buf)
		if err != nil {
			return
		}
		_, payload, err := socksUDPDecode(buf[:n])
		if err != nil {
			continue
		}
		if f.dst != nil {
			_ = sendTransparentUDP(payload, f.dst, client)
		}
	}
}

func parseOrigDst(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_IP {
			continue
		}
		if m.Header.Type != unix.IP_ORIGDSTADDR && m.Header.Type != unix.IP_RECVORIGDSTADDR {
			continue
		}
		if len(m.Data) < 8 {
			continue
		}
		port := int(binary.BigEndian.Uint16(m.Data[2:4]))
		ip := net.IPv4(m.Data[4], m.Data[5], m.Data[6], m.Data[7])
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	return nil, errors.New("нет original dest")
}

func sendTransparentUDP(payload []byte, src, dst *net.UDPAddr) error {
	if src == nil || dst == nil || src.IP.To4() == nil || dst.IP.To4() == nil {
		return errors.New("udp addr")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	lsa := &unix.SockaddrInet4{Port: src.Port}
	copy(lsa.Addr[:], src.IP.To4())
	if err := unix.Bind(fd, lsa); err != nil {
		return err
	}
	rsa := &unix.SockaddrInet4{Port: dst.Port}
	copy(rsa.Addr[:], dst.IP.To4())
	return unix.Sendto(fd, payload, 0, rsa)
}

func socksIfaceNames() []string {
	return socksIfaces()
}

func socksIfaces() []string {
	out := []string{wgIfaceName}
	for _, name := range []string{rawIfaceName, csqttTunIface} {
		if _, err := os.Stat("/sys/class/net/" + name); err == nil {
			out = append(out, name)
		}
	}
	return out
}

func socksInstallNet() error {
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/route_localnet", []byte("1"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/lo/route_localnet", []byte("1"), 0644)
	runCmdSilent("ip", "rule", "del", "fwmark", socksMarkHex, "lookup", socksTable)
	if out, err := runCmd("ip", "rule", "add", "fwmark", socksMarkHex, "lookup", socksTable, "pref", socksRulePref); err != nil {
		return fmt.Errorf("ip rule: %s", out)
	}
	runCmdSilent("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", socksTable)
	return socksInstallIptables()
}

func socksInstallIptables() error {
	if !commandExists("iptables") {
		return errors.New("нет iptables")
	}
	socksRemoveIptables()
	socksClearCsqttTproxy()
	port := strconv.Itoa(socksTproxyPort)
	for _, iface := range socksIfaces() {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "mangle", "-A", "PREROUTING",
				"-i", iface, "-p", proto,
				"-m", "addrtype", "!", "--dst-type", "LOCAL",
				"-m", "comment", "--comment", socksComment,
				"-j", "TPROXY", "--on-port", port, "--tproxy-mark", socksMarkSpec,
			}
			if out, err := runCmd("iptables", args...); err != nil {
				return fmt.Errorf("iptables TPROXY %s %s: %s", iface, proto, out)
			}
		}
		runCmdSilent("iptables", "-I", "INPUT", "-i", iface, "-m", "mark", "--mark", socksMarkSpec,
			"-m", "comment", "--comment", socksComment, "-j", "ACCEPT")
	}
	return nil
}

func socksEnsureIfaces() {
	socksClearCsqttTproxy()
	if !commandExists("iptables") {
		return
	}
	port := strconv.Itoa(socksTproxyPort)
	for _, iface := range socksIfaces() {
		for _, proto := range []string{"tcp", "udp"} {
			check := []string{"-t", "mangle", "-C", "PREROUTING",
				"-i", iface, "-p", proto,
				"-m", "addrtype", "!", "--dst-type", "LOCAL",
				"-m", "comment", "--comment", socksComment,
				"-j", "TPROXY", "--on-port", port, "--tproxy-mark", socksMarkSpec,
			}
			if _, err := runCmd("iptables", check...); err != nil {
				args := []string{"-t", "mangle", "-A", "PREROUTING",
					"-i", iface, "-p", proto,
					"-m", "addrtype", "!", "--dst-type", "LOCAL",
					"-m", "comment", "--comment", socksComment,
					"-j", "TPROXY", "--on-port", port, "--tproxy-mark", socksMarkSpec,
				}
				runCmdSilent("iptables", args...)
			}
		}
		inCheck := []string{"-C", "INPUT", "-i", iface, "-m", "mark", "--mark", socksMarkSpec,
			"-m", "comment", "--comment", socksComment, "-j", "ACCEPT"}
		if _, err := runCmd("iptables", inCheck...); err != nil {
			runCmdSilent("iptables", "-I", "INPUT", "-i", iface, "-m", "mark", "--mark", socksMarkSpec,
				"-m", "comment", "--comment", socksComment, "-j", "ACCEPT")
		}
	}
}

func socksRemoveIptables() {
	if !commandExists("iptables") {
		return
	}
	port := strconv.Itoa(socksTproxyPort)
	for i := 0; i < 8; i++ {
		for _, iface := range []string{wgIfaceName, rawIfaceName, csqttTunIface} {
			for _, proto := range []string{"tcp", "udp"} {
				runCmdSilent("iptables", "-t", "mangle", "-D", "PREROUTING",
					"-i", iface, "-p", proto,
					"-m", "addrtype", "!", "--dst-type", "LOCAL",
					"-m", "comment", "--comment", socksComment,
					"-j", "TPROXY", "--on-port", port, "--tproxy-mark", socksMarkSpec)
			}
			runCmdSilent("iptables", "-D", "INPUT", "-i", iface, "-m", "mark", "--mark", socksMarkSpec,
				"-m", "comment", "--comment", socksComment, "-j", "ACCEPT")
		}
	}
}

func socksRemoveNet() {
	socksRemoveIptables()
	runCmdSilent("ip", "rule", "del", "fwmark", socksMarkHex, "lookup", socksTable)
	runCmdSilent("ip", "route", "flush", "table", socksTable)
}

func socksClearCsqttTproxy() {
	if !commandExists("iptables") {
		return
	}
	dump, err := runCmd("iptables-save")
	if err != nil || dump == "" {
		return
	}
	table := ""
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if line == "COMMIT" {
			table = ""
			continue
		}
		if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, "CSQTT_TPROXY") {
			continue
		}
		args := []string{}
		if table != "" && table != "filter" {
			args = append(args, "-t", table)
		}
		args = append(args, "-D")
		args = append(args, splitIptablesArgs(strings.TrimPrefix(line, "-A "))...)
		runCmdSilent("iptables", args...)
	}
	runCmdSilent("ip", "rule", "del", "fwmark", "0x1/0x1", "lookup", "100")
}

func splitIptablesArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ' ' && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
