package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func socksDialAddr(p SocksProfile) string {
	host := p.Host
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p.Port)))
}

func socksTCPDial(p SocksProfile, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", socksDialAddr(p), timeout)
}

func socks5Handshake(conn net.Conn, user, pass string) error {
	if user != "" {
		if _, err := conn.Write([]byte{5, 2, 0x00, 0x02}); err != nil {
			return err
		}
	} else if _, err := conn.Write([]byte{5, 1, 0x00}); err != nil {
		return err
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return errors.New("SOCKS: не версия 5")
	}
	switch hdr[1] {
	case 0x00:
		return nil
	case 0x02:
		if user == "" {
			return errors.New("SOCKS: нужна авторизация")
		}
		u, pw := []byte(user), []byte(pass)
		if len(u) > 255 || len(pw) > 255 {
			return errors.New("SOCKS: логин/пароль слишком длинные")
		}
		req := make([]byte, 0, 3+len(u)+len(pw))
		req = append(req, 1, byte(len(u)))
		req = append(req, u...)
		req = append(req, byte(len(pw)))
		req = append(req, pw...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return err
		}
		if hdr[1] != 0 {
			return errors.New("SOCKS: отказ авторизации")
		}
		return nil
	case 0xff:
		return errors.New("SOCKS: нет подходящего метода")
	default:
		return fmt.Errorf("SOCKS: метод %d", hdr[1])
	}
}

func socks5ReadReply(conn net.Conn) (net.IP, uint16, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, 0, err
	}
	if hdr[0] != 5 {
		return nil, 0, errors.New("SOCKS: неверная версия ответа")
	}
	if hdr[1] != 0 {
		return nil, 0, fmt.Errorf("SOCKS: ответ %d", hdr[1])
	}
	switch hdr[3] {
	case 1:
		rest := make([]byte, 6)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, 0, err
		}
		return net.IPv4(rest[0], rest[1], rest[2], rest[3]), binary.BigEndian.Uint16(rest[4:]), nil
	case 3:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			return nil, 0, err
		}
		rest := make([]byte, int(ln[0])+2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, 0, err
		}
		host := string(rest[:len(rest)-2])
		port := binary.BigEndian.Uint16(rest[len(rest)-2:])
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return net.IPv4zero, port, nil
			}
			ip = ips[0]
		}
		if v4 := ip.To4(); v4 != nil {
			return v4, port, nil
		}
		return net.IPv4zero, port, nil
	case 4:
		rest := make([]byte, 18)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, 0, err
		}
		return net.IPv4zero, binary.BigEndian.Uint16(rest[16:]), nil
	default:
		return nil, 0, fmt.Errorf("SOCKS: atyp %d", hdr[3])
	}
}

func socks5Command(conn net.Conn, cmd byte, ip net.IP, port uint16) (net.IP, uint16, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, 0, errors.New("SOCKS: нужен IPv4")
	}
	req := []byte{5, cmd, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(req[8:], port)
	if _, err := conn.Write(req); err != nil {
		return nil, 0, err
	}
	return socks5ReadReply(conn)
}

func socks5Connect(p SocksProfile, ip net.IP, port uint16) (net.Conn, error) {
	conn, err := socksTCPDial(p, 8*time.Second)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5Handshake(conn, p.Username, p.Password); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, err := socks5Command(conn, 0x01, ip, port); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

type socksUDPAssoc struct {
	ctrl  net.Conn
	relay *net.UDPAddr
}

func socks5UDPAssociate(p SocksProfile) (*socksUDPAssoc, error) {
	conn, err := socksTCPDial(p, 8*time.Second)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5Handshake(conn, p.Username, p.Password); err != nil {
		conn.Close()
		return nil, err
	}
	bindIP, bindPort, err := socks5Command(conn, 0x03, net.IPv4zero, 0)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if bindIP == nil || bindIP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		bindIP = net.ParseIP(host)
	}
	if bindIP == nil {
		conn.Close()
		return nil, errors.New("SOCKS: пустой UDP relay")
	}
	return &socksUDPAssoc{
		ctrl:  conn,
		relay: &net.UDPAddr{IP: bindIP, Port: int(bindPort)},
	}, nil
}

func socksUDPEncode(dst *net.UDPAddr, payload []byte) []byte {
	ip4 := dst.IP.To4()
	if ip4 == nil {
		return nil
	}
	out := make([]byte, 10+len(payload))
	out[3] = 1
	copy(out[4:8], ip4)
	binary.BigEndian.PutUint16(out[8:10], uint16(dst.Port))
	copy(out[10:], payload)
	return out
}

func socksUDPDecode(buf []byte) (*net.UDPAddr, []byte, error) {
	if len(buf) < 10 || buf[0] != 0 || buf[1] != 0 {
		return nil, nil, errors.New("SOCKS UDP: заголовок")
	}
	if buf[3] != 1 {
		return nil, nil, errors.New("SOCKS UDP: не IPv4")
	}
	ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
	port := int(binary.BigEndian.Uint16(buf[8:10]))
	return &net.UDPAddr{IP: ip, Port: port}, buf[10:], nil
}

func socksPortOpen(p SocksProfile) bool {
	c, err := socksTCPDial(p, 1500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func socksProbe(p SocksProfile) error {
	c, err := socksTCPDial(p, 3*time.Second)
	if err != nil {
		return fmt.Errorf("SOCKS %s недоступен: %w", socksDialAddr(p), err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5Handshake(c, p.Username, p.Password); err != nil {
		return err
	}
	return nil
}
