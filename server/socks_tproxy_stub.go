//go:build !linux

package main

import "errors"

func socksSnapshot() (active bool, tcp, udp int, health string) {
	return false, 0, 0, "только Linux"
}

func socksActivateID(id string) error {
	return errors.New("SOCKS5 TPROXY есть только на Linux")
}

func socksDeactivate() {}

func socksRestore() {}

func socksRefreshIfaces() {}
