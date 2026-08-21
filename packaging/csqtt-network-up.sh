#!/bin/sh
# qWDTT-panel helper: NAT/ports for CSQTT TUN subnet (original, not CSQTT deploy.sh).
set -eu
STAMP="/run/csqtt-network-ready"
PEER_PORT="${CSQTT_PEER_PORT:-46000}"
SSH_PORT="${CSQTT_SSH_PORT:-22}"
WEB_PORT="${CSQTT_WEB_PORT:-46002}"
CSQTT_IFACE="${CSQTT_IFACE:-csqtt1}"
IPT_COMMENT="CSQTT_MANAGED"
SUBNET="10.66.67.0/24"
XT_WAIT="${CSQTT_XT_WAIT:-2}"

if [ -e "$STAMP" ] && [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
  exit 0
fi

command -v ip >/dev/null 2>&1 || exit 20
command -v iptables >/dev/null 2>&1 || exit 21
[ -w /proc/sys/net/ipv4/ip_forward ] && echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

WAN_IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
[ -n "$WAN_IFACE" ] || WAN_IFACE=$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1 {print $2}')
[ -n "$WAN_IFACE" ] || exit 22

ipt() { iptables -w "$XT_WAIT" "$@"; }
ipt -C INPUT -p udp --dport "$PEER_PORT" -m comment --comment "$IPT_COMMENT" -j ACCEPT 2>/dev/null \
  || ipt -I INPUT -p udp --dport "$PEER_PORT" -m comment --comment "$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "$SSH_PORT" -m comment --comment "$IPT_COMMENT" -j ACCEPT 2>/dev/null \
  || ipt -I INPUT -p tcp --dport "$SSH_PORT" -m comment --comment "$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "$WEB_PORT" -m comment --comment "$IPT_COMMENT" -j ACCEPT 2>/dev/null \
  || ipt -I INPUT -p tcp --dport "$WEB_PORT" -m comment --comment "$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -i "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT 2>/dev/null \
  || ipt -I FORWARD -i "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -o "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT 2>/dev/null \
  || ipt -I FORWARD -o "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT
ipt -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN_IFACE" -m comment --comment "$IPT_COMMENT" -j MASQUERADE 2>/dev/null \
  || ipt -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN_IFACE" -m comment --comment "$IPT_COMMENT" -j MASQUERADE
ipt -t mangle -C FORWARD -s "$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || ipt -t mangle -I FORWARD -s "$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
ipt -t mangle -C FORWARD -d "$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || ipt -t mangle -I FORWARD -d "$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu

mkdir -p /run
: > "$STAMP"
