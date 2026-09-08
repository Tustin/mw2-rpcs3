#!/bin/sh
set -eu

: "${MW2_DNS_REDIRECT_IP:?set MW2_DNS_REDIRECT_IP to the client-reachable host IPv4}"
sed "s/__MW2_DNS_REDIRECT_IP__/${MW2_DNS_REDIRECT_IP}/g" /etc/dnsmasq.conf.template > /etc/dnsmasq.conf
exec dnsmasq --no-daemon --conf-file=/etc/dnsmasq.conf
