package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
)

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}
var globalV6 = netip.MustParsePrefix("2000::/3")
var hostname = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?$`)

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return false
	}
	if address.Is6() && !globalV6.Contains(address) {
		return false
	}
	for _, prefix := range blocked {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validHost(host string) bool {
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == ""
	}
	return hostname.MatchString(host)
}

func fmtPort(port int) string { return strconv.Itoa(port) }

type destinationResolver func(context.Context, string, int) ([]netip.Addr, error)

func resolveDestination(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	if !validHost(host) || port < 1 || port > 65535 {
		return nil, errors.New("invalid destination")
	}
	var addresses []netip.Addr
	if address, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{address}
	} else {
		var err error
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("no destination addresses")
	}
	for _, address := range addresses {
		if !publicAddress(address) {
			return nil, errors.New("destination blocked")
		}
	}
	return addresses, nil
}
