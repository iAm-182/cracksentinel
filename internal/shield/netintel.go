package shield

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type cidrService struct {
	net     *net.IPNet
	service string
	isC2Bot bool
}

var (
	cidrOnce  sync.Once
	cidrTable []cidrService

	dnsMu    sync.RWMutex
	dnsCache = map[string]string{}
)

func initCIDRTable() {
	raw := []struct {
		cidr    string
		service string
		isC2Bot bool
	}{
		// Telegram Messenger & Bot API Data Centers (AS62041 / AS59930)
		{"149.154.160.0/20", "Telegram Bot API / DC", true},
		{"91.108.4.0/22", "Telegram Bot API / DC", true},
		{"91.108.8.0/22", "Telegram Bot API / DC", true},
		{"91.108.12.0/22", "Telegram Bot API / DC", true},
		{"91.108.16.0/22", "Telegram Bot API / DC", true},
		{"91.108.56.0/22", "Telegram Bot API / DC", true},
		{"95.161.64.0/20", "Telegram Bot API / DC", true},

		// Discord / Cloudflare Anycast Edge (AS13335)
		{"162.159.128.0/19", "Discord / Cloudflare Edge", false},
		{"104.16.0.0/12", "Cloudflare CDN / Edge", false},
		{"172.64.0.0/13", "Cloudflare CDN / Edge", false},
		{"188.114.96.0/20", "Cloudflare CDN / Edge", false},
		{"1.1.1.0/24", "Cloudflare DNS (1.1.1.1)", false},
		{"1.0.0.0/24", "Cloudflare DNS (1.0.0.1)", false},

		// Valve / Steam Network (AS32590)
		{"155.133.224.0/19", "Valve / Steam Network", false},
		{"162.254.192.0/21", "Valve / Steam Network", false},
		{"185.25.180.0/22", "Valve / Steam Network", false},
		{"205.196.6.0/24", "Valve / Steam Network", false},
		{"208.64.200.0/22", "Valve / Steam Network", false},

		// GitHub / Raw Payload Hosting (AS36459)
		{"185.199.108.0/22", "GitHub Raw / Pages", false},
		{"140.82.112.0/20", "GitHub API / Git", false},

		// Google / GCP / DNS
		{"8.8.8.0/24", "Google DNS (8.8.8.8)", false},
		{"8.8.4.0/24", "Google DNS (8.8.4.4)", false},
		{"142.250.0.0/15", "Google / YouTube", false},
		{"172.217.0.0/16", "Google / GCP", false},
		{"34.0.0.0/9", "Google Cloud (GCP)", false},
		{"35.184.0.0/13", "Google Cloud (GCP)", false},

		// Microsoft / Azure / Windows
		{"20.0.0.0/8", "Microsoft Azure", false},
		{"13.64.0.0/11", "Microsoft Azure", false},
		{"40.64.0.0/10", "Microsoft Cloud", false},
		{"52.96.0.0/12", "Microsoft 365 / Cloud", false},
	}
	for _, r := range raw {
		if _, ipnet, err := net.ParseCIDR(r.cidr); err == nil && ipnet != nil {
			cidrTable = append(cidrTable, cidrService{
				net:     ipnet,
				service: r.service,
				isC2Bot: r.isC2Bot,
			})
		}
	}
}

// identifyRemoteService classifies an external IP + port using the offline CIDR intelligence
// table and non-blocking background reverse-DNS cache.
func identifyRemoteService(remoteIP string, remotePort uint16) (service string, isTelegramDC bool, hostname string) {
	cidrOnce.Do(initCIDRTable)
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return "", false, ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "Local / Private LAN", false, ""
	}

	// Non-blocking reverse-DNS cache lookup
	dnsMu.RLock()
	host, seen := dnsCache[remoteIP]
	dnsMu.RUnlock()
	if !seen {
		dnsMu.Lock()
		if len(dnsCache) > 2048 {
			dnsCache = map[string]string{}
		}
		dnsCache[remoteIP] = "" // mark in-flight so we never spawn duplicate lookups
		dnsMu.Unlock()
		go func(targetIP string) {
			ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(ctx, targetIP)
			if err == nil && len(names) > 0 {
				h := strings.TrimSuffix(names[0], ".")
				dnsMu.Lock()
				dnsCache[targetIP] = h
				dnsMu.Unlock()
			}
		}(remoteIP)
	}

	for _, entry := range cidrTable {
		if entry.net.Contains(ip) {
			return entry.service, entry.isC2Bot, host
		}
	}

	switch remotePort {
	case 3333, 14444, 45700:
		return "Stratum Mining Pool Port", false, host
	case 9001, 9050:
		return "Tor Relay / SOCKS Port", false, host
	case 4444, 1337, 5555, 6666, 6667, 7777:
		return "Known RAT / Backdoor Port", false, host
	}
	if host != "" {
		return host, false, host
	}
	return "External Server", false, ""
}
