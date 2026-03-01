// Package pluginoption provides options for hooked protocols.
package pluginoption

import (
	C "github.com/sagernet/sing-box/constant"
)

const (
	TypeJuicity     = "juicity"
	TypeTrustTunnel = "trusttunnel"
	TypeBalancer    = "balancer"
	TypeAnchor      = "anchor"
	TypeProtect     = "protect"
	TypeSSR         = "ssr"
)

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeJuicity:
		return "Juicity"
	case TypeTrustTunnel:
		return "TrustTunnel"
	case TypeBalancer:
		return "Balancer"
	case TypeSSR:
		return "ShadowsocksR"
	default:
		return C.ProxyDisplayName(proxyType)
	}
}
