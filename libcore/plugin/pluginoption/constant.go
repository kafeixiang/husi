// Package pluginoption provides options for hooked protocols.
package pluginoption

import (
	C "github.com/sagernet/sing-box/constant"
)

const (
	TypeJuicity      = "juicity"
	TypeTrustTunnel  = "trusttunnel"
	TypeShadowsocksR = "shadowsocksr"
)

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeJuicity:
		return "Juicity"
	case TypeTrustTunnel:
		return "TrustTunnel"
	case TypeShadowsocksR:
		return "ShadowsocksR"
	default:
		return C.ProxyDisplayName(proxyType)
	}
}
