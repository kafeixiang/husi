// Package pluginoption provides options for hooked protocols.
package pluginoption

import (
	C "github.com/sagernet/sing-box/constant"
)

const (
	TypeJuicity     = "juicity"
	TypeTrustTunnel = "trusttunnel"
	TypeSSR         = "ssr"
	TypeMieru       = "mieru"
	TypeSnell       = "snell"
)

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeJuicity:
		return "Juicity"
	case TypeTrustTunnel:
		return "TrustTunnel"
	case TypeSSR:
		return "ShadowsocksR"
	case TypeMieru:
		return "Mieru"
	case TypeSnell:
		return "Snell"
	default:
		return C.ProxyDisplayName(proxyType)
	}
}
