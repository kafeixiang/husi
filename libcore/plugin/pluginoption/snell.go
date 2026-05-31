package pluginoption

import (
	"github.com/sagernet/sing-box/option"
)

type SnellOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	PSK        string                          `json:"psk"`
	Version    int                             `json:"version,omitempty"`
	Reuse      bool                            `json:"reuse,omitempty"`
	Network    option.NetworkList              `json:"network,omitempty"`
	Obfs       *SnellObfsOptions               `json:"obfs,omitempty"`
	UDPOverTCP *option.UDPOverTCPOptions       `json:"udp_over_tcp,omitempty"`
	Multiplex  *option.OutboundMultiplexOptions `json:"multiplex,omitempty"`
	option.OutboundTLSOptionsContainer
}

type SnellObfsOptions struct {
	Type string `json:"type,omitempty"`
	Host string `json:"host,omitempty"`
}
