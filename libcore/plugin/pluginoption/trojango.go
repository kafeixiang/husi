package pluginoption

import (
	"github.com/sagernet/sing-box/option"
)

type TrojanGoOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	Password string             `json:"password"`
	Network  option.NetworkList `json:"network,omitempty"`
	option.OutboundTLSOptionsContainer
	Transport   *option.V2RayTransportOptions `json:"transport,omitempty"`
	Shadowsocks *TrojanGoShadowsocksOptions   `json:"shadowsocks,omitempty"`
	Mux         *TrojanGoMuxOptions           `json:"mux,omitempty"`
	Plugin      string                        `json:"plugin,omitempty"`
}

type TrojanGoShadowsocksOptions struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}

type TrojanGoMuxOptions struct {
	Enabled     bool `json:"enabled,omitempty"`
	Concurrency int  `json:"concurrency,omitempty"`
	IdleTimeout int  `json:"idle_timeout,omitempty"`
}
