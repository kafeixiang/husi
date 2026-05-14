package pluginoption

import (
	"github.com/sagernet/sing-box/option"
)

type SSROutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	Method        string   `json:"method,omitempty"`
	Password      string   `json:"password,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	ProtocolParam string   `json:"protocol_param,omitempty"`
	Obfs          string   `json:"obfs,omitempty"`
	ObfsParam     string   `json:"obfs_param,omitempty"`
	Network       []string `json:"network,omitempty"`
	UDPOverTCP    bool     `json:"udp_over_tcp,omitempty"`
}
