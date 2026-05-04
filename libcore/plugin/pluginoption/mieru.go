package pluginoption

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type MieruOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	ServerPortRanges badoption.Listable[string] `json:"server_ports,omitempty"`
	Transport        string                     `json:"transport,omitempty"`
	UserName         string                     `json:"username,omitempty"`
	Password         string                     `json:"password,omitempty"`
	Multiplexing     string                     `json:"multiplexing,omitempty"`
	TrafficPattern   string                     `json:"traffic_pattern,omitempty"`
	HandshakeMode    string                     `json:"handshake_mode,omitempty"`
	UserHint         bool                       `json:"user_hint,omitempty"`
	MTU              int                        `json:"mtu,omitempty"`
}

type MieruInboundOptions struct {
	option.ListenOptions
	Users          []MieruUser `json:"users,omitempty"`
	Transport      string      `json:"transport,omitempty"`
	TrafficPattern string      `json:"traffic_pattern,omitempty"`
}

type MieruUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}
