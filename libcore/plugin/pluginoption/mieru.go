package pluginoption

import (
	"encoding/json"
	"strconv"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type flexString string

func (s *flexString) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = flexString(str)
		return nil
	}
	var num int64
	if err := json.Unmarshal(data, &num); err == nil {
		*s = flexString(strconv.FormatInt(num, 10))
		return nil
	}
	return nil
}

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '[' {
		var list []string
		if err := json.Unmarshal(data, &list); err == nil {
			*s = list
			return nil
		}
		var numList []int64
		if err := json.Unmarshal(data, &numList); err == nil {
			strList := make([]string, len(numList))
			for i, n := range numList {
				strList[i] = strconv.FormatInt(n, 10)
			}
			*s = strList
			return nil
		}
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = []string{str}
		return nil
	}
	var num int64
	if err := json.Unmarshal(data, &num); err == nil {
		*s = []string{strconv.FormatInt(num, 10)}
		return nil
	}
	return nil
}

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
	MTU              int                        `json:"mtu,omitempty"`
}

func (o *MieruOutboundOptions) UnmarshalJSON(data []byte) error {
	type Alias MieruOutboundOptions
	var raw struct {
		Alias
		User            flexString `json:"user,omitempty"`
		Pass            flexString `json:"pass,omitempty"`
		Port            stringList `json:"port,omitempty"`
		ServerPorts     stringList `json:"server_ports,omitempty"`
		ServerPorts1    stringList `json:"server-ports,omitempty"`
		PortRange       stringList `json:"port_range,omitempty"`
		PortRange1      stringList `json:"port-range,omitempty"`
		PortRanges      stringList `json:"port_ranges,omitempty"`
		PortRanges1     stringList `json:"port-ranges,omitempty"`
		HandshakeMode   flexString `json:"handshake_mode,omitempty"`
		HandshakeMode1  flexString `json:"handshake-mode,omitempty"`
		Multiplexing    flexString `json:"multiplexing,omitempty"`
		TrafficPattern  flexString `json:"traffic_pattern,omitempty"`
		TrafficPattern1 flexString `json:"traffic-pattern,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*o = MieruOutboundOptions(raw.Alias)
	if o.UserName == "" && raw.User != "" {
		o.UserName = string(raw.User)
	}
	if o.Password == "" && raw.Pass != "" {
		o.Password = string(raw.Pass)
	}
	if len(o.ServerPortRanges) == 0 {
		var found []string
		if len(raw.ServerPorts) > 0 {
			found = raw.ServerPorts
		} else if len(raw.ServerPorts1) > 0 {
			found = raw.ServerPorts1
		} else if len(raw.PortRange) > 0 {
			found = raw.PortRange
		} else if len(raw.PortRange1) > 0 {
			found = raw.PortRange1
		} else if len(raw.PortRanges) > 0 {
			found = raw.PortRanges
		} else if len(raw.PortRanges1) > 0 {
			found = raw.PortRanges1
		} else if len(raw.Port) > 0 {
			if o.ServerPort == 0 {
				found = raw.Port
			}
		}
		if len(found) > 0 {
			o.ServerPortRanges = badoption.Listable[string](found)
		}
	}
	if o.HandshakeMode == "" {
		if raw.HandshakeMode != "" {
			o.HandshakeMode = string(raw.HandshakeMode)
		} else if raw.HandshakeMode1 != "" {
			o.HandshakeMode = string(raw.HandshakeMode1)
		}
	}
	if o.Multiplexing == "" && raw.Multiplexing != "" {
		o.Multiplexing = string(raw.Multiplexing)
	}
	if o.TrafficPattern == "" {
		if raw.TrafficPattern != "" {
			o.TrafficPattern = string(raw.TrafficPattern)
		} else if raw.TrafficPattern1 != "" {
			o.TrafficPattern = string(raw.TrafficPattern1)
		}
	}
	return nil
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
