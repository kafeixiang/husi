package mieru

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

func TestRegisterOutbound(t *testing.T) {
	registry := outbound.NewRegistry()
	RegisterOutbound(registry)
	require.NotNil(t, registry)
}

func TestNewOutboundValidation(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	// Missing server
	_, err := NewOutbound(ctx, nil, logger, "test", pluginoption.MieruOutboundOptions{})
	require.Error(t, err)

	// Valid option construction
	opts := pluginoption.MieruOutboundOptions{
		UserName:      "user",
		Password:      "pass",
		Transport:     "TCP",
		HandshakeMode: "HANDSHAKE_STANDARD",
	}
	opts.Server = "127.0.0.1"
	opts.ServerPort = 8080

	out, err := NewOutbound(ctx, nil, logger, "test", opts)
	require.NoError(t, err)
	require.NotNil(t, out)
	defer common.Close(out)
}

func TestUnmarshalJSONAliases(t *testing.T) {
	jsonStr := `{
		"server": "12.34.56.78",
		"port-range": "2012-2022",
		"transport": "tcp",
		"user": "ducaiguozei",
		"pass": "xijinping",
		"multiplexing": "MULTIPLEXING_HIGH",
		"handshake-mode": "HANDSHAKE_NO_WAIT"
	}`

	var opts pluginoption.MieruOutboundOptions
	err := json.Unmarshal([]byte(jsonStr), &opts)
	require.NoError(t, err)
	require.Equal(t, "12.34.56.78", opts.Server)
	require.Equal(t, "ducaiguozei", opts.UserName)
	require.Equal(t, "xijinping", opts.Password)
	require.Equal(t, "MULTIPLEXING_HIGH", opts.Multiplexing)
	require.Equal(t, "HANDSHAKE_NO_WAIT", opts.HandshakeMode)
	require.Len(t, opts.ServerPortRanges, 1)
	require.Equal(t, "2012-2022", opts.ServerPortRanges[0])

	config, err := buildMieruClientConfig(opts, mieruDialer{}, nil)
	require.NoError(t, err)
	require.NotNil(t, config)
}

func TestSinglePortAndRangeInServerPortRanges(t *testing.T) {
	jsonStr := `{
		"server": "example.com",
		"server_ports": ["443", "2012-2022"],
		"username": "user",
		"password": "pass"
	}`

	var opts pluginoption.MieruOutboundOptions
	err := json.Unmarshal([]byte(jsonStr), &opts)
	require.NoError(t, err)
	require.Len(t, opts.ServerPortRanges, 2)
	require.Equal(t, "443", opts.ServerPortRanges[0])
	require.Equal(t, "2012-2022", opts.ServerPortRanges[1])

	config, err := buildMieruClientConfig(opts, mieruDialer{}, nil)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Len(t, config.Profile.Servers[0].PortBindings, 2)
	require.Nil(t, config.Profile.Servers[0].PortBindings[0].PortRange)
	require.Equal(t, int32(443), config.Profile.Servers[0].PortBindings[0].GetPort())
	require.Equal(t, "2012-2022", config.Profile.Servers[0].PortBindings[1].GetPortRange())
}

func TestJSONTrafficPattern(t *testing.T) {
	opts := pluginoption.MieruOutboundOptions{
		UserName:       "user",
		Password:       "pass",
		Transport:      "TCP",
		TrafficPattern: `{"seed": 42, "unlockAll": true}`,
	}
	opts.Server = "127.0.0.1"
	opts.ServerPort = 8080

	config, err := buildMieruClientConfig(opts, mieruDialer{}, nil)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotNil(t, config.Profile.TrafficPattern)
	require.Equal(t, int32(42), config.Profile.TrafficPattern.GetSeed())
	require.True(t, config.Profile.TrafficPattern.GetUnlockAll())
}

func TestInterfaceUpdated(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	opts := pluginoption.MieruOutboundOptions{
		UserName: "user",
		Password: "pass",
	}
	opts.Server = "127.0.0.1"
	opts.ServerPort = 8080

	out, err := NewOutbound(ctx, nil, logger, "test", opts)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Verify InterfaceUpdated does not panic when client is stopped
	if listener, ok := out.(adapter.InterfaceUpdateListener); ok {
		listener.InterfaceUpdated(ctx)
	} else {
		t.Fatal("Outbound should implement InterfaceUpdateListener")
	}

	defer common.Close(out)
}
