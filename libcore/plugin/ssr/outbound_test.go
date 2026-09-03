package ssr

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

func TestNewOutbound(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		password      string
		obfs          string
		obfsParam     string
		protocol      string
		protocolParam string
	}{
		{
			name:     "plain_origin",
			method:   "aes-256-cfb",
			password: "password",
			obfs:     "plain",
			protocol: "origin",
		},
		{
			name:     "dummy_none",
			method:   "none",
			password: "password",
			obfs:     "plain",
			protocol: "origin",
		},
		{
			name:          "tls1.2_auth_chain_a",
			method:        "rc4-md5",
			password:      "pass123",
			obfs:          "tls1.2_ticket_auth",
			obfsParam:     "cloudflare.com",
			protocol:      "auth_chain_a",
			protocolParam: "12:secret",
		},
		{
			name:          "http_simple_auth_aes128_sha1",
			method:        "chacha20-ietf",
			password:      "pass456",
			obfs:          "http_simple",
			obfsParam:     "bing.com",
			protocol:      "auth_aes128_sha1",
			protocolParam: "34:secret2",
		},
		{
			name:     "auth_chain_b",
			method:   "aes-128-ctr",
			password: "pass789",
			obfs:     "plain",
			protocol: "auth_chain_b",
		},
		{
			name:     "compatible_suffixes",
			method:   "plain",
			password: "password",
			obfs:     "tls1.2_ticket_auth_compatible",
			protocol: "auth_sha1_v4_compatible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := pluginoption.SSROutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: 8388,
				},
				Method:        tt.method,
				Password:      tt.password,
				Obfs:          tt.obfs,
				ObfsParam:     tt.obfsParam,
				Protocol:      tt.protocol,
				ProtocolParam: tt.protocolParam,
			}
			out, err := NewOutbound(context.Background(), nil, nil, "ssr-tag", opts)
			if err != nil {
				t.Fatalf("NewOutbound failed: %v", err)
			}
			if out == nil {
				t.Fatalf("NewOutbound returned nil")
			}
		})
	}
}
