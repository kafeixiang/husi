package libcore

import (
	"bytes"
	"context"
	"time"
	_ "unsafe"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/humanize"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// FormatBytes formats the bytes length to humanize.
func FormatBytes(length int64) string {
	return humanize.Bytes(uint64(length))
}

// FormatMemoryBytes formats the bytes length in memory format.
func FormatMemoryBytes(length int64) string {
	return humanize.MemoryBytes(uint64(length))
}

// parseConfig parses configContent to option.Options.
func parseConfig(ctx context.Context, configContent string) (option.Options, error) {
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configContent))
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}

// FormatConfig formats json.
func FormatConfig(configContent string) (*StringWrapper, error) {
	ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry())
	configMap, err := json.UnmarshalExtendedContext[map[string]any](ctx, []byte(configContent))
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(configMap)
	if err != nil {
		return nil, err
	}

	return wrapString(buffer.String()), nil
}

// CheckConfig checks whether configContent can run as sing-box configuration.
func CheckConfig(configContent string) error {
	ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry())
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return E.Cause(err, "parse config")
	}

	if options.Route != nil {
		// AutoDetectInterface will be automatically enabled by platform interface,
		// while platformInterfaceStub not including it. (tun.ErrNetlinkBanned)
		options.Route.AutoDetectInterface = false
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	service.MustRegister[platformInterfaceStub](ctx, platformInterfaceStub{})
	instance, err := box.New(box.Options{
		Options: options,
		Context: ctx,
	})
	if err != nil {
		return E.Cause(err, "create box")
	}
	defer instance.Close()
	return nil
}

// ParseDuration parses Go style duration.
func ParseDuration(raw string) (int64, error) {
	duration, err := parseMyDuration(raw)
	return int64(duration), err
}

//go:linkname parseMyDuration github.com/sagernet/sing/common/json/badoption/internal/my_time.ParseDuration
func parseMyDuration(raw string) (time.Duration, error)
