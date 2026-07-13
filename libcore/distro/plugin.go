package distro

import (
	_ "libcore/combinedapi"
	"libcore/plugin/http"
	"libcore/plugin/juicity"
	"libcore/plugin/mieru"
	"libcore/plugin/plugindns"
	"libcore/plugin/ssr"
	"libcore/plugin/trusttunnel"
	"libcore/plugin/vless"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
)

func registerPluginsOutbound(registry *outbound.Registry) {
	http.RegisterOutbound(registry)
	juicity.RegisterOutbound(registry)
	mieru.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	trusttunnel.RegisterOutbound(registry)
	ssr.RegisterOutbound(registry)
}

func registerPluginsDNSTransport(registry *dns.TransportRegistry) {
	plugindns.RegisterTCP(registry)
	plugindns.RegisterTLS(registry)
}
