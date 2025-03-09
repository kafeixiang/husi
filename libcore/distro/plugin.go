package distro

import (
	"libcore/plugin/anytls"
	"libcore/plugin/balancer"

	"github.com/sagernet/sing-box/adapter/outbound"
)

func registerPluginsOutbound(registry *outbound.Registry) {
	anytls.RegisterOutbound(registry)
	balancer.RegisterOutbound(registry)
}
