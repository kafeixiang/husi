package libcore

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/conntrack"
	C "github.com/sagernet/sing-box/constant"
	_ "github.com/sagernet/sing-box/include"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"libcore/protect"
	"libcore/v2rayapilite"
)

var mainInstance *BoxInstance

func ResetAllConnections() {
	conntrack.Close()
	boxlog.Debug("Reset system connections done.")
}

type BoxInstance struct {
	*box.Box

	cancel context.CancelFunc

	// state is sing-box state
	// 0: never started
	// 1: running
	// 2: closed
	state int

	v2api *v2rayapilite.V2RayServerLite

	selector *outbound.Selector

	pauseManager pause.Manager
	servicePauseFields
}

func NewSingBoxInstance(config string, forTest bool) (b *BoxInstance, err error) {
	defer catchPanic("NewSingBoxInstance", func(panicErr error) { err = panicErr })

	options, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	// create box
	ctx, cancel := context.WithCancel(context.Background())
	ctx = pause.WithDefaultManager(ctx)
	platformWrapper := &boxPlatformInterfaceWrapper{}
	boxOption := box.Options{
		Options:           options,
		Context:           ctx,
		PlatformInterface: platformWrapper,
	}

	// If set PlatformLogWrapper, box will set something about cache file,
	// which will panic with simple configuration (when URL test).
	if !forTest {
		boxOption.PlatformLogWriter = platformLogWrapper
	}

	instance, err := box.New(boxOption)
	if err != nil {
		cancel()
		return nil, E.Cause(err, "create service")
	}

	b = &BoxInstance{
		Box:          instance,
		cancel:       cancel,
		pauseManager: service.FromContext[pause.Manager](ctx),
	}

	// selector
	if proxy, haveProxyOutbound := b.Box.Router().Outbound("proxy"); haveProxyOutbound {
		if selector, isSelector := proxy.(*outbound.Selector); isSelector {
			b.selector = selector
		}
	}

	return b, nil
}

func (b *BoxInstance) Start() (err error) {
	defer catchPanic("box.Start", func(panicErr error) { err = panicErr })

	if b.state == 0 {
		b.state = 1
		defer func() {
			if b.selector != nil && intfGUI != nil {
				go b.listenSelectorChange(context.Background(), intfGUI.SelectorCallback)
			}
		}()
		return b.Box.Start()
	}
	return E.New("already started")
}

func (b *BoxInstance) Close() (err error) {
	defer catchPanic("BoxInstance.Close", func(panicErr error) { err = panicErr })

	// no double close
	if b.state == 2 {
		return nil
	}
	b.state = 2

	// clear main instance
	if mainInstance == b {
		mainInstance = nil
		goServeProtect(false)
	}

	// close box
	chClosed := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), C.StopTimeout)
	defer cancel()
	start := time.Now()
	go func() {
		defer catchPanic("box.Close", func(panicErr error) { err = panicErr })
		b.cancel()
		_ = b.Box.Close()
		close(chClosed)
	}()
	select {
	case <-ctx.Done():
		boxlog.Warn("Closing sing-box takes longer than expected.")
	case <-chClosed:
		boxlog.Info(fmt.Sprintf("sing-box closed in %d ms.", time.Since(start).Milliseconds()))
	}

	return nil
}

func (b *BoxInstance) NeedWIFIState() bool {
	return b.Box.Router().NeedWIFIState()
}

func (b *BoxInstance) SetAsMain() {
	mainInstance = b
	goServeProtect(true)
}

func (b *BoxInstance) SetV2rayStats(outbounds string) {
	b.v2api = v2rayapilite.NewSbV2rayServer(option.V2RayStatsServiceOptions{
		Enabled:   true,
		Outbounds: strings.Split(outbounds, "\n"),
	})
	b.Box.Router().SetV2RayServer(b.v2api)
}

func (b *BoxInstance) QueryStats(tag, direct string) int64 {
	if b.v2api == nil {
		return 0
	}
	return b.v2api.QueryStats(fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, direct))
}

func (b *BoxInstance) SelectOutbound(tag string) (ok bool) {
	if b.selector != nil {
		return b.selector.SelectOutbound(tag)
	}
	return false
}

var protectCloser io.Closer

func goServeProtect(start bool) {
	if protectCloser != nil {
		_ = protectCloser.Close()
		protectCloser = nil
	}

	if start {
		protectCloser = protect.ServerProtect(ProtectPath, func(fd int) error {
			if intfBox == nil {
				return E.New("not init intfBox")
			}
			return intfBox.AutoDetectInterfaceControl(int32(fd))
		})
	}
}
