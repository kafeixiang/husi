package libcore

import (
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/group"
)

func (b *BoxInstance) SelectOutbound(tag string) (ok bool) {
	if selector, isSelector := b.group.(*group.Selector); isSelector {
		ok = selector.SelectOutbound(tag)
		if ok {
			b.platformInterface.GroupCallback(tag)
		}
	}
	return
}

// watchGroupChange monitors changes in the selector.
// The interval at which the selector is checked is dynamically adjusted.
//
// block
func (b *BoxInstance) watchGroupChange() {
	const (
		duration0 = 500 * time.Millisecond
		duration1 = 700 * time.Millisecond
		duration2 = 1000 * time.Millisecond
		duration3 = 2000 * time.Millisecond
	)

	var durationLevel uint8 = 0
	ticker := time.NewTicker(duration0)
	defer ticker.Stop()

	updateTicker := func(changed bool) {
		if changed {
			ticker.Reset(duration0)
			durationLevel = 0
			return
		}

		switch durationLevel {
		case 0:
			ticker.Reset(duration1)
		case 1:
			ticker.Reset(duration2)
		case 2:
			ticker.Reset(duration3)
		case 3:
			// Already the longest
			return
		default:
			ticker.Reset(duration0)
		}
		durationLevel++
	}

	oldTag := b.group.Now()
	log.TraceContext(b.ctx, "Start watching group change")

	for {
		select {
		case <-b.ctx.Done():
			log.TraceContext(b.ctx, "Group change monitor close by context: ", b.ctx.Err())
			return
		case <-ticker.C:
			if b.state.Load() == boxStateClosed {
				log.TraceContext(b.ctx, "Group change monitor close because of box close")
				return
			}
		}

		newTag := b.group.Now()
		changed := oldTag != newTag
		if changed {
			b.platformInterface.GroupCallback(newTag)
			oldTag = newTag
		}
		updateTicker(changed)
	}

}
