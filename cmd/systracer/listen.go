package main

import (
	"context"
	"fmt"

	"github.com/aegistudio/shaft"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/chaitin/systracer/listen"
)

var (
	listenEnabled bool
)

func initListenModule() shaft.Option {
	if !(allEnabled || listenEnabled) {
		return shaft.Module()
	}
	return shaft.Module(
		listen.Module,
		shaft.Provide(func(
			ctx context.Context, group *errgroup.Group,
			logger *zap.SugaredLogger, ch <-chan listen.Event,
		) ([]moduleBarrier, error) {
			group.Go(func() error {
				for {
					var event listen.Event
					select {
					case <-ctx.Done():
						return nil
					case event = <-ch:
					}
					eventContext := fmt.Sprintf("%s %d",
						event.Timestamp.Format("2006-01-02T15:04:05.999999999"), event.PID)
					eventAddr := ""
					switch event.Family {
					case unix.AF_INET:
						eventAddr = fmt.Sprintf("%s:%d",
							event.Addr, event.Port)
					case unix.AF_INET6:
						eventAddr = fmt.Sprintf("[%s]:%d",
							event.Addr, event.Port)
					}
					switch event.Op {
					case listen.OpListenStart:
						logger.Infof(
							"%s - listen_tcp(%d, %q, %d)",
							eventContext, *event.FD,
							eventAddr, *event.Backlog)
					case listen.OpListenEnd:
						logger.Infof(
							"%s - unlisten_tcp(%q)",
							eventContext, eventAddr)
					}
				}
			})
			return nil, nil
		}),
	)
}

func init() {
	moduleInits = append(moduleInits, initListenModule)
	rootCmd.PersistentFlags().BoolVar(
		&listenEnabled, "listen", listenEnabled,
		"collect listen event for logging")
}
