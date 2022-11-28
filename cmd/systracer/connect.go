package main

import (
	"context"
	"fmt"
	"syscall"

	"github.com/aegistudio/shaft"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/chaitin/systracer/connect"
)

var (
	connectEnabled bool
)

func initConnectModule() shaft.Option {
	if !(allEnabled || connectEnabled) {
		return shaft.Module()
	}
	return shaft.Module(
		connect.Module,
		shaft.Provide(func(
			ctx context.Context, group *errgroup.Group,
			logger *zap.SugaredLogger, ch <-chan connect.Event,
		) ([]moduleBarrier, error) {
			group.Go(func() error {
				for {
					var event connect.Event
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
					eventType := fmt.Sprintf("%d", event.Type)
					switch event.Type {
					case unix.SOCK_STREAM:
						eventType = "tcp"
					case unix.SOCK_DGRAM:
						eventType = "udp"
					case unix.SOCK_RAW, unix.SOCK_PACKET:
						eventType = "raw"
					}
					switch event.Op {
					case connect.OpConnectStart:
						logger.Infof(
							"%s - connect_%s(%d, %q)",
							eventContext, eventType,
							event.FD, eventAddr)
					case connect.OpConnectEnd:
						eventResult := "0"
						if event.Errno != nil {
							if errno := *event.Errno; errno != 0 {
								eventResult = fmt.Sprintf("%d (%s)",
									errno, syscall.Errno(-errno))
							}
						}
						logger.Infof(
							"%s - connect_%s(%d, %q) = %s",
							eventContext, eventType,
							event.FD, eventAddr, eventResult)
					}
				}
			})
			return nil, nil
		}),
	)
}

func init() {
	moduleInits = append(moduleInits, initConnectModule)
	rootCmd.PersistentFlags().BoolVar(
		&connectEnabled, "connect", connectEnabled,
		"collect connect event for logging")
}
