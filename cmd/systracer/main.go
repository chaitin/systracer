package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/chaitin/systracer"
)

type moduleBarrier struct{}

var (
	moduleInits []func() shaft.Option
	allEnabled  bool
	logLevel    = "info"
)

var rootCmd = &cobra.Command{
	Use:  "systracer",
	Long: "Linux system activity tracer",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		for _, moduleInit := range moduleInits {
			if err := serpent.AddOption(
				cmd, moduleInit()); err != nil {
				return err
			}
		}
		return nil
	},
	RunE: serpent.Executor(shaft.Module(
		shaft.Stack(func(
			next func(*errgroup.Group, context.Context) error,
			rootCtx serpent.CommandContext,
		) error {
			cancelCtx, cancel := context.WithCancel(rootCtx)
			group, ctx := errgroup.WithContext(cancelCtx)
			defer func() { _ = group.Wait() }()
			defer cancel()
			return next(group, ctx)
		}),
		shaft.Invoke(func(
			group *errgroup.Group, _ []moduleBarrier,
			logger *zap.SugaredLogger,
		) error {
			logger.Info("initialization complete")
			return group.Wait()
		}),
		shaft.Provide(func(
			ctx context.Context, group *errgroup.Group,
			options []systracer.Option,
		) (systracer.Manager, error) {
			return systracer.New(ctx, group, options...)
		}),
		shaft.Stack(func(
			next func(*zap.Logger, *zap.SugaredLogger) error,
		) error {
			level, err := zapcore.ParseLevel(logLevel)
			if err != nil {
				return err
			}
			consoleLevel := zap.NewAtomicLevelAt(level)
			consoleConfig := zap.NewDevelopmentEncoderConfig()
			consoleConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			consoleErrors := zapcore.Lock(os.Stderr)
			consoleEncoder := zapcore.NewConsoleEncoder(consoleConfig)
			loggerCore := zapcore.NewCore(
				consoleEncoder, consoleErrors, consoleLevel)
			logger := zap.New(loggerCore)
			sugaredLogger := logger.Sugar()
			defer logger.Sync()
			return next(logger, sugaredLogger)
		}),
	)).RunE,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(
		&allEnabled, "all", allEnabled,
		"capture all supported events")
	rootCmd.PersistentFlags().StringVar(
		&logLevel, "log-level", logLevel,
		"setup the log level of the logger")
}

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt)
	defer cancel()
	if err := serpent.ExecuteContext(ctx, rootCmd); err != nil {
		os.Exit(1)
	}
}
