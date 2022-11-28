// Package systracer is the framework of linux event tracing
// system developed by Chaitin Tech.
package systracer

import (
	"reflect"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// ErrBadTracePoint is the error returned when the target
// trace point cannot be attached to.
var ErrBadTracePoint = errors.New("bad tracepoint")

// Condition is common embed field for defining an extra
// condition for current field.
type Condition struct{}

// typeCondition is the specified case for condition.
var typeCondition = reflect.TypeOf(Condition{})

// StringAddr is the special type used in the place of
// the string to fetch the address canary when decoding
// the string, when it is meaningful.
type StringAddr struct {
	String string
	Addr   uint64
}

// typeStringAddr is the specified case for string addr.
var typeStringAddr = reflect.TypeOf(StringAddr{})

// Event stores common event data made by all types of
// concrete tracing events. The format is defined by
// "<debugfs>/tracing/trace" file.
//
// The comm field is ommitted out since it is always
// imcomplete (rendered as "<...>) and is not essentially
// required by all events.
type Event struct {
	TaskPID   uint32
	Timestamp time.Time
	epoch     time.Duration
}

// ProbeEvent is the event triggered when touching any
// of the breakpoint inside a function.
type ProbeEvent struct {
	Event
}

// typeProbeEvent is the event kind of probe.
var typeProbeEvent = reflect.TypeOf(ProbeEvent{})

// ReturnEvent is the event triggered when a return
// instruction in function is executed.
type ReturnEvent struct {
	Event
}

// typeReturnEvent is the event kind of return.
var typeReturnEvent = reflect.TypeOf(ReturnEvent{})

// Trace is a controlling handle for trace events.
//
// The trace handle is initially not started to avoid
// deadlocking when used as collectors. The caller must
// manually activate them after their master thread
// has been initialized.
//
// And the trace can be stopped at runtime, it is
// recommended to disable certain tracing when there's
// no subscribers and the master thread nned not to
// track the real time state with the trace.
type Trace interface {
	ID() uint64
	SetCondition(string) error
	SetEnabled(bool)
	GetDone() uint64
	GetLost() uint64
	Close()
}

// Manager is the manager of traces.
//
// The manager is the monolithic consumer to read from
// trace pipe "<tracefs>/instances/<namespace>/trace_pipe"
// and generate events per registered events.
type Manager interface {
	// TraceKProbe creates either a kprobe (when handled
	// event is ProbeEvent) or a kretprobe (when handled
	// event is ReturnEvent).
	TraceKProbe(
		location string, handler interface{},
	) (Trace, <-chan struct{}, error)

	// TraceUProbe creates either a uprobe (when handled
	// event is ProbeEvent) or a uretprobe (when handled
	// event is ReturnEvent).
	TraceUProbe(
		library, location string, handler interface{},
	) (Trace, <-chan struct{}, error)
}

type option struct {
	tracefsPath   string
	instanceName  string
	limitInterval time.Duration
	logger        *zap.Logger
}

// Option to initialize the systrace subsystem.
type Option func(*option)

// WithTraceFSPath is the path of the tracefs. The
// default value is "/sys/kernel/debug/tracing".
func WithTraceFSPath(path string) Option {
	return func(opt *option) {
		opt.tracefsPath = path
	}
}

// WithInstanceName is the name of the trace instance.
// The default value is "systrace".
func WithInstanceName(name string) Option {
	return func(opt *option) {
		opt.instanceName = name
	}
}

// WithLimitInterval specifies the interval of receiving
// event from trace pipe. Setting this value to 0 will
// disable the reception limit. The default value is 0.
func WithLimitInterval(dur time.Duration) Option {
	return func(opt *option) {
		opt.limitInterval = dur
	}
}

// WithLogger specifies the logger for the manager.
// The default value is zap.L().
func WithLogger(logger *zap.Logger) Option {
	return func(opt *option) {
		opt.logger = logger
	}
}

// WithOptions aggregate a set of options together.
func WithOptions(opts ...Option) Option {
	return func(o *option) {
		for _, opt := range opts {
			opt(o)
		}
	}
}

// newOption creates the option with all default values.
func newOption() *option {
	return &option{
		tracefsPath:  "/sys/kernel/debug/tracing",
		instanceName: "systrace",
		logger:       zap.L(),
	}
}
