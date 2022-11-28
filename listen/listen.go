package listen

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"github.com/aegistudio/shaft"
	"github.com/pkg/errors"

	"github.com/chaitin/systracer"
	"github.com/chaitin/systracer/pkg/kversion"
)

// Op is the listen event op for linux.
//
// The operation involves a listen and unlisten event. The
// listen event is issued when a socket has successfully
// listen while the unlisten event is issued when a
// listening socket is closed.
type Op uint8

const (
	OpListenStart = Op(iota)
	OpListenEnd
)

// Event is the standard information for a linux listen
// event. Since it is only possible to listen TCP socket
// (?->0x0a), we can omit out the type judgement.
type Event struct {
	Op        Op
	Timestamp time.Time
	PID       uint32
	FD        *int
	Family    uint16 // AF_*
	Addr      string
	Port      uint16
	Backlog   *int
}

// collector is the collector for the linux listen events.
// It keeps track of listen state registries and and will
// periodically perform cleanup.
type collector struct {
	ctx    context.Context
	ch     chan<- Event
	starts map[uint32]*Event
}

func (c *collector) dispatch(event Event) {
	select {
	case <-c.ctx.Done():
	case c.ch <- event:
	}
}

// handleEntryListen handles the event triggered when
// a syscall listen or its equivalences are encoutered.
// We can only decode the address family when the
// inet_listen or inet6_listen is called.
//
// listen(FD, Backlog)
func (col *collector) handleEntryListen(
	event entrySyscallListen,
) {
	listenEvent := &Event{}
	listenEvent.Timestamp = event.Timestamp
	listenEvent.PID = event.TaskPID
	listenEvent.FD = new(int)
	*listenEvent.FD = int(event.FD)
	listenEvent.Backlog = new(int)
	*listenEvent.Backlog = int(event.Backlog)
	col.starts[event.TaskPID] = listenEvent
}

// handleProtocolListenInet4 handles the event triggered
// when it enters inet_listen.
//
// inet_listen(&socket{
//     ...
//     .sk = &sock{
//         .skc_rcv_saddr = Address,
//         .skc_num       = Port,
//         .skc_family    = AF_INET = 2,
//         //.skc_state   = != 0x0a,
//     },
// }, Backlog)
func (col *collector) handleProtocolListenInet4(
	event systracer.ProbeEvent, sk StructSockListenInet4,
) {
	listenEvent := col.starts[event.TaskPID]
	if listenEvent == nil {
		return
	}
	listenEvent.Timestamp = event.Timestamp
	listenEvent.Family = syscall.AF_INET
	var ipv4 [4]byte
	binary.BigEndian.PutUint32(ipv4[:], sk.Address)
	listenEvent.Addr = net.IP(ipv4[:]).String()
	listenEvent.Port = sk.Port
}

// handleProtocolListenInet4_V2_6_12 handles the inet_listen ipv4
// tracepoint event for linux version 2.6.12 ~ 5.3 (excluded).
func (col *collector) handleProtocolListenInet4_V2_6_12(
	event entryProtocolListenInet4_V2_6_12,
) {
	col.handleProtocolListenInet4(event.ProbeEvent, event.Sk)
}

// handleProtocolListenInet4_v5_3 handles the inet_listen ipv4
// tracepoint event for linux version above 5.3 (included).
func (col *collector) handleProtocolListenInet4_V5_3(
	event entryProtocolListenInet4_V5_3,
) {
	col.handleProtocolListenInet4(event.ProbeEvent, event.Sk)
}

// handleProtocolListenInet6 handles the event triggered
// when it enters inet6_listen.
//
// inet_listen(&socket{
//     ...
//     .sk = &sock{
//         .skc_num          = Port,
//         .skc_family       = AF_INET6 = 10,
//         .sin_v6_rev_saddr = Address,
//     },
// }, Backlog)
func (col *collector) handleProtocolListenInet6(
	event systracer.ProbeEvent, sk StructSockListenInet6,
) {
	listenEvent := col.starts[event.TaskPID]
	if listenEvent == nil {
		return
	}
	listenEvent.Timestamp = event.Timestamp
	listenEvent.Family = syscall.AF_INET6
	var ipv6 [16]byte
	binary.BigEndian.PutUint32(ipv6[0:4], sk.Address0)
	binary.BigEndian.PutUint32(ipv6[4:8], sk.Address1)
	binary.BigEndian.PutUint32(ipv6[8:12], sk.Address2)
	binary.BigEndian.PutUint32(ipv6[12:16], sk.Address3)
	listenEvent.Addr = net.IP(ipv6[:]).String()
	listenEvent.Port = sk.Port
}

// handleProtocolListenInet4_V2_6_12 handles the inet_listen ipv6
// tracepoint event for linux version 2.6.12 ~ 5.3 (excluded).
func (col *collector) handleProtocolListenInet6_V2_6_12(
	event entryProtocolListenInet6_V2_6_12,
) {
	col.handleProtocolListenInet6(event.ProbeEvent, event.Sk)
}

// handleProtocolListenInet4_v5_3 handles the inet_listen ipv6
// tracepoint event for linux version above 5.3 (included).
func (col *collector) handleProtocolListenInet6_V5_3(
	event entryProtocolListenInet6_V5_3,
) {
	col.handleProtocolListenInet6(event.ProbeEvent, event.Sk)
}

// handleExitListen handles the event when the listen
// syscall or its equivalences have returned.
//
// This should generate the listen event when the retcode
// is 0, and the address family is known to us.
func (col *collector) handleExitListen(
	event exitSyscallListen,
) {
	listenEvent := col.starts[event.TaskPID]
	if listenEvent == nil {
		return
	}
	listenStartEvent := *listenEvent
	listenStartEvent.Op = OpListenStart
	listenStartEvent.Timestamp = event.Timestamp
	delete(col.starts, event.TaskPID)
	if event.Errno == 0 && listenEvent.Family != 0 {
		col.dispatch(listenStartEvent)
	}
}

// handleTCPCloseInet4 handles the event triggered
// when it enters tcp_close.
//
// tcp_close(&socket{
//     ...
//     .sk = &sock{
//         .skc_rcv_saddr = Address,
//         .skc_num       = Port,
//         .skc_family    = AF_INET = 2,
//         .skc_state     = == 0x0a,
//     },
// })
func (col *collector) handleTCPCloseInet4(
	event entryTCPCloseInet4,
) {
	if event.State != 10 {
		return
	}
	var listenEndEvent Event
	listenEndEvent.Op = OpListenEnd
	listenEndEvent.PID = event.TaskPID
	listenEndEvent.Timestamp = event.Timestamp
	listenEndEvent.Family = syscall.AF_INET
	var ipv4 [4]byte
	binary.BigEndian.PutUint32(ipv4[:], event.Address)
	listenEndEvent.Addr = net.IP(ipv4[:]).String()
	listenEndEvent.Port = event.Port
	col.dispatch(listenEndEvent)
}

// handleTCPCloseInet6 handles the event triggered
// when it enters tcp_close.
//
// tcp_close(&socket{
//     ...
//     .sk = &sock{
//         .skc_num          = Port,
//         .skc_family       = AF_INET6 = 10,
//         .sin_v6_rev_saddr = Address,
//         .skc_state        = == 0x0a,
//     },
// })
func (col *collector) handleTCPCloseInet6(
	event entryTCPCloseInet6,
) {
	if event.State != 10 {
		return
	}
	var listenEndEvent Event
	listenEndEvent.Op = OpListenEnd
	listenEndEvent.PID = event.TaskPID
	listenEndEvent.Timestamp = event.Timestamp
	listenEndEvent.Family = syscall.AF_INET6
	var ipv6 [16]byte
	binary.BigEndian.PutUint32(ipv6[0:4], event.Address0)
	binary.BigEndian.PutUint32(ipv6[4:8], event.Address1)
	binary.BigEndian.PutUint32(ipv6[8:12], event.Address2)
	binary.BigEndian.PutUint32(ipv6[12:16], event.Address3)
	listenEndEvent.Addr = net.IP(ipv6[:]).String()
	listenEndEvent.Port = event.Port
	col.dispatch(listenEndEvent)
}

func stackListenEventSource(
	next func(<-chan Event) error,
	rootCtx context.Context, manager systracer.Manager,
) error {
	// Attempt to initialize the listen data source.
	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()
	var lastSyncCh <-chan struct{}
	eventCh := make(chan Event)

	// Create the listen event collector first.
	collector := &collector{
		ctx:    ctx,
		ch:     eventCh,
		starts: make(map[uint32]*Event),
	}

	// Search the event collector handler for IPv4 event.
	var handleProtocolListenInet4, handleProtocolListenInet6 interface{}
	if kversion.Current >= kversion.Must("5.3") {
		handleProtocolListenInet4 = collector.handleProtocolListenInet4_V5_3
		handleProtocolListenInet6 = collector.handleProtocolListenInet6_V5_3
	} else if kversion.Current >= kversion.Must("2.6.12") {
		handleProtocolListenInet4 = collector.handleProtocolListenInet4_V2_6_12
		handleProtocolListenInet6 = collector.handleProtocolListenInet6_V2_6_12
	} else {
		return errors.Errorf("listen event unsupported")
	}

	// Attempt to attach to the inet_listen first.
	listenInet4, _, err := manager.TraceKProbe(
		"inet_listen", handleProtocolListenInet4)
	if err != nil {
		return err
	}
	defer listenInet4.Close()
	listenInet6, _, err := manager.TraceKProbe(
		"inet_listen", handleProtocolListenInet6)
	if err != nil {
		return err
	}
	defer listenInet6.Close()

	// Attempt to attach to the inet_release then.
	shutdownInet4, _, err := manager.TraceKProbe(
		"tcp_close", collector.handleTCPCloseInet4)
	if err != nil {
		return err
	}
	defer shutdownInet4.Close()

	shutdownInet6, _, err := manager.TraceKProbe(
		"tcp_close", collector.handleTCPCloseInet6)
	if err != nil {
		return err
	}
	defer shutdownInet6.Close()

	// Attempt to attach to correct location of the
	// syscall listen. Please notice that once a point
	// of tracing is found, the other functions must
	// also attach to that point.
	var exitListen, entryListen systracer.Trace
	candidates := []string{
		"sys_listen", "__sys_listen",
	}
	for _, candidate := range candidates {
		var syncCh <-chan struct{}

		// Try to attach to the kretprobe of candidate.
		exitListen, _, err = manager.TraceKProbe(
			candidate, collector.handleExitListen)
		if err == systracer.ErrBadTracePoint {
			continue
		}
		if err != nil {
			return err
		}
		defer exitListen.Close()

		// Try to attach to the syscall entry event.
		// nolint
		entryListen, syncCh, err = manager.TraceKProbe(
			candidate, collector.handleEntryListen)
		if err != nil {
			return err
		}
		defer entryListen.Close()
		lastSyncCh = syncCh

		// Creation completed for now.
		break
	}
	if exitListen == nil {
		return systracer.ErrBadTracePoint
	}

	// Wait for the completion of entry initialization.
	select {
	case <-ctx.Done():
		return nil
	case <-lastSyncCh:
	}
	defer cancel()
	listenInet4.SetEnabled(true)
	listenInet6.SetEnabled(true)
	shutdownInet4.SetEnabled(true)
	shutdownInet6.SetEnabled(true)
	exitListen.SetEnabled(true)
	entryListen.SetEnabled(true)
	return next(eventCh)
}

// Module is the DI module of listen event.
//
// The module requires a context and a trace manager, and
// injects an event channel of <-chan Event.
var Module = shaft.Stack(stackListenEventSource)
