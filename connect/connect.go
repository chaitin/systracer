// Package connect defines the event source of network
// connection events on linux.
package connect

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/aegistudio/shaft"

	"github.com/chaitin/systracer"
)

// Op is the event op of connect event.
type Op uint8

const (
	OpConnectStart = Op(iota)
	OpConnectEnd
)

// Event is the generated event of this module.
type Event struct {
	Op        Op
	PID       uint32
	Timestamp time.Time
	FD        int
	Errno     *int32
	Family    uint16
	Type      uint16
	Addr      string
	FlowInfo  *uint32
	Scope     *uint32
	Port      uint16
}

// collector is the event's collector.
type collector struct {
	ctx        context.Context
	ch         chan<- Event
	registries map[uint32]*Event
}

func (c *collector) dispatch(event Event) {
	select {
	case <-c.ctx.Done():
	case c.ch <- event:
	}
}

// handleConnectInet4 handles the event triggered when
// a syscall connect or its equivalences are encountered
// and represents a IPv4 event record.
//
// connect(FD, &sockaddr_in{
//     .sin_family = AF_INET = 2,
//     .sin_port   = Port,
//     .sin_addr   = { Address },
// }, sizeof(sockaddr_in) == 16)
func (col *collector) handleConnectInet4(
	event entrySyscallConnectInet4,
) {
	connectEvent := &Event{}
	connectEvent.Timestamp = event.Timestamp
	connectEvent.PID = event.TaskPID
	connectEvent.FD = int(event.FD)
	connectEvent.Family = event.Family
	connectEvent.Port = event.Port
	var ipv4 [4]byte
	binary.BigEndian.PutUint32(ipv4[:], event.Address)
	connectEvent.Addr = net.IP(ipv4[:]).String()
	col.registries[event.TaskPID] = connectEvent
}

// handleConnectInet6 handles the event triggered when
// a syscall connect or its equivalences are encountered
// and represents a IPv4 event record.
//
// connect(FD, &sockaddr_in6{
//      .sin6_family   = AF_INET6 = 10,
//      .sin6_port     = Port,
//      .sin6_flowinfo = FlowInfo,
//      .sin6_addr     = in6_addr{
//         Address0, Address1, Address2, Address3,
//      },
//      .sin6_scope_id = Scope,
// }, sizeof(sockaddr_in6) = 28})
func (col *collector) handleConnectInet6(
	event entrySyscallConnectInet6,
) {
	connectEvent := &Event{}
	connectEvent.Timestamp = event.Timestamp
	connectEvent.PID = event.TaskPID
	connectEvent.FD = int(event.FD)
	connectEvent.Family = event.Family
	connectEvent.Port = event.Port
	connectEvent.FlowInfo = new(uint32)
	*connectEvent.FlowInfo = event.FlowInfo
	connectEvent.Scope = new(uint32)
	*connectEvent.Scope = event.Scope
	var ipv6 [16]byte
	binary.BigEndian.PutUint32(ipv6[0:4], event.Address0)
	binary.BigEndian.PutUint32(ipv6[4:8], event.Address1)
	binary.BigEndian.PutUint32(ipv6[8:12], event.Address2)
	binary.BigEndian.PutUint32(ipv6[12:16], event.Address3)
	connectEvent.Addr = net.IP(ipv6[:]).String()
	col.registries[event.TaskPID] = connectEvent
}

// handleExitConnect handles the event when the connect
// syscall or its equivalences have returned. This should
// generate the connect end event, and delete the record
// since it has been completed.
func (col *collector) handleExitConnect(
	event exitSyscallConnect,
) {
	connectEvent := col.registries[event.TaskPID]
	if connectEvent == nil {
		return
	}
	connectEndEvent := *connectEvent
	connectEndEvent.Timestamp = event.Timestamp
	connectEndEvent.Op = OpConnectEnd
	connectEndEvent.Errno = new(int32)
	*connectEndEvent.Errno = event.Errno
	delete(col.registries, event.TaskPID)
	col.dispatch(connectEndEvent)
}

// handleInetProtocolConnect is the event triggered when
// the proto_ops->connect corresponded functions are called
// (e.g. inet_stream_connect and inet_dgram_connect).
//
// The type field will be fetched at this point, which
// will query the (struct socket*)->type field. And an
// connect start event must be generated after that.
func (col *collector) handleInetProtocolConnect(
	event entryInetProtocolConnect,
) {
	connectEvent := col.registries[event.TaskPID]
	if connectEvent == nil {
		return
	}
	connectEvent.Type = event.Type
	connectStartEvent := *connectEvent
	connectStartEvent.Op = OpConnectStart
	col.dispatch(connectStartEvent)
}

func stackConnectEventSource(
	next func(<-chan Event) error,
	rootCtx context.Context, manager systracer.Manager,
) error {
	// Attempt to initialize the connect data source.
	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()
	var lastSyncCh <-chan struct{}
	eventCh := make(chan Event)

	// Create the connect event collector first.
	collector := &collector{
		ctx:        ctx,
		ch:         eventCh,
		registries: make(map[uint32]*Event),
	}

	// Attempt to attach to the inet_dgram_connect and
	// the inet_stream_connect first.
	inetDgramConnect, _, err := manager.TraceKProbe(
		"inet_dgram_connect",
		collector.handleInetProtocolConnect)
	if err != nil {
		return err
	}
	defer inetDgramConnect.Close()

	inetStreamConnect, _, err := manager.TraceKProbe(
		"inet_stream_connect",
		collector.handleInetProtocolConnect)
	if err != nil {
		return err
	}
	defer inetStreamConnect.Close()

	// Attempt to attach to correct location of the
	// syscall connect. Please notice that once a point
	// of tracing is found, the other functions must
	// also attach to that point.
	var exitConnect, connectInet4, connectInet6 systracer.Trace
	candidates := []string{
		"sys_connect", "__sys_connect",
	}
	for _, candidate := range candidates {
		var syncCh <-chan struct{}

		// Try to attach to the kretprobe of candidate.
		// nolint
		exitConnect, syncCh, err = manager.TraceKProbe(
			candidate, collector.handleExitConnect)
		if err == systracer.ErrBadTracePoint {
			continue
		}
		if err != nil {
			return err
		}
		lastSyncCh = syncCh
		defer exitConnect.Close()

		// Try to attach to the connect ipv4 event.
		connectInet4, syncCh, err = manager.TraceKProbe(
			candidate, collector.handleConnectInet4)
		if err != nil {
			return err
		}
		lastSyncCh = syncCh
		defer connectInet4.Close()

		// Try to attach to the connect ipv6 event.
		// This is optional because some older kernel
		// may have no ipv6 support.
		connectInet6, syncCh, err = manager.TraceKProbe(
			candidate, collector.handleConnectInet6)
		if err != nil && err != systracer.ErrBadTracePoint {
			return err
		}
		if connectInet6 != nil {
			lastSyncCh = syncCh
			defer connectInet6.Close()
		}

		// Creation completed for now.
		break
	}
	if exitConnect == nil {
		return systracer.ErrBadTracePoint
	}

	// Wait for the synchronization of probe point.
	select {
	case <-ctx.Done():
		return nil
	case <-lastSyncCh:
	}
	defer cancel()
	inetDgramConnect.SetEnabled(true)
	inetStreamConnect.SetEnabled(true)
	exitConnect.SetEnabled(true)
	connectInet4.SetEnabled(true)
	if connectInet6 != nil {
		connectInet6.SetEnabled(true)
	}
	return next(eventCh)
}

// Module is the DI module of connect event.
//
// The module requires a context and a trace manager, and
// injects an event channel of <-chan Event.
var Module = shaft.Stack(stackConnectEventSource)
