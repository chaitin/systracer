package systracer

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/chaitin/systracer/pkg/alloc"
	"github.com/chaitin/systracer/pkg/kversion"
)

// epollNotWorking indicates whether there's support for
// polling tracing pipe with epoll.
//
// XXX: on linux version 3.10, the epoll will fail to
// generate edge trigger event for tracefs files, rendering
// the trace to be not working.
//
// To prevent so, if the polling is not working, we will
// enforce it to always read something from the buffer.
var epollNotWorking = kversion.Current < kversion.Must("3.11")

// traceCreateRequest is the request for creating an
// instance of trace, and wait for creation completion.
type traceCreateRequest struct {
	handle     *traceHandle
	err        error
	handler    interface{}
	desc       *traceEventDescriptor
	typ        string
	tracepoint string
	doneCh     chan struct{}
	syncCh     <-chan struct{}
}

// createTrace is the request to create a trace object
// with the dispatched request.
func (mgr *traceManager) createTrace(
	typ, tracepoint string,
	handler interface{}, desc *traceEventDescriptor,
) (Trace, <-chan struct{}, error) {
	req := &traceCreateRequest{
		handler:    handler,
		desc:       desc,
		typ:        typ,
		tracepoint: tracepoint,
		doneCh:     make(chan struct{}),
	}
	select {
	case <-mgr.rootCtx.Done():
		return nil, nil, mgr.rootCtx.Err()
	case mgr.createCh <- req:
	}

	select {
	case <-mgr.rootCtx.Done():
		return nil, nil, mgr.rootCtx.Err()
	case <-req.doneCh:
		var handle Trace
		if req.handle != nil {
			handle = req.handle
		}
		return handle, req.syncCh, req.err
	}
}

// traceManager implements tracing.TraceManager.
type traceManager struct {
	rootCtx  context.Context
	lastErr  error
	createCh chan *traceCreateRequest
	fetchCh  chan *fetchWriterStateRequest
}

// cleanupNamespace cleans up specified namespace.
func cleanupNamespace(log *zap.SugaredLogger, root, namespace string) {
	logger := log.With(
		zap.String("root", root),
		zap.String("namespace", namespace),
	)
	if err := removeAllProbe(
		root, "kprobe_events", namespace); err != nil {
		logger.Infof("remove kprobes: %s", err)
	}
	if err := removeAllProbe(
		root, "uprobe_events", namespace); err != nil {
		logger.Infof("remove uprobes: %s", err)
	}
	if err := removeInstance(root, namespace); err != nil {
		logger.Infof("remove instance: %s", err)
	}
}

// traceManagerState holds registry of traces.
type traceManagerState struct {
	rootCtx     context.Context
	root        string
	namespace   string
	traceID     uint64
	registries  map[uint64]*traceHandle
	enableCh    chan *traceEnableRequest
	closeCh     chan *traceCloseRequest
	conditionCh chan *conditionUpdateRequest
	syncCh      chan struct{}
}

// destroy will clean up all previously allocated
// instances of traces.
func (s *traceManagerState) destroy() {
	for _, registry := range s.registries {
		registry.destroy(s.root, s.namespace)
	}
}

// markUnsync is the action to mark current manager state
// is not synchronized with the writer, and must perform
// the synchronization action, returning channel for
// synchronization completion notification.
func (s *traceManagerState) markUnsync() <-chan struct{} {
	if s.syncCh == nil {
		s.syncCh = make(chan struct{})
	}
	return s.syncCh
}

// markSync is the action to mark current manager state
// as up-to-date with the writer thread.
func (s *traceManagerState) markSync() {
	if s.syncCh == nil {
		return
	}
	close(s.syncCh)
	s.syncCh = nil

	// XXX: the request synchronization is a process of
	// copy-on-write, since the number of items in the
	// table is far less than data to process.
	newRegistries := make(map[uint64]*traceHandle)
	for id, handle := range s.registries {
		newRegistries[id] = handle
	}
	s.registries = newRegistries
}

// handleCreate will handle the request of creation.
func (s *traceManagerState) handleCreate(
	request *traceCreateRequest,
) {
	defer close(request.doneCh)
	defer func() {
		if err := recover(); err != nil {
			request.err = errors.Wrap(errors.Errorf(
				"handleCreate panics: %s", err),
				"allocate trace")
		}
	}()
	request.err = func() error {
		// Attempt to allocate a new identity.
		newTraceID := alloc.Alloc(s.traceID, 0,
			func(id uint64) bool {
				return s.registries[id] != nil
			})
		if newTraceID == 0 {
			return errors.Wrap(errors.New(
				"no available trace ID"),
				"allocate trace")
		}
		s.traceID = newTraceID

		// Allocate and initialize the trace.
		handle := &traceHandle{
			id:          newTraceID,
			createTime:  uint64(time.Now().UnixNano()),
			ctx:         s.rootCtx,
			enableCh:    s.enableCh,
			closeCh:     s.closeCh,
			conditionCh: s.conditionCh,
			handler:     request.handler,
			desc:        request.desc,
			typ:         request.typ,
		}
		if err := handle.init(s.root, s.namespace,
			request.tracepoint); err != nil {
			if err != ErrBadTracePoint {
				return errors.Wrap(err,
					"initialize trace")
			}
			return ErrBadTracePoint
		}
		s.registries[newTraceID] = handle
		request.handle = handle
		request.syncCh = s.markUnsync()
		return nil
	}()
}

// handleEnable will handle the request of start.
func (s *traceManagerState) handleEnable(
	request *traceEnableRequest,
) error {
	defer close(request.doneCh)
	if request.handle.id == 0 {
		return nil
	}
	return request.handle.setEnabled(
		s.root, s.namespace, request.enabled)
}

// handleRemove will handle the request of deletion.
func (s *traceManagerState) handleRemove(
	request *traceCloseRequest,
) {
	defer close(request.doneCh)
	if request.handle.id == 0 {
		return
	}
	delete(s.registries, request.handle.id)
	request.handle.destroy(s.root, s.namespace)
	s.markUnsync()
}

// handleCondition will handle the request of condition.
func (s *traceManagerState) handleCondition(
	request *conditionUpdateRequest,
) {
	defer close(request.doneCh)
	if request.handle.id == 0 {
		return
	}
	err := request.handle.updateCondition(
		s.root, s.namespace, request.condition)
	if err != nil {
		request.err = errors.Wrap(err,
			"update trace condition")
	}
}

// traceWriterState is the state held on writer thread.
type traceWriterState struct {
	registries map[uint64]*traceHandle
	baseTime   time.Time
	baseEpoch  time.Duration
	logger     *zap.SugaredLogger
}

// fetchWriterStateRequest is an internal request for
// retrieving trace writer state and modify it.
type fetchWriterStateRequest struct {
	state  *traceWriterState
	doneCh chan struct{}
}

// fetchWriterState requests for the trace writer state.
func (mgr *traceManager) fetchWriterState() (
	*traceWriterState, error,
) {
	req := &fetchWriterStateRequest{
		doneCh: make(chan struct{}),
	}
	select {
	case <-mgr.rootCtx.Done():
		return nil, mgr.rootCtx.Err()
	case mgr.fetchCh <- req:
	}
	select {
	case <-mgr.rootCtx.Done():
		return nil, mgr.rootCtx.Err()
	case <-req.doneCh:
		return req.state, nil
	}
}

// pow10 is the series of exponents to 10^exponent values.
var pow10 = [10]uint64{
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
}

// parseSecond parses the number representing the value
// of second (with period dot).
func parseSecond(value []byte) (time.Duration, error) {
	dotIndex := bytes.Index(value, []byte("."))
	var beforeDot, afterDot []byte
	if dotIndex < 0 {
		beforeDot = value
		afterDot = nil
	} else {
		beforeDot = value[:dotIndex]
		afterDot = value[dotIndex+1:]
	}
	var result int64

	// Parse the component before the dot.
	if len(beforeDot) > 0 {
		val, err := strconv.ParseUint(
			string(beforeDot), 10, 64)
		if err != nil {
			return time.Duration(0), err
		}
		result += int64(val * pow10[9])
	}

	// Parse the component after the dot.
	if len(afterDot) > 0 {
		if len(afterDot) > 9 {
			afterDot = afterDot[0:9]
		}
		val, err := strconv.ParseUint(
			string(afterDot), 10, 64)
		if err != nil {
			return time.Duration(0), err
		}
		result += int64(val * pow10[9-len(afterDot)])
	}

	return time.Duration(result), nil
}

// handleData will process the input of reader.
//
// This operation will limit the epoch of event and
// produces the end epoch, which will ensures that
// events will not process more than once when used
// under the circumstances like side chain mitigating.
func (s *traceWriterState) handleData(
	input []byte, startEpoch time.Duration,
) time.Duration {
	limitEpoch := startEpoch

	// Loop and parse input data.
	for len(input) > 0 {
		func() {
			var err error

			// Skip the current strip of input and find
			// the dash character.
			if len(input) < 17 || input[16] != '-' {
				return
			}
			input = input[17:]

			// Skip and read the PID sequence.
			var taskPID uint32
			for i := 0; i < len(input); i++ {
				if input[i] == ' ' {
					value, err := strconv.ParseUint(
						string(input[:i]), 10, 32)
					input = input[i+1:]
					if err != nil {
						s.logger.Debugf(
							"parse taskid %q: %s",
							string(input[:i]), err)
						return
					}
					taskPID = uint32(value)
					break
				}
				if input[i] < '0' || input[i] > '9' {
					return
				}
			}

			// Skip the central portion of CPUID and IRQ.
			input = bytes.TrimLeft(input, " ")
			for i := 0; i < len(input); i++ {
				if input[i] == ' ' {
					input = input[i+1:]
					break
				}
			}
			for i := 0; i < len(input); i++ {
				if input[i] == ' ' {
					input = input[i+1:]
					break
				}
			}

			// Parse the duration since the timepoint of
			// start of the boot time. (If this could not
			// be completed, the timestamp will be now).
			var epoch time.Duration
			for i := 0; i < len(input); i++ {
				if input[i] == ':' {
					epoch, err = parseSecond(
						bytes.TrimSpace(input[:i]))
					if err != nil {
						s.logger.Debugf(
							"parse epoch %q: %s",
							string(input[:i]), err)
						return
					}
					input = input[i+1:]
					break
				}
				if input[i] == '.' || input[i] == ' ' {
					continue
				}
				if input[i] < '0' || input[i] > '9' {
					return
				}
			}
			timestamp := s.baseTime.Add(epoch - s.baseEpoch)

			// Judge whether the event is earlier than the
			// limit epoch, and we will just parse and skip
			// that event if it happens so.
			if limitEpoch != 0 && limitEpoch >= epoch {
				return
			}
			limitEpoch = epoch

			// Read the portion of the message key.
			var key []byte
			for i := 0; i < len(input); i++ {
				if input[i] == ':' {
					key = input[:i]
					input = input[i+1:]
					break
				} else if input[i] == '\n' {
					key = input[:i]
					input = input[i:]
					break
				}
			}
			createTime, id := parseProbeName(
				bytes.TrimSpace(key))
			if id == 0 {
				return
			}
			handle := s.registries[id]
			if handle == nil ||
				handle.createTime != createTime {
				return
			}

			// Skip the parenthesis of trace.
			input = bytes.TrimLeft(input, " ")
			if len(input) > 0 && input[0] == '(' {
				for i := 0; i < len(input); i++ {
					if input[i] == ')' {
						input = input[i+1:]
						break
					}
				}
			}
			input = bytes.TrimLeft(input, " ")

			// A counter for recording whether the handle
			// has been called successfully.
			var handleSuccess bool
			defer func() {
				handle.complete(handleSuccess)
			}()
			defer func() {
				if err := recover(); err != nil {
					s.logger.Errorf(
						"handle #%d panics: %s",
						handle.id, err)
				}
			}()

			// Attempt to allocate the instance of
			// event before we call handler.
			argument := reflect.New(handle.desc.typ)
			baseEvent := (*Event)(
				unsafe.Pointer(argument.Pointer()))
			baseEvent.TaskPID = taskPID
			baseEvent.Timestamp = timestamp
			baseEvent.epoch = epoch

			// Fill the fields in the log event.
			offset, err := handle.desc.fill(
				argument.Pointer(), input)
			input = input[offset:]
			if err != nil {
				s.logger.Errorf(
					"handle #%d errors: %s",
					handle.id, err)
				return
			}

			// If the handle is not enabled, just don't
			// invoke the function and return.
			if !handle.enabled {
				return
			}

			// Invoke the function and complete the processing.
			f := reflect.ValueOf(handle.handler)
			_ = f.Call([]reflect.Value{
				reflect.Indirect(argument),
			})
			handleSuccess = true
		}()

		// Seek for the next endline and forward.
		index := bytes.Index(input, []byte("\n"))
		if index < 0 {
			break
		}
		input = input[index+1:]
	}

	return limitEpoch
}

// maxReadPacketSize is the maximum size allowed for
// the manager reader packet.
const maxReadPacketSize = 10 * 1024 * 1024

// runReaderThread will execute the reader thread
// with specified pipe and channel.
func (mgr *traceManager) runReaderThread(
	tracePipe *os.File, spliceIn, spliceOut int,
	sendCh chan<- []byte,
) error {
	var err error
	conn, err := tracePipe.SyscallConn()
	if err != nil {
		return errors.Wrap(err, "syscall connect")
	}

	for {
		var data []byte
		tracePipeConsume := func(fd uintptr) error {
			for len(data) < maxReadPacketSize {
				// XXX: trace pipe file supports splicing right
				// at its initial implementation, and unlike
				// its read counterpart, it contains nearly no
				// backward goto statement, which reduces its
				// chance for triggering known bug in the kernel.
				n, err := unix.Splice(
					int(fd), nil, spliceOut, nil,
					maxReadPacketSize, unix.SPLICE_F_NONBLOCK)
				if n > 0 {
					// Read and splice next data in buffer.
					buf := make([]byte, n)
					m, err := syscall.Read(spliceIn, buf)
					if err != nil {
						return err
					}
					data = append(data, buf[:m]...)
				} else if n == 0 {
					// No more data to read now, we will
					// just exit and return error.
					return syscall.EBADF
				} else if err == syscall.EAGAIN ||
					err == syscall.EWOULDBLOCK ||
					err == syscall.EINTR {
					// Current buffer has been emptied,
					// now we should perform the action.
					return nil
				} else {
					return err
				}
			}
			return nil
		}

		if epollNotWorking {
			// If epoll is not working, we will always
			// attempt to read from the epoll pipe, this
			// requires the minimum limit timeout to be
			// non-zero to prevent creating a busy looping.
			_ = tracePipeConsume(tracePipe.Fd())
		} else {
			var innerErr error
			if err := conn.Read(func(fd uintptr) bool {
				innerErr := tracePipeConsume(fd)
				if innerErr != nil {
					return true
				}
				return len(data) > 0
			}); err != nil {
				// XXX: the error is from standard library,
				// internal/poll.ErrFileClosing, the piece
				// of code above is provided by standard
				// library, so it is safe to do so.
				if err.Error() == "use of closed file" {
					err = nil
				}
				return errors.Wrap(err, "read pipe")
			}
			if innerErr != nil {
				return errors.Wrap(innerErr, "read pipe")
			}
		}

		// Create and copy out buffer, and send data
		// back to the manager thread.
		select {
		case <-mgr.rootCtx.Done():
			return nil
		case sendCh <- data:
		}
	}
}

// synchronizeRegistryRequest is the request communicating
// between the master and writer.
type synchronizeRegistryRequest struct {
	registries map[uint64]*traceHandle
}

// currentSyncRequest retrieve the current request of
// synchronization from the trace manager state.
func (s *traceManagerState) currentSyncRequest() (
	request *synchronizeRegistryRequest,
) {
	if s.syncCh == nil {
		return nil
	}
	return &synchronizeRegistryRequest{
		registries: s.registries,
	}
}

// minimumTickerInterval is the interval which is the lowest
// frequecy the writer thread could operate on.
var minimumTickerInterval = 50 * time.Millisecond

// runWriterThread will execute the writer thread for
// processing data from the reader and side chain.
func (mgr *traceManager) runWriterThread(
	syncCh <-chan *synchronizeRegistryRequest,
	receiveCh <-chan []byte, limitInterval time.Duration,
) error {
	// Writer state for handling the dispatch relation
	// of the trace data payload.
	state := &traceWriterState{
		registries: make(map[uint64]*traceHandle),
	}

	// Initialize the ticker which limits the reader
	// production rate.
	var tick *time.Ticker
	defer func() {
		if tick != nil {
			tick.Stop()
		}
	}()

	// Clamp the minimum of timeout to a value
	// so that the reader thread will not be trapped
	// in a raging busy loop in realtime mode.
	if epollNotWorking {
		if limitInterval < minimumTickerInterval {
			limitInterval = minimumTickerInterval
		}
	}

	// Must not be too small, or delivering
	// time event will iteself brings load.
	if limitInterval > minimumTickerInterval {
		tick = time.NewTicker(limitInterval)
	}

	// Execute the writer thread for handling data
	// from the reader thread and side chain.
	received := false
	for {
		// Create the channel of tick flipping and
		// reader consuming.
		var timerCh <-chan time.Time
		var currentReceiveCh <-chan []byte
		if tick != nil && received {
			timerCh = tick.C
			currentReceiveCh = nil
		} else {
			timerCh = nil
			currentReceiveCh = receiveCh
		}

		// Wait for the next tick for reception.
		select {
		case <-mgr.rootCtx.Done():
			return nil
		case req := <-mgr.fetchCh:
			req.state = state
			close(req.doneCh)
		case data := <-currentReceiveCh:
			received = true
			_ = state.handleData(data, time.Duration(0))
		case <-timerCh:
			received = false
		case request := <-syncCh:
			state.registries = request.registries
		}
	}
}

// runMasterThread will execute the master thread
// after the environment has been setup.
func (mgr *traceManager) runMasterThread(
	tracePipe *os.File, spliceIn, spliceOut int,
	root, namespace string, log *zap.SugaredLogger,
	syncCh chan *synchronizeRegistryRequest,
) error {
	defer cleanupNamespace(log, root, namespace)
	defer func() { _ = tracePipe.Close() }()
	defer func() {
		_ = syscall.Close(spliceIn)
		_ = syscall.Close(spliceOut)
	}()

	// Registries of all available probes.
	state := &traceManagerState{
		rootCtx:     mgr.rootCtx,
		root:        root,
		namespace:   namespace,
		registries:  make(map[uint64]*traceHandle),
		enableCh:    make(chan *traceEnableRequest),
		closeCh:     make(chan *traceCloseRequest),
		conditionCh: make(chan *conditionUpdateRequest),
	}
	defer state.destroy()

	// Loop and handle trace manager events.
	for {
		var currentSyncCh chan<- *synchronizeRegistryRequest
		syncRequest := state.currentSyncRequest()
		if syncRequest != nil {
			currentSyncCh = syncCh
		}
		select {
		case <-mgr.rootCtx.Done():
			return nil
		case req := <-mgr.createCh:
			state.handleCreate(req)
		case req := <-state.enableCh:
			if err := state.handleEnable(req); err != nil {
				log.Errorf(
					"cannot enable handle #%d: %s",
					req.handle.id, err)
			}
		case req := <-state.closeCh:
			state.handleRemove(req)
		case req := <-state.conditionCh:
			state.handleCondition(req)
		case currentSyncCh <- syncRequest:
			state.markSync()
		}
	}
}

// newInternal will create an instance of the manager.
func newInternal(
	ctx context.Context, group *errgroup.Group, options ...Option,
) (*traceManager, error) {
	var err error
	option := newOption()
	WithOptions(options...)(option)
	logger := option.logger.Named("systracer").Sugar()
	root := option.tracefsPath
	namespace := option.instanceName

	// Verify that the specified file system is tracefs
	// or debugfs, the debugfs directory must have last
	// component name of tracing.
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		return nil, err
	}
	isValidFileSystem := false
	if fs.Type == unix.TRACEFS_MAGIC {
		isValidFileSystem = true
	} else if fs.Type == unix.DEBUGFS_MAGIC &&
		filepath.Base(root) == "tracing" {
		isValidFileSystem = true
	}
	if !isValidFileSystem {
		return nil, errors.Errorf(
			"invalid file system with magic %x", fs.Type)
	}

	// Attempt to clean up previous run pass of manager.
	hasCreated := false
	cleanupNamespace(logger, root, namespace)
	defer func() {
		if !hasCreated {
			cleanupNamespace(logger, root, namespace)
		}
	}()

	// Create a new namespace under the specified directory.
	if err := unix.Mkdir(filepath.Join(root, "instances",
		namespace), 0600); err != nil && err != unix.EEXIST {
		return nil, errors.Errorf(
			"cannot create instance %q: %s", namespace, err)
	}

	// Clear the content of previous trace.
	if err = ioutil.WriteFile(filepath.Join(
		root, "instances", namespace, "tracing_on"),
		[]byte("0"), os.FileMode(0600)); err != nil {
		return nil, err
	}
	if err = ioutil.WriteFile(filepath.Join(
		root, "instances", namespace, "trace"),
		[]byte(""), os.FileMode(0600)); err != nil {
		return nil, err
	}

	// Setup trace data recording parameters.
	if err = ioutil.WriteFile(filepath.Join(
		root, "instances", namespace, "trace_clock"),
		[]byte("global"), os.FileMode(0600)); err != nil {
		return nil, err
	}
	traceOptions := []string{
		"print-parent", "nosym-offset", "nosym-addr",
		"noverbose", "nohex", "nobin", "noblock",
		"nostacktrace", "trace_printk", "noftrace-preempt",
		"nobranch", "noannotate", "nouserstacktrace",
		"nosym-userobj", "noprintk-msg-only",
		"context-info", "nolatency-format",
		"nosleep-time", "nograph-time",
		"norecord-cmd", "norecord-tgid",
		"nodisable-on-free", "irq-info",
		"nomarkers", "nofunction-trace",
		"notest_nop_accept", "notest_nop_reject",
	}
	for _, traceOption := range traceOptions {
		_ = ioutil.WriteFile(filepath.Join(
			root, "instances", namespace, "trace_options"),
			[]byte(traceOption), os.FileMode(0600))
	}

	// Re-enable the trace instance after setup.
	if err = ioutil.WriteFile(filepath.Join(
		root, "instances", namespace, "tracing_on"),
		[]byte("1"), os.FileMode(0600)); err != nil {
		return nil, err
	}

	// Attempt to open the trace pipe of the manager.
	fd, err := syscall.Open(filepath.Join(
		root, "instances", namespace, "trace_pipe"),
		syscall.O_RDONLY|syscall.O_NONBLOCK, 0400)
	if err != nil {
		return nil, err
	}
	tracePipe := os.NewFile(uintptr(fd), "trace_pipe")
	defer func() {
		if !hasCreated {
			_ = tracePipe.Close()
		}
	}()

	// Attempt to create splice pipe for reading.
	var spliceFd [2]int
	if err := syscall.Pipe2(spliceFd[:],
		syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		return nil, err
	}
	spliceIn, spliceOut := spliceFd[0], spliceFd[1]
	defer func() {
		if !hasCreated {
			_ = syscall.Close(spliceIn)
			_ = syscall.Close(spliceOut)
		}
	}()

	// Attempt update the capacity of the trace pipe to
	// increase the capacity of the event tracing.
	//
	// However the program still works without this
	// setup, it is just an optional optimization.
	_, _ = unix.FcntlInt(uintptr(spliceOut),
		unix.F_SETPIPE_SZ, maxReadPacketSize)

	// Start the new trace manager and return.
	receiveCh := make(chan []byte)
	syncCh := make(chan *synchronizeRegistryRequest)
	manager := &traceManager{
		rootCtx:  ctx,
		createCh: make(chan *traceCreateRequest),
		fetchCh:  make(chan *fetchWriterStateRequest),
	}
	group.Go(func() error {
		return manager.runMasterThread(
			tracePipe, spliceIn, spliceOut,
			root, namespace, logger, syncCh)
	})
	group.Go(func() error {
		return manager.runReaderThread(
			tracePipe, spliceIn, spliceOut, receiveCh)
	})
	group.Go(func() error {
		return manager.runWriterThread(
			syncCh, receiveCh, option.limitInterval)
	})
	hasCreated = true
	return manager, nil
}

type calibrateEvent struct {
	ProbeEvent
	Condition `tracing:"Name ~ \"/proc/self/calibrate/*\"`

	Name StringAddr `tracing:"$arg2"`
}

// New will create an instance of the manager.
func New(
	ctx context.Context, group *errgroup.Group, options ...Option,
) (Manager, error) {
	// The implementation will be splitted into two steps,
	// first we create the uncalibrated manager, then we
	// attempt to calibrate it and return it to caller.
	calibrated := false
	cancelCtx, cancel := context.WithCancel(ctx)
	innerGroup, innerCtx := errgroup.WithContext(cancelCtx)
	defer func() {
		if !calibrated {
			cancel()
			_ = innerGroup.Wait()
		}
	}()
	manager, err := newInternal(innerCtx, innerGroup, options...)
	if err != nil {
		return nil, err
	}
	state, err := manager.fetchWriterState()
	if err != nil {
		return nil, err
	}
	calibrateDone := make(chan struct{})
	var calibrateOnce sync.Once
	symbols := []string{"vfs_fstatat", "vfs_statx"}
	var calibrateErr error
	registered := false
	for _, symbol := range symbols {
		calibrate, _, err := manager.TraceKProbe(symbol, func(
			event calibrateEvent,
		) {
			str := filepath.Base(event.Name.String)
			unixNano, err := strconv.ParseUint(str, 16, 64)
			if err != nil {
				return
			}
			baseTime := time.Unix(0, int64(unixNano))
			if !state.baseTime.IsZero() {
				startNew := baseTime.Add(-event.epoch)
				startOld := state.baseTime.Add(-state.baseEpoch)
				if startOld.Sub(startNew) > 500*time.Millisecond {
					return
				}
			}
			state.baseTime = baseTime
			state.baseEpoch = event.epoch
			calibrateOnce.Do(func() {
				close(calibrateDone)
			})
		})
		if err != nil {
			calibrateErr = err
			continue
		}
		registered = true
		defer calibrate.Close()
		calibrate.SetEnabled(true)
	}
	if !registered {
		return nil, calibrateErr
	}
	var stat unix.Stat_t
	unixNano := time.Now().UnixNano()
	_ = unix.Fstatat(unix.AT_FDCWD, fmt.Sprintf(
		"/proc/self/calibrate/%x", unixNano), &stat, 0)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, errors.New("calibration timed out")
	case <-calibrateDone:
	}
	group.Go(func() error {
		defer cancel()
		<-innerCtx.Done()
		return innerGroup.Wait()
	})
	calibrated = true
	return manager, nil
}
