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
	"sync/atomic"
	"syscall"

	"github.com/pkg/errors"
)

// traceHandle refers to a single trace registry managed
// by the trace manager and can update its options.
type traceHandle struct {
	id          uint64
	createTime  uint64
	numDone     uint64
	numLoss     uint64
	ctx         context.Context
	enableCh    chan *traceEnableRequest
	closeCh     chan *traceCloseRequest
	conditionCh chan *conditionUpdateRequest
	handler     interface{}
	desc        *traceEventDescriptor
	condition   string
	typ         string
	enabled     bool
}

// getProbeName formats the probe name.
func (t *traceHandle) getProbeName() string {
	return fmt.Sprintf("probe_%x_%x", t.createTime, t.id)
}

// getEnableFilePath evaluates the path for setting the
// probe enabled or disabled.
func (t *traceHandle) getEnableFilePath(
	root, namespace string,
) string {
	probeName := t.getProbeName()
	return filepath.Join(root, "instances",
		namespace, "events", namespace, probeName, "enable")
}

// parseProbeName convert from probe name to id.
//
// If the probe name cannot be parsed, it will return 0
// directly, which is not an valid id for probe.
func parseProbeName(name []byte) (createTime, id uint64) {
	if !bytes.HasPrefix(name, []byte("probe_")) {
		return
	}
	name = name[len("probe_"):]
	if index := bytes.Index(name, []byte("_")); index > 0 {
		createTime, _ = strconv.ParseUint(
			string(name[:index]), 16, 64)
		id, _ = strconv.ParseUint(
			string(name[index+1:]), 16, 64)
	}
	return
}

// ID is the current ID of the trace handle.
func (t *traceHandle) ID() uint64 {
	return t.id
}

// GetDone retrieves the number of done events.
func (t *traceHandle) GetDone() uint64 {
	return atomic.LoadUint64(&t.numDone)
}

// GetLost retrieves the number of lost events.
func (t *traceHandle) GetLost() uint64 {
	return atomic.LoadUint64(&t.numLoss)
}

// complete increment the corresponding counter.
func (t *traceHandle) complete(success bool) {
	if success {
		atomic.AddUint64(&t.numDone, 1)
	} else {
		atomic.AddUint64(&t.numLoss, 1)
	}
}

// traceEnableRequest is the request to enable or
// disable the handle.
type traceEnableRequest struct {
	enabled bool
	handle  *traceHandle
	doneCh  chan struct{}
}

// SetEnabled requests for the enable state update.
func (t *traceHandle) SetEnabled(enabled bool) {
	if t.enabled == enabled {
		return
	}
	req := &traceEnableRequest{
		enabled: enabled,
		handle:  t,
		doneCh:  make(chan struct{}),
	}
	select {
	case <-t.ctx.Done():
		return
	case t.enableCh <- req:
		<-req.doneCh
	}
}

// setEnabled flips the state of the handle.
func (t *traceHandle) setEnabled(
	root, namespace string, enabled bool,
) error {
	if t.enabled == enabled {
		return nil
	}
	enableString := []byte("0")
	if enabled {
		enableString = []byte("1")

		// XXX: when converting from enabled to disabled
		// status, the condition might always be reset,
		// so we should at least attempt to reset the
		// condition before restarting.
		//
		// We will revert to disabled status if the error
		// cannot be resolved.
		if err := t.updateCondition(
			root, namespace, t.condition); err != nil {
			return err
		}
	}

	// <tracefs>/instances/<ns>/events/<ns>/<probeID>/enable.
	enableFilePath := t.getEnableFilePath(root, namespace)
	if err := ioutil.WriteFile(enableFilePath,
		enableString, os.FileMode(0600)); err != nil {
		return err
	}
	t.enabled = enabled
	return nil
}

// traceCloseRequest is the request to close the handle.
type traceCloseRequest struct {
	handle *traceHandle
	doneCh chan struct{}
}

// Close will send the message to the manager.
func (t *traceHandle) Close() {
	req := &traceCloseRequest{
		handle: t,
		doneCh: make(chan struct{}),
	}
	select {
	case <-t.ctx.Done():
		return
	case t.closeCh <- req:
	}
	select {
	case <-t.ctx.Done():
		return
	case <-req.doneCh:
	}
}

// conditionUpdateRequest is the request to update condition
// of the current trace handle.
type conditionUpdateRequest struct {
	handle    *traceHandle
	err       error
	condition string
	doneCh    chan struct{}
}

// SetCondition will dispatch the condition to manager
// and waits for its result.
func (t *traceHandle) SetCondition(condition string) error {
	req := &conditionUpdateRequest{
		handle:    t,
		condition: condition,
		doneCh:    make(chan struct{}),
	}
	select {
	case <-t.ctx.Done():
		return t.ctx.Err()
	case t.conditionCh <- req:
		<-req.doneCh
		return req.err
	}
}

// evaluateCondition evaluates the condition string for
// specified two conditions.
func evaluateCondition(left, right string) string {
	switch {
	case left == "" && right != "":
		return right
	case left != "" && right != "":
		return fmt.Sprintf("(%s) && (%s)", left, right)
	case left != "" && right == "":
		return left
	default:
		return "0"
	}
}

// updateCondition is the real function to set condition.
func (t *traceHandle) updateCondition(
	root, namespace, condition string,
) error {
	// <tracefs>/instances/<ns>/events/<ns>/<probeID>/filter.
	target := filepath.Join(
		root, "instances", namespace, "events",
		namespace, t.getProbeName(), "filter")

	// Evaluate the old condition so it could be recovered
	// if there's error encountered.
	oldCondition := evaluateCondition(
		t.desc.initialCondition, t.condition)
	defer func() {
		if t.condition != condition {
			// XXX: attempt to rollback to previous condition,
			// and will disable the probe if it cannot be
			// actually reverted.
			err := ioutil.WriteFile(target,
				[]byte(oldCondition), os.FileMode(0600))
			if err != nil {
				enableFilePath := t.getEnableFilePath(
					root, namespace)
				_ = ioutil.WriteFile(enableFilePath,
					[]byte("0"), os.FileMode(0600))
			}
		}
	}()

	// Evaluate the new condition and update it.
	newCondition := evaluateCondition(
		t.desc.initialCondition, condition)
	err := ioutil.WriteFile(target,
		[]byte(newCondition), os.FileMode(0600))
	if err != nil {
		// Report error directly if it is not EINVAL.
		pathErr, ok := err.(*os.PathError)
		if !ok {
			return err
		}
		if pathErr.Err != syscall.EINVAL {
			return err
		}

		// Attempt to fetch and report the error cause.
		cause, readErr := ioutil.ReadFile(target)
		if readErr != nil {
			return err
		}
		return errors.Errorf(
			"filter expression %q syntax error: %s",
			newCondition, string(cause))
	}
	t.condition = condition
	return nil
}

// init attempt to initialize a specific probe, this
// must be done after the fields inside the trace handle
// have already been initialized.
func (t *traceHandle) init(
	root, namespace, tracepoint string,
) error {
	var err error
	var probeCreated bool

	// Determine the type prefix of the probe.
	var prefix string
	switch t.desc.meta {
	case typeProbeEvent:
		prefix = "p"
	case typeReturnEvent:
		prefix = "r"
	default:
		return errors.Errorf(
			"type %s is not supported", t.desc.meta)
	}

	// Evaluate the probe name and insertion statement.
	probeName := t.getProbeName()
	probeHeader := fmt.Sprintf("%s:%s/%s %s",
		prefix, namespace, probeName, tracepoint)
	probeExpr := probeHeader + " " + t.desc.format()

	// Open and write the tracepoint into manifest.
	fd, err := syscall.Open(filepath.Join(root, t.typ),
		syscall.O_WRONLY|syscall.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	if _, err = syscall.Write(fd, []byte(probeHeader)); err != nil {
		if err == syscall.EINVAL || err == syscall.ENOENT {
			return ErrBadTracePoint
		}
		return err
	}
	if err = removeProbe(
		root, t.typ, namespace, probeName); err != nil {
		return err
	}
	if _, err = syscall.Write(fd, []byte(probeExpr)); err != nil {
		if err == syscall.EINVAL {
			return errors.Errorf(
				"probe expression %q syntax error", probeExpr)
		}
		return err
	}
	defer func() {
		// Remove the tracepoint from the tracefs.
		if !probeCreated {
			_ = removeProbe(root, t.typ, namespace, probeName)
		}
	}()

	// Set the initial condition of the probe.
	if err = t.updateCondition(root, namespace, ""); err != nil {
		return err
	}

	// Attempt to enable the probe, this should reveals some
	// problem when the specified trace point is actually
	// invalid, especially for those in uprobe.
	enableFilePath := t.getEnableFilePath(root, namespace)
	if err = ioutil.WriteFile(enableFilePath,
		[]byte("1"), os.FileMode(0600)); err != nil {
		return err
	}
	if err = ioutil.WriteFile(enableFilePath,
		[]byte("0"), os.FileMode(0600)); err != nil {
		return err
	}
	probeCreated = true
	return nil
}

// destroy will attempt to remove the single probe.
func (t *traceHandle) destroy(root, namespace string) {
	_ = removeProbe(root, t.typ, namespace, t.getProbeName())
	t.id = 0
}

// parseEventHandler is the common code to parse and
// compile the event handler.
func parseEventHandler(
	handler interface{},
) (*traceEventDescriptor, error) {
	handlerType := reflect.TypeOf(handler)
	if kind := handlerType.Kind(); kind != reflect.Func {
		return nil, errors.Wrapf(
			errors.Errorf("invalid kind %s", kind),
			"parse event handler")
	}
	if handlerType.NumIn() != 1 {
		return nil, errors.Wrapf(
			errors.Errorf("invalid input amount"),
			"parse event handler")
	}
	typ := handlerType.In(0)
	desc, err := compileTraceEvent(typ)
	if err != nil {
		return nil, errors.Wrapf(err, "parse event")
	}
	return desc, nil
}

// TraceKProbe will register a kprobe event.
func (mgr *traceManager) TraceKProbe(
	location string, handler interface{},
) (Trace, <-chan struct{}, error) {
	desc, err := parseEventHandler(handler)
	if err != nil {
		return nil, nil, err
	}
	return mgr.createTrace("kprobe_events",
		location, handler, desc)
}

// TraceUProbe will register a uprobe event.
func (mgr *traceManager) TraceUProbe(
	library, location string, handler interface{},
) (Trace, <-chan struct{}, error) {
	desc, err := parseEventHandler(handler)
	if err != nil {
		return nil, nil, err
	}
	return mgr.createTrace("uprobe_events",
		fmt.Sprintf("%s:%s", library, location),
		handler, desc)
}
