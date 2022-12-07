// Package inode provides service for uniquely pinning and
// addressing an inode for path.
package inode

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aegistudio/shaft"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/chaitin/systracer"
	"github.com/chaitin/systracer/pkg/alloc"
	"github.com/chaitin/systracer/pkg/kversion"
)

// inodePinResult is the response captured corresponding to
// each inode pinning request.
type inodePinResult struct {
	inode, cookie uint64
}

// collector is the collector for receiving the reaction of
// the inode pinning, and send it back to the master thread.
type collector struct {
	rootCtx  context.Context
	resultCh chan<- inodePinResult
}

// handleInodePin is the handler for inode pinning captured
// by security_inode_getsecurity. We filter out only the
// "security.systracer.inode_pin.*".
func (col *collector) handleInodePin(
	name string, inode uint64,
) {
	prefix := "systracer.inode_pin."
	if !strings.HasPrefix(name, prefix) {
		return
	}
	cookie, err := strconv.ParseUint(
		name[len(prefix):], 16, 64)
	if err != nil {
		return
	}
	result := inodePinResult{
		inode:  inode,
		cookie: cookie,
	}
	select {
	case <-col.rootCtx.Done():
	case col.resultCh <- result:
	}
}

// handleSecurityInodePin handles the inode pinning event
// from version 2.6.24 (inclusive) to 5.12 (exclusive).
//
// security_inode_getsecurity(
//    Inode, "systracer.inode_pin.${hex Cookie}")
func (col *collector) handleSecurityInodePin_V2_6_24(
	event entrySecurityInodePin_V2_6_24,
) {
	col.handleInodePin(event.Name, event.Inode)
}

// handleSecurityInodePin handles the inode pinning event
// from 5.12 (inclusive) to now.
//
// security_inode_getsecurity(
//    MountNS, Inode, "systracer.inode_pin.${hex Cookie}")
func (col *collector) handleSecurityInodePin_V5_12(
	event entrySecurityInodePin_V5_12,
) {
	col.handleInodePin(event.Name, event.Inode)
}

// inodePin is the state of deduplicated inode which holds
// strong reference to the open inode to keep the validity
// of the addressing result.
type inodePin struct {
	id     uint64
	name   string
	inode  uint64
	file   *os.File
	ref    uint64
	doneCh chan struct{}
}

// Inode is the actually pinned inode.
type Inode struct {
	manager *Manager
	inner   *inodePin
	once    sync.Once
}

// Inode returns the address of the pinned inode.
func (inode *Inode) Inode() uint64 {
	return inode.inner.inode
}

// Unpin removes the strong reference held by caller.
func (inode *Inode) Unpin() {
	inode.once.Do(func() {
		inode.manager.unpin(inode.inner)
	})
	runtime.SetFinalizer(inode, nil)
}

// inodePinRequest for performing inode pinning.
type inodePinRequest struct {
	name   string
	mode   int
	doneCh chan struct{}
	result *inodePin
	err    error
}

// Manager for performing and managing inode pins.
type Manager struct {
	rootCtx context.Context
	pinCh   chan *inodePinRequest
	unpinCh chan *inodePin
}

// pin requests for requesting and opening an inode pin.
func (m *Manager) pin(name string, mode int) (*Inode, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	req := &inodePinRequest{
		name:   abs,
		mode:   mode,
		doneCh: make(chan struct{}),
	}
	select {
	case <-m.rootCtx.Done():
		return nil, m.rootCtx.Err()
	case m.pinCh <- req:
	}
	select {
	case <-m.rootCtx.Done():
		return nil, m.rootCtx.Err()
	case <-req.doneCh:
	}
	if req.err != nil {
		return nil, req.err
	}
	select {
	case <-m.rootCtx.Done():
		return nil, m.rootCtx.Err()
	case <-req.result.doneCh:
	}
	result := &Inode{
		inner:   req.result,
		manager: m,
	}
	runtime.SetFinalizer(result, func(value *Inode) {
		value.Unpin()
	})
	return result, nil
}

// PinFile is the request for pinning single file.
func (m *Manager) PinFile(name string) (*Inode, error) {
	return m.pin(name, syscall.O_RDONLY|syscall.O_CLOEXEC)
}

// PinDir is the request for pinning single dir.
func (m *Manager) PinDir(name string) (*Inode, error) {
	return m.pin(name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
}

// unpin is the request for closing an inode pin.
func (m *Manager) unpin(p *inodePin) {
	select {
	case <-m.rootCtx.Done():
	case m.unpinCh <- p:
	}
}

// managerState is the state triggered by
// either pin completion event, retest timers and
// registrations/unregistrations.
type managerState struct {
	last       uint64
	cookieBase uint64

	all     map[uint64]*inodePin
	names   map[string]*inodePin
	cookies map[uint64]*inodePin
}

// close destroys all allocated instances in the state.
func (s *managerState) close() {
	for _, pin := range s.all {
		_ = pin.file.Close()
		pin.id = 0
	}
}

// performInodePin executes the actual inode pinning with
// our specified fd and cookie.
func performInodePin(fd uintptr, cookie uint64) {
	filename := fmt.Sprintf("/proc/self/fd/%d", fd)
	attribute := fmt.Sprintf(
		"security.systracer.inode_pin.%x", cookie)
	var buf [1024]byte
	_, _ = syscall.Getxattr(filename, attribute, buf[:])
}

// pin attempts to allocate and create a pin in the state.
func (s *managerState) pin(
	name string, flag int,
) (rpin *inodePin, rerr error) {
	// Attempt to open the specified file for later use,
	// please notice that the file might be swapped for
	// later use and will not close then.
	fd, err := syscall.Open(name, flag, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	// If there's previous node for the file, attempt to
	// allocate specified node for the file.
	if previous, ok := s.names[name]; ok {
		// Retrieve previous and current file information.
		newInfo, err := f.Stat()
		if err != nil {
			return nil, err
		}
		newStat := newInfo.Sys().(*syscall.Stat_t)
		oldInfo, err := previous.file.Stat()
		if err != nil {
			return nil, err
		}
		oldStat := oldInfo.Sys().(*syscall.Stat_t)

		// Compare the information and return the previous
		// one if they are the same.
		if newStat.Dev == oldStat.Dev &&
			newStat.Ino == oldStat.Ino &&
			newStat.Rdev == oldStat.Rdev {
			previous.ref++
			return previous, nil
		}
	}

	// Attempt to allocate a new node for the subscription.
	id := alloc.Alloc(s.last, uint64(1<<48), func(id uint64) bool {
		return s.all[id] != nil
	})
	if id == 0 {
		return nil, errors.New(
			"cannot allocate more inode pin")
	}
	created := &inodePin{
		id:     id,
		name:   name,
		file:   f,
		ref:    1,
		doneCh: make(chan struct{}),
	}
	s.all[id] = created
	s.last = id
	s.names[name] = created
	f = nil

	// Mark the file and create a new cookie here.
	s.cookieBase++
	cookie := s.cookieBase
	s.cookies[cookie] = created
	performInodePin(created.file.Fd(), cookie)
	return created, nil
}

// unpin attempts to decrement reference and potentially
// remove a pin from the state.
func (s *managerState) unpin(p *inodePin) {
	if p.id == 0 {
		return
	}
	p.ref--
	if p.ref > 0 {
		return
	}
	if s.names[p.name] == p {
		delete(s.names, p.name)
	}
	delete(s.all, p.id)
	if p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
	p.id = 0
}

// reallocateCookie will attempt to reset current cookies.
func (s *managerState) reallocateCookie() {
	newCookies := make(map[uint64]*inodePin)
	for _, target := range s.cookies {
		if target.id == 0 {
			continue
		}
		s.cookieBase++
		cookie := s.cookieBase
		newCookies[cookie] = target
		performInodePin(target.file.Fd(), cookie)
	}
	s.cookies = newCookies
}

// handleResult handles the inode pin result.
func (s *managerState) handleResult(
	event inodePinResult,
) {
	target := s.cookies[event.cookie]
	if target == nil {
		return
	}
	delete(s.cookies, event.cookie)
	target.inode = event.inode
	close(target.doneCh)
}

// hasPending see whether there's pending pind request.
func (s *managerState) hasPending() bool {
	return len(s.cookies) != 0
}

// runMasterThread executes the master thread.
func (m *Manager) runMasterThread(
	resultCh <-chan inodePinResult,
) {
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	state := &managerState{
		all:     make(map[uint64]*inodePin),
		names:   make(map[string]*inodePin),
		cookies: make(map[uint64]*inodePin),
	}
	defer state.close()
	for {
		var tickCh <-chan time.Time
		if ticker != nil {
			tickCh = ticker.C
		}

		// Serve user request, inode pin event and
		// reallocate tick within select.
		select {
		case <-m.rootCtx.Done():
			return
		case event := <-resultCh:
			state.handleResult(event)
		case req := <-m.pinCh:
			func() {
				defer close(req.doneCh)
				req.result, req.err = state.pin(
					req.name, req.mode)
			}()
		case req := <-m.unpinCh:
			state.unpin(req)
		case <-tickCh:
			state.reallocateCookie()
		}

		// Setup or shutdown current reallocate ticker.
		if state.hasPending() {
			if ticker == nil {
				ticker = time.NewTicker(5 * time.Second)
			}
		} else {
			if ticker != nil {
				ticker.Stop()
				ticker = nil
			}
		}
	}
}

// stackInodeManager will attempt to create an inode pin
// manager and stack it for later operations.
func stackInodeManager(
	next func(*Manager) error,
	rootCtx context.Context, group *errgroup.Group,
	manager systracer.Manager,
) error {
	// Setup the collector for receiving events.
	resultCh := make(chan inodePinResult)
	collector := &collector{
		rootCtx:  rootCtx,
		resultCh: resultCh,
	}

	// Attach to the security_inode_getsecurity
	// for receiving file hook result.
	var target interface{}
	target = collector.handleSecurityInodePin_V2_6_24
	if kversion.Current >= kversion.Must("5.12") {
		target = collector.handleSecurityInodePin_V5_12
	}
	inodePinProbe, syncCh, err := manager.TraceKProbe(
		"security_inode_getsecurity", target)
	if err != nil {
		return err
	}
	defer inodePinProbe.Close()

	// Wait for the completion of probe creation.
	select {
	case <-rootCtx.Done():
		return nil
	case <-syncCh:
	}

	// Startup the inode pin master thread.
	result := &Manager{
		rootCtx: rootCtx,
		pinCh:   make(chan *inodePinRequest),
		unpinCh: make(chan *inodePin),
	}
	group.Go(func() error {
		inodePinProbe.SetEnabled(true)
		result.runMasterThread(resultCh)
		return nil
	})
	return next(result)
}

// Module is the DI module of the inode manager.
//
// The module requires a context, an errgroup and a trace
// manager, and injects an inode pin manager.
var Module = shaft.Stack(stackInodeManager)
