package rcnotify

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/aegistudio/shaft"
	"github.com/pkg/errors"

	"github.com/chaitin/systracer"
	"github.com/chaitin/systracer/inode"
	"github.com/chaitin/systracer/pkg/kversion"
)

// extractPathComponent is the code for creating a
// valid portion of path component.
func extractPathComponent(src []systracer.StringAddr) []string {
	var result []string
	for i := 0; i < len(src); i++ {
		if src[i].Addr == 0 {
			break
		}
		if i > 0 && src[i].Addr == src[i-1].Addr {
			break
		}
		result = append(result, src[i].String)
	}
	return result
}

// Op is the file event op for linux.
//
// The event operations are defined dedicated for linux,
// and some extra information will be filled based on
// different event type.
//
// The operations can be or-ed together to represent
// set of events for notification.
type Op uint64

const (
	OpCreate = Op(1 << iota)
	OpMkdir
	OpMknod
	OpDelete
	OpRmdir
	OpRename
	OpAttrib
	OpLink
	OpSymlink

	OpAll = OpCreate | OpMkdir | OpDelete | OpRmdir |
		OpRename | OpAttrib | OpLink | OpSymlink
)

// Attr indicates valid fields in the attribute event.
//
// These fields are or-ed together to represent the set
// of fields that has been updated by the event.
type Attr uint32

const (
	AttrMode = Attr(1 << iota)
	AttrUID
	AttrGID
)

// eventRaw is the trasported event on linux waiting
// to be dispatched to master.
//
// Master should translate and lookup using the source
// and target path and translate file events.
type eventRaw struct {
	op        Op
	timestamp time.Time
	pid       uint32
	source    path
	target    path
	attr      Attr
	mode      *uint16
	dev       *uint32
	symlink   *string
	uid       *uint32
	gid       *uint32
}

// eventRegistry is the common registry holding
// information used for later notification.
type eventRegistry struct {
	event       eventRaw
	targetInode uint64
	sourceInode uint64
}

// Event is standard format of linux directory event.
type Event struct {
	Op        Op
	Timestamp time.Time
	PID       uint32
	Target    *string
	Source    *string
	Attr      Attr
	Mode      *uint16
	Dev       *uint32
	Uid       *uint32
	Gid       *uint32
}

// dispatchPolicy stores information for the dispatcher,
// including the file name corresponding to inode, and
// its related flags.
//
// while dispatching events, the subscriber works in a
// hierarchical manner, the dispatch policy nearer to
// the leaf will be applied first.
type dispatchPolicy struct {
	name    string
	opFlags Op
}

// subscriber stores the information for dispatching
// the subscribed events to the subscriber.
type subscriber struct {
	ctx        context.Context
	done       *uint8
	allOpFlags Op
	eventCh    chan<- Event
	policies   map[uint64]dispatchPolicy
}

// composeSuffix composes the suffix with path.
func composeSuffix(components []string) string {
	size := len(components)
	result := make([]string, size)
	for j := 0; j < size; j++ {
		result[j] = components[size-j-1]
	}
	return filepath.Join(result...)
}

// evaluatePathPolicy attempts to evaluate the path and
// calculate the policies for the path.
func (s *subscriber) evaluatePathPolicy(p path) (*string, Op) {
	paths, inodes := p.extract()
	for i, inode := range inodes {
		if inode == 0 {
			continue
		}
		policy, ok := s.policies[inode]
		if !ok {
			continue
		}
		targetSuffix := composeSuffix(paths[:i])
		result := new(string)
		*result = filepath.Join(policy.name, targetSuffix)
		return result, policy.opFlags
	}
	return nil, Op(0)
}

// dispatch is the handler for dispatching event
// to receivers.
func (s *subscriber) dispatch(
	rawEvent eventRaw, visited *uint8,
) {
	if s.done == visited {
		// The event has already been dispatched,
		// so we won't dispatch it again here.
		return
	}
	s.done = visited
	if s.allOpFlags&rawEvent.op == 0 {
		return
	}

	// Prepare the base for the new dispatching of
	// specified file event.
	var event Event
	event.Op = rawEvent.op
	event.PID = rawEvent.pid
	event.Timestamp = rawEvent.timestamp
	event.Attr = rawEvent.attr
	event.Mode = rawEvent.mode
	event.Dev = rawEvent.dev
	event.Uid = rawEvent.uid
	event.Gid = rawEvent.gid
	event.Source = rawEvent.symlink

	// Compose the path parameters for the event.
	var opFlags, allFlags Op
	event.Target, allFlags = s.evaluatePathPolicy(rawEvent.target)
	switch rawEvent.op {
	case OpRename, OpLink:
		event.Source, opFlags = s.evaluatePathPolicy(rawEvent.source)
		allFlags |= opFlags
	case OpSymlink:
		event.Source = rawEvent.symlink
	}

	// Dispatch the collected event to subscriber.
	if allFlags&rawEvent.op == 0 {
		return
	}
	select {
	case <-s.ctx.Done():
	case s.eventCh <- event:
	}
}

// collector is the collector for the linux file related
// events. It keeps track of file state registries and
// will periodically perform cleanup.
type collector struct {
	registries  map[uint32]*eventRegistry
	dispatchMap *sync.Map
}

// allocateRename will attempt to allocate a new
// or previously existing registry for rename.
func (col *collector) allocateRename(
	taskPID uint32, event entrySecurityInodeRename,
) *eventRegistry {
	registry := col.registries[taskPID]
	if registry != nil {
		if registry.event.op != OpRename ||
			registry.sourceInode != event.SrcDir ||
			registry.targetInode != event.DstDir {
			delete(col.registries, taskPID)
			registry = nil
		}
	}
	if registry == nil {
		registry = &eventRegistry{
			event: eventRaw{
				op: OpRename,
			},
			sourceInode: event.SrcDir,
			targetInode: event.DstDir,
		}
		col.registries[taskPID] = registry
	}
	return registry
}

// handleRenameSource handles the event triggered
// when renaming the file and is captured by our
// trace probe.
//
// security_inode_rename(sourcePath, &dentry{
//    <d_name,d_path> = Source,
// }, targetPath, ...)
func (col *collector) handleRenameSource(
	event entrySecurityInodeRenameSource,
) {
	registry := col.allocateRename(
		event.TaskPID, event.Event)
	registry.event.source = event.Source
}

// handleRenameTarget handles the event triggered
// when renaming the file and is captured by our
// trace probe.
//
// security_inode_rename(sourcePath, ...,
//    targetPath, &dentry{
//       <d_name,d_path> = Target,
//    })
func (col *collector) handleRenameTarget(
	event entrySecurityInodeRenameTarget,
) {
	registry := col.allocateRename(
		event.TaskPID, event.Event)
	registry.event.target = event.Target
}

// handleCreate handles the event triggered when
// creating a file and is captured by our trace probe.
//
// security_inode_create(targetInode, &dentry{
//    <d_name,d_path> = targetPath,
// }, mode, dev)
func (col *collector) handleCreate(
	event entrySecurityInodeCreate,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:     OpCreate,
			mode:   new(uint16),
			target: event.Path,
		},
		targetInode: event.Dir,
	}
	*registry.event.mode = event.Mode
	col.registries[event.TaskPID] = registry
}

// handleMknod handles the event triggered when
// creating a device and is captured by our
// trace probe.
//
// security_inode_mknod(targetInode, &dentry{
//    <d_name,d_path> = targetPath,
// }, mode, dev)
func (col *collector) handleMknod(
	event entrySecurityInodeMknod,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:     OpMknod,
			mode:   new(uint16),
			dev:    new(uint32),
			target: event.Path,
		},
		targetInode: event.Dir,
	}
	*registry.event.mode = event.Mode
	*registry.event.dev = event.Dev
	col.registries[event.TaskPID] = registry
}

// handleMkdir handles the event triggered when
// creating a direcotry and is captured by our
// trace probe.
//
// security_inode_mkdir(targetInode, &dentry{
//    <d_name,d_path> = targetPath,
// }, mode)
func (col *collector) handleMkdir(
	event entrySecurityInodeMkdir,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:     OpMkdir,
			mode:   new(uint16),
			target: event.Path,
		},
		targetInode: event.Dir,
	}
	*registry.event.mode = event.Mode
	col.registries[event.TaskPID] = registry
}

// allocateLink will attempt to allocate a new
// or previously existing registry for link.
func (col *collector) allocateLink(
	taskPID uint32, event entrySecurityInodeLink,
) *eventRegistry {
	registry := col.registries[taskPID]
	if registry != nil {
		if registry.event.op != OpLink ||
			registry.targetInode != event.Dir {
			delete(col.registries, taskPID)
			registry = nil
		}
	}
	if registry == nil {
		registry = &eventRegistry{
			event: eventRaw{
				op: OpLink,
			},
			targetInode: event.Dir,
		}
		col.registries[taskPID] = registry
	}
	return registry
}

// handleLinkSource handles the event triggered
// when creating hard link of the file and is captured
// by our trace probe.
//
// security_inode_link(source, &dentry{
//    <d_name,d_path> = Dir,
// }, ...)
func (col *collector) handleLinkSource(
	event entrySecurityInodeLinkSource,
) {
	registry := col.allocateLink(
		event.TaskPID, event.Event)
	registry.event.source = event.Source
}

// handleRenameTarget handles the event triggered
// when creating hard link of the file and is captured
// by our trace probe.
//
// security_inode_link(..., &dentry{
//    <d_name,d_path> = Target,
// }, target)
func (col *collector) handleLinkTarget(
	event entrySecurityInodeLinkTarget,
) {
	registry := col.allocateLink(
		event.TaskPID, event.Event)
	registry.event.target = event.Target
}

// handleSymlink handles the event triggered when
// creating soft link of the file and is captured by
// our trace probe.
//
// security_inode_symlink(targetInode, &dentry{
//    <d_name,d_path> = Target,
// }, source)
func (col *collector) handleSymlink(
	event entrySecurityInodeSymlink,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:      OpSymlink,
			target:  event.Path,
			symlink: new(string),
		},
		targetInode: event.Dir,
	}
	*registry.event.symlink = event.Name
	col.registries[event.TaskPID] = registry
}

// handleUnlink handles the event triggered when
// removing a file and is captured by our trace probe.
//
// security_inode_unlink(targetInode, &dentry{
//    <d_name,d_path> = targetPath,
// })
func (col *collector) handleUnlink(
	event entrySecurityInodeUnlink,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:     OpDelete,
			target: event.Path,
		},
		targetInode: event.Path.I0,
	}
	col.registries[event.TaskPID] = registry
}

// handleRmdir handles the event triggered when
// removing a direcotry and is captured by our
// trace probe.
//
// security_inode_rmdir(targetInode, &dentry{
//    <d_name,d_path> = targetPath,
// })
func (col *collector) handleRmdir(
	event entrySecurityInodeRmdir,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:     OpRmdir,
			target: event.Path,
		},
		targetInode: event.Path.I0,
	}
	col.registries[event.TaskPID] = registry
}

// handleSetattr handles the event triggered when
// updating a file attributes and is captured by
// our trace probe.
//
// security_inode_setattr(&dentry{
//    <d_name,d_path> = targetPath,
// }, &iattr{
//    ia_mode = Mode,
//    ia_uid  = Uid,
//    ia_gid  = Gid,
// })
func (col *collector) handleSetattr(
	event entrySecurityInodeSetattr,
) {
	registry := &eventRegistry{
		event: eventRaw{
			op:     OpAttrib,
			target: event.Path,
		},
		targetInode: event.Path.I0,
	}
	if Attr(event.Valid)&AttrMode != 0 {
		registry.event.attr |= AttrMode
		registry.event.mode = new(uint16)
		*registry.event.mode = event.Mode
	}
	if Attr(event.Valid)&AttrUID != 0 {
		registry.event.attr |= AttrUID
		registry.event.uid = new(uint32)
		*registry.event.uid = event.Uid
	}
	if Attr(event.Valid)&AttrGID != 0 {
		registry.event.attr |= AttrGID
		registry.event.gid = new(uint32)
		*registry.event.gid = event.Gid
	}
	if registry.event.attr == 0 {
		// No event we are interested, so we will
		// just skip reporting the events.
		return
	}
	col.registries[event.TaskPID] = registry
}

// handleFsnotify_V2_6_32 handles the fsnotify event
// from 2.6.32 (inclusive) to 5.9 (exclusive).
func (col *collector) handleFsnotify_V2_6_32(
	event entryFsnotify_V2_6_32,
) {
	if _, ok := col.registries[event.TaskPID]; !ok {
		return
	}
	col.handleFsnotify(eventFsnotify{
		TaskPID:      event.TaskPID,
		Timestamp:    event.Timestamp,
		Inode:        uint64(event.Inode),
		Access:       event.Access,
		ModifyAttrib: event.ModifyAttrib,
		CloseOpen:    event.CloseOpen,
		Dentry:       event.Dentry,
		Filename:     event.Filename,
	})
}

// handleFsnotify_V5_9 handles the fsnotify event
// from 5.9 (inclusive) to now.
func (col *collector) handleFsnotify_V5_9(
	event entryFsnotify_V5_9,
) {
	if _, ok := col.registries[event.TaskPID]; !ok {
		return
	}
	baseEvent := eventFsnotify{
		TaskPID:      event.TaskPID,
		Timestamp:    event.Timestamp,
		Access:       event.Access,
		ModifyAttrib: event.ModifyAttrib,
		CloseOpen:    event.CloseOpen,
		Dentry:       event.Dentry,
		Filename:     event.Filename,
		Visited:      new(uint8),
	}
	if event.Inode != 0 {
		baseEvent.Inode = uint64(event.Inode)
		col.handleFsnotify(baseEvent)
	}
	if event.Dir != 0 {
		baseEvent.Inode = uint64(event.Dir)
		col.handleFsnotify(baseEvent)
	}
}

// handleFsnotifyParent_V5_9 handles the fsnotify
// parent event from 5.9 (inclusive) to now.
func (col *collector) handleFsnotifyParent_V5_9(
	event entryFsnotifyParent_V5_9,
) {
	if _, ok := col.registries[event.TaskPID]; !ok {
		return
	}
	col.handleFsnotify(eventFsnotify{
		TaskPID:      event.TaskPID,
		Timestamp:    event.Timestamp,
		Inode:        uint64(event.Inode),
		Access:       event.Access,
		ModifyAttrib: event.ModifyAttrib,
		CloseOpen:    event.CloseOpen,
		Dentry:       event.Dentry,
		Filename:     event.Filename,
	})
}

// handleFsnotify handles the event triggered when
// fsnotify dispatch call is invoked and is captured
// by our trace probe.
func (col *collector) handleFsnotify(
	event eventFsnotify,
) {
	registry := col.registries[event.TaskPID]
	if registry == nil {
		return
	}

	// Judge whether it is dispatch condition.
	switch registry.event.op {
	case OpSymlink:
		fallthrough
	case OpLink:
		fallthrough
	case OpCreate, OpMkdir, OpMknod:
		switch event.Dentry {
		case 4:
			if event.Inode != registry.targetInode {
				return
			}
		default:
			return
		}
	case OpAttrib:
		switch event.ModifyAttrib {
		case 2:
			if event.Inode != registry.targetInode {
				return
			}
		default:
			return
		}
	case OpDelete, OpRmdir:
		switch {
		case event.ModifyAttrib == 2:
			fallthrough
		case event.Dentry == 16:
			if event.Inode != registry.targetInode {
				return
			}
		default:
			return
		}
	case OpRename:
		switch event.Dentry {
		case 1:
			if event.Inode != registry.sourceInode {
				return
			}
		case 2:
			if event.Inode != registry.targetInode {
				return
			}
		default:
			return
		}
	default:
		return
	}

	// Dispatch the stored event at this point.
	delete(col.registries, event.TaskPID)
	registry.event.pid = event.TaskPID
	registry.event.timestamp = event.Timestamp
	_, targetInodes := registry.event.target.extract()
	for _, inode := range targetInodes {
		if subs, ok := col.dispatchMap.Load(inode); ok {
			for _, sub := range subs.([]*subscriber) {
				sub.dispatch(registry.event, event.Visited)
			}
		}
	}
	if registry.event.op&(OpRename|OpLink) != 0 {
		_, sourceInodes := registry.event.source.extract()
		for _, inode := range sourceInodes {
			if subs, ok := col.dispatchMap.Load(inode); ok {
				for _, sub := range subs.([]*subscriber) {
					sub.dispatch(registry.event, event.Visited)
				}
			}
		}
	}
}

// Watcher is the subscription of the dispatch info.
type Watcher struct {
	C      <-chan Event
	mgr    *Manager
	cancel context.CancelFunc
	sub    *subscriber
	inodes []*inode.Inode
	once   sync.Once
}

func (s *Watcher) Close() {
	s.cancel()
	s.once.Do(func() {
		s.mgr.evict(s.sub)
		for _, inode := range s.inodes {
			inode.Unpin()
		}
		s.inodes = nil
	})
	runtime.SetFinalizer(s, nil)
}

// Manager is the manager for all directory events.
type Manager struct {
	ctx         context.Context
	mtx         sync.Mutex
	subsets     map[uint64]map[*subscriber]struct{}
	dispatchMap *sync.Map
	inodeMgr    *inode.Manager
}

func (m *Manager) evict(sub *subscriber) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for inode := range sub.policies {
		subset, ok := m.subsets[inode]
		if !ok {
			continue
		}
		delete(subset, sub)
		if len(subset) == 0 {
			delete(m.subsets, inode)
			m.dispatchMap.Delete(inode)
		}
		var remainings []*subscriber
		for remaining := range subset {
			remainings = append(remainings, remaining)
		}
		m.dispatchMap.Store(inode, remainings)
	}
}

func (m *Manager) emplace(sub *subscriber) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for inode := range sub.policies {
		subset, ok := m.subsets[inode]
		if !ok {
			subset = make(map[*subscriber]struct{})
			m.subsets[inode] = subset
		}
		subset[sub] = struct{}{}
		var updated []*subscriber
		for item := range subset {
			updated = append(updated, item)
		}
		m.dispatchMap.Store(inode, updated)
	}
}

type watchPoint struct {
	name    string
	watch   func(*inode.Manager) (*inode.Inode, error)
	opFlags Op
}

type option struct {
	watchPoints []watchPoint
}

// Option is the options for creating watcher.
type Option func(*option)

// WatchFile specifies a file for watching.
func WatchFile(opFlags Op, file string) Option {
	return func(opt *option) {
		opt.watchPoints = append(opt.watchPoints, watchPoint{
			name: file,
			watch: func(mgr *inode.Manager) (*inode.Inode, error) {
				return mgr.PinFile(file)
			},
			opFlags: opFlags,
		})
	}
}

// WatchDir specifies a directory for watching.
func WatchDir(opFlags Op, dir string) Option {
	return func(opt *option) {
		opt.watchPoints = append(opt.watchPoints, watchPoint{
			name: dir,
			watch: func(mgr *inode.Manager) (*inode.Inode, error) {
				return mgr.PinDir(dir)
			},
			opFlags: opFlags,
		})
	}
}

// WithOptions aggregates a set of options for execution.
func WithOptions(opts ...Option) Option {
	return func(option *option) {
		for _, opt := range opts {
			opt(option)
		}
	}
}

// Watch with specified options and returns error.
func (mgr *Manager) Watch(opts ...Option) (*Watcher, error) {
	var option option
	WithOptions(opts...)(&option)

	// Attempt to create pins for specified watchers.
	created := false
	ctx, cancel := context.WithCancel(mgr.ctx)
	defer func() {
		if !created {
			cancel()
		}
	}()
	eventCh := make(chan Event)
	subscriber := &subscriber{
		ctx:      ctx,
		done:     new(uint8),
		eventCh:  eventCh,
		policies: make(map[uint64]dispatchPolicy),
	}
	result := &Watcher{
		C:      eventCh,
		mgr:    mgr,
		cancel: cancel,
		sub:    subscriber,
	}
	for _, watchPoint := range option.watchPoints {
		pin, err := watchPoint.watch(mgr.inodeMgr)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !created {
				pin.Unpin()
			}
		}()
		subscriber.policies[pin.Inode()] = dispatchPolicy{
			name:    watchPoint.name,
			opFlags: watchPoint.opFlags,
		}
		subscriber.allOpFlags |= watchPoint.opFlags
		result.inodes = append(result.inodes, pin)
	}

	// Attempt to emplace all the modifications to map
	// and return the result.
	defer func() {
		if !created {
			mgr.evict(subscriber)
		}
	}()
	mgr.emplace(subscriber)
	runtime.SetFinalizer(result, func(value *Watcher) {
		value.Close()
	})
	created = true
	return result, nil
}

// stackRcnotifyManager will attempt to create a rcnotify
// manager and stack it for later operations.
func stackRcnotifyManager(
	next func(*Manager) error,
	rootCtx context.Context, manager systracer.Manager,
	inodeMgr *inode.Manager,
) error {
	dispatchMap := new(sync.Map)
	result := &Manager{
		ctx:         rootCtx,
		subsets:     make(map[uint64]map[*subscriber]struct{}),
		dispatchMap: dispatchMap,
		inodeMgr:    inodeMgr,
	}
	collector := &collector{
		registries:  make(map[uint32]*eventRegistry),
		dispatchMap: dispatchMap,
	}

	// Attach to the fsnotify dispatcher first.
	var fsnotifyHandler interface{}
	fsnotifyHandler = collector.handleFsnotify_V2_6_32
	if kversion.Current >= kversion.Must("5.9") {
		fsnotifyHandler = collector.handleFsnotify_V5_9
	}
	fsnotify, _, err := manager.TraceKProbe(
		"fsnotify", fsnotifyHandler)
	if err != nil {
		return err
	}
	defer fsnotify.Close()

	// There's also fsnotify parent handler for those
	// version >= 5.9, we will also register them here.
	var fsnotifyParent systracer.Trace
	if kversion.Current >= kversion.Must("5.9") {
		fsnotifyParent, _, err = manager.TraceKProbe(
			"__fsnotify_parent",
			collector.handleFsnotifyParent_V5_9)
		if err != nil {
			return err
		}
		defer fsnotifyParent.Close()
	}

	// Define a collection of probe points and their
	// associated probes for registering.
	probes := map[string][]interface{}{
		"security_inode_rename": {
			collector.handleRenameSource,
			collector.handleRenameTarget,
		},
		"security_inode_create": {
			collector.handleCreate,
		},
		"security_inode_mknod": {
			collector.handleMknod,
		},
		"security_inode_mkdir": {
			collector.handleMkdir,
		},
		"security_inode_link": {
			collector.handleLinkSource,
			collector.handleLinkTarget,
		},
		"security_inode_symlink": {
			collector.handleSymlink,
		},
		"security_inode_unlink": {
			collector.handleUnlink,
		},
		"security_inode_rmdir": {
			collector.handleRmdir,
		},
		"security_inode_setattr": {
			collector.handleSetattr,
		},
	}
	var lastSyncCh <-chan struct{}
	var registries []systracer.Trace
	for point, handlers := range probes {
		for _, handler := range handlers {
			registry, syncCh, err := manager.
				TraceKProbe(point, handler)
			if err != nil {
				return errors.Wrapf(err,
					"initializing %s", handler)
			}
			defer registry.Close()
			lastSyncCh = syncCh
			registries = append(registries, registry)
		}
	}

	// Wait for synchronization of the kprobe registry.
	select {
	case <-rootCtx.Done():
		return nil
	case <-lastSyncCh:
	}
	fsnotify.SetEnabled(true)
	if fsnotifyParent != nil {
		fsnotifyParent.SetEnabled(true)
	}
	for _, registry := range registries {
		registry.SetEnabled(true)
	}
	return next(result)
}

// Module is the DI module of the rcnotify manager.
//
// The module requires a context, a trace manager and
// an inode manager, and injects a rcnotify manager.
var Module = shaft.Stack(stackRcnotifyManager)
