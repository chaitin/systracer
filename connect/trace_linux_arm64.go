package connect

import (
	"github.com/chaitin/systracer"
)

type entrySyscallConnectInet4 struct {
	systracer.ProbeEvent
	FD      int64  `tracing:"%x0"`
	Family  uint16 `tracing:"+0(%x1),Family == 2"`
	Port    uint16 `tracing:"+2(%x1),,bigendian"`
	Address uint32 `tracing:"+4(%x1),,bigendian"`
	Len     uint64 `tracing:"%x2,Len >= 16"`
}

type entrySyscallConnectInet6 struct {
	systracer.ProbeEvent
	FD       int64  `tracing:"%x0"`
	Family   uint16 `tracing:"+0(%x1),Family == 10"`
	Port     uint16 `tracing:"+2(%x1),,bigendian"`
	FlowInfo uint32 `tracing:"+4(%x1)"`
	Address0 uint32 `tracing:"+8(%x1),,bigendian"`
	Address1 uint32 `tracing:"+12(%x1),,bigendian"`
	Address2 uint32 `tracing:"+16(%x1),,bigendian"`
	Address3 uint32 `tracing:"+20(%x1),,bigendian"`
	Scope    uint32 `tracing:"+24(%x1)"`
	Len      uint64 `tracing:"%x2,Len >= 28"`
}

type exitSyscallConnect struct {
	systracer.ReturnEvent
	Errno int32 `tracing:"%x0"`
}

type entryInetProtocolConnect struct {
	systracer.ProbeEvent

	// (struct socket*)->type
	Type uint16 `tracing:"+4(%x0)"`
}
