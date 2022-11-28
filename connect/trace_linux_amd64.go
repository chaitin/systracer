package connect

import (
	"github.com/chaitin/systracer"
)

type entrySyscallConnectInet4 struct {
	systracer.ProbeEvent
	FD      int64  `tracing:"%di"`
	Family  uint16 `tracing:"+0(%si),Family == 2"`
	Port    uint16 `tracing:"+2(%si),,bigendian"`
	Address uint32 `tracing:"+4(%si),,bigendian"`
	Len     uint64 `tracing:"%dx,Len >= 16"`
}

type entrySyscallConnectInet6 struct {
	systracer.ProbeEvent
	FD       int64  `tracing:"%di"`
	Family   uint16 `tracing:"+0(%si),Family == 10"`
	Port     uint16 `tracing:"+2(%si),,bigendian"`
	FlowInfo uint32 `tracing:"+4(%si)"`
	Address0 uint32 `tracing:"+8(%si),,bigendian"`
	Address1 uint32 `tracing:"+12(%si),,bigendian"`
	Address2 uint32 `tracing:"+16(%si),,bigendian"`
	Address3 uint32 `tracing:"+20(%si),,bigendian"`
	Scope    uint32 `tracing:"+24(%si)"`
	Len      uint64 `tracing:"%dx,Len >= 28"`
}

type exitSyscallConnect struct {
	systracer.ReturnEvent
	Errno int32 `tracing:"%ax"`
}

type entryInetProtocolConnect struct {
	systracer.ProbeEvent

	// (struct socket*)->type
	Type uint16 `tracing:"+4(%di)"`
}
