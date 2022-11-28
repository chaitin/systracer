package connect

import (
	"github.com/chaitin/systracer"
)

type entrySyscallConnectInet4 struct {
	systracer.ProbeEvent
	FD      int32  `tracing:"+4(%sp)"`
	Family  uint16 `tracing:"+0(+8(%sp)),Family == 2"`
	Port    uint16 `tracing:"+2(+8(%sp)),,bigendian"`
	Address uint32 `tracing:"+4(+8(%sp)),,bigendian"`
	Len     uint32 `tracing:"+12(%sp),Len >= 16"`
}

type entrySyscallConnectInet6 struct {
	systracer.ProbeEvent
	FD       int32  `tracing:"+4(%sp)"`
	Family   uint16 `tracing:"+0(+8(%sp)),Family == 10"`
	Port     uint16 `tracing:"+2(+8(%sp)),,bigendian"`
	FlowInfo uint32 `tracing:"+4(+8(%sp))"`
	Address0 uint32 `tracing:"+8(+8(%sp)),,bigendian"`
	Address1 uint32 `tracing:"+12(+8(%sp)),,bigendian"`
	Address2 uint32 `tracing:"+16(+8(%sp)),,bigendian"`
	Address3 uint32 `tracing:"+20(+8(%sp)),,bigendian"`
	Scope    uint32 `tracing:"+24(+8(%sp))"`
	Len      uint64 `tracing:"+12(%sp),Len >= 28"`
}

type exitSyscallConnect struct {
	systracer.ReturnEvent
	Errno int32 `tracing:"%ax"`
}

type entryInetProtocolConnect struct {
	systracer.ProbeEvent

	// (struct socket*)->type
	Type uint16 `tracing:"+4(+0(%sp))"`
}
