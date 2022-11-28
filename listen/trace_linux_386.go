package listen

import (
	"github.com/chaitin/systracer"
)

type entrySyscallListen struct {
	systracer.ProbeEvent
	FD      int64 `tracing:"%di"`
	Backlog int64 `tracing:"%si"`
}

type exitSyscallListen struct {
	systracer.ReturnEvent
	Errno int32 `tracing:"%ax"`
}

type StructSockListenInet4 struct {
	// (struct socket*)->sk
	Address uint32 `tracing:"+4({1}),,bigendian"`
	Port    uint16 `tracing:"+14({1})"`
	Family  uint16 `tracing:"+16({1}),{0}Family == 2"`
}

type entryProtocolListenInet4_V2_6_12 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet4 `tracing:"+20(%ax)"`
}

type entryProtocolListenInet4_V5_3 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet4 `tracing:"+16(%ax)"`
}

type StructSockListenInet6 struct {
	// (struct socket*)->sk
	Port     uint16 `tracing:"+14({1})"`
	Family   uint16 `tracing:"+16({1}),{0}Family == 10"`
	Address0 uint32 `tracing:"+56({1}),,bigendian"`
	Address1 uint32 `tracing:"+60({1}),,bigendian"`
	Address2 uint32 `tracing:"+64({1}),,bigendian"`
	Address3 uint32 `tracing:"+68({1}),,bigendian"`
}

type entryProtocolListenInet6_V2_6_12 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet6 `tracing:"+20(%ax)"`
}

type entryProtocolListenInet6_V5_3 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet6 `tracing:"+16(%ax)"`
}

type entryTCPCloseInet4 struct {
	systracer.ProbeEvent

	// (struct socket*)->sk
	// Sk uint64 `tracing:"%ax"`

	Address uint32 `tracing:"+4(%ax),,bigendian"`
	Port    uint16 `tracing:"+14(%ax)"`
	Family  uint16 `tracing:"+16(%ax),Family == 2"`
	State   uint8  `tracing:"+18(%ax),State == 10"`
}

type entryTCPCloseInet6 struct {
	systracer.ProbeEvent

	// (struct socket*)->sk
	// Sk uint64 `tracing:"ax"`

	Port     uint16 `tracing:"+14(%ax)"`
	Family   uint16 `tracing:"+16(%ax),Family == 10"`
	State    uint8  `tracing:"+18(%ax),State == 10"`
	Address0 uint32 `tracing:"+56(%ax),,bigendian"`
	Address1 uint32 `tracing:"+60(%ax),,bigendian"`
	Address2 uint32 `tracing:"+64(%ax),,bigendian"`
	Address3 uint32 `tracing:"+68(%ax),,bigendian"`
}
