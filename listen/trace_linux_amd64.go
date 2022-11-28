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
	// (struct socket*)({1})->sk
	Address uint32 `tracing:"+4({1}),,bigendian"`
	Port    uint16 `tracing:"+14({1})"`
	Family  uint16 `tracing:"+16({1}),{0}Family == 2"`
}

type entryProtocolListenInet4_V2_6_12 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet4 `tracing:"+32(%di)"`
}

type entryProtocolListenInet4_V5_3 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet4 `tracing:"+24(%di)"`
}

type StructSockListenInet6 struct {
	// (struct socket*)({1})->sk
	Port     uint16 `tracing:"+14({1})"`
	Family   uint16 `tracing:"+16({1}),{0}Family == 10"`
	Address0 uint32 `tracing:"+72({1}),,bigendian"`
	Address1 uint32 `tracing:"+76({1}),,bigendian"`
	Address2 uint32 `tracing:"+80({1}),,bigendian"`
	Address3 uint32 `tracing:"+84({1}),,bigendian"`
}

type entryProtocolListenInet6_V2_6_12 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet6 `tracing:"+32(%di)"`
}

type entryProtocolListenInet6_V5_3 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet6 `tracing:"+24(%di)"`
}

type entryTCPCloseInet4 struct {
	systracer.ProbeEvent

	// (struct socket*)->sk
	// Sk uint64 `tracing:"di"`

	Address uint32 `tracing:"+4(%di),,bigendian"`
	Port    uint16 `tracing:"+14(%di)"`
	Family  uint16 `tracing:"+16(%di),Family == 2"`
	State   uint8  `tracing:"+18(%di),State == 10"`
}

type entryTCPCloseInet6 struct {
	systracer.ProbeEvent

	// (struct socket*)->sk
	// Sk uint64 `tracing:"di"`

	Port     uint16 `tracing:"+14(%di)"`
	Family   uint16 `tracing:"+16(%di),Family == 10"`
	State    uint8  `tracing:"+18(%di),State == 10"`
	Address0 uint32 `tracing:"+72(%di),,bigendian"`
	Address1 uint32 `tracing:"+76(%di),,bigendian"`
	Address2 uint32 `tracing:"+80(%di),,bigendian"`
	Address3 uint32 `tracing:"+84(%di),,bigendian"`
}
