package listen

import (
	"github.com/chaitin/systracer"
)

type entrySyscallListen struct {
	systracer.ProbeEvent
	FD      int64 `tracing:"%x0"`
	Backlog int64 `tracing:"%x1"`
}

type exitSyscallListen struct {
	systracer.ReturnEvent
	Errno int32 `tracing:"%x0"`
}

type StructSockListenInet4 struct {
	// (struct socket*)({1})->sk
	Address uint32 `tracing:"+4({1}),,bigendian"`
	Port    uint16 `tracing:"+14({1})"`
	Family  uint16 `tracing:"+16({1}),{0}Family == 2"`
}

type entryProtocolListenInet4_V2_6_12 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet4 `tracing:"+32(%x0)"`
}

type entryProtocolListenInet4_V5_3 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet4 `tracing:"+24(%x0)"`
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
	Sk StructSockListenInet6 `tracing:"+32(%x0)"`
}

type entryProtocolListenInet6_V5_3 struct {
	systracer.ProbeEvent
	Sk StructSockListenInet6 `tracing:"+24(%x0)"`
}

type entryTCPCloseInet4 struct {
	systracer.ProbeEvent

	// (struct socket*)->sk
	// Sk uint64 `tracing:"x0"`

	Address uint32 `tracing:"+4(%x0),,bigendian"`
	Port    uint16 `tracing:"+14(%x0)"`
	Family  uint16 `tracing:"+16(%x0),Family == 2"`
	State   uint8  `tracing:"+18(%x0),State == 10"`
}

type entryTCPCloseInet6 struct {
	systracer.ProbeEvent

	// (struct socket*)->sk
	// Sk uint64 `tracing:"x0"`

	Port     uint16 `tracing:"+14(%x0)"`
	Family   uint16 `tracing:"+16(%x0),Family == 10"`
	State    uint8  `tracing:"+18(%x0),State == 10"`
	Address0 uint32 `tracing:"+72(%x0),,bigendian"`
	Address1 uint32 `tracing:"+76(%x0),,bigendian"`
	Address2 uint32 `tracing:"+80(%x0),,bigendian"`
	Address3 uint32 `tracing:"+84(%x0),,bigendian"`
}
