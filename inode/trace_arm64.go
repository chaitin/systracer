package inode

import (
	"github.com/chaitin/systracer"
)

type entrySecurityInodePin_V2_6_24 struct {
	systracer.ProbeEvent
	Inode uint64 `tracing:"%x0"`
	Name  string `tracing:"%x1,Name ~ \"systracer.inode_pin.*\""`
}

type entrySecurityInodePin_V5_12 struct {
	systracer.ProbeEvent
	Inode uint64 `tracing:"%x1"`
	Name  string `tracing:"%x2,Name ~ \"systracer.inode_pin.*\""`
}
