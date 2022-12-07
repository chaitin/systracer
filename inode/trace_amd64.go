package inode

import (
	"github.com/chaitin/systracer"
)

type entrySecurityInodePin_V2_6_24 struct {
	systracer.ProbeEvent
	Inode uint64 `tracing:"%di"`
	Name  string `tracing:"%si,Name ~ \"systracer.inode_pin.*\""`
}

type entrySecurityInodePin_V5_12 struct {
	systracer.ProbeEvent
	Inode uint64 `tracing:"%si"`
	Name  string `tracing:"%dx,Name ~ \"systracer.inode_pin.*\""`
}
