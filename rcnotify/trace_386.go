package rcnotify

import (
	"time"

	"github.com/chaitin/systracer"
)

type eventFsnotify struct {
	TaskPID      uint32
	Timestamp    time.Time
	Inode        uint64
	Access       uint32
	ModifyAttrib uint32
	CloseOpen    uint32
	Dentry       uint32
	Filename     string
	Visited      *uint8
}

type entryFsnotify_V2_6_32 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Inode        uint32 `tracing:"%ax"`
	Access       uint32 `tracing:"%dx,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%dx,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%dx,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%dx,,bit[6:12]"`
	Filename     string `tracing:"+8(+8(%sp))"`
}

type entryFsnotify_V5_9 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Access       uint32 `tracing:"%ax,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%ax,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%ax,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%ax,,bit[6:12]"`
	Dir          uint32 `tracing:"+4(%sp)"`
	Filename     string `tracing:"+8(+8(%sp))"`
	Inode        uint32 `tracing:"+12(%sp)`
}

type entryFsnotifyParent_V5_9 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Filename     string `tracing:"+40(%ax)"`
	Inode        uint64 `tracing:"+48(%ax)"`
	Access       uint32 `tracing:"%dx,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%dx,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%dx,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%dx,,bit[6:12]"`
}

type path struct {
	N0 systracer.StringAddr `tracing:"+28({1})"`
	N1 systracer.StringAddr `tracing:"+28(+16({1}))"`
	N2 systracer.StringAddr `tracing:"+28(+16(+16({1})))"`
	N3 systracer.StringAddr `tracing:"+28(+16(+16(+16({1}))))"`
	N4 systracer.StringAddr `tracing:"+28(+16(+16(+16(+16({1})))))"`
	N5 systracer.StringAddr `tracing:"+28(+16(+16(+16(+16(+16({1}))))))"`
	N6 systracer.StringAddr `tracing:"+28(+16(+16(+16(+16(+16(+16({1})))))))"`
	N7 systracer.StringAddr `tracing:"+28(+16(+16(+16(+16(+16(+16(+16({1}))))))))"`
	N8 systracer.StringAddr `tracing:"+28(+16(+16(+16(+16(+16(+16(+16(+16({1})))))))))"`

	I0 uint64 `tracing:"+32({1})"`
	I1 uint64 `tracing:"+32(+16({1}))"`
	I2 uint64 `tracing:"+32(+16(+16({1})))"`
	I3 uint64 `tracing:"+32(+16(+16(+16({1}))))"`
	I4 uint64 `tracing:"+32(+16(+16(+16(+16({1})))))"`
	I5 uint64 `tracing:"+32(+16(+16(+16(+16(+16({1}))))))"`
	I6 uint64 `tracing:"+32(+16(+16(+16(+16(+16(+16({1})))))))"`
	I7 uint64 `tracing:"+32(+16(+16(+16(+16(+16(+16(+16({1}))))))))"`
	I8 uint64 `tracing:"+32(+16(+16(+16(+16(+16(+16(+16(+16({1})))))))))"`
	I9 uint64 `tracing:"+32(+16(+16(+16(+16(+16(+16(+16(+16(+16({1}))))))))))"`
}

func (d path) extract() ([]string, []uint64) {
	nodes := []systracer.StringAddr{
		d.N0, d.N1, d.N2, d.N3, d.N4, d.N5, d.N6, d.N7, d.N8,
	}
	resultPath := extractPathComponent(nodes)
	inodes := []uint64{
		d.I0, d.I1, d.I2, d.I3, d.I4, d.I5, d.I6, d.I7, d.I8, d.I9,
	}
	resultInodes := inodes[:len(resultPath)+1]
	return resultPath, resultInodes
}

type entrySecurityInodeRename struct {
	SrcDir uint64 `tracing:"%ax"`
	DstDir uint64 `tracing:"%cx"`
}

type entrySecurityInodeRenameSource struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeRename
	Source path `tracing:"%dx"`
}

type entrySecurityInodeRenameTarget struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeRename
	Target path `tracing:"+4(%sp)"`
}

type entrySecurityInodeCreate struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%ax"`
	Path path   `tracing:"%dx"`
	Mode uint16 `tracing:"%cx"`
}

type entrySecurityInodeMknod struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%ax"`
	Path path   `tracing:"%dx"`
	Mode uint16 `tracing:"%cx"`
	Dev  uint32 `tracing:"+4(%sp)"`
}

type entrySecurityInodeMkdir struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%ax"`
	Path path   `tracing:"%dx"`
	Mode uint16 `tracing:"%cx"`
}

type entrySecurityInodeLink struct {
	Dir uint64 `tracing:"%dx"`
}

type entrySecurityInodeLinkSource struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeLink
	Source path `tracing:"%ax"`
}

type entrySecurityInodeLinkTarget struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeLink
	Target path `tracing:"%cx"`
}

type entrySecurityInodeSymlink struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%ax"`
	Path path   `tracing:"%dx"`
	Name string `tracing:"%cx"`
}

type entrySecurityInodeUnlink struct {
	systracer.ProbeEvent
	Path path `tracing:"%dx"`
}

type entrySecurityInodeRmdir struct {
	systracer.ProbeEvent
	Path path `tracing:"%dx"`
}

type entrySecurityInodeSetattr struct {
	systracer.ProbeEvent
	Path  path   `tracing:"%di"`
	Valid uint32 `tracing:"+0(%si)"`
	Mode  uint16 `tracing:"+4(%si)"`
	Uid   uint32 `tracing:"+8(%si)"`
	Gid   uint32 `tracing:"+12(%si)"`
}
