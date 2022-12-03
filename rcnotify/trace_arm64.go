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

	Inode        uint64 `tracing:"%x0"`
	Access       uint32 `tracing:"%x1,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%x1,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%x1,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%x1,,bit[6:12]"`
	Filename     string `tracing:"+8(%x4)"`
}

type entryFsnotify_V5_9 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Access       uint32 `tracing:"%x0,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%x0,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%x0,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%x0,,bit[6:12]"`
	Dir          uint64 `tracing:"%x3"`
	Filename     string `tracing:"+8(%x4)"`
	Inode        uint64 `tracing:"%x5"`
}

type entryFsnotifyParent_V5_9 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Filename     string `tracing:"+40(%x0)"`
	Inode        uint64 `tracing:"+48(%x0)"`
	Access       uint32 `tracing:"%x1,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%x1,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%x1,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%x1,,bit[6:12]"`
}

type path struct {
	N0 systracer.StringAddr `tracing:"+40({1})"`
	N1 systracer.StringAddr `tracing:"+40(+24({1}))"`
	N2 systracer.StringAddr `tracing:"+40(+24(+24({1})))"`
	N3 systracer.StringAddr `tracing:"+40(+24(+24(+24({1}))))"`
	N4 systracer.StringAddr `tracing:"+40(+24(+24(+24(+24({1})))))"`
	N5 systracer.StringAddr `tracing:"+40(+24(+24(+24(+24(+24({1}))))))"`
	N6 systracer.StringAddr `tracing:"+40(+24(+24(+24(+24(+24(+24({1})))))))"`
	N7 systracer.StringAddr `tracing:"+40(+24(+24(+24(+24(+24(+24(+24({1}))))))))"`
	N8 systracer.StringAddr `tracing:"+40(+24(+24(+24(+24(+24(+24(+24(+24({1})))))))))"`

	I0 uint64 `tracing:"+48({1})"`
	I1 uint64 `tracing:"+48(+24({1}))"`
	I2 uint64 `tracing:"+48(+24(+24({1})))"`
	I3 uint64 `tracing:"+48(+24(+24(+24({1}))))"`
	I4 uint64 `tracing:"+48(+24(+24(+24(+24({1})))))"`
	I5 uint64 `tracing:"+48(+24(+24(+24(+24(+24({1}))))))"`
	I6 uint64 `tracing:"+48(+24(+24(+24(+24(+24(+24({1})))))))"`
	I7 uint64 `tracing:"+48(+24(+24(+24(+24(+24(+24(+24({1}))))))))"`
	I8 uint64 `tracing:"+48(+24(+24(+24(+24(+24(+24(+24(+24({1})))))))))"`
	I9 uint64 `tracing:"+48(+24(+24(+24(+24(+24(+24(+24(+24(+24({1}))))))))))"`
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
	SrcDir uint64 `tracing:"%x0"`
	DstDir uint64 `tracing:"%x2"`
}

type entrySecurityInodeRenameSource struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeRename
	Source path `tracing:"%x1"`
}

type entrySecurityInodeRenameTarget struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeRename
	Target path `tracing:"%x3"`
}

type entrySecurityInodeCreate struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%x0"`
	Path path   `tracing:"%x1"`
	Mode uint16 `tracing:"%x2"`
}

type entrySecurityInodeMknod struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%x0"`
	Path path   `tracing:"%x1"`
	Mode uint16 `tracing:"%x2"`
	Dev  uint32 `tracing:"%x3"`
}

type entrySecurityInodeMkdir struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%x0"`
	Path path   `tracing:"%x1"`
	Mode uint16 `tracing:"%x2"`
}

type entrySecurityInodeLink struct {
	Dir uint64 `tracing:"%x1"`
}

type entrySecurityInodeLinkSource struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeLink
	Source path `tracing:"%x0"`
}

type entrySecurityInodeLinkTarget struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeLink
	Target path `tracing:"%x2"`
}

type entrySecurityInodeSymlink struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%x0"`
	Path path   `tracing:"%x1"`
	Name string `tracing:"%x2"`
}

type entrySecurityInodeUnlink struct {
	systracer.ProbeEvent
	Path path `tracing:"%x1"`
}

type entrySecurityInodeRmdir struct {
	systracer.ProbeEvent
	Path path `tracing:"%x1"`
}

type entrySecurityInodeSetattr struct {
	systracer.ProbeEvent
	Path  path   `tracing:"%x0"`
	Valid uint32 `tracing:"+0(%x1)"`
	Mode  uint16 `tracing:"+4(%x1)"`
	Uid   uint32 `tracing:"+8(%x1)"`
	Gid   uint32 `tracing:"+12(%x1)"`
}
