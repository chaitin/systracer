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

	Inode        uint64 `tracing:"%di"`
	Access       uint32 `tracing:"%si,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%si,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%si,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%si,,bit[6:12]"`
	Filename     string `tracing:"+8(%r8)"`
}

type entryFsnotify_V5_9 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Access       uint32 `tracing:"%di,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%di,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%di,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%di,,bit[6:12]"`
	Dir          uint64 `tracing:"%cx"`
	Filename     string `tracing:"+8(%r8)"`
	Inode        uint64 `tracing:"%r9"`
}

type entryFsnotifyParent_V5_9 struct {
	systracer.ProbeEvent
	systracer.Condition `tracing:"(ModifyAttrib == 2) || (Dentry != 0)"`

	Filename     string `tracing:"+40(%di)"`
	Inode        uint64 `tracing:"+48(%di)"`
	Access       uint32 `tracing:"%si,Access == 0,bit[0]"`
	ModifyAttrib uint32 `tracing:"%si,,bit[1:2]"`
	CloseOpen    uint32 `tracing:"%si,CloseOpen == 0,bit[3:5]"`
	Dentry       uint32 `tracing:"%si,,bit[6:12]"`
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
	SrcDir uint64 `tracing:"%di"`
	DstDir uint64 `tracing:"%dx"`
}

type entrySecurityInodeRenameSource struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeRename
	Source path `tracing:"%si"`
}

type entrySecurityInodeRenameTarget struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeRename
	Target path `tracing:"%cx"`
}

type entrySecurityInodeCreate struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%di"`
	Path path   `tracing:"%si"`
	Mode uint16 `tracing:"%dx"`
}

type entrySecurityInodeMknod struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%di"`
	Path path   `tracing:"%si"`
	Mode uint16 `tracing:"%dx"`
	Dev  uint32 `tracing:"%cx"`
}

type entrySecurityInodeMkdir struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%di"`
	Path path   `tracing:"%si"`
	Mode uint16 `tracing:"%dx"`
}

type entrySecurityInodeLink struct {
	Dir uint64 `tracing:"%si"`
}

type entrySecurityInodeLinkSource struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeLink
	Source path `tracing:"%di"`
}

type entrySecurityInodeLinkTarget struct {
	systracer.ProbeEvent
	Event  entrySecurityInodeLink
	Target path `tracing:"%dx"`
}

type entrySecurityInodeSymlink struct {
	systracer.ProbeEvent
	Dir  uint64 `tracing:"%di"`
	Path path   `tracing:"%si"`
	Name string `tracing:"%dx"`
}

type entrySecurityInodeUnlink struct {
	systracer.ProbeEvent
	Path path `tracing:"%si"`
}

type entrySecurityInodeRmdir struct {
	systracer.ProbeEvent
	Path path `tracing:"%si"`
}

type entrySecurityInodeSetattr struct {
	systracer.ProbeEvent
	Path  path   `tracing:"%di"`
	Valid uint32 `tracing:"+0(%si)"`
	Mode  uint16 `tracing:"+4(%si)"`
	Uid   uint32 `tracing:"+8(%si)"`
	Gid   uint32 `tracing:"+12(%si)"`
}
