package kallsyms

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	assert := assert.New(t)
	symtabs := Parse(bytes.Trim([]byte(`
ffffffff90d38450 t do_open
ffffffffc01920e0 r __func__.24	[video]
ffffffff91ff03ae d .LC1
ffffffffc027b1b0 r .LC1	[drm]
ffffffffc0275fa8 r .LC1	[drm]
ffffffffc0ba88a0 t do_open	[nfs]
`), "\n"), nil)

	coreSymtab := symtabs[""]
	assert.NotNil(coreSymtab)
	assert.Equal(uint64(0xffffffff91ff03ae), coreSymtab.Lookup(".LC1", "Dd"))
	assert.Equal(uint64(0), coreSymtab.Lookup(".LC1", "Tt"))
	assert.Equal(uint64(0xffffffff90d38450), coreSymtab.Lookup("do_open", "Tt"))

	nfsSymtab := symtabs["nfs"]
	assert.NotNil(nfsSymtab)
	assert.Equal(uint64(0xffffffffc0ba88a0), nfsSymtab.Lookup("do_open", "Tt"))

	drmSymtab := symtabs["drm"]
	assert.NotNil(drmSymtab)
	assert.Equal(uint64(0), drmSymtab.Lookup(".LC1", "Dd"))
	assert.Equal(uint64(0xffffffffc0275fa8), drmSymtab.Lookup(".LC1", "Rr"))

	videoSymtab := symtabs["video"]
	assert.NotNil(videoSymtab)
	assert.Equal(uint64(0), videoSymtab.Lookup(".LC1", "Dd"))
	assert.Equal(uint64(0xffffffffc01920e0), videoSymtab.Lookup("__func__.24", "Rr"))
}
