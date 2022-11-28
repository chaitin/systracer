package systracer

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// OpenEvent is a demo event dedicated for being
// used as example of parsing.
type OpenEvent struct {
	ProbeEvent
	Dir      int64  `tracing:"%di"`
	Filename string `tracing:"%si"`
	Flags    uint64 `tracing:"%dx"`
	Mode     uint64 `tracing:"%cx"`
}

// TestOpenEvent is the event for performing tests
// strongly associated with the open event.
func TestOpenEvent(t *testing.T) {
	var err error
	assert := assert.New(t)

	// Attempt to compile and validate OpenEvent.
	desc, err := compileTraceEvent(
		reflect.TypeOf(OpenEvent{}))
	assert.NoError(err)
	if err != nil {
		return
	}
	assert.Equal(4, len(desc.fields), "number of fields")
	assert.Equal("", desc.initialCondition, "initial condition")

	// Evaluate and test the format of open event.
	expectedFormat := strings.Join([]string{
		"Dir=%di:s64", "FilenameStart=%si:u64",
		"Filename=+0(%si):string", "FilenameEnd=%si:u64",
		"Flags=%dx:u64", "Mode=%cx:u64",
	}, " ")
	actualFormat := desc.format()
	assert.Equal(expectedFormat, actualFormat, "format")

	// Attempt to parse and fill the event struct.
	var testEvent1 OpenEvent
	testLog1 := bytes.Trim([]byte(`
Dir=-100 FilenameStart=-12345678 Filename="/proc/self/status" FilenameEnd=-12345678 Flags=0x8000 Mode=0x0
`), "\n")
	len1, err := desc.fill(
		uintptr(unsafe.Pointer(&testEvent1)), testLog1)
	assert.NoError(err)
	if err != nil {
		return
	}
	assert.Equal(len(testLog1), len1, "log read")
	assert.Equal(int64(-100), testEvent1.Dir, "dirfd")
	assert.Equal("/proc/self/status", testEvent1.Filename, "filename")
	assert.Equal(uint64(0x8000), testEvent1.Flags, "flags")
	assert.Equal(uint64(0), testEvent1.Mode, "mode")
}
