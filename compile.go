package systracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
)

// traceEventField contains information about what to do
// with the field comes at first.
type traceEventField interface {
	// format returns the format string that could be
	// set as the fetch expression.
	//
	// It is usually in the form of <name>=<fetch>:<type>,
	// and some field might be composite and contains
	// multiple of such form.
	format() string

	// fill will attempt to parse the input string and
	// fill information into the struct.
	fill(input []byte, data uintptr) (int, error)
}

// bytesFault is the sequence of fault bytes.
var bytesFault = []byte("(fault)")

// bytesHex is the sequence of hexdecimal number.
var bytesHex = []byte("0x")

// traceFillInteger will attempt to parse the
// content from the number field and later place it
// inside the specified address.
func traceFillInteger(
	addr uintptr, kind reflect.Kind,
	bigEndian bool, number []byte,
) (step int, err error) {
	// If fault is encountered, the string will
	// shift forward for the size of fault and
	// left the remained fields unchanged.
	if bytes.HasPrefix(number, bytesFault) {
		return len(bytesFault), nil
	}

	// Attempt to parse it as string.
	base := 10
	offset := 0
	negative := false
	if bytes.HasPrefix(number, bytesHex) {
		base = 16
		offset = len(bytesHex)
	} else if len(number) > 0 && number[0] == '-' {
		offset = 1
		negative = true
	}

	// Seek for the next space or end of line.
	step = offset
	for step < len(number) &&
		number[step] != ' ' && number[step] != '\n' {
		step++
	}

	// Attempt to parse the number and return.
	var v uint64
	v, err = strconv.ParseUint(
		string(number[offset:step]), base, 64)
	if err != nil {
		return
	}

	// Transform byte order if mismatched order.
	if bigEndian {
		switch kind {
		case reflect.Uint16, reflect.Int16:
			var buf [2]byte
			*(*uint16)((unsafe.Pointer)(&buf[0])) = uint16(v)
			v = uint64(binary.BigEndian.Uint16(buf[:]))
		case reflect.Uint32, reflect.Int32:
			var buf [4]byte
			*(*uint32)((unsafe.Pointer)(&buf[0])) = uint32(v)
			v = uint64(binary.BigEndian.Uint32(buf[:]))
		case reflect.Uint64, reflect.Int64:
			var buf [8]byte
			*(*uint64)((unsafe.Pointer)(&buf[0])) = uint64(v)
			v = uint64(binary.BigEndian.Uint64(buf[:]))
		}
	}

	// Negate the number if it is negative.
	if negative {
		v = uint64(-int64(v))
	}

	// Switch the concrete type of integer and fill.
	switch kind {
	case reflect.Uint8:
		*(*uint8)((unsafe.Pointer)(addr)) = uint8(v)
	case reflect.Int8:
		*(*int8)((unsafe.Pointer)(addr)) = int8(v)
	case reflect.Uint16:
		*(*uint16)((unsafe.Pointer)(addr)) = uint16(v)
	case reflect.Int16:
		*(*int16)((unsafe.Pointer)(addr)) = int16(v)
	case reflect.Uint32:
		*(*uint32)((unsafe.Pointer)(addr)) = uint32(v)
	case reflect.Int32:
		*(*int32)((unsafe.Pointer)(addr)) = int32(v)
	case reflect.Uint64:
		*(*uint64)((unsafe.Pointer)(addr)) = uint64(v)
	case reflect.Int64:
		*(*int64)((unsafe.Pointer)(addr)) = int64(v)
	}
	return
}

// traceIntegerField is a field corresponding to integer.
type traceIntegerField struct {
	name      string
	offset    uintptr
	fetch     string
	kind      reflect.Kind
	typename  string
	bigEndian bool
}

// format returns the format for the field.
func (f traceIntegerField) format() string {
	return fmt.Sprintf("%s=%s%s",
		f.name, f.fetch, f.typename)
}

// fill parsed integer data and move forward.
func (f traceIntegerField) fill(
	input []byte, data uintptr,
) (forward int, err error) {
	bytesName := []byte(f.name + "=")
	if !bytes.HasPrefix(input, bytesName) {
		return 0, errors.Errorf(
			"expect integer field start token %q", f.name)
	}
	forward, err = traceFillInteger(data+f.offset,
		f.kind, f.bigEndian, input[len(bytesName):])
	forward += len(bytesName)
	return
}

// traceStringField is a field corresponding to string.
//
// XXX: despite outputing double quote symbols, all string
// variables written from kernel is not quoted and written
// to buffer directly. And this behaviour is even not
// fixed by kernel yet (>=5.0).
//
// To work around, we enforce the kernel to output the
// canary to identify the end of string. The canary is
// either default to the string address or manually
// specified, and must be hard to detect.
type traceStringField struct {
	name   string
	offset uintptr
	fetch  string
	canary string

	isStringAddr bool
}

// format returns the format for the field.
func (f traceStringField) format() string {
	return fmt.Sprintf(
		"%sStart=%s:u64 %s=+0(%s):string %sEnd=%s:u64",
		f.name, f.canary, f.name, f.fetch, f.name, f.canary)
}

// fill parsed string data and move forward.
func (f traceStringField) fill(
	input []byte, addr uintptr,
) (forward int, err error) {
	pointer := (unsafe.Pointer)(addr + f.offset)

	// Extract the string start token canaries.
	bytesStart := []byte(f.name + "Start=")
	if !bytes.HasPrefix(input, bytesStart) {
		return 0, errors.Errorf(
			"expect string field start token %q", f.name)
	}
	var address uint64
	addressStep, err := traceFillInteger(
		uintptr(unsafe.Pointer(&address)),
		reflect.Uint64, false, input[len(bytesStart):])
	if err != nil {
		return 0, err
	}
	if f.isStringAddr {
		(*StringAddr)(pointer).Addr = address
	}

	// Construct the string end token canaries.
	lenFirstPortion := len(bytesStart) + addressStep
	bytesEnd := input[len(bytesStart):lenFirstPortion]
	bytesEnd = []byte(" " + f.name + "End=" + string(bytesEnd))

	// Attempt to find the enclosing part of the
	// string in the input.
	addressEnd := bytes.Index(input[lenFirstPortion:], bytesEnd)
	if addressEnd < 0 {
		return 0, errors.Errorf(
			"expect string field end token %q", f.name)
	}
	forward = lenFirstPortion + addressEnd + len(bytesEnd)

	// Construct and parse the string.
	bytesString := input[lenFirstPortion+1 : lenFirstPortion+addressEnd]
	bytesMiddle := []byte(f.name + "=")
	if !bytes.HasPrefix(bytesString, bytesMiddle) {
		err = errors.Errorf(
			"expect string field middle token %q", f.name)
		return
	}
	bytesString = bytesString[len(bytesMiddle):]
	if bytes.Equal(bytesString, bytesFault) {
		return
	}
	bytesString = bytesString[1 : len(bytesString)-1]
	if f.isStringAddr {
		(*StringAddr)(pointer).String = string(bytesString)
	} else {
		*(*string)(pointer) = string(bytesString)
	}
	return
}

// traceEventDescriptor describes the way to process event.
//
// The first field will always be untagged and must be one of
// the offspring of tracing.Event (e.g. tracing.ProbeEvent and
// tracing.ReturnEvent). The first field determines how will
// the events be registered and processed.
type traceEventDescriptor struct {
	typ    reflect.Type
	meta   reflect.Type
	fields []traceEventField

	initialCondition string
}

// format returns the event field format concatenated.
func (efd traceEventDescriptor) format() string {
	var formats []string
	for _, field := range efd.fields {
		formats = append(formats, field.format())
	}
	return strings.Join(formats, " ")
}

// mapIntegerName is the map from the kind to the name.
var mapIntegerName = map[reflect.Kind]string{
	reflect.Uint8:  ":u8",
	reflect.Int8:   ":s8",
	reflect.Uint16: ":u16",
	reflect.Int16:  ":s16",
	reflect.Uint32: ":u32",
	reflect.Int32:  ":s32",
	reflect.Uint64: ":u64",
	reflect.Int64:  ":s64",
}

// mapIntegerSize is the map from the kind to the size.
var mapIntegerSize = map[reflect.Kind]uint64{
	reflect.Uint8:  8,
	reflect.Int8:   8,
	reflect.Uint16: 16,
	reflect.Int16:  16,
	reflect.Uint32: 32,
	reflect.Int32:  32,
	reflect.Uint64: 64,
	reflect.Int64:  64,
}

// compileTraceEvent will attempt to parse the fields and
// convert the event specified by type into the event
// descriptor.
func compileTraceEvent(
	typ reflect.Type,
) (*traceEventDescriptor, error) {
	result := &traceEventDescriptor{
		typ: typ,
	}

	// Ensure that the specified type should be  struct.
	if kind := typ.Kind(); kind != reflect.Struct {
		return nil, errors.Errorf("invalid kind %q", kind)
	}

	// Detect and collect first field.
	if typ.NumField() == 0 {
		return nil, errors.New("empty struct")
	}
	firstField := typ.Field(0)
	if !firstField.Anonymous {
		return nil, errors.New("first field must be anonymous")
	}
	result.meta = firstField.Type
	switch result.meta {
	case typeProbeEvent:
	case typeReturnEvent:
	default:
		return nil, errors.Errorf(
			"type %s cannot be first field", result.meta)
	}

	// Perform conversion of each field recursively.
	var stackTyp []reflect.Type
	var stackIndex []int
	var stackOffset []uintptr
	var stackNames []string
	var stackArgs [][]string
	var conds []string
	stackTyp = append(stackTyp, typ)
	stackIndex = append(stackIndex, 1)
	stackOffset = append(stackOffset, 0)
	stackNames = append(stackNames, "")
	stackArgs = append(stackArgs, nil)
	for len(stackTyp) > 0 {
		// Fetch current field for parsing.
		currentTyp := stackTyp[len(stackTyp)-1]
		currentIndex := stackIndex[len(stackIndex)-1]
		if currentTyp.NumField() <= currentIndex {
			stackTyp = stackTyp[:len(stackTyp)-1]
			stackIndex = stackIndex[:len(stackIndex)-1]
			stackOffset = stackOffset[:len(stackOffset)-1]
			stackArgs = stackArgs[:len(stackArgs)-1]
			if len(stackIndex) > 0 {
				stackIndex[len(stackIndex)-1]++
			}
			continue
		}
		currentField := typ.FieldByIndex(stackIndex)
		currentKind := currentField.Type.Kind()
		fieldOffset := stackOffset[len(stackOffset)-1] +
			currentField.Offset
		tag := currentField.Tag.Get("tracing")

		// Apply alternations to the tracing tag with
		// arguments specified on stack.
		currentPrefix := strings.Join(stackNames, "_")
		tag = strings.ReplaceAll(tag, "{0}", currentPrefix)
		for i, value := range stackArgs[len(stackArgs)-1] {
			tag = strings.ReplaceAll(tag,
				fmt.Sprintf("{%d}", i+1), value)
		}

		// Specially processing for the condition field,
		// which is special embedding of condition.
		if currentField.Type == typeCondition {
			if tag != "" {
				conds = append(conds, tag)
			}
			stackIndex[len(stackIndex)-1]++
			continue
		}
		args := strings.Split(tag, ",")

		// Specially processing for the struct kind,
		// which is considered as embedding.
		if currentKind == reflect.Struct &&
			currentField.Type != typeStringAddr {
			stackTyp = append(stackTyp, currentField.Type)
			stackIndex = append(stackIndex, 0)
			stackOffset = append(stackOffset, fieldOffset)
			stackNames = append(stackNames, currentField.Name)
			stackArgs = append(stackArgs, args)
			continue
		}

		// Analyze and prepare current parameter.
		//
		// The first two parameters must always be
		// fetcher and condition (optional). Callers
		// could add more conditions after that.
		if tag == "" {
			stackIndex[len(stackIndex)-1]++
			continue
		}
		fetch := args[0]
		if len(args) > 1 && args[1] != "" {
			conds = append(conds, args[1])
		}

		// Evaluate current name and offset.
		if currentField.Anonymous {
			return nil, errors.New(
				"cannot embed non-struct field")
		}
		fieldName := currentPrefix + currentField.Name

		// Fallback tracing.StringAddr to string kind.
		isStringAddr := false
		if currentField.Type == typeStringAddr {
			currentKind = reflect.String
			isStringAddr = true
		}

		// Find out the kind of the current field.
		switch currentKind {
		case reflect.Uint8, reflect.Int8,
			reflect.Uint16, reflect.Int16,
			reflect.Uint32, reflect.Int32,
			reflect.Uint64, reflect.Int64:
			var bigEndian bool
			typename := mapIntegerName[currentKind]
			for i := 2; i < len(args); i++ {
				arg := args[i]
				switch {
				case arg == "":
				case arg == "bigendian":
					bigEndian = true
				case strings.HasPrefix(arg, "bit[") &&
					strings.HasSuffix(arg, "]"):
					size := mapIntegerSize[currentKind]
					start := arg[len("bit[") : len(arg)-1]
					end := start
					if col := strings.Index(start, ":"); col >= 0 {
						start = start[0:col]
						end = end[col+1:]
					}
					vstart, err := strconv.ParseUint(start, 10, 64)
					if err != nil {
						return nil, errors.Errorf(
							"malformed start %q: %s", arg, err)
					}
					vend, err := strconv.ParseUint(end, 10, 64)
					if err != nil {
						return nil, errors.Errorf(
							"malformed end %q: %s", arg, err)
					}
					if vstart > vend || vend >= size {
						return nil, errors.Errorf(
							`invalid bit range "%d:%d"`, vstart, vend)
					}
					typename = fmt.Sprintf(":b%d@%d/%d",
						vend-vstart+1, vstart, size)
				default:
					return nil, errors.Errorf(
						"unknown modifier %q", arg)
				}
			}
			result.fields = append(result.fields,
				&traceIntegerField{
					name:      fieldName,
					offset:    fieldOffset,
					fetch:     fetch,
					kind:      currentKind,
					typename:  typename,
					bigEndian: bigEndian,
				})
		case reflect.String:
			canary := fetch
			if len(args) > 2 && args[2] != "" {
				canary = fetch
			}
			result.fields = append(result.fields,
				&traceStringField{
					name:         fieldName,
					offset:       fieldOffset,
					fetch:        fetch,
					canary:       canary,
					isStringAddr: isStringAddr,
				})
		default:
			return nil, errors.Errorf(
				"unacceptible kind %s", currentKind)
		}
		stackIndex[len(stackIndex)-1]++
	}

	// Evaluate the initial condition for the queries.
	if len(conds) == 1 {
		result.initialCondition = conds[0]
	} else if len(conds) > 1 {
		result.initialCondition = "(" + strings.Join(
			conds, ") && (") + ")"
	}

	return result, nil
}

// fill will parse the given log and fill the content.
func (efd traceEventDescriptor) fill(
	data uintptr, log []byte,
) (forward int, err error) {
	forward = 0
	for i, field := range efd.fields {
		// Remove spaces encountered.
		for log[forward] == ' ' {
			forward++
		}
		if log[forward] == '\n' {
			err = errors.Errorf(
				"unexpected truncation in field #%d", i)
			return
		}

		// Start parsing the field.
		var current int
		current, err = field.fill(log[forward:], data)
		forward += current
		if err != nil {
			return
		}
	}
	return
}
