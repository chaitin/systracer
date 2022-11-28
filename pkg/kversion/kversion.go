// Package kversion fetches the linux kernel version,
// and parse them with semantic versioning.
package kversion

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
)

// Version stores the kernel version using semantic
// versioning, but converted to a 64bit numeric value.
type Version uint64

// Predefined component for composing into version.
const (
	offsetPreRelease = 0
	bitsPreRelease   = 32
	offsetPatch      = bitsPreRelease
	bitsPatch        = 16
	offsetMinor      = offsetPatch + bitsPatch
	bitsMinor        = 8
	offsetMajor      = offsetMinor + bitsMinor
	bitsMajor        = 64 - offsetMajor
)

// Major returns the value of the major version.
func (v Version) Major() int64 {
	return (int64(v) >> offsetMajor) & ((1 << bitsMajor) - 1)
}

// Minor returns the value of the minor version.
func (v Version) Minor() int64 {
	return (int64(v) >> offsetMinor) & ((1 << bitsMinor) - 1)
}

// Patch returns the value of the patch version.
func (v Version) Patch() int64 {
	return (int64(v) >> offsetPatch) & ((1 << bitsPatch) - 1)
}

// PreRelease returns the value of the pre-release version.
func (v Version) PreRelease() int64 {
	return (int64(v) >> offsetPreRelease) & ((1 << bitsPreRelease) - 1)
}

// String formats the kernel version as triplets.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d-%d",
		v.Major(), v.Minor(), v.Patch(), v.PreRelease())
}

// regexpKv is the regular expression for parsing
// the kernel version string.
var regexKv = regexp.MustCompile(
	`([0-9]+)\.([0-9]+)(\.[0-9]+)?(-[0-9]+)?`)

// Parse the specified kernel version.
func Parse(version string) (Version, error) {
	var err error
	kv := []byte(version)

	// Parse the provided kernel version.
	m := regexKv.FindSubmatchIndex(kv)
	if len(m) < 10 || m[0] != 0 {
		return Version(0), errors.Wrapf(
			err, "malformed %q", version)
	}

	// Parse the major, minor and patch version.
	majorComponent := string(kv[m[2]:m[3]])
	major, err := strconv.ParseUint(majorComponent, 10, bitsMajor)
	if err != nil {
		return Version(0), errors.Wrapf(
			err, "invalid major %q", majorComponent)
	}
	minorComponent := string(kv[m[4]:m[5]])
	minor, err := strconv.ParseUint(minorComponent, 10, bitsMinor)
	if err != nil {
		return Version(0), errors.Wrapf(
			err, "invalid minor %q", minorComponent)
	}

	// Check the optional kernel version.
	var patch uint64
	if m[6] >= 0 && m[7] >= 0 {
		patchComponent := string(kv[m[6]+1 : m[7]])
		patch, err = strconv.ParseUint(patchComponent, 10, bitsPatch)
		if err != nil {
			return Version(0), errors.Wrapf(
				err, "invalid patch %q", patchComponent)
		}
	}
	var preRelease uint64
	if m[8] >= 0 && m[9] >= 0 {
		preReleaseComponent := string(kv[m[8]+1 : m[9]])
		preRelease, err = strconv.ParseUint(
			preReleaseComponent, 10, bitsPreRelease)
		if err != nil {
			return Version(0), errors.Wrapf(
				err, "invalid pre-release %q", preReleaseComponent)
		}
	}

	// Return the parsed version result.
	return Version(preRelease |
		(major << offsetMajor) |
		(minor << offsetMinor) |
		(patch << offsetPatch)), nil
}

// Must forcefully parses the version and panics if
// the version specified cannot resolve.
func Must(version string) Version {
	v, err := Parse(version)
	if err != nil {
		panic(err)
	}
	return v
}

// Current is the version retrieved when the process
// has just been initialized.
var Current Version

// init initializes the current version retrieved
// from the kernel.
func init() {
	kv, kverr := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	if kverr != nil {
		panic(kverr)
	}
	Current = Must(string(kv))
}
