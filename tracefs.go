package systracer

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

// setError represents a set of errors that could be returned
// by tracefs when operating on a set of entities.
type setError struct {
	Op  string
	Arg []string
	Err []error
}

// Error returns the formatted error string.
func (e *setError) Error() string {
	var errString []string
	for _, err := range e.Err {
		errString = append(errString, err.Error())
	}
	return fmt.Sprintf(
		"errors returned while %s(%q): %s", e.Op,
		strings.Join(e.Arg, ", "),
		strings.Join(errString, "\n"))
}

// disableInstance will attempt to disable all events associated
// with a single instance.
func disableInstance(tracefs, instance string) error {
	if instance == "" {
		return errors.New("invalid empty instance name")
	}
	set := &setError{
		Op:  "disableInstance",
		Arg: []string{tracefs, instance},
	}

	// Walk the instance event directory and disable event.
	if err := filepath.Walk(
		filepath.Join(tracefs, "instances", instance),
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				set.Err = append(set.Err, err)
			}
			if info == nil {
				return nil
			}
			if info.Name() == "enable" && !info.IsDir() {
				if err = ioutil.WriteFile(path, []byte("0"),
					os.FileMode(0600)); err != nil {
					set.Err = append(set.Err, err)
				}
			}
			return nil
		}); err != nil {
		set.Err = append(set.Err, err)
	}
	if len(set.Err) > 0 {
		return set
	}
	return nil
}

// removeInstance will attempt to remove an instance from
// currently registered traces.
func removeInstance(tracefs, instance string) error {
	if instance == "" {
		return errors.New("invalid empty instance name")
	}

	// We won't have to remove the instance if the instance
	// has already been deleted.
	set := &setError{
		Op:  "removeInstance",
		Arg: []string{tracefs, instance},
	}
	instancePath := filepath.Join(tracefs, "instances", instance)
	var stat syscall.Stat_t
	if err := syscall.Stat(instancePath, &stat); err != nil {
		if err == syscall.ENOENT {
			return nil
		}
		set.Err = append(set.Err, err)
		return set
	}

	// Disable current tracing of the instance.
	if err := ioutil.WriteFile(
		filepath.Join(instancePath, "tracing_on"),
		[]byte("0"), os.FileMode(0600)); err != nil {
		set.Err = append(set.Err, err)
		return set
	}

	// Cleanup content of all ring buffers in the instance.
	//
	// XXX: though it is unnecessary, there's a bug
	// (RingBufferDetonator) that exists in kernel ranged from
	// 3.10 to 5.14-rc3, which means it should exist in exactly
	// all linux that cloudwalker agent operates on.
	//
	// https://github.com/torvalds/linux/commit/67f0d6d9883c13174669f88adac4f0ee656cc16a
	//
	// When the bug is triggered, if will stuck inside a deadloop
	// that can only be bailed out by disabling the tracing and
	// cleanup the ring buffers.
	if err := ioutil.WriteFile(
		filepath.Join(instancePath, "trace"),
		nil, os.FileMode(0600)); err != nil {
		set.Err = append(set.Err, err)
		return set
	}

	// If the instance could be removed directly, we will just
	// attempt to remove and return. And if we will only try
	// to perform more work if it is EBUSY.
	err := syscall.Rmdir(instancePath)
	if err == nil || err == syscall.ENOENT {
		return nil
	}
	if err != syscall.EBUSY {
		set.Err = append(set.Err, err)
		return set
	}

	// Record the errors generated while disabling instance.
	//
	// Please notice that it is only considered an error when we
	// cannot remove the instance directory.
	if err := disableInstance(tracefs, instance); err != nil {
		if subset, ok := err.(*setError); ok {
			set.Err = append(set.Err, subset.Err...)
		} else {
			set.Err = append(set.Err, err)
		}
	}

	// Remove the root directory of instance.
	err = syscall.Rmdir(instancePath)
	if err == nil || err == syscall.ENOENT {
		return nil
	}
	set.Err = append(set.Err, err)
	return set
}

// removeProbe will attempt to remove a single probe from
// specified file, while disabling all of them.
func removeProbe(tracefs, typ, namespace, probe string) error {
	if typ == "" {
		return errors.New("invalid empty typ name")
	}
	if namespace == "" {
		return errors.New("invalid empty namespace name")
	}
	if probe == "" {
		return errors.New("invalid empty probe name")
	}

	// Attempt to open the probe manifest first. Under no
	// circumstance should the open fail.
	var err error
	set := &setError{
		Op:  "removeProbe",
		Arg: []string{tracefs, typ, namespace, probe},
	}
	fd, err := syscall.Open(filepath.Join(tracefs, typ),
		syscall.O_WRONLY|syscall.O_APPEND, 0600)
	if err != nil {
		set.Err = append(set.Err, err)
		return set
	}
	defer func() { _ = syscall.Close(fd) }()

	// Attempt to remove the probe from the file.
	eraseWord := []byte(fmt.Sprintf(
		"-:%s/%s", namespace, probe))
	_, err = syscall.Write(fd, eraseWord)
	if err == nil || err == syscall.ENOENT {
		return nil
	}
	if err != syscall.EBUSY {
		set.Err = append(set.Err, err)
		return set
	}

	// Disable the probe in all of the item list.
	if err = ioutil.WriteFile(filepath.Join(
		tracefs, "events", namespace, probe, "enable"),
		[]byte("0"), os.FileMode(0600)); err != nil {
		set.Err = append(set.Err, err)
	}
	dirents, err := ioutil.ReadDir(
		filepath.Join(tracefs, "instances"))
	if err != nil && !os.IsNotExist(err) {
		set.Err = append(set.Err, err)
	}
	for _, dirent := range dirents {
		if !dirent.IsDir() {
			continue
		}
		if err = ioutil.WriteFile(filepath.Join(
			tracefs, "instances", dirent.Name(),
			"events", namespace, probe, "enable"),
			[]byte("0"), os.FileMode(0600)); err != nil {
			set.Err = append(set.Err, err)
		}
	}

	// Reattempt to disable the probe from the file.
	_, err = syscall.Write(fd, eraseWord)
	if err == nil || err == syscall.ENOENT {
		return nil
	}
	set.Err = append(set.Err, err)
	return set
}

// removeAllProbe will remove all probes under namespace.
func removeAllProbe(tracefs, typ, namespace string) error {
	if typ == "" {
		return errors.New("invalid empty typ name")
	}
	if namespace == "" {
		return errors.New("invalid empty namespace name")
	}

	// Iterate and invoke remove method on the events.
	var err error
	set := &setError{
		Op:  "removeAllProbe",
		Arg: []string{tracefs, typ, namespace},
	}
	dirents, err := ioutil.ReadDir(
		filepath.Join(tracefs, "events", namespace))
	if err != nil && !os.IsNotExist(err) {
		set.Err = append(set.Err, err)
	}
	for _, dirent := range dirents {
		if !dirent.IsDir() {
			continue
		}
		if err := removeProbe(tracefs, typ, namespace,
			dirent.Name()); err != nil {
			if subset, ok := err.(*setError); ok {
				set.Err = append(set.Err, subset.Err...)
			} else {
				set.Err = append(set.Err, err)
			}
		}
	}
	if len(set.Err) > 0 {
		return set
	}
	return nil
}
