package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// SIGKILL this helper when the spawning parent exits. If the parent already died
// before prctl took effect, the helper was reparented to init: exit instead.
func bindParentLifetime() error {
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return errors.New("cannot bind helper lifetime to parent")
	}
	if os.Getppid() == 1 {
		return errors.New("parent process exited")
	}
	return nil
}
