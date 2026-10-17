//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// The parent passes anonymous pipes (or a socketpair) on fds 0 and 1; terminals,
// regular files and devices are refused.
func isPrivatePipe(file *os.File) bool {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return false
	}
	kind := st.Mode & unix.S_IFMT
	return kind == unix.S_IFIFO || kind == unix.S_IFSOCK
}
