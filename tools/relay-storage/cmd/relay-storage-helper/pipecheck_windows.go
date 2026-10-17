package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// The parent passes connected named-pipe ends; consoles and files are refused.
func isPrivatePipe(file *os.File) bool {
	typeID, err := windows.GetFileType(windows.Handle(file.Fd()))
	return err == nil && typeID == windows.FILE_TYPE_PIPE
}

// The parent's job object (KILL_ON_JOB_CLOSE) ends the helper with the parent.
func bindParentLifetime() error { return nil }
