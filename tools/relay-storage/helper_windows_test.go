package storage

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

const helperTestBinary = "PicoFidoStorage-test.exe"

// Windows helpers protect test profiles with the real per-user DPAPI.
var helperTestBuildFlags []string

func hideTestWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
