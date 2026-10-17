package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows profiles are DPAPI blobs bound to the current Windows user. The
// on-disk format (DPAPI over PF2CLD01 + JSON) is unchanged from earlier releases.
const profileExtension = ".dpapi"

func cloudProfileDirectory() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return "", errors.New("cannot find local profile directory")
	}
	return filepath.Join(base, "PicoFido2Remote", "safe-end", "cloud"), nil
}

func dpapi(data []byte, encrypt bool) ([]byte, error) {
	if len(data) == 0 || len(data) > profileLimit {
		return nil, errors.New("invalid protected profile size")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	runtime.KeepAlive(data)
	if err != nil {
		return nil, errors.New("cannot protect or unlock cloud profile for this Windows user")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	clearable := unsafe.Slice(out.Data, int(out.Size))
	defer clear(clearable)
	if out.Size > profileLimit {
		return nil, errors.New("protected profile too large")
	}
	return bytes.Clone(clearable), nil
}

// The namespace is authenticated by the decoded JSON identity check on Windows.
func protectProfile(plain []byte, _ string) ([]byte, error)    { return dpapi(plain, true) }
func unprotectProfile(cipher []byte, _ string) ([]byte, error) { return dpapi(cipher, false) }

func openProfileForRead(path string) (*os.File, error) { return os.Open(path) }

func publishProfile(temp, path string, initial bool) error {
	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if !initial {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}

// profileLock is the marker file opened with share mode 0: no other handle,
// in this or another process, can open it while the lock is held.
type profileLock struct{ h windows.Handle }

func openProfileLock(path string, initial bool) (*profileLock, error) {
	name, err := windows.UTF16PtrFromString(path + ".lock")
	if err != nil {
		return nil, err
	}
	creation := uint32(windows.OPEN_EXISTING)
	if initial {
		creation = windows.CREATE_NEW
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, creation, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if initial && (errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS)) {
			return nil, errProfileLockExists
		}
		return nil, errors.New("cloud profile uninitialized, already initialized or in use")
	}
	return &profileLock{h: h}, nil
}
func (l *profileLock) writeMarker(marker []byte) error {
	var n uint32
	if err := windows.WriteFile(l.h, marker, &n, nil); err != nil || int(n) != len(marker) {
		return errors.New("cannot initialize cloud profile marker")
	}
	if err := windows.FlushFileBuffers(l.h); err != nil {
		return errors.New("cannot flush cloud profile marker")
	}
	return nil
}

// readMarker returns at most one byte more than a valid marker so callers can
// reject trailing data with an exact comparison.
func (l *profileLock) readMarker() ([]byte, error) {
	marker := make([]byte, len(profileMarkerMagic)+32+1)
	var n uint32
	if err := windows.ReadFile(l.h, marker, &n, nil); err != nil {
		return nil, err
	}
	return marker[:n], nil
}
func (l *profileLock) close() {
	if l.h != windows.InvalidHandle {
		windows.CloseHandle(l.h)
		l.h = windows.InvalidHandle
	}
}
