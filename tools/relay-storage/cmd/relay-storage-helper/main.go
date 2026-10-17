package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	storage "pico-fido2/relay-storage"
)

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("PicoFidoStorage protocol PF2STO01 (idle reuse, deferred verification); rclone 1.75.2; etcd client 3.6.16")
		return nil
	}
	if (len(os.Args) == 3 || len(os.Args) == 4) && (os.Args[1] == "--pipe" || os.Args[1] == "--setup-pipe" || os.Args[1] == "--enroll-pipe" || os.Args[1] == "--maintain-pipe") {
		if err := bindParentLifetime(); err != nil {
			return err
		}
		for _, file := range []*os.File{os.Stdin, os.Stdout} {
			if !isPrivatePipe(file) {
				return errors.New("private parent-child pipes are required")
			}
		}
		path, err := storage.DefaultProfilePath(os.Args[2])
		if err != nil {
			return err
		}
		if len(os.Args) == 4 {
			path = os.Args[3]
		}
		if os.Args[1] == "--setup-pipe" {
			return storage.ServeProfileSetup(context.Background(), os.Stdin, os.Stdout, path, os.Args[2])
		}
		if os.Args[1] == "--enroll-pipe" {
			return storage.ServeEnrollment(context.Background(), os.Stdin, os.Stdout, path, os.Args[2])
		}
		if os.Args[1] == "--maintain-pipe" {
			return storage.ServeMaintenance(context.Background(), os.Stdin, os.Stdout, path, os.Args[2])
		}
		return storage.ServeProfilePipe(context.Background(), os.Stdin, os.Stdout, path, os.Args[2])
	}
	return errors.New("usage: PicoFidoStorage --version | --pipe NAMESPACE [PROFILE_PATH] | --setup-pipe NAMESPACE [PROFILE_PATH] | --enroll-pipe NAMESPACE [PROFILE_PATH] | --maintain-pipe NAMESPACE [PROFILE_PATH]")
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Storage helper:", err)
		if errors.Is(err, storage.ErrAudit) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
