//go:build unix && !linux

package main

// Without a parent-death signal the helper relies on parent pipe EOF, which
// cancels every pipe session and in-flight storage operation.
func bindParentLifetime() error { return nil }
