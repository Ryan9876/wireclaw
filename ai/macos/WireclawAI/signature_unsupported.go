//go:build !darwin || !cgo

package main

// A build without the native validator cannot authorize helper execution.
func verifyCodeSignature(string, string) error { return errBundleVerification }
