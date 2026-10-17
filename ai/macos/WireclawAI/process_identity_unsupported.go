//go:build !darwin || !cgo

package main

type processIdentity struct{ started, executable string }

func processIdentityForPID(int) (processIdentity, error) {
	return processIdentity{}, errProcessIdentity
}
