//go:build !unix

package main

// restrictUmask is a no-op where there is no umask (Windows). The supported
// deployments (container, Helm, Linux binary) are all Unix.
func restrictUmask() {}
