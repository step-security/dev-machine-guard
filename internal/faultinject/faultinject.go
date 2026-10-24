// Package faultinject provides named checkpoints for self-update fault tests.
//
// Release builds compile Point to an inlinable no-op. Builds tagged
// selfupdate_faults read DMG_FAULT=<checkpoint>[@user|@system]:<action>[,...]
// (merged with the link-time Baked value) and act at the matching checkpoint.
// Actions: kill (os.Exit(137), no cleanup), err (return ErrInjected), hang
// (block until killed), diskfull (return an error wrapping the OS disk-full
// errno), panic (a real Go panic, so recovery paths run), sleep<duration>
// (block that long, Go duration syntax up to 10m, then continue), exit<N>
// (os.Exit(N)). S6.mutex fires with the scan instance mutex held. With
// DMG_FAULT_TRACE=<file>, every reached checkpoint name is appended to file.
//
// Checkpoint names may contain ':' (S4.downloaded:<asset>); the action is the
// text after the last ':'.
package faultinject

import "errors"

// ErrInjected is wrapped by every error Point returns for an injected fault.
var ErrInjected = errors.New("faultinject: injected fault")
