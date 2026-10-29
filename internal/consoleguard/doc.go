// Package consoleguard holds the tests that keep the agent from opening
// console windows on Windows. It has no production code.
//
//   - consoleguard_test.go (every OS) parses each non-test file that builds
//     for Windows and fails on a process spawn that does not hide its console.
//   - probe_windows_test.go (Windows) starts a probe that behaves like
//     wsl.exe through every production spawn path and fails if the probe
//     ends up with a visible console window.
//
// See AGENTS.md §7.4.
package consoleguard
