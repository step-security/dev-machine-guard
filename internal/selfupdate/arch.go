package selfupdate

// NativeArch is the machine's architecture as a release-asset suffix
// (amd64 | arm64). On Windows it comes from IsWow64Process2, so an x64 build
// emulated on arm64 converges to the arm64 build.
func NativeArch() string { return nativeArch() }
