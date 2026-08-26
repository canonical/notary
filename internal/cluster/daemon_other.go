//go:build !linux

package cluster

// Start reports that clustering is unavailable. dqlite is built against
// libdqlite, which requires Linux kernel AIO, so the clustered storage path
// only exists on Linux. Everything else in Notary builds and runs unchanged on
// other platforms.
func Start(opts Options) (Node, error) {
	return nil, ErrUnsupportedPlatform
}
