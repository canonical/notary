package cluster

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ParseAdvertiseAddress reports whether address is a usable cluster advertise
// address: a bare host:port, with no scheme.
//
// dqlite stores and dials this string as-is. A URL such as the spec's
// https://host:port would be advertised to peers and never connect.
func ParseAdvertiseAddress(address string) error {
	if address == "" {
		return errors.New("cluster address is required")
	}
	if strings.Contains(address, "://") {
		return errors.New("cluster address must be host:port, not a URL")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("cluster address must be host:port: %w", err)
	}
	if host == "" || port == "" {
		return errors.New("cluster address must be host:port")
	}

	return nil
}
