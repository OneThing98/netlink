package netlink

import (
	"errors"
	"net"
)

var (
	ErrWrongSockType = errors.New("Wrong socket type")
	ErrShortResponse = errors.New("Got short response from netlink")
)

// A Route is a subnet associated with the interface to reach it.
type Route struct {
	*net.IPNet
	Iface   *net.Interface
	Default bool
}
