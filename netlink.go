package netlink

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	DEFAULT_CHANGE = 0xFFFFFFFF
	IFLA_INFO_KIND = 1
	VETH_INFO_PEER = 1
	IFLA_NET_NS_FD = 28
)

var nextSeqNr int

// check Endianess
func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	//here is how this works
	//1. get the address of x(a uint32)
	//2. convert the uint32 pointer unsafe pointer for type casting
	//3. cast the unsafe pointer to a *byte, treating the first byte of x as a byte
	//4. dereference the *byte to read the first byte of x
	//5. compare the first byte to 0x01 to check if the system is bigEndian
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func getSeq() int {
	nextSeqNr = nextSeqNr + 1
	return nextSeqNr
}

type IfInfoMsg struct {
	unix.IfInfomsg
}

func newIfinfoMsg(family int) *IfInfoMsg {
	return &IfInfoMsg{
		IfInfomsg: unix.IfInfomsg{
			Family: uint8(family),
		},
	}
}

func (msg *IfInfoMsg) ToWireFormat() []byte {
	native := nativeEndian()
	length := unix.SizeofIfInfomsg
	b := make([]byte, length)
	b[0] = msg.Family
	native.PutUint32(b[4:8], uint32(msg.Index))
	native.PutUint32(b[8:12], msg.Flags)
	native.PutUint32(b[12:16], msg.Change)
	return b
}
