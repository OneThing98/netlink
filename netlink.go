package netlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	IFNAMSIZ       = 16
	DEFAULT_CHANGE = 0xFFFFFFFF
	IFLA_INFO_KIND = 1
	IFLA_INFO_DATA = 2
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

func getIpFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return unix.AF_INET
	}
	if ip.To4() != nil {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

type NetlinkRequestData interface {
	Len() int
	ToWireFormat() []byte
}

type IfInfomsg struct {
	unix.IfInfomsg
}

func newIfInfomsg(family int) *IfInfomsg {
	return &IfInfomsg{
		IfInfomsg: unix.IfInfomsg{
			Family: uint8(family),
		},
	}
}

func newIfInfomsgChild(parent *RtAttr, family int) *IfInfomsg {
	msg := newIfInfomsg(family)
	parent.children = append(parent.children, msg)
	return msg
}

func (msg *IfInfomsg) ToWireFormat() []byte {
	native := nativeEndian()
	length := unix.SizeofIfInfomsg
	b := make([]byte, length)
	b[0] = msg.Family
	b[1] = 0
	native.PutUint16(b[2:4], msg.Type)
	native.PutUint32(b[4:8], uint32(msg.Index))
	native.PutUint32(b[8:12], msg.Flags)
	native.PutUint32(b[12:16], msg.Change)
	return b
}

func (msg *IfInfomsg) Len() int {
	return unix.SizeofIfInfomsg
}

type RtAttr struct {
	unix.RtAttr
	Data     []byte
	children []NetlinkRequestData
}

type IfAddrmsg struct {
	unix.IfAddrmsg
}

func newIfAddrmsg(family int) *IfAddrmsg {
	return &IfAddrmsg{
		IfAddrmsg: unix.IfAddrmsg{
			Family: uint8(family),
		},
	}
}

func (msg *IfAddrmsg) ToWireFormat() []byte {
	native := nativeEndian()
	length := unix.SizeofIfAddrmsg
	b := make([]byte, length)
	b[0] = msg.Family
	b[1] = msg.Prefixlen
	b[2] = msg.Flags
	b[3] = msg.Scope
	native.PutUint32(b[4:8], msg.Index)
	return b
}

func (msg *IfAddrmsg) Len() int {
	return unix.SizeofIfAddrmsg
}

type RtMsg struct {
	unix.RtMsg
}

func newRtMsg(family int) *RtMsg {
	return &RtMsg{
		RtMsg: unix.RtMsg{
			Family:   uint8(family),
			Table:    unix.RT_TABLE_MAIN,
			Scope:    unix.RT_SCOPE_UNIVERSE,
			Protocol: unix.RTPROT_BOOT,
			Type:     unix.RTN_UNICAST,
		},
	}
}

func (msg *RtMsg) ToWireFormat() []byte {
	native := nativeEndian()

	length := unix.SizeofRtMsg
	b := make([]byte, length)
	b[0] = msg.Family
	b[1] = msg.Dst_len
	b[2] = msg.Src_len
	b[3] = msg.Tos
	b[4] = msg.Table
	b[5] = msg.Protocol
	b[6] = msg.Scope
	b[7] = msg.Type
	native.PutUint32(b[8:12], msg.Flags)
	return b
}

func (msg *RtMsg) Len() int {
	return unix.SizeofRtMsg
}

func rtaAlignOf(attrlen int) int {
	return (attrlen + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func newRtAttr(attrType int, data []byte) *RtAttr {
	return &RtAttr{
		RtAttr: unix.RtAttr{
			Type: uint16(attrType),
		},
		children: []NetlinkRequestData{},
		Data:     data,
	}
}

func newRtAttrChild(parent *RtAttr, attrType int, data []byte) *RtAttr {
	attr := newRtAttr(attrType, data)
	parent.children = append(parent.children, attr)
	return attr
}

func (a *RtAttr) Len() int {
	l := 0
	for _, child := range a.children {
		l += child.Len() + unix.SizeofRtAttr
	}
	if l == 0 {
		l++
	}
	return rtaAlignOf(l + len(a.Data))
}

func (a *RtAttr) ToWireFormat() []byte {
	native := nativeEndian()

	length := a.Len()
	buf := make([]byte, rtaAlignOf(length+unix.SizeofRtAttr))

	if a.Data != nil {
		copy(buf[4:], a.Data)
	} else {
		next := 4
		for _, child := range a.children {
			childBuf := child.ToWireFormat()
			copy(buf[next:], childBuf)
			next += rtaAlignOf(len(childBuf))
		}
	}

	if l := uint16(rtaAlignOf(length)); l != 0 {
		native.PutUint16(buf[0:2], l+1)
	}
	native.PutUint16(buf[2:4], a.Type)

	return buf
}

type NetlinkRequest struct {
	unix.NlMsghdr
	Data []NetlinkRequestData
}

func (rr *NetlinkRequest) ToWireFormat() []byte {
	native := nativeEndian()

	length := rr.Len
	dataBytes := make([][]byte, len(rr.Data))
	for i, data := range rr.Data {
		dataBytes[i] = data.ToWireFormat()
		length += uint32(len(dataBytes[i]))
	}
	b := make([]byte, length)
	native.PutUint32(b[0:4], length)
	native.PutUint16(b[4:6], rr.Type)
	native.PutUint16(b[6:8], rr.Flags)
	native.PutUint32(b[8:12], rr.Seq)
	native.PutUint32(b[12:16], rr.Pid)

	next := 16
	for _, data := range dataBytes {
		copy(b[next:], data)
		next += len(data)
	}
	return b
}

func (rr *NetlinkRequest) AddData(data NetlinkRequestData) {
	if data != nil {
		rr.Data = append(rr.Data, data)
	}
}

func newNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.NLMSG_HDRLEN),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
			Seq:   uint32(getSeq()),
		},
	}
}

type NetlinkSocket struct {
	fd  int
	lsa unix.SockaddrNetlink
}

func getNetlinkSocket() (*NetlinkSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd: fd,
	}
	s.lsa.Family = unix.AF_NETLINK
	if err := unix.Bind(fd, &s.lsa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return s, nil
}

func (s *NetlinkSocket) Close() {
	unix.Close(s.fd)
}

func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
	if err := unix.Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
	rb := make([]byte, unix.Getpagesize())
	nr, _, err := unix.Recvfrom(s.fd, rb, 0)
	if err != nil {
		return nil, err
	}
	if nr < unix.NLMSG_HDRLEN {
		return nil, ErrShortResponse
	}
	rb = rb[:nr]
	return syscall.ParseNetlinkMessage(rb)
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
	lsa, err := unix.Getsockname(s.fd)
	if err != nil {
		return 0, err
	}
	switch v := lsa.(type) {
	case *unix.SockaddrNetlink:
		return v.Pid, nil
	}
	return 0, ErrWrongSockType
}

func (s *NetlinkSocket) HandleAck(seq uint32) error {
	native := nativeEndian()

	pid, err := s.GetPid()
	if err != nil {
		return err
	}

done:
	for {
		msgs, err := s.Receive()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				return fmt.Errorf("wrong Seq nr %d, expected %d", m.Header.Seq, seq)
			}
			if m.Header.Pid != pid {
				return fmt.Errorf("wrong pid %d, expected %d", m.Header.Pid, pid)
			}
			if m.Header.Type == unix.NLMSG_DONE {
				break done
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				return unix.Errno(-error)
			}
		}
	}

	return nil
}

// Add a new default gateway. Identical to:
// ip route add default via $ip
func AddDefaultGw(ip net.IP) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	family := getIpFamily(ip)

	wb := newNetlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)

	msg := newRtMsg(family)
	wb.AddData(msg)

	var ipData []byte
	if family == unix.AF_INET {
		ipData = ip.To4()
	} else {
		ipData = ip.To16()
	}

	gateway := newRtAttr(unix.RTA_GATEWAY, ipData)

	wb.AddData(gateway)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

// Bring up a particular network interface
func NetworkLinkUp(iface *net.Interface) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_UP
	msg.Flags = unix.IFF_UP
	msg.Index = int32(iface.Index)
	wb.AddData(msg)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

func NetworkLinkDown(iface *net.Interface) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_UP
	msg.Flags = 0 & ^unix.IFF_UP
	msg.Index = int32(iface.Index)
	wb.AddData(msg)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

func NetworkSetMTU(iface *net.Interface, mtu int) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	msg.Type = unix.RTM_SETLINK
	msg.Flags = unix.NLM_F_REQUEST
	msg.Index = int32(iface.Index)
	msg.Change = DEFAULT_CHANGE
	wb.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(mtu))

	data := newRtAttr(unix.IFLA_MTU, b)
	wb.AddData(data)

	if err := s.Send(wb); err != nil {
		return err
	}
	return s.HandleAck(wb.Seq)
}

// same as ip link set $name master $master
func NetworkSetMaster(iface, master *net.Interface) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	msg.Type = unix.RTM_SETLINK
	msg.Flags = unix.NLM_F_REQUEST
	msg.Index = int32(iface.Index)
	msg.Change = DEFAULT_CHANGE
	wb.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(master.Index))

	data := newRtAttr(unix.IFLA_MASTER, b)
	wb.AddData(data)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

func NetworkSetNsPid(iface *net.Interface, nspid int) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	msg.Type = unix.RTM_SETLINK
	msg.Flags = unix.NLM_F_REQUEST
	msg.Index = int32(iface.Index)
	msg.Change = DEFAULT_CHANGE
	wb.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(nspid))

	data := newRtAttr(unix.IFLA_NET_NS_PID, b)
	wb.AddData(data)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

func NetworkSetNsFd(iface *net.Interface, fd int) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	msg.Type = unix.RTM_SETLINK
	msg.Flags = unix.NLM_F_REQUEST
	msg.Index = int32(iface.Index)
	msg.Change = DEFAULT_CHANGE
	wb.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(fd))

	data := newRtAttr(IFLA_NET_NS_FD, b)
	wb.AddData(data)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

// Add an Ip address to an interface. This is identical to:
// ip addr add $ip/$ipNet dev $iface
func NetworkLinkAddIp(iface *net.Interface, ip net.IP, ipNet *net.IPNet) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	family := getIpFamily(ip)

	wb := newNetlinkRequest(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)

	msg := newIfAddrmsg(family)
	msg.Index = uint32(iface.Index)
	prefixLen, _ := ipNet.Mask.Size()
	msg.Prefixlen = uint8(prefixLen)
	wb.AddData(msg)

	var ipData []byte
	if family == unix.AF_INET {
		ipData = ip.To4()
	} else {
		ipData = ip.To16()
	}

	localData := newRtAttr(unix.IFA_LOCAL, ipData)
	wb.AddData(localData)

	addrData := newRtAttr(unix.IFA_ADDRESS, ipData)
	wb.AddData(addrData)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

func zeroTerminated(s string) []byte {
	return []byte(s + "\000")
}

func nonZeroTerminated(s string) []byte {
	return []byte(s)
}

// Add a new network link of a specified type. This is identical to
// running: ip add link $name type $linkType
func NetworkLinkAdd(name string, linkType string) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	wb.AddData(msg)

	if name != "" {
		nameData := newRtAttr(unix.IFLA_IFNAME, zeroTerminated(name))
		wb.AddData(nameData)
	}

	kindData := newRtAttr(IFLA_INFO_KIND, nonZeroTerminated(linkType))

	infoData := newRtAttr(unix.IFLA_LINKINFO, kindData.ToWireFormat())
	wb.AddData(infoData)

	if err := s.Send(wb); err != nil {
		return err
	}

	return s.HandleAck(wb.Seq)
}

// Returns an array of IPNet for all the currently routed subnets on ipv4
// This is similar to the first column of "ip route" output
func NetworkGetRoutes() ([]Route, error) {
	native := nativeEndian()

	s, err := getNetlinkSocket()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_DUMP)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	wb.AddData(msg)

	if err := s.Send(wb); err != nil {
		return nil, err
	}

	pid, err := s.GetPid()
	if err != nil {
		return nil, err
	}

	res := make([]Route, 0)

done:
	for {
		msgs, err := s.Receive()
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != wb.Seq {
				return nil, fmt.Errorf("Wrong Seq nr %d, expected 1", m.Header.Seq)
			}
			if m.Header.Pid != pid {
				return nil, fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, pid)
			}
			if m.Header.Type == unix.NLMSG_DONE {
				break done
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				return nil, unix.Errno(-error)
			}
			if m.Header.Type != unix.RTM_NEWROUTE {
				continue
			}

			var r Route

			msg := (*RtMsg)(unsafe.Pointer(&m.Data[0:unix.SizeofRtMsg][0]))

			if msg.Flags&unix.RTM_F_CLONED != 0 {
				// Ignore cloned routes
				continue
			}

			if msg.Table != unix.RT_TABLE_MAIN {
				// Ignore non-main tables
				continue
			}

			if msg.Family != unix.AF_INET {
				// Ignore non-ipv4 routes
				continue
			}

			if msg.Dst_len == 0 {
				// Default routes
				r.Default = true
			}

			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return nil, err
			}
			for _, attr := range attrs {
				switch attr.Attr.Type {
				case unix.RTA_DST:
					ip := attr.Value
					r.IPNet = &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(int(msg.Dst_len), 8*len(ip)),
					}
				case unix.RTA_OIF:
					index := int(native.Uint32(attr.Value[0:4]))
					r.Iface, _ = net.InterfaceByIndex(index)
				}
			}
			if r.Default || r.IPNet != nil {
				res = append(res, r)
			}
		}
	}

	return res, nil
}

func getIfSocket() (fd int, err error) {
	for _, socket := range []int{
		unix.AF_INET,
		unix.AF_PACKET,
		unix.AF_INET6,
	} {
		if fd, err = unix.Socket(socket, unix.SOCK_DGRAM, 0); err == nil {
			break
		}
	}
	if err == nil {
		return fd, nil
	}
	return -1, err
}

func NetworkChangeName(iface *net.Interface, newName string) error {
	fd, err := getIfSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	data := [IFNAMSIZ * 2]byte{}
	// the "-1"s here are very important for ensuring we get proper null
	// termination of our new C strings
	copy(data[:IFNAMSIZ-1], iface.Name)
	copy(data[IFNAMSIZ:IFNAMSIZ*2-1], newName)

	if _, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFNAME, uintptr(unsafe.Pointer(&data[0]))); errno != 0 {
		return errno
	}
	return nil
}

func NetworkCreateVethPair(name1, name2 string) error {
	s, err := getNetlinkSocket()
	if err != nil {
		return err
	}
	defer s.Close()

	wb := newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)

	msg := newIfInfomsg(unix.AF_UNSPEC)
	wb.AddData(msg)

	nameData := newRtAttr(unix.IFLA_IFNAME, zeroTerminated(name1))
	wb.AddData(nameData)

	nest1 := newRtAttr(unix.IFLA_LINKINFO, nil)
	newRtAttrChild(nest1, IFLA_INFO_KIND, zeroTerminated("veth"))
	nest2 := newRtAttrChild(nest1, IFLA_INFO_DATA, nil)
	nest3 := newRtAttrChild(nest2, VETH_INFO_PEER, nil)

	newIfInfomsgChild(nest3, unix.AF_UNSPEC)
	newRtAttrChild(nest3, unix.IFLA_IFNAME, zeroTerminated(name2))

	wb.AddData(nest1)

	if err := s.Send(wb); err != nil {
		return err
	}
	return s.HandleAck(wb.Seq)
}
