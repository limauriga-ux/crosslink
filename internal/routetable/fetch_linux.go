//go:build linux

package routetable

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func fetchEntries(skipIface string) ([]Entry, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, err
	}

	var entries []Entry
	for _, msg := range msgs {
		if msg.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}
		if len(msg.Data) < unix.SizeofRtMsg {
			continue
		}
		rtm := (*unix.RtMsg)(unsafe.Pointer(&msg.Data[0]))
		if rtm.Family != unix.AF_INET {
			continue
		}

		attrs, err := syscall.ParseNetlinkRouteAttr(&syscall.NetlinkMessage{
			Header: msg.Header, Data: msg.Data,
		})
		if err != nil {
			continue
		}

		var dst net.IP
		var gw net.IP
		var ifIndex int
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.RTA_DST:
				dst = net.IP(attr.Value)
			case unix.RTA_GATEWAY:
				gw = net.IP(attr.Value)
			case unix.RTA_OIF:
				ifIndex = int(binary.LittleEndian.Uint32(attr.Value))
			}
		}
		iface, err := net.InterfaceByIndex(ifIndex)
		if err != nil || iface.Name == skipIface {
			continue
		}
		prefix := int(rtm.Dst_len)
		if dst == nil {
			dst = net.IPv4zero
		}
		mask := net.CIDRMask(prefix, 32)
		ipnet := &net.IPNet{IP: dst.Mask(mask).To4(), Mask: mask}
		entries = append(entries, Entry{Dest: ipnet, Gateway: gw, Iface: iface.Name})
	}
	return entries, nil
}
