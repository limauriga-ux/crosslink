//go:build darwin

package routetable

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

func fetchEntries(skipIface string) ([]Entry, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}

	ifaces, _ := net.Interfaces()
	ifaceByIndex := make(map[int]string, len(ifaces))
	for _, iface := range ifaces {
		ifaceByIndex[iface.Index] = iface.Name
	}

	var entries []Entry
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.Flags&syscall.RTF_UP == 0 {
			continue
		}
		ifName := ifaceByIndex[rm.Index]
		if ifName == "" || ifName == skipIface {
			continue
		}

		var dst net.IP
		var mask net.IPMask
		var gw net.IP

		for i, addr := range rm.Addrs {
			if addr == nil {
				continue
			}
			switch i {
			case syscall.RTAX_DST:
				if a, ok := addr.(*route.Inet4Addr); ok {
					dst = net.IP(a.IP[:])
				}
			case syscall.RTAX_GATEWAY:
				if a, ok := addr.(*route.Inet4Addr); ok {
					gw = net.IP(a.IP[:])
				}
			case syscall.RTAX_NETMASK:
				if a, ok := addr.(*route.Inet4Addr); ok {
					mask = net.IPMask(a.IP[:])
				}
			}
		}
		if dst == nil {
			continue
		}
		if mask == nil {
			mask = net.IPMask{255, 255, 255, 255}
		}
		ipnet := &net.IPNet{IP: dst.Mask(mask), Mask: mask}
		entries = append(entries, Entry{Dest: ipnet, Gateway: gw, Iface: ifName})
	}
	return entries, nil
}
