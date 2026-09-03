//go:build windows

package routetable

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

func fetchEntries(skipIface string) ([]Entry, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	rows := table.Rows()
	var entries []Entry
	for _, row := range rows {
		iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
		if err != nil || iface.Name == skipIface {
			continue
		}
		prefix := int(row.DestinationPrefix.PrefixLength)
		// RawSockaddrInet: Family is first field, then Port, then Data ([6]uint32).
		// For AF_INET, the IPv4 address is stored in the first 4 bytes of Data.
		raw := row.DestinationPrefix.Prefix
		var ipBytes [4]byte
		if raw.Family == windows.AF_INET {
			// Data[0] holds the in_addr (4 bytes) in the low 32 bits (little-endian host order)
			b := (*[4]byte)(unsafe.Pointer(&raw.Data[0]))
			ipBytes = *b
		}
		ip := net.IP(ipBytes[:])
		mask := net.CIDRMask(prefix, 32)
		ipnet := &net.IPNet{IP: ip.Mask(mask), Mask: mask}

		nhRaw := row.NextHop
		var gwBytes [4]byte
		if nhRaw.Family == windows.AF_INET {
			b := (*[4]byte)(unsafe.Pointer(&nhRaw.Data[0]))
			gwBytes = *b
		}
		gw := net.IP(gwBytes[:])
		entries = append(entries, Entry{Dest: ipnet, Gateway: gw, Iface: iface.Name})
	}
	return entries, nil
}
