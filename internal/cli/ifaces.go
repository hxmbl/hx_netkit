package cli

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// ifaceInfo describes a capture-capable network interface.
type ifaceInfo struct {
	Name    string
	Addrs   []netip.Prefix
	HasV4   bool
	Private bool // has an RFC1918 address
}

// listIfaces returns up interfaces that have at least one address,
// private-addressed ones first.
func listIfaces() ([]ifaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []ifaceInfo
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		info := ifaceInfo{Name: ifc.Name}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			bits, _ := ipn.Mask.Size()
			ad, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			p := netip.PrefixFrom(ad.Unmap(), bits)
			info.Addrs = append(info.Addrs, p)
			a4 := ad.Unmap()
			if a4.Is4() {
				info.HasV4 = true
				if a4.IsPrivate() {
					info.Private = true
				}
			}
		}
		if len(info.Addrs) > 0 {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Private && !out[j].Private })
	return out, nil
}

func (i ifaceInfo) describe() string {
	parts := []string{i.Name}
	for _, p := range i.Addrs {
		if p.Addr().Is4() || p.Addr().Is4In6() {
			parts = append(parts, p.String())
		}
	}
	return strings.Join(parts, " · ")
}

// suggestTarget derives a /24 CIDR from the interface's private IPv4
// address; empty when no suitable address exists.
func suggestTarget(i ifaceInfo) string {
	for _, p := range i.Addrs {
		if !p.Addr().Is4() || !p.Addr().IsPrivate() {
			continue
		}
		base := netip.PrefixFrom(p.Addr(), 24).Masked()
		return fmt.Sprintf("%s/24", base.Addr())
	}
	return ""
}
