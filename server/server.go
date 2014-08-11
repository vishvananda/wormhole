package server

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func getSource(dest net.IP) (net.IP, error) {
	var source net.IP
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("Failed to get routes")
	}
	var link *netlink.Link
	for _, route := range routes {
		if route.Dst == nil {
			link = route.Link
			source = route.Src

		} else if route.Dst.Contains(dest) {
			link = route.Link
			source = route.Src
			break
		}
	}
	if link == nil {
		return nil, fmt.Errorf("Failed to find route to target: %s", dest)
	}
	if source == nil {
		// no source in route to target so use the first ip from interface
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("Failed to find source ip for interface: %s", link)
		}
		source = addrs[0].IP
	}
	return source, nil
}

func Main() {
	parseFlags()

	csig := make(chan os.Signal, 1)
	signal.Notify(csig, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-csig
		cleanupSegments()
		cleanupTunnels()
		shutdownAPI()
		os.Exit(0)
	}()

	initTunnels()
	defer cleanupTunnels()

	initSegments()
	defer cleanupSegments()

	serveAPI()
}
