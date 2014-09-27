package server

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"syscall"

	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/wormhole/client"
	"github.com/vishvananda/wormhole/pkg/netaddr"
)

var tunnelsMutex sync.Mutex
var tunnels map[string]*client.Tunnel
var listeners map[string]int

var usedIPsMutex sync.Mutex
var usedIPs map[string]bool

var unusedPortsMutex sync.Mutex
var unusedPorts []int

type IPInUse error
type NoPortsAvailable error

func initTunnels() {
	tunnels = make(map[string]*client.Tunnel)
	listeners = make(map[string]int)
	usedIPs = make(map[string]bool)
	for p := opts.udpStartPort; p <= opts.udpEndPort; p++ {
		unusedPorts = append(unusedPorts, p)
	}
	discoverTunnels()
}

func cleanupTunnels() {
	// Currently we leave tunnels in place
}

func addTunnel(key string, tunnel *client.Tunnel, listener int) {
	tunnelsMutex.Lock()
	defer tunnelsMutex.Unlock()
	tunnels[key] = tunnel
	listeners[key] = listener
}

func getTunnel(key string) *client.Tunnel {
	return tunnels[key]
}

func getListener(key string) int {
	return listeners[key]
}

func removeTunnel(key string) {
	tunnelsMutex.Lock()
	defer tunnelsMutex.Unlock()
	delete(tunnels, key)
	delete(listeners, key)
}

func reserveIP(ip net.IP) error {
	usedIPsMutex.Lock()
	defer usedIPsMutex.Unlock()
	ipStr := ip.String()
	exists := usedIPs[ipStr]
	if exists {
		return IPInUse(fmt.Errorf("IP %s is in use", ip))
	}
	usedIPs[ipStr] = true
	return nil
}

func unreserveIP(ip net.IP) {
	usedIPsMutex.Lock()
	defer usedIPsMutex.Unlock()
	delete(usedIPs, ip.String())
}

func allocatePort() (int, error) {
	unusedPortsMutex.Lock()
	defer unusedPortsMutex.Unlock()

	if len(unusedPorts) == 0 {
		return 0, NoPortsAvailable(fmt.Errorf("No ports available"))
	}
	var port int
	port, unusedPorts = unusedPorts[0], unusedPorts[1:]
	return port, nil
}

func releasePort(port int) {
	unusedPortsMutex.Lock()
	defer unusedPortsMutex.Unlock()
	unusedPorts = append(unusedPorts, port)
}

func discoverTunnels() {
	glog.Infof("Discovering existing tunnels")
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		glog.Errorf("Failed to get loopback device: %v", err)
		return
	}
	addrs, err := netlink.AddrList(lo, netlink.FAMILY_ALL)
	if err != nil {
		glog.Errorf("Failed to get addrs: %v", err)
		return
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		glog.Errorf("Failed to get routes: %v", err)
		return
	}
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		glog.Errorf("Failed to get xfrm policies: %v", err)
		return
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		glog.Errorf("Failed to get xfrm states: %v", err)
		return
	}
	for _, addr := range addrs {
		if opts.cidr.Contains(addr.IP) {
			tunnel := client.Tunnel{}
			tunnel.Src = addr.IP
			err := reserveIP(tunnel.Src)
			if err != nil {
				glog.Warningf("Duplicate tunnel ip detected: %v", tunnel.Src)
			}
			tunnel.Dst = nil
			glog.Infof("Potential tunnel found from %s", tunnel.Src)
			for _, route := range routes {
				if route.Src == nil || !route.Src.Equal(tunnel.Src) {
					continue
				}
				tunnel.Dst = route.Dst.IP
				break
			}
			if tunnel.Dst == nil {
				glog.Warningf("could not find dst for tunnel src %s", tunnel.Src)
				continue
			}
			err = reserveIP(tunnel.Dst)
			if err != nil {
				glog.Warningf("Duplicate tunnel ip detected: %v", tunnel.Dst)
			}
			var dst net.IP
			for _, policy := range policies {
				if !policy.Dst.IP.Equal(tunnel.Dst) {
					continue
				}
				if len(policy.Tmpls) == 0 {
					glog.Warningf("Tunnel policy has no associated template")
					continue
				}
				dst = policy.Tmpls[0].Dst
				break
			}
			if dst == nil {
				glog.Warningf("could not find ip for tunnel between %s and %s", tunnel.Src, tunnel.Dst)
				continue
			}
			for _, state := range states {
				if !state.Dst.Equal(dst) {
					continue
				}
				tunnel.Reqid = state.Reqid
				if state.Auth == nil {
					glog.Warningf("Tunnel state has no associated authentication entry")
					continue
				}
				tunnel.AuthKey = state.Auth.Key
				if state.Crypt == nil {
					glog.Warningf("Tunnel state has no associated encryption entry")
					continue
				}
				tunnel.EncKey = state.Crypt.Key
				if state.Encap != nil {
					tunnel.SrcPort = state.Encap.SrcPort
					tunnel.SrcPort = state.Encap.DstPort
				}
				glog.Infof("Discovered tunnel between %v and %v over %v", tunnel.Src, tunnel.Dst, dst)
				var socket int
				if tunnel.SrcPort != 0 {
					socket, err = createEncapListener(tunnel.Src, tunnel.SrcPort)
					if err != nil {
						glog.Warningf("Failed to create udp listener: %v", err)
					}
				}
				addTunnel(dst.String(), &tunnel, socket)
				break
			}
		}
	}
	glog.Infof("Finished discovering existing tunnels")
}

func getLink(ip net.IP) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("Failed to get links")
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("Failed to get addrs")
		}
		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("Could not find address")
}

func getSrcIP(dst net.IP) (net.IP, error) {
	if dst == nil {
		return opts.external, nil
	}
	tunnel := getTunnel(dst.String())
	if tunnel == nil {
		return opts.src, nil
	} else {
		return tunnel.Src, nil
	}
}

func randomIPPair(cidr *net.IPNet) (first net.IP, second net.IP, err error) {
	ones, total := cidr.Mask.Size()
	max := int64((1 << uint64(total-ones-1)))
	value, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return
	}
	first = netaddr.IPAdd(cidr.IP, value.Uint64()*2+1)
	second = netaddr.IPAdd(first, 1)
	return
}

func randomKey() []byte {
	value := make([]byte, 32)
	rand.Read(value)
	return value
}

func getUnusedPort() int {
	// TODO: use a port range
	return 4500
}

func createTunnel(host string, udp bool) (net.IP, net.IP, error) {
	c, err := client.NewClient(host, opts.config)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()

	dst, err := c.GetSrcIP(nil)

	tunnel := &client.Tunnel{}

	exists := getTunnel(dst.String())
	if exists != nil {
		glog.Infof("Tunnel already exists: %v, %v", exists.Src, exists.Dst)
		// tunnel dst and src are reversed from remote
		tunnel.Reqid = exists.Reqid
		tunnel.Src = exists.Dst
		tunnel.Dst = exists.Src
		tunnel.AuthKey = exists.AuthKey
		tunnel.EncKey = exists.EncKey
		tunnel.SrcPort = exists.DstPort
		tunnel.SrcPort = exists.SrcPort
	} else {
		tunnel = &client.Tunnel{}
		if udp {
			var err error
			tunnel.DstPort, err = allocatePort()
			if err != nil {
				glog.Errorf("No ports available: %v", dst)
				return nil, nil, err
			}
			glog.Infof("Using %d for encap port", tunnel.DstPort)
		}

		tunnel.AuthKey = randomKey()
		tunnel.EncKey = randomKey()
		// random number between 1 and 2^32
		bigreq, err := rand.Int(rand.Reader, big.NewInt(int64(^uint32(0))))
		if err != nil {
			glog.Errorf("Failed to generate reqid: %v", err)
			return nil, nil, err
		}
		tunnel.Reqid = int(bigreq.Int64()) + 1
	}

	// While tail not created
	for {
		if tunnel.Src == nil {
			// Select random pair of addresses from cidr
			for {
				tunnel.Dst, tunnel.Src, err = randomIPPair(opts.cidr)
				if err != nil {
					return nil, nil, err
				}
				err = reserveIP(tunnel.Dst)
				if err != nil {
					glog.Infof("IP in use: %v", tunnel.Dst)
					continue
				}
				err = reserveIP(tunnel.Src)
				if err != nil {
					unreserveIP(tunnel.Dst)
					glog.Infof("IP in use: %v", tunnel.Src)
					continue
				}
				break
			}
		}
		// create tail of tunnel
		var out *client.Tunnel
		dst, out, err = c.BuildTunnel(opts.external, tunnel)
		if err != nil {
			_, ok := err.(IPInUse)
			if ok {
				unreserveIP(tunnel.Dst)
				unreserveIP(tunnel.Src)
				tunnel.Src = nil
				if exists != nil {
					glog.Warningf("Destroying local tunnel due to remote ip conflict")
					destroyTunnel(dst)
					exists = nil
				}
				continue
			}
			glog.Errorf("Remote BuildTunnel failed: %v", err)
			// cleanup partial tunnel
			c.DestroyTunnel(opts.external)
			return nil, nil, err
		}
		if exists != nil && !out.Equal(tunnel) {
			glog.Warningf("Destroying remote mismatched tunnel")
			c.DestroyTunnel(opts.external)
			continue
		}
		tunnel = out
		break
	}

	// tunnel dst and src are reversed from remote
	tunnel.Src, tunnel.Dst = tunnel.Dst, tunnel.Src
	tunnel.SrcPort, tunnel.DstPort = tunnel.DstPort, tunnel.SrcPort
	if exists == nil {
		_, tunnel, err = buildTunnelLocal(dst, tunnel)
		if err != nil {
			glog.Errorf("Local buildTunnel failed: %v", err)
			c.DestroyTunnel(opts.external)
			destroyTunnel(dst)
			return nil, nil, err
		}
	}
	return tunnel.Src, tunnel.Dst, nil
}

func deleteTunnel(host string) error {
	c, err := client.NewClient(host, opts.config)
	if err != nil {
		return err
	}
	defer c.Close()

	dst, _ := c.DestroyTunnel(opts.external)
	if dst != nil {
		destroyTunnel(dst)
	}
	return nil
}

func createEncapListener(ip net.IP, port int) (int, error) {
	const (
		UDP_ENCAP          = 100
		UDP_ENCAP_ESPINUDP = 2
	)
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	err = syscall.SetsockoptInt(s, syscall.IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
	if err != nil {
		return 0, err
	}
	var family int
	if len(ip) <= net.IPv4len {
		family = syscall.AF_INET
	} else if ip.To4() != nil {
		family = syscall.AF_INET
	} else {
		family = syscall.AF_INET6
	}
	var bindaddr syscall.Sockaddr
	switch family {
	case syscall.AF_INET:
		if len(ip) == 0 {
			ip = net.IPv4zero
		}
		sa := new(syscall.SockaddrInet4)
		for i := 0; i < net.IPv4len; i++ {
			sa.Addr[i] = ip[i]
		}
		sa.Port = port
		bindaddr = sa
	case syscall.AF_INET6:
		sa := new(syscall.SockaddrInet6)
		for i := 0; i < net.IPv6len; i++ {
			sa.Addr[i] = ip[i]
		}
		sa.Port = port
		// TODO: optionally allow zone for ipv6
		// sa.ZoneId = uint32(zoneToInt(zone))
		bindaddr = sa
	}
	err = syscall.Bind(s, bindaddr)
	if err != nil {
		return 0, err
	}
	return s, nil
}

func deleteEncapListener(socket int) {
	err := syscall.Close(socket)
	if err != nil {
		glog.Warningf("Failed to delete tunnel udp listener: %v", err)
	}
}

func buildTunnel(dst net.IP, tunnel *client.Tunnel) (net.IP, *client.Tunnel, error) {
	exists := getTunnel(dst.String())
	if exists != nil {
		glog.Infof("Tunnel already exists: %v, %v", exists.Src, exists.Dst)
		return opts.external, exists, nil
	}
	var err error
	if tunnel.DstPort != 0 {
		tunnel.SrcPort, err = allocatePort()
		if err != nil {
			glog.Errorf("No ports available: %v", tunnel.Dst)
			return nil, nil, err
		}
	}
	err = reserveIP(tunnel.Dst)
	if err != nil {
		glog.Infof("IP in use: %v", tunnel.Dst)
		return nil, nil, err
	}
	err = reserveIP(tunnel.Src)
	if err != nil {
		unreserveIP(tunnel.Dst)
		glog.Infof("IP in use: %v", tunnel.Src)
		return nil, nil, err
	}
	return buildTunnelLocal(dst, tunnel)
}

func buildTunnelLocal(dst net.IP, tunnel *client.Tunnel) (net.IP, *client.Tunnel, error) {
	var socket int
	if tunnel.SrcPort != 0 {
		var err error
		socket, err = createEncapListener(tunnel.Src, tunnel.SrcPort)
		if err != nil {
			glog.Errorf("Failed to create udp listener: %v", err)
			return nil, nil, err
		}
	}
	addTunnel(dst.String(), tunnel, socket)

	src := opts.src

	srcNet := netlink.NewIPNet(tunnel.Src)
	dstNet := netlink.NewIPNet(tunnel.Dst)

	glog.Infof("Building tunnel: %v, %v", tunnel.Src, tunnel.Dst)
	// add IP address to loopback device
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		glog.Errorf("Failed to get loopback device: %v", err)
		return nil, nil, err
	}
	err = netlink.AddrAdd(lo, &netlink.Addr{IPNet: srcNet})
	if err != nil {
		glog.Errorf("Failed to add %v to loopback: %v", tunnel.Src, err)
		return nil, nil, err
	}

	link, err := getLink(src)
	if err != nil {
		glog.Errorf("Failed to get link for address: %v", err)
		return nil, nil, err
	}
	// add source route to tunnel ips device
	route := &netlink.Route{
		Scope: netlink.SCOPE_LINK,
		Src:   tunnel.Src,
		Dst:   dstNet,
		Link:  link,
	}
	err = netlink.RouteAdd(route)
	if err != nil {
		glog.Errorf("Failed to add route %v: %v", route, err)
		return nil, nil, err
	}

	for _, policy := range getPolicies(tunnel.Reqid, src, dst, srcNet, dstNet) {
		glog.Infof("building Policy: %v", policy)
		// create xfrm policy rules
		err = netlink.XfrmPolicyAdd(&policy)
		if err != nil {
			if err == syscall.EEXIST {
				glog.Infof("Skipped adding policy %v because it already exists", policy)
			} else {
				glog.Errorf("Failed to add policy %v: %v", policy, err)
				return nil, nil, err
			}
		}
	}
	for _, state := range getStates(tunnel.Reqid, src, dst, tunnel.SrcPort, tunnel.DstPort, tunnel.AuthKey, tunnel.EncKey) {
		glog.Infof("building State: %v", state)
		// crate xfrm state rules
		err = netlink.XfrmStateAdd(&state)
		if err != nil {
			if err == syscall.EEXIST {
				glog.Infof("Skipped adding state %v because it already exists", state)
			} else {
				glog.Errorf("Failed to add state %v: %v", state, err)
				return nil, nil, err
			}
		}
	}
	glog.Infof("Finished building tunnel: %v, %v", tunnel.Src, tunnel.Dst)
	return opts.external, tunnel, nil
}

func destroyTunnel(dst net.IP) (net.IP, error) {
	// Determine the src and dst ips for the tunnel
	key := dst.String()
	tunnel := getTunnel(dst.String())
	if tunnel == nil {
		s := fmt.Sprintf("Failed to find tunnel to dst %s", dst)
		glog.Errorf(s)
		return nil, fmt.Errorf(s)
	}

	src := opts.external

	srcNet := netlink.NewIPNet(tunnel.Src)
	dstNet := netlink.NewIPNet(tunnel.Dst)

	glog.Infof("Destroying Tunnel: %v, %v", tunnel.Src, tunnel.Dst)

	for _, state := range getStates(tunnel.Reqid, src, dst, 0, 0, nil, nil) {
		// crate xfrm state rules
		err := netlink.XfrmStateDel(&state)
		if err != nil {
			glog.Errorf("Failed to delete state %v: %v", state, err)
		}
	}

	for _, policy := range getPolicies(tunnel.Reqid, src, dst, srcNet, dstNet) {
		// create xfrm policy rules
		err := netlink.XfrmPolicyDel(&policy)
		if err != nil {
			glog.Errorf("Failed to delete policy %v: %v", policy, err)
		}
	}

	link, err := getLink(src)
	if err != nil {
		glog.Errorf("Failed to get link for address: %v", err)
	} else {

		// del source route to tunnel ips device
		route := &netlink.Route{
			Scope: netlink.SCOPE_LINK,
			Src:   tunnel.Src,
			Dst:   dstNet,
			Link:  link,
		}
		err = netlink.RouteDel(route)
		if err != nil {
			glog.Errorf("Failed to delete route %v: %v", route, err)
		}
	}

	// del IP address to loopback device
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		glog.Errorf("Failed to get loopback device: %v", err)
	} else {
		err = netlink.AddrDel(lo, &netlink.Addr{IPNet: srcNet})
		if err != nil {
			glog.Errorf("Failed to delete %v from loopback: %v", tunnel.Src, err)
		}
	}
	if tunnel.SrcPort != 0 {
		deleteEncapListener(getListener(key))
		releasePort(tunnel.SrcPort)
	}
	unreserveIP(tunnel.Src)
	unreserveIP(tunnel.Dst)
	removeTunnel(key)
	glog.Infof("Finished destroying tunnel: %v, %v", tunnel.Src, tunnel.Dst)
	return src, nil
}

func getPolicies(reqid int, src net.IP, dst net.IP, srcNet *net.IPNet, dstNet *net.IPNet) []netlink.XfrmPolicy {
	policies := make([]netlink.XfrmPolicy, 0)
	out := netlink.XfrmPolicy{
		Src: srcNet,
		Dst: dstNet,
		Dir: netlink.XFRM_DIR_OUT,
	}
	otmpl := netlink.XfrmPolicyTmpl{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Reqid: reqid,
	}
	out.Tmpls = append(out.Tmpls, otmpl)
	policies = append(policies, out)
	in := netlink.XfrmPolicy{
		Src: dstNet,
		Dst: srcNet,
		Dir: netlink.XFRM_DIR_IN,
	}
	itmpl := netlink.XfrmPolicyTmpl{
		Src:   dst,
		Dst:   src,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Reqid: reqid,
	}
	in.Tmpls = append(in.Tmpls, itmpl)
	policies = append(policies, in)
	return policies
}

func getStates(reqid int, src net.IP, dst net.IP, srcPort int, dstPort int, authKey []byte, encKey []byte) []netlink.XfrmState {
	states := make([]netlink.XfrmState, 0)
	out := netlink.XfrmState{
		Src:          src,
		Dst:          dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          reqid,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha256)",
			Key:  authKey,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  encKey,
		},
	}
	if srcPort != 0 && dstPort != 0 {
		out.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
	}
	states = append(states, out)
	in := netlink.XfrmState{
		Src:          dst,
		Dst:          src,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          reqid,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha256)",
			Key:  authKey,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  encKey,
		},
	}
	if srcPort != 0 && dstPort != 0 {
		in.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: dstPort,
			DstPort: srcPort,
		}
	}
	states = append(states, in)
	return states
}
