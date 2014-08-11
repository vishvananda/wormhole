package server

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/vishvananda/netns"
	"github.com/vishvananda/wormhole/client"
	"github.com/vishvananda/wormhole/pkg/proxy"
	"github.com/vishvananda/wormhole/utils"
)

var segmentsMutex sync.Mutex
var segments map[string]*Segment

func initSegments() {
	segments = make(map[string]*Segment)
}

func cleanupSegments() {
	for id, s := range segments {
		glog.Infof("Cleaning segment %s", id)
		s.Cleanup()
		glog.Infof("Finished cleaning segment %s", id)
	}
	segmentsMutex.Lock()
	defer segmentsMutex.Unlock()
	for id, _ := range segments {
		glog.Infof("Deleting segment %s", id)
		delete(segments, id)
		glog.Infof("Finished deleting segment %s", id)
	}
}

func addSegment(key string, segment *Segment) {
	segmentsMutex.Lock()
	defer segmentsMutex.Unlock()
	segments[key] = segment
}

func getSegment(key string) *Segment {
	return segments[key]
}

func removeSegment(key string) {
	segmentsMutex.Lock()
	defer segmentsMutex.Unlock()
	delete(segments, key)
}

type ConnectionInfo struct {
	Proto    string
	Ns       netns.NsHandle
	Hostname string
	Port     int
}

type Segment struct {
	Head      ConnectionInfo
	Tail      ConnectionInfo
	Init      []client.SegmentCommand
	Trig      []client.SegmentCommand
	ChildHost string
	ChildId   string
	Proxy     *proxy.Proxier
	DockerIds []string
}

func (s Segment) String() string {
	var initstring, trigstring string
	for _, a := range s.Init {
		initstring += fmt.Sprintf("%s: %v ", client.CommandName[a.Type], a)
	}
	for _, a := range s.Trig {
		trigstring += fmt.Sprintf("%s: %v ", client.CommandName[a.Type], a)
	}
	return fmt.Sprintf("{%v %v [%s] [%s]}", s.Head, s.Tail, strings.TrimSpace(initstring), strings.TrimSpace(trigstring))
}

func (s *Segment) Cleanup() {
	if s.Proxy != nil {
		s.Proxy.StopProxy("segment")
		s.Proxy = nil
	}
	if s.ChildId != "" {
		if s.ChildHost == "" {
			deleteSegment(s.ChildId)
		} else {
			c, err := client.NewClient(s.ChildHost, opts.config)
			if err != nil {
				glog.Errorf("Failed to connect to child host at %s: %v", s.ChildHost, err)
			} else {
				c.DeleteSegment(s.ChildId)
			}
		}
	}
	if len(s.DockerIds) != 0 {
		args := []string{"rm", "-f"}
		args = append(args, s.DockerIds...)
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			glog.Errorf("Error deleting docker container %v: %s", err, out)
		}
	}
	if s.Head.Ns.IsOpen() {
		s.Head.Ns.Close()
	}
	if s.Tail.Ns.IsOpen() {
		s.Tail.Ns.Close()
	}
}

func NewSegment() *Segment {
	return &Segment{Head: ConnectionInfo{Ns: netns.None()}, Tail: ConnectionInfo{Ns: netns.None()}}
}

func createSegment(id string, init []client.SegmentCommand, trig []client.SegmentCommand) (string, error) {
	cinfo, err := createSegmentLocal(id, init, trig, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s:%d", cinfo.Proto, cinfo.Hostname, cinfo.Port), nil
}

func createSegmentLocal(id string, init []client.SegmentCommand, trig []client.SegmentCommand, cinfo *ConnectionInfo) (*ConnectionInfo, error) {
	exists := getSegment(id)
	if exists != nil {
		return nil, fmt.Errorf("Segment %s already exists", id)
	}
	glog.Infof("Creating segment %s", id)
	s := NewSegment()
	if cinfo != nil {
		s.Head = *cinfo
	}
	s.Init = init
	s.Trig = trig
	err := s.Initialize()
	if err != nil {
		return nil, err
	}
	s.Proxy = proxy.NewProxier(s, s.Head.Hostname)
	s.Proxy.SetNs(s.Head.Ns)
	s.Head.Port, err = s.Proxy.AddService("segment", s.Head.Proto, s.Head.Port)
	if err != nil {
		return nil, err
	}
	addSegment(id, s)
	glog.Infof("Finished creating segment %s", id)
	return &s.Head, nil
}

func deleteSegment(id string) error {
	glog.Infof("Deleting segment %s", id)
	s := getSegment(id)
	if s != nil {
		s.Cleanup()
	}
	removeSegment(id)
	glog.Infof("Finished deleting segment %s", id)
	return nil
}

func executeCommands(commands *[]client.SegmentCommand, seg *Segment) error {
	// Range is not used to skip a copy
	for i := 0; i < len(*commands); i++ {
		var err error
		switch (*commands)[i].Type {
		case client.NONE:
		case client.DOCKER_NS:
			err = executeDockerNs(&(*commands)[i], seg)
		case client.DOCKER_RUN:
			err = executeDockerRun(&(*commands)[i], seg)
		case client.CHILD:
			err = executeChild(&(*commands)[i], seg, false)
		case client.CHAIN:
			err = executeChild(&(*commands)[i], seg, true)
		case client.REMOTE:
			err = executeRemote(&(*commands)[i], seg)
		case client.TUNNEL:
			err = executeTunnel(&(*commands)[i], seg, false)
		case client.UDPTUNNEL:
			err = executeTunnel(&(*commands)[i], seg, true)
		case client.URL:
			err = executeUrl(&(*commands)[i], seg)
		default:
			err = fmt.Errorf("Command type %d recognized", (*commands)[i].Type)
		}
		if err != nil {
			return err
		}
	}
	*commands = make([]client.SegmentCommand, 0)
	return nil
}

func (s *Segment) Initialize() error {
	err := executeCommands(&s.Init, s)
	if err != nil {
		return err
	}
	// Head proto defaults to tcp if not set
	if s.Head.Proto == "" {
		s.Head.Proto = "tcp"
	}
	if s.Head.Hostname == "" {
		s.Head.Hostname = "127.0.0.1"
	}
	return nil
}

func hostEqual(proto string, h1 string, h2 string) bool {
	// TODO: check all local addresses if h1 is 0.0.0.0
	if h1 == h2 {
		return true
	}
	if proto[:3] == "udp" {
		a1, err := net.ResolveUDPAddr(proto, h1)
		if err != nil {
			return false
		}
		a2, err := net.ResolveUDPAddr(proto, h2)
		if err != nil {
			return false
		}
		return a1.IP.Equal(a2.IP) && a1.Zone == a2.Zone && a1.Port == a2.Port
	} else if proto[:3] == "tcp" {
		a1, err := net.ResolveTCPAddr(proto, h1)
		if err != nil {
			return false
		}
		a2, err := net.ResolveTCPAddr(proto, h2)
		if err != nil {
			return false
		}
		return a1.IP.Equal(a2.IP) && a1.Zone == a2.Zone && a1.Port == a2.Port
	}
	return false
}

func (s *Segment) Trigger() error {
	err := executeCommands(&s.Trig, s)
	if err != nil {
		return err
	}
	// Tail proto defaults to Head proto if not set
	if s.Tail.Proto == "" {
		s.Tail.Proto = s.Head.Proto
	}
	if s.Tail.Hostname == "" {
		s.Tail.Hostname = "127.0.0.1"
	}
	// Tail port defaults to Head port if not set
	if s.Tail.Port == 0 {
		s.Tail.Port = s.Head.Port
	}
	host1 := net.JoinHostPort(s.Head.Hostname, strconv.Itoa(s.Head.Port))
	host2 := net.JoinHostPort(s.Tail.Hostname, strconv.Itoa(s.Tail.Port))

	if hostEqual(s.Head.Proto, host1, host2) && s.Head.Ns.Equal(s.Tail.Ns) {
		return fmt.Errorf("Cannot proxy to self")
	}
	return nil
}

// NextEndpoint is an implementation of the loadbalancer interface for proxy.
func (s *Segment) NextEndpoint(service string, srcAddr net.Addr) (netns.NsHandle, string, error) {
	err := s.Trigger()
	if err != nil {
		return netns.None(), "", err
	}
	host := net.JoinHostPort(s.Tail.Hostname, strconv.Itoa(s.Tail.Port))
	return s.Tail.Ns, host, nil
}

func executeUrl(command *client.SegmentCommand, seg *Segment) error {
	ci := &seg.Head
	if command.Tail {
		ci = &seg.Tail
	}
	proto, ns, hostname, port, err := utils.ParseUrl(command.Arg)
	if err != nil {
		return err
	}
	if proto != "" {
		ci.Proto = proto
	}
	if ns != "" {
		var err error
		ci.Ns, err = netns.GetFromName(ns)
		if err != nil {
			return err
		}
	}
	if hostname != "" {
		ci.Hostname = hostname
	}
	if port != 0 {
		ci.Port = port
	}
	return nil
}

func executeDockerNs(command *client.SegmentCommand, seg *Segment) error {
	ci := &seg.Head
	if command.Tail {
		ci = &seg.Tail
	}
	var err error
	ci.Ns, err = netns.GetFromDocker(command.Arg)
	return err
}

func executeDockerRun(command *client.SegmentCommand, seg *Segment) error {
	ci := &seg.Head
	if command.Tail {
		ci = &seg.Tail
	}
	args := strings.Fields(command.Arg)
	// TODO: use the api here instead of shelling out
	args = append([]string{"run", "-d"}, args...)
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(out))
	seg.DockerIds = append(seg.DockerIds, id)

	ci.Ns, err = netns.GetFromDocker(id)
	return err
}

func executeChild(command *client.SegmentCommand, seg *Segment, chain bool) error {
	id := utils.Uuid()
	cinfo, err := createSegmentLocal(id, command.ChildInit, command.ChildTrig, &seg.Tail)
	if err != nil {
		return err
	}
	if chain {
		seg.Tail = *cinfo
	}
	seg.ChildId = id
	return nil
}

func executeRemote(command *client.SegmentCommand, seg *Segment) error {
	c, err := client.NewClient(command.Arg, opts.config)
	if err != nil {
		return err
	}
	dst, err := c.GetSrcIP(opts.src)
	if err != nil {
		return err
	}
	urlCommand := client.SegmentCommand{Type: client.URL, Arg: dst.String()}
	command.ChildInit = append(command.ChildInit, urlCommand)
	id := utils.Uuid()
	url, err := c.CreateSegment(id, command.ChildInit, command.ChildTrig)
	if err != nil {
		return err
	}
	seg.Tail.Proto, _, seg.Tail.Hostname, seg.Tail.Port, err = utils.ParseUrl(url)
	if err != nil {
		return err
	}
	seg.ChildHost = command.Arg
	seg.ChildId = id
	return nil
}

func executeTunnel(command *client.SegmentCommand, seg *Segment, udp bool) error {
	_, dst, err := createTunnel(command.Arg, udp)
	if err != nil {
		return err
	}
	urlCommand := client.SegmentCommand{Type: client.URL, Arg: dst.String()}
	command.ChildInit = append(command.ChildInit, urlCommand)
	c, err := client.NewClient(command.Arg, opts.config)
	if err != nil {
		return err
	}
	id := utils.Uuid()
	url, err := c.CreateSegment(id, command.ChildInit, command.ChildTrig)
	if err != nil {
		return err
	}
	seg.Tail.Proto, _, seg.Tail.Hostname, seg.Tail.Port, err = utils.ParseUrl(url)
	if err != nil {
		return err
	}
	seg.ChildHost = command.Arg
	seg.ChildId = id
	return nil
}
