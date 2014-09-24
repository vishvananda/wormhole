package functional

import (
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type Server struct {
	Cmd         *exec.Cmd
	CommandLine string
	Outb        *bytes.Buffer
	Errb        *bytes.Buffer
}

type Context struct {
	t       *testing.T
	Failed  bool
	Servers []Server
	Ns      *netns.NsHandle
}

func addrAdd(t *testing.T, l netlink.Link, a string) {
	addr, err := netlink.ParseAddr(a)
	if err != nil {
		t.Fatal(err)
	}

	err = netlink.AddrAdd(l, addr)
	if err != nil && err != syscall.EEXIST {
		t.Fatal(err)
	}
}

func ensureNetwork(t *testing.T) *netns.NsHandle {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal("Failed to list addresses", err)
	}
	for _, a := range addrs {
		if a.Label == "lo-wormhole" {
			// NOTE(vish): We are already namespaced so just continue. This
			//             means we can leak data between tests if wormhole
			//             doesn't cleanup afeter itself, but it makes the
			//             tests run 5x faster.
			return nil
		}
	}
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		t.Fatal(err)
	}

	addrAdd(t, link, "127.0.0.1/32 lo-wormhole")
	addrAdd(t, link, "127.0.0.2/32")

	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	err = netlink.RouteAdd(&netlink.Route{Link: link, Dst: dst})
	if err != nil {
		t.Fatal(err)
	}
	return &ns
}
func getContext(t *testing.T) *Context {
	runtime.LockOSThread()
	ns := ensureNetwork(t)
	c := &Context{t: t, Ns: ns}
	return c
}

func conditionalClose(ns *netns.NsHandle) {
	if ns != nil && ns.IsOpen() {
		ns.Close()
	}
}

func (c *Context) cleanup() {
	defer runtime.UnlockOSThread()
	defer conditionalClose(c.Ns)
	var wg sync.WaitGroup
	for _, s := range c.Servers {
		err := s.Cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			c.Logf("Failed to terminate %s: %v", s.CommandLine, err)
		}
		done := make(chan error, 1)
		go func(s Server) {
			done <- s.Cmd.Wait()
		}(s)
		wg.Add(1)
		go c.waitExit(s.Cmd, s.CommandLine, done, &wg)
	}
	wg.Wait()
	if c.Failed {
		for _, s := range c.Servers {
			c.Logf("DUMPING PROCESS '%s'", s.CommandLine)
			c.Logf("STDOUT")
			c.Logf(string(s.Outb.Bytes()))
			c.Logf("STDERR")
			c.Logf(string(s.Errb.Bytes()))
		}
	}
}

func (c *Context) waitExit(cmd *exec.Cmd, commandLine string, done chan error, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}
	select {
	case <-time.After(1 * time.Second):
		c.Logf("Killing process %s because it did not exit in time", commandLine)
		err := cmd.Process.Kill()
		if err != nil {
			c.Logf("Failed to kill %s: %v", commandLine, err)
		}
		<-done // allow goroutine to exit
	case err := <-done:
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					signal := status.Signal()
					if signal != syscall.SIGTERM {
						c.Failed = true
						c.Logf("Process %s exited with abnormal signal %d", commandLine, status.Signal())
					}
				} else {
					exitStatus := status.ExitStatus()
					if exitStatus != 0 {
						c.Failed = true
						c.Logf("Process %s exited with abnormal status %d", commandLine, exitStatus)
					}
				}
			}
		} else if err != nil {
			c.Failed = true
			c.Logf("Process %s exited with error %v", commandLine, err)
		}
	}
}

func (c *Context) Fatalf(format string, arg ...interface{}) {
	c.Failed = true
	c.t.Fatalf(format, arg...)
}

func (c *Context) Logf(format string, arg ...interface{}) {
	c.t.Logf(format, arg...)
}

func (c *Context) start(name string, arg ...string) {
	s := Server{}
	s.Cmd = exec.Command(name, arg...)
	s.CommandLine = strings.Join(append([]string{name}, arg...), " ")

	s.Outb = new(bytes.Buffer)
	s.Errb = new(bytes.Buffer)
	s.Cmd.Stdout = s.Outb
	s.Cmd.Stderr = s.Errb

	err := s.Cmd.Start()
	if err != nil {
		c.Fatalf("Error starting %s: %v", s.CommandLine, err)
	}
	c.Servers = append(c.Servers, s)
}

func (c *Context) execute(name string, arg ...string) (string, string) {
	cmd := exec.Command(name, arg...)
	commandLine := strings.Join(append([]string{name}, arg...), " ")

	var err error
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Start()
	if err != nil {
		c.Fatalf("Error starting %s: %v", commandLine, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	c.waitExit(cmd, commandLine, done, nil)
	return string(outb.Bytes()), string(errb.Bytes())
}

func (c *Context) listening(address string) bool {
	network := "tcp"
	parts := strings.SplitN(address, "://", 2)
	if len(parts) == 2 {
		network = parts[0]
		address = parts[1]
	}
	if network != "unix" && !strings.Contains(address, ":") {
		address += ":9999"
	}
	conn, err := net.Dial(network, address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *Context) wait(address string) {
	for i := 0; i < 100; i++ {
		if c.listening(address) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Fatalf("Nothing started listening on '%s'", address)
}

func (c *Context) sendTimeout(msg string, address string) string {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		c.Fatalf("Dial to %s failed: %v", address, err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(msg))
	if err != nil {
		c.Fatalf("Write to server at %s failed: %v", address, err)
	}

	reply := make([]byte, 1024)

	n, err := conn.Read(reply)
	if err != nil {
		c.Fatalf("Read from server at %s failed: %v", address, err)
	}
	return string(reply[:n])
}

func (c *Context) validatePolicy(policy netlink.XfrmPolicy, src string, dst string) {
	if policy.Tmpls[0].Dst.String() != dst || policy.Tmpls[0].Src.String() != src {
		c.Fatalf("Policy src and dst don't match: %v != %v, %v", policy, dst, src)
	}
}

func (c *Context) validateState(state netlink.XfrmState, src string, dst string, udp bool) {
	if state.Dst.String() != dst || state.Src.String() != src {
		c.Fatalf("State src and dst don't match: %v != %v, %v", state, dst, src)
	}
	if udp != (state.Encap != nil) {
		c.Fatalf("Udp and encap don't match: %v != %v", udp, state.Encap != nil)
	}
}

func (c *Context) validateTunnel(udp bool) {
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		c.Fatalf("Failed to get policies: %v", err)
	}
	if len(policies) != 4 {
		c.Fatalf("Wrong number of policies found: %v", policies)
	}
	c.validatePolicy(policies[0], "127.0.0.2", "127.0.0.1")
	c.validatePolicy(policies[1], "127.0.0.1", "127.0.0.2")
	c.validatePolicy(policies[2], "127.0.0.1", "127.0.0.2")
	c.validatePolicy(policies[3], "127.0.0.2", "127.0.0.1")
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		c.Fatalf("Failed to get states: %v", err)
	}
	if len(states) != 2 {
		c.Fatalf("Wrong number of states found: %v", states)
	}
	c.validateState(states[0], "127.0.0.1", "127.0.0.2", udp)
	c.validateState(states[1], "127.0.0.2", "127.0.0.1", udp)
}

func (c *Context) validateNoTunnel() {
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		c.Fatalf("Failed to get policies: %v", err)
	}
	if len(policies) != 0 {
		c.Fatalf("Policies not removed")
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		c.Fatalf("Failed to get states: %v", err)
	}
	if len(states) != 0 {
		c.Fatalf("States not removed")
	}
}

const (
	SERVER = "./wormholed"
	CLIENT = "./wormhole"
	PONG   = "./pong/pong"
)

func TestServerStartTerminate(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER)
	c.wait("")
}

func TestServerStartTerminateOtherPort(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	host := ":6666"
	c.start(SERVER, "-H", host)
	c.wait(host)
}

func TestPing(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER)
	c.wait("")
	stdout, _ := c.execute(CLIENT, "ping")
	pingms, err := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
	if err != nil {
		c.Fatalf("Failed to convert result of ping to float: %v", stdout)
	}
	if pingms > 10.0 {
		c.Fatalf("Ping took too long: %v", pingms)
	}
}

func TestPingUnix(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	host := "unix://./socket"
	c.start(SERVER, "-H", host)
	c.wait(host)
	stdout, _ := c.execute(CLIENT, "-H", host, "ping")
	pingms, err := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
	if err != nil {
		c.Fatalf("Failed to convert result of ping to float: %v", stdout)
	}
	if pingms > 10.0 {
		c.Fatalf("Ping took too long: %v", pingms)
	}
}

func TestPingRemote(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER)
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host)
	c.wait(host)
	stdout, _ := c.execute(CLIENT, "ping", host)
	pingms, err := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
	if err != nil {
		c.Fatalf("Failed to convert result of ping to float: %v", stdout)
	}
	if pingms > 10.0 {
		c.Fatalf("Ping took too long: %v", pingms)
	}
}

func TestTunnel(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER, "-I", "127.0.0.1")
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host, "-I", "127.0.0.2")
	c.wait(host)
	c.execute(CLIENT, "tunnel-create", ":6666")
	c.validateTunnel(false)
	c.execute(CLIENT, "tunnel-delete", ":6666")
	c.validateNoTunnel()
}

func TestTunnelDoubleCreate(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER, "-I", "127.0.0.1")
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host, "-I", "127.0.0.2")
	c.wait(host)
	stdout1, _ := c.execute(CLIENT, "tunnel-create", ":6666")
	stdout2, _ := c.execute(CLIENT, "tunnel-create", ":6666")
	if stdout1 != stdout2 {
		c.Fatalf("Second tunnel create retuned new result: %s != %s", stdout1, stdout2)
	}
	c.validateTunnel(false)
	c.execute(CLIENT, "tunnel-delete", ":6666")
	c.validateNoTunnel()
}

func TestTunnelUdp(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER, "-I", "127.0.0.1")
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host, "-I", "127.0.0.2")
	c.wait(host)
	c.execute(CLIENT, "tunnel-create", "--udp", ":6666")
	c.validateTunnel(true)
	c.execute(CLIENT, "tunnel-delete", ":6666")
	c.validateNoTunnel()
}

func TestCreateDelete(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER)
	c.wait("")
	stdout, _ := c.execute(CLIENT, "create", "url", ":9000", "tail", "url", ":9001")
	parts := strings.Fields(strings.TrimSpace(stdout))
	if len(parts) != 2 {
		c.Fatalf("Bad data returned from create: %s", stdout)
	}
	id := parts[0]
	if !c.listening(":9000") {
		c.Fatalf("Segment is not listening")
	}
	c.execute(CLIENT, "delete", id)
	if c.listening(":9000") {
		c.Fatalf("Segment is still listening")
	}
}

func TestDockerRun(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER)
	c.wait("")
	c.execute(CLIENT, "create", "url", ":9000", "tail", "url", ":9001", "docker-run", "wormhole/pong")
	msg := "ping"
	result := c.sendTimeout(msg, ":9000")
	if result != msg {
		c.Fatalf("Incorrect response from ping: %s != %s", result, msg)
	}
}

func TestChain(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER)
	c.wait("")
	c.execute(CLIENT, "create", "url", ":9000", "chain", "url", ":9001", "tail", "url", ":9002")
	c.start(PONG, ":9002")
	msg := "ping"
	result := c.sendTimeout(msg, ":9000")
	if result != msg {
		c.Fatalf("Incorrect response from ping: %s != %s", result, msg)
	}
}

func TestRemote(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER, "-I", "127.0.0.1")
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host, "-I", "127.0.0.2")
	c.wait(host)
	c.execute(CLIENT, "create", "url", ":9000", "remote", ":6666", "url", ":9001", "tail", "url", ":9002")
	c.start(PONG, ":9002")
	msg := "ping"
	result := c.sendTimeout(msg, ":9000")
	if result != msg {
		c.Fatalf("Incorrect response from ping: %s != %s", result, msg)
	}
}

func TestRemoteTunnel(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER, "-I", "127.0.0.1")
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host, "-I", "127.0.0.2")
	c.wait(host)
	c.execute(CLIENT, "create", "url", ":9000", "tunnel", ":6666", "url", ":9001", "tail", "url", ":9002")
	c.start(PONG, ":9002")
	msg := "ping"
	result := c.sendTimeout(msg, ":9000")
	if result != msg {
		c.Fatalf("Incorrect response from ping: %s != %s", result, msg)
	}
	c.validateTunnel(false)
	c.execute(CLIENT, "tunnel-delete", ":6666")
	c.validateNoTunnel()
}

func TestRemoteUdptunnel(t *testing.T) {
	c := getContext(t)
	defer c.cleanup()
	c.start(SERVER, "-I", "127.0.0.1")
	c.wait("")
	host := ":6666"
	c.start(SERVER, "-H", host, "-I", "127.0.0.2")
	c.wait(host)
	c.execute(CLIENT, "create", "url", ":9000", "udptunnel", ":6666", "url", ":9001", "tail", "url", ":9002")
	c.start(PONG, ":9002")
	msg := "ping"
	result := c.sendTimeout(msg, ":9000")
	if result != msg {
		c.Fatalf("Incorrect response from ping: %s != %s", result, msg)
	}
	c.validateTunnel(true)
	c.execute(CLIENT, "tunnel-delete", ":6666")
	c.validateNoTunnel()
}
