package client

import (
	"bytes"
	"github.com/raff/tls-ext"
	"github.com/vishvananda/wormhole/utils"
	"net"
	"net/rpc"
)

const (
	NONE       = iota
	URL        = iota
	DOCKER_NS  = iota
	DOCKER_RUN = iota
	CHILD      = iota
	CHAIN      = iota
	REMOTE     = iota
	TUNNEL     = iota
	UDPTUNNEL  = iota
)

var CommandName = []string{
	NONE:       "none",
	DOCKER_NS:  "docker-ns",
	DOCKER_RUN: "docker-run",
	CHILD:      "child",
	CHAIN:      "chain",
	REMOTE:     "remote",
	TUNNEL:     "tunnel",
	URL:        "url",
}

type SegmentCommand struct {
	Type      int
	Tail      bool
	Arg       string
	ChildInit []SegmentCommand
	ChildTrig []SegmentCommand
}

type Tunnel struct {
	Reqid   int
	AuthKey []byte
	EncKey  []byte
	Src     net.IP
	Dst     net.IP
	SrcPort int
	DstPort int
}

func (t Tunnel) Equal(o *Tunnel) bool {
	return t.Reqid == o.Reqid && bytes.Equal(t.AuthKey, o.AuthKey) && bytes.Equal(t.EncKey, o.EncKey) && t.Src.Equal(o.Src) && t.Dst.Equal(o.Dst) && t.SrcPort == o.SrcPort && t.DstPort == o.DstPort
}

func (s *SegmentCommand) AddInit(c *SegmentCommand) {
	s.ChildInit = append(s.ChildInit, *c)
}

func (s *SegmentCommand) AddTrig(c *SegmentCommand) {
	s.ChildTrig = append(s.ChildTrig, *c)
}

type Client struct {
	RpcClient *rpc.Client
}

func NewClient(host string, config *tls.Config) (*Client, error) {
	proto, address := utils.ParseAddr(host)
	conn, err := tls.Dial(proto, address, config)
	if err != nil {
		return nil, err
	}
	return &Client{rpc.NewClient(conn)}, nil
}

func (c *Client) Close() error {
	return c.RpcClient.Close()
}

type EchoArgs struct {
	Value []byte
	Host  string
}

type EchoReply struct {
	Value []byte
}

func (c *Client) Echo(value []byte, host string) ([]byte, error) {
	reply := EchoReply{}
	args := EchoArgs{value, host}
	err := c.RpcClient.Call("Api.Echo", args, &reply)
	return reply.Value, err
}

type CreateTunnelArgs struct {
	Host string
	Udp  bool
}

type CreateTunnelReply struct {
	Src net.IP
	Dst net.IP
}

func (c *Client) CreateTunnel(host string, udp bool) (net.IP, net.IP, error) {
	reply := CreateTunnelReply{}
	args := CreateTunnelArgs{host, udp}
	err := c.RpcClient.Call("Api.CreateTunnel", args, &reply)
	return reply.Src, reply.Dst, err
}

type DeleteTunnelArgs struct {
	Host string
}

type DeleteTunnelReply struct {
}

func (c *Client) DeleteTunnel(host string) error {
	reply := DeleteTunnelReply{}
	args := DeleteTunnelArgs{host}
	err := c.RpcClient.Call("Api.DeleteTunnel", args, &reply)
	return err
}

type CreateSegmentArgs struct {
	Id   string
	Init []SegmentCommand
	Trig []SegmentCommand
}

type CreateSegmentReply struct {
	Url string
}

func (c *Client) CreateSegment(id string, init []SegmentCommand, trig []SegmentCommand) (string, error) {
	reply := CreateSegmentReply{}
	args := CreateSegmentArgs{id, init, trig}
	err := c.RpcClient.Call("Api.CreateSegment", args, &reply)
	return reply.Url, err
}

type DeleteSegmentArgs struct {
	Id string
}

type DeleteSegmentReply struct {
}

func (c *Client) DeleteSegment(id string) error {
	reply := DeleteSegmentReply{}
	args := DeleteSegmentArgs{id}
	err := c.RpcClient.Call("Api.DeleteSegment", args, &reply)
	return err
}

type GetSrcIPArgs struct {
	Dst net.IP
}

type GetSrcIPReply struct {
	Src net.IP
}

func (c *Client) GetSrcIP(dst net.IP) (net.IP, error) {
	reply := GetSrcIPReply{}
	args := GetSrcIPArgs{dst}
	err := c.RpcClient.Call("Api.GetSrcIP", args, &reply)
	return reply.Src, err
}

type BuildTunnelArgs struct {
	Dst    net.IP
	Tunnel *Tunnel
}

type BuildTunnelReply struct {
	Src    net.IP
	Tunnel *Tunnel
}

func (c *Client) BuildTunnel(dst net.IP, tunnel *Tunnel) (net.IP, *Tunnel, error) {
	reply := BuildTunnelReply{}
	args := BuildTunnelArgs{dst, tunnel}
	err := c.RpcClient.Call("Api.BuildTunnel", args, &reply)
	return reply.Src, reply.Tunnel, err
}

type DestroyTunnelArgs struct {
	Dst net.IP
}

// DestroyTunnel has no reply value
type DestroyTunnelReply struct {
	Src   net.IP
	Error error
}

func (c *Client) DestroyTunnel(dst net.IP) (net.IP, error) {
	reply := DestroyTunnelReply{}
	args := DestroyTunnelArgs{dst}
	err := c.RpcClient.Call("Api.DestroyTunnel", args, &reply)
	return reply.Src, err
}
