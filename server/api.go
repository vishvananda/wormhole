package server

import (
	"bufio"
	"encoding/gob"
	"github.com/raff/tls-ext"
	"github.com/vishvananda/wormhole/client"
	"github.com/vishvananda/wormhole/utils"
	"io"
	"log"
	"net"
	"net/rpc"
)

type Api int

func (t *Api) Echo(args *client.EchoArgs, reply *client.EchoReply) (err error) {
	reply.Value, err = echo(args.Host, args.Value)
	return err
}

func (t *Api) CreateTunnel(args *client.CreateTunnelArgs, reply *client.CreateTunnelReply) (err error) {
	reply.Src, reply.Dst, err = createTunnel(args.Host, args.Udp)
	return err
}

func (t *Api) DeleteTunnel(args *client.DeleteTunnelArgs, reply *client.DeleteTunnelReply) (err error) {
	return deleteTunnel(args.Host)
	return err
}

func (t *Api) CreateSegment(args *client.CreateSegmentArgs, reply *client.CreateSegmentReply) (err error) {
	reply.Url, err = createSegment(args.Id, args.Init, args.Trig)
	return err
}

func (t *Api) DeleteSegment(args *client.DeleteSegmentArgs, reply *client.DeleteSegmentReply) (err error) {
	err = deleteSegment(args.Id)
	return err
}

func (t *Api) GetSrcIP(args *client.GetSrcIPArgs, reply *client.GetSrcIPReply) (err error) {
	reply.Src, err = getSrcIP(args.Dst)
	return err
}

func (t *Api) BuildTunnel(args *client.BuildTunnelArgs, reply *client.BuildTunnelReply) (err error) {
	reply.Src, reply.Tunnel, err = buildTunnel(args.Dst, args.Tunnel)
	return err
}

func (t *Api) DestroyTunnel(args *client.DestroyTunnelArgs, reply *client.DestroyTunnelReply) (err error) {
	reply.Src, err = destroyTunnel(args.Dst)
	return err
}

type gobServerCodec struct {
	rwc    io.ReadWriteCloser
	dec    *gob.Decoder
	enc    *gob.Encoder
	encBuf *bufio.Writer
}

func (c *gobServerCodec) ReadRequestHeader(r *rpc.Request) error {
	return c.dec.Decode(r)
}

func (c *gobServerCodec) ReadRequestBody(body interface{}) error {
	return c.dec.Decode(body)
}

func (c *gobServerCodec) WriteResponse(r *rpc.Response, body interface{}) (err error) {
	if err = c.enc.Encode(r); err != nil {
		return
	}
	if err = c.enc.Encode(body); err != nil {
		return
	}
	return c.encBuf.Flush()
}

func (c *gobServerCodec) Close() error {
	return c.rwc.Close()
}

func handle(conn net.Conn) {
	buf := bufio.NewWriter(conn)
	srv := &gobServerCodec{conn, gob.NewDecoder(conn), gob.NewEncoder(buf), buf}
	rpc.ServeCodec(srv)
}

var listener net.Listener

func serveAPI() {
	rpc.Register(new(Api))
	proto, address := utils.ParseAddr(opts.hosts[0])
	var err error
	listener, err = tls.Listen(proto, address, opts.config)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Accept: %v", err)
			return
		}
		go handle(conn)
	}
}

func shutdownAPI() {
	listener.Close()
}
