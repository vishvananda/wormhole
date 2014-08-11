package cli

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/vishvananda/wormhole/client"
	"github.com/vishvananda/wormhole/utils"
	"log"
	"os"
	"time"
)

func ping(args []string, c *client.Client) {
	host := ""
	if len(args) > 1 {
		log.Fatalf("Unknown args for ping: %v", args[1:])
	}
	if len(args) == 1 {
		var err error
		host, err = utils.ValidateAddr(args[0])
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	startTime := time.Now()

	log.Printf("Connection took %v", time.Since(startTime))
	value := make([]byte, 16)
	rand.Read(value)
	echoTime := time.Now()
	result, err := c.Echo(value, host)
	if err != nil {
		log.Fatalf("client.Echo failed: %v", err)
	}
	if !bytes.Equal(value, result) {
		log.Fatalf("Incorrect response from echo")
	}
	log.Printf("Reply took %v: %v", time.Since(echoTime), result)
	// milliseconds
	fmt.Printf("%f\n", float64(time.Since(startTime))/1000000)
}

func tunnelCreate(args []string, c *client.Client) {
	host := ""
	udp := false
	filtered := make([]string, 0)
	for _, arg := range args {
		if arg == "--udp" {
			udp = true
		} else {
			filtered = append(filtered, arg)
		}
	}
	args = filtered
	if len(args) > 1 {
		log.Fatalf("Too many args for tunnel-create: %v", args[1:])
	} else if len(args) == 0 {
		log.Fatalf("Argument host is required for tunnel-create")
	}
	host = args[0]
	var err error
	host, err = utils.ValidateAddr(args[0])
	if err != nil {
		log.Fatalf("%v", err)
	}

	src, dst, err := c.CreateTunnel(host, udp)
	if err != nil {
		log.Fatalf("client.CreateTunnel failed: %v", err)
	}
	fmt.Printf("%v %v\n", src, dst)
}

func tunnelDelete(args []string, c *client.Client) {
	host := ""
	if len(args) > 1 {
		log.Fatalf("Unknown args for tunnel-delete: %v", args[1:])
	}
	if len(args) == 1 {
		var err error
		host, err = utils.ValidateAddr(args[0])
		if err != nil {
			log.Fatalf("%v", err)
		}
	} else {
		log.Fatalf("Argument host is required for tunnel-delete")
	}

	err := c.DeleteTunnel(host)
	if err != nil {
		log.Fatalf("client.DeleteTunnel failed: %v", err)
	}
}

func segmentCreate(args []string, c *client.Client) {
	id, init, trig, err := parseSegment(args)
	if err != nil {
		log.Fatalf("Could not parse create: %v", err)
	}

	url, err := c.CreateSegment(id, init, trig)
	if err != nil {
		log.Fatalf("client.CreateSegment failed: %v", err)
	}
	fmt.Printf("%v %v\n", id, url)
}

func segmentDelete(args []string, c *client.Client) {
	id := ""
	if len(args) > 1 {
		log.Fatalf("Unknown args for delete: %v", args[1:])
	}
	if len(args) == 1 {
		id = args[0]
	} else {
		log.Fatalf("Argument id is required for delete")
	}

	err := c.DeleteSegment(id)
	if err != nil {
		log.Fatalf("client.DeleteSegment failed: %v", err)
	}
}

func parseSegment(args []string) (string, []client.SegmentCommand, []client.SegmentCommand, error) {
	id := utils.Uuid()
	s := client.SegmentCommand{}
	chain, tail, trigger := false, false, false
	command := ""
	cur := &s
	for len(args) > 0 {
		command, args = args[0], args[1:]
		var action *client.SegmentCommand
		switch command {
		case "id":
			id = parseName(&args)
			continue
		case "url":
			action = parseUrl(tail, &args)
		case "docker-ns":
			action = parseDockerNs(tail, &args)
		case "docker-run":
			action = parseDockerRun(tail, &args)
		case "child":
			action = parseChild()
			chain = true
		case "chain":
			action = parseChain()
			chain = true
		case "remote":
			action = parseRemote(&args)
			chain = true
		case "tunnel":
			action = parseTunnel(&args)
			chain = true
		case "udptunnel":
			action = parseUdptunnel(&args)
			chain = true
		case "tail":
			tail = true
			continue
		case "trigger":
			trigger = true
			tail = true
			continue
		default:
			log.Fatalf("Action %s not recognized", command)
		}
		if trigger {
			cur.AddTrig(action)
			if chain {
				cur = &cur.ChildTrig[len(cur.ChildTrig)-1]
				chain = false
				trigger = false
				tail = false
			}
		} else {
			cur.AddInit(action)
			if chain {
				cur = &cur.ChildInit[len(cur.ChildInit)-1]
				chain = false
				trigger = false
				tail = false
			}
		}
	}
	return id, s.ChildInit, s.ChildTrig, nil
}

func parseName(args *[]string) string {
	if len(*args) == 0 {
		createFail("Argument ID is required for id")
	}
	var id string
	id, *args = (*args)[0], (*args)[1:]
	return id
}

func parseUrl(tail bool, args *[]string) *client.SegmentCommand {
	if len(*args) == 0 {
		createFail("Argument URL is required for url")
	}

	url := (*args)[0]
	proto, _, _, _, err := utils.ParseUrl(url)
	if err != nil {
		createFail(fmt.Sprintf("Unable to parse URL: %v", url))
	}
	if proto != "" && proto != "tcp" && proto != "udp" {
		createFail("Only tcp and udp protocols are currently supported.")
	}
	*args = (*args)[1:]
	return &client.SegmentCommand{Type: client.URL, Tail: tail, Arg: url}
}

func parseDockerNs(tail bool, args *[]string) *client.SegmentCommand {
	if len(*args) == 0 {
		createFail("Argument ID is required for docker-ns")
	}
	var id string
	id, *args = (*args)[0], (*args)[1:]
	return &client.SegmentCommand{Type: client.DOCKER_NS, Tail: tail, Arg: id}
}

func parseDockerRun(tail bool, args *[]string) *client.SegmentCommand {
	if len(*args) == 0 {
		createFail("Argument ARGS is required for docker-run")
	}
	var run string
	run, *args = (*args)[0], (*args)[1:]
	return &client.SegmentCommand{Type: client.DOCKER_RUN, Tail: tail, Arg: run}
}

func parseChild() *client.SegmentCommand {
	return &client.SegmentCommand{Type: client.CHILD}
}

func parseChain() *client.SegmentCommand {
	return &client.SegmentCommand{Type: client.CHAIN}
}

func parseRemote(args *[]string) *client.SegmentCommand {
	if len(*args) == 0 {
		createFail("Argument HOST is required for remote")
	}
	host, err := utils.ValidateAddr((*args)[0])
	if err != nil {
		createFail(fmt.Sprintf("Unable to parse HOST: %v", host))
	}
	*args = (*args)[1:]
	return &client.SegmentCommand{Type: client.REMOTE, Arg: host}
}

func parseTunnel(args *[]string) *client.SegmentCommand {
	if len(*args) == 0 {
		createFail("Argument HOST is required for tunnel")
	}
	host, err := utils.ValidateAddr((*args)[0])
	if err != nil {
		createFail(fmt.Sprintf("Unable to parse HOST: %v", host))
	}
	*args = (*args)[1:]
	return &client.SegmentCommand{Type: client.TUNNEL, Arg: host}
}

func parseUdptunnel(args *[]string) *client.SegmentCommand {
	if len(*args) == 0 {
		createFail("Argument HOST is required for udptunnel")
	}
	host, err := utils.ValidateAddr((*args)[0])
	if err != nil {
		createFail(fmt.Sprintf("Unable to parse HOST: %v", host))
	}
	*args = (*args)[1:]
	return &client.SegmentCommand{Type: client.UDPTUNNEL, Arg: host}
}

func createFail(msg string) {
	fmt.Println(msg)
	usage("create")
}

func usage(command string) {
	u := ""
	if command == "" {
		u = `Usage: %s [ OPTIONS ] [ help ] COMMAND { SUBCOMMAND ... }
where  COMMAND := { ping | create | delete | tunnel-create | tunnel-delete }
       OPTIONS := { -K[eyfile] | -H[ost] }`
	} else {
		switch command {
		case "ping":
			u = `Usage: %s ping HOST
Pings wormholed on HOST  and prints the latency in ms.`
		case "create":
			u = `Usage: %s create { SUBCOMMAND ... }
where  SUBCOMMAND := { url | name | docker-ns | docker-run | child |
                       child | chain | remote | tunnel | udptunnel |
                       tail | trigger }

Creates a proxy wormhole. The wormhole has a head and a tail. The head
represents where the proxy listens, and the tail represents where the
proxy connects. Both the head and the tail have the following values:

    protocol: the protocol of the connection (currently udp or tcp)
    namespace: the network namespace of the connection
    host: hostname or ip address of the connection
    port: port of the connection

Prints the id and the listen url of the wormhole.

SUBCOMMANDS
===========

url URL
    set the head data to values specified in URL
    URL is in the form {protocol://}{namespace@}{host}{:port}

id ID
    sets the id of the wormhole to ID

docker-ns ID
    set the namespace using docker ID

docker-run ARGS
    docker-run using ARGS and set the namespace to the container's namespace

child
    create a child wormhole using the current proxy values as a base
    everything following this command applies to child wormhole

chain
    create a child wormhole using the current proxy values as a base
    set the current wormhole's values to the child wormhole
    everything following this command applies to child wormhole

remote HOST
    create a child wormhole on HOST
    set the current wormhole's tail values to the child wormhole

tunnel HOST
    create an ipsec tunnel to HOST
    create a child wormhole on HOST
    set the current wormhole's tail values to the child wormhole

udptunnel HOST
    create an ipsec tunnel to HOST using espinudp encapsulation
    create a child wormhole on HOST
    set the current wormhole's tail values to the child wormhole

tail
    all following commands modify the tail instead of the head

trigger
    all following commands modify the tail instead of the head
    all following commands are executed when something connects to the head

`
		case "delete":
			u = `Usage: %s delete ID
Deletes the proxy wormhole ID.`
		case "tunnel-create":
			u = `Usage: %s tunnel-create [--udp] HOST
Creates an ipsec tunnel to HOST and prints out the source and destination
tunnel ip addresses. If --udp is specified the tunnel will use espinudp
encapsulation. Wormholed must be running on HOST with the same key as the
local wormholed.`
		case "tunnel-delete":
			u = `Usage: %s tunnel-delete HOST
Deletes an ipsec tunnel to HOST.`
		default:
			log.Printf("Unknown command: %v", command)
		}
	}
	fmt.Printf(u, os.Args[0])
	fmt.Println()
}

func Main() {
	args := parseFlags()
	if len(args) == 0 {
		usage("")
		return
	}

	command, args := args[0], args[1:]
	if command == "help" {
		if len(args) != 0 {
			usage(args[0])
		} else {
			usage("")
		}
		return
	}

	c, err := client.NewClient(opts.host, opts.config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer c.Close()
	switch command {
	case "ping":
		ping(args, c)
	case "create":
		segmentCreate(args, c)
	case "delete":
		segmentDelete(args, c)
	case "tunnel-create":
		tunnelCreate(args, c)
	case "tunnel-delete":
		tunnelDelete(args, c)
	default:
		log.Printf("Unknown command: %v", command)
		usage("")
	}
}
