package server

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/raff/tls-ext"
	"github.com/raff/tls-psk"
	"github.com/vishvananda/wormhole/utils"
)

type options struct {
	hosts        []string
	src          net.IP
	cidr         *net.IPNet
	config       *tls.Config
	udpStartPort int
	udpEndPort   int
}

var opts *options

func parseFlags() {
	keyfile := flag.String("K", "/etc/wormhole/key.secret", "Keyfile for psk auth (if not found defaults to insecure key)")
	src := flag.String("I", "", "Ip for tunnel (defaults to src of default route)")
	cidr := flag.String("C", "100.65.0.0/14", "Cidr for overlay ips (must be the same on all hosts)")
	ports := flag.String("P", "4500-4599", "Inclusive port range for udp tunnels")
	hosts := utils.NewListOpts(utils.ValidateAddr)
	flag.Var(&hosts, "H", "Multiple tcp://host:port or unix://path/to/socket to bind")

	flag.Parse()
	if hosts.Len() == 0 {
		hosts.Set("")
	}

	var srcIP net.IP
	if *src == "" {
		var err error
		srcIP, err = getSource(nil)
		if err != nil {
			log.Fatalf("Failed to find default route ip. Please specify -I")
		}
	} else {
		log.Printf("Got a source ip of %v", *src)
		srcIP = net.ParseIP(*src)
		if srcIP == nil {
			log.Fatalf("Invalid source IP for tunnels: %v", src)
		}
	}
	_, cidrNet, err := net.ParseCIDR(*cidr)
	if err != nil {
		log.Fatalf("Failed to parse -C: %v", err)
	}
	portParts := strings.Split(*ports, "-")
	startPort, err := strconv.Atoi(portParts[0])
	if err != nil {
		log.Fatalf("Port range %s is not valid: %v", ports, err)
	}
	endPort := startPort
	if len(portParts) > 1 {
		endPort, err = strconv.Atoi(portParts[1])
		if err != nil {
			log.Fatalf("Port range %s is not valid: %v", ports, err)
		}
	}

	key := "wormhole"
	b, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Printf("Failed to open keyfile %s: %v", *keyfile, err)
		log.Printf("** WARNING: USING INSECURE PRE-SHARED-KEY **")
	} else {
		key = string(b)
	}

	var config = &tls.Config{
		CipherSuites: []uint16{psk.TLS_PSK_WITH_AES_128_CBC_SHA},
		Certificates: []tls.Certificate{tls.Certificate{}},
		Extra: psk.PSKConfig{
			GetKey: func(id string) ([]byte, error) {
				return []byte(key), nil
			},
			GetIdentity: func() string {
				name, err := os.Hostname()
				if err != nil {
					log.Printf("Failed to determine hostname: %v", err)
					return "wormhole"
				}
				return name
			},
		},
	}

	opts = &options{
		hosts:        hosts.GetAll(),
		src:          srcIP,
		cidr:         cidrNet,
		config:       config,
		udpStartPort: startPort,
		udpEndPort:   endPort,
	}
}
