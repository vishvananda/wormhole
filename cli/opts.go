package cli

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/raff/tls-ext"
	"github.com/raff/tls-psk"
	"github.com/vishvananda/wormhole/utils"
)

type options struct {
	host   string
	config *tls.Config
}

var opts *options

func parseFlags() []string {
	keyfile := flag.String("K", "/etc/wormhole/key.secret", "Keyfile for psk auth (if not found defaults to insecure key)")
	host := flag.String("H", "127.0.0.1", "server tcp://host:port or unix://path/to/socket")

	flag.Parse()
	validHost, err := utils.ValidateAddr(*host)
	if err != nil {
		log.Fatalf("%v", err)
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
		host:   validHost,
		config: config,
	}

	return flag.Args()
}
