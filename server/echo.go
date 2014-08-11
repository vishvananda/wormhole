package server

import (
	"bytes"
	"fmt"

	"github.com/golang/glog"
	"github.com/vishvananda/wormhole/client"
	"github.com/vishvananda/wormhole/utils"
)

func echo(host string, value []byte) ([]byte, error) {
	glog.Infof("Echo called with: %v %v", host, value)
	if host == "" {
		return value, nil
	} else {
		host, err := utils.ValidateAddr(host)
		if err != nil {
			return nil, err
		}
		c, err := client.NewClient(host, opts.config)
		if err != nil {
			return nil, err
		}
		response, err := c.Echo(value, "")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(value, response) {
			return response, fmt.Errorf("Incorrect response from echo")
		}
		glog.Infof("Echo response is: %v", response)
		return response, nil
	}
}
