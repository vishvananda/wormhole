package utils

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

const (
	DEFAULT_PORT = 9999
	DEFAULT_HOST = ""
	DEFAULT_UNIX = "/var/run/wormhole"
)

func Uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type ValidatorFctType func(val string) (string, error)

// ListOpts type
type ListOpts struct {
	values    []string
	validator ValidatorFctType
}

func NewListOpts(validator ValidatorFctType) ListOpts {
	return ListOpts{
		validator: validator,
	}
}

func (opts *ListOpts) String() string {
	return fmt.Sprintf("%v", []string(opts.values))
}

// Set validates if needed the input value and add it to the
// internal slice.
func (opts *ListOpts) Set(value string) error {
	if opts.validator != nil {
		v, err := opts.validator(value)
		if err != nil {
			return err
		}
		value = v
	}
	opts.values = append(opts.values, value)
	return nil
}

// Delete remove the given element from the slice.
func (opts *ListOpts) Delete(key string) {
	for i, k := range opts.values {
		if k == key {
			opts.values = append(opts.values[:i], opts.values[i+1:]...)
			return
		}
	}
}

// GetAll returns the values' slice.
func (opts *ListOpts) GetAll() []string {
	return opts.values
}

// Len returns the amount of element in the slice.
func (opts *ListOpts) Len() int {
	return len(opts.values)
}

func ValidateAddr(addr string) (string, error) {
	var (
		proto string
		host  string
		port  int
	)

	switch {
	case strings.HasPrefix(addr, "unix://"):
		proto = "unix"
		addr = strings.TrimPrefix(addr, "unix://")
		if addr == "" {
			addr = DEFAULT_UNIX
		}
	case strings.HasPrefix(addr, "tcp://"):
		proto = "tcp"
		addr = strings.TrimPrefix(addr, "tcp://")
	default:
		if strings.Contains(addr, "://") {
			return "", fmt.Errorf("Invalid bind address protocol: %s", addr)
		}
		proto = "tcp"
	}

	if proto != "unix" && strings.Contains(addr, ":") {
		hostParts := strings.Split(addr, ":")
		if len(hostParts) != 2 {
			return "", fmt.Errorf("Invalid bind address format: %s", addr)
		}
		if hostParts[0] != "" {
			host = hostParts[0]
		} else {
			host = DEFAULT_HOST
		}

		if p, err := strconv.Atoi(hostParts[1]); err == nil && p != 0 {
			port = p
		} else {
			port = DEFAULT_PORT
		}

	} else {
		host = addr
		port = DEFAULT_PORT
	}
	if proto == "unix" {
		return fmt.Sprintf("%s://%s", proto, host), nil
	}
	return fmt.Sprintf("%s://%s:%d", proto, host, port), nil
}

func ParseAddr(host string) (string, string) {
	res := strings.SplitN(host, "://", 2)
	return res[0], res[1]
}

func ParseUrl(url string) (proto string, ns string, hostname string, port int, err error) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		return
	}
	switch {
	case strings.HasPrefix(url, "unix://"):
		url = strings.TrimPrefix(url, "unix://")
		proto = "unix"
	case strings.HasPrefix(url, "tcp://"):
		url = strings.TrimPrefix(url, "tcp://")
		proto = "tcp"
	case strings.HasPrefix(url, "udp://"):
		url = strings.TrimPrefix(url, "udp://")
		proto = "udp"
	default:
		if strings.Contains(url, "://") {
			err = fmt.Errorf("Invalid segment protocol: %s", url)
			return
		}
	}
	if strings.Contains(url, "@") {
		if proto == "unix" {
			err = fmt.Errorf("Namespace not supported in unix protocol")
		}
		nsParts := strings.Split(url, "@")
		if len(nsParts) != 2 {
			err = fmt.Errorf("Only one namespace is allowed")
		}
		ns = nsParts[0]
		url = nsParts[1]
	}
	n := len(url) - 1
	if n > 0 && url[0] == '[' && url[n] == ']' {
		url = url[1:n]
	} else {
		i := strings.LastIndex(url, ":")
		if i != -1 {
			if proto == "unix" {
				err = fmt.Errorf("Port not supported in unix protocol")
			}
			strPort := url[i+1:]
			url = url[0:i]
			if len(strPort) != 0 {
				if p, err := strconv.Atoi(strPort); err == nil && p != 0 {
					port = p
				} else {
					err = fmt.Errorf("Invalid value for port: %v", strPort)
				}
			}
			n := len(url) - 1
			if n > 0 && url[0] == '[' && url[n] == ']' {
				url = url[1:n]
			} else if strings.Contains(url, ":") {
				err = fmt.Errorf("Only one port is allowed")
			}
		}
	}
	if proto != "unix" && (strings.Contains(url, "[") || strings.Contains(url, "]")) {
		err = fmt.Errorf("Invalid characters in hostname")
	}
	hostname = url
	return
}
