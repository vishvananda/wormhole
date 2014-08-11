package utils

import (
	"testing"
)

func validate(t *testing.T, url string, proto string, ns string, hostname string, port int) {
	pr, n, h, po, err := ParseUrl(url)
	if err != nil {
		t.Fatal("Error parsing %v: %v", url, err)
	}
	if proto != pr {
		t.Fatalf("Protocol doesn't match for %v: (Expected: '%v' != Actual '%v')", url, proto, pr)
	}
	if ns != n {
		t.Fatalf("Namespace doesn't match for %v: (Expected: '%v' != Actual '%v')", url, ns, n)
	}
	if hostname != h {
		t.Fatalf("Hostname doesn't match for %v: (Expected: '%v' != Actual '%v')", url, hostname, h)
	}
	if port != po {
		t.Fatalf("Port doesn't match for %v: (Expected: '%v' != Actual '%v')", url, port, po)
	}
}

func errors(t *testing.T, url string) {
	pr, n, h, po, err := ParseUrl(url)
	if err == nil {
		t.Fatalf("No error for %v: (Actual '%v', '%v', '%v', '%v')", url, pr, n, h, po)
	}
}

func TestParseUrl(t *testing.T) {
	validate(t, "", "", "", "", 0)
	validate(t, ":40", "", "", "", 40)
	validate(t, "foo", "", "", "foo", 0)
	validate(t, "foo:", "", "", "foo", 0)
	validate(t, "foo:40", "", "", "foo", 40)
	validate(t, "ns@", "", "ns", "", 0)
	validate(t, "ns@foo", "", "ns", "foo", 0)
	validate(t, "ns@:40", "", "ns", "", 40)
	validate(t, "ns@foo:40", "", "ns", "foo", 40)
	validate(t, "tcp://", "tcp", "", "", 0)
	validate(t, "udp://", "udp", "", "", 0)
	validate(t, "unix://", "unix", "", "", 0)
	validate(t, "tcp://foo", "tcp", "", "foo", 0)
	validate(t, "tcp://:40", "tcp", "", "", 40)
	validate(t, "tcp://foo:40", "tcp", "", "foo", 40)
	validate(t, "tcp://ns@", "tcp", "ns", "", 0)
	validate(t, "tcp://ns@foo", "tcp", "ns", "foo", 0)
	validate(t, "tcp://ns@:40", "tcp", "ns", "", 40)
	validate(t, "tcp://ns@foo:40", "tcp", "ns", "foo", 40)
	validate(t, "[::1]:40", "", "", "::1", 40)
}

func TestParseUrlErrors(t *testing.T) {
	errors(t, "multiple@namespace@foo")
	errors(t, "invalid://host")
	errors(t, "multiple:ports:foo")
	errors(t, "unix://with@namepace")
	errors(t, "unix://with:port")
	errors(t, "::1:40")
	errors(t, "[bad]bracketing")
}
