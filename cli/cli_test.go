package cli

import (
	"github.com/vishvananda/wormhole/client"
	"testing"
)

func validateBasicParse(t *testing.T, args []string, commandType int) {
	_, init, _, err := parseSegment(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(init) != 1 {
		t.Fatalf("Parse Failed to create action: %v", args)
	}
	if init[0].Type != commandType {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[0].Type], client.CommandName[commandType])
	}
}
func TestSegmentParseBasic(t *testing.T) {
	validateBasicParse(t, []string{"url", ":40"}, client.URL)
	validateBasicParse(t, []string{"docker-ns", "foo"}, client.DOCKER_NS)
	validateBasicParse(t, []string{"docker-run", "foo"}, client.DOCKER_RUN)
	validateBasicParse(t, []string{"child"}, client.CHILD)
	validateBasicParse(t, []string{"chain"}, client.CHAIN)
	validateBasicParse(t, []string{"remote", "foo"}, client.REMOTE)
	validateBasicParse(t, []string{"tunnel", "foo"}, client.TUNNEL)
	validateBasicParse(t, []string{"udptunnel", "foo"}, client.UDPTUNNEL)
}

func TestParseId(t *testing.T) {
	id, _, _, err := parseSegment([]string{"id", "foo"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "foo" {
		t.Fatalf("Id Parse Failed")
	}
}

func TestSegmentParseComplex(t *testing.T) {
	args := []string{"id", "foo", "url", ":40", "docker-run", "bar"}
	id, init, _, err := parseSegment(args)
	if err != nil {
		t.Fatal(err)
	}
	if id != "foo" {
		t.Fatalf("Name Parse Failed")
	}
	if len(init) != 2 {
		t.Fatalf("Wrong number of actions, %v: %v", args, len(init))
	}
	if init[0].Type != client.URL {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[0].Type], client.CommandName[client.URL])
	}
	if init[1].Type != client.DOCKER_RUN {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[1].Type], client.CommandName[client.DOCKER_RUN])
	}
}

func TestSegmentParseRemote(t *testing.T) {
	args := []string{"id", "foo", "url", ":40", "remote", "bar", "docker-run", "baz"}
	id, init, _, err := parseSegment(args)
	if err != nil {
		t.Fatal(err)
	}
	if id != "foo" {
		t.Fatalf("Name Parse Failed")
	}
	if len(init) != 2 {
		t.Fatalf("Wrong number of actions, %v: %v", args, len(init))
	}
	if init[0].Type != client.URL {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[0].Type], client.CommandName[client.URL])
	}
	if init[1].Type != client.REMOTE {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[1].Type], client.CommandName[client.REMOTE])
	}
	if len(init[1].ChildInit) != 1 {
		t.Fatalf("Wrong number of child actions, %v: %v", args, len(init[1].ChildInit))
	}
	if init[1].ChildInit[0].Type != client.DOCKER_RUN {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[1].ChildInit[0].Type], client.CommandName[client.DOCKER_RUN])
	}
}

func TestSegmentParseTrigger(t *testing.T) {
	args := []string{"id", "foo", "url", ":40", "trigger", "docker-run", "baz"}
	id, init, trig, err := parseSegment(args)
	if err != nil {
		t.Fatal(err)
	}
	if id != "foo" {
		t.Fatalf("Name Parse Failed")
	}
	if len(init) != 1 {
		t.Fatalf("Wrong number of actions, %v: %v", args, len(init))
	}
	if init[0].Type != client.URL {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[init[0].Type], client.CommandName[client.URL])
	}
	if len(trig) != 1 {
		t.Fatalf("Wrong number of actions, %v: %v", args, len(trig))
	}
	if trig[0].Type != client.DOCKER_RUN {
		t.Fatalf("Types don't match, %v: %s != %s", args, client.CommandName[trig[0].Type], client.CommandName[client.DOCKER_RUN])
	}
}
