package server

import (
	"github.com/vishvananda/wormhole/client"
	"testing"
)

func TestInitializeModifyCurrent(t *testing.T) {
	seg := Segment{}
	seg.Init = append(seg.Init, client.SegmentCommand{Type: client.URL, Arg: ":1"})
	seg.Initialize()
	if seg.Head.Port != 1 {
		t.Fatal("Command did not modify value")
	}
}

func TestInitializeModifyTail(t *testing.T) {
	seg := Segment{}
	seg.Init = append(seg.Init, client.SegmentCommand{Type: client.URL, Arg: ":1", Tail: true})
	seg.Initialize()
	if seg.Tail.Port != 1 {
		t.Fatal("Command did not modify value")
	}
}

func TestInitializeDouble(t *testing.T) {
	seg := Segment{}
	seg.Init = append(seg.Init, client.SegmentCommand{Type: client.URL, Arg: ":1"})
	seg.Init = append(seg.Init, client.SegmentCommand{Type: client.URL, Arg: ":2"})
	seg.Initialize()
	if seg.Head.Port != 2 {
		t.Fatal("Second command did not modify value")
	}
}

func TestInitializeEmpties(t *testing.T) {
	seg := Segment{}
	seg.Init = append(seg.Init, client.SegmentCommand{Type: client.URL, Arg: ":1"})
	seg.Initialize()
	if len(seg.Init) != 0 {
		t.Fatal("Initialize commands still in queue")
	}
}
