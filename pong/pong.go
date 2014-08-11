package main

import (
	"log"
	"io"
	"os"
	"os/signal"
	"net"
	"syscall"
)

func main() {
	host := ":9001"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	listener, err := net.Listen("tcp", host)
	if err != nil {
		log.Fatalf("Listen Error: %v", err)
	}
	defer listener.Close()

	csig := make(chan os.Signal, 1)
	signal.Notify(csig, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-csig
		listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Accept Error: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err == io.EOF {
				return
			}
			if err != nil {
				log.Fatalf("Read Error: %v", err)
			}
			if n != 0 {
				_, err := conn.Write(buf[:n])
				if err != nil {
					log.Fatalf("Write Error: %v", err)
				}
				os.Exit(0)
			}
		}()
	}
}
