package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/twiz718/dns-exfiltration/pkg/server"
)

func main() {

	debug := flag.Bool("debug", false, "enable debug output")
	port := flag.Int("port", 5555, "dns server port")
	flag.Parse()

	done := make(chan bool, 1)
	srv := server.NewServer(*debug, done)
	go srv.Run(*port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	done <- true
	log.Fatalf("Signal (%v) received, stopping\n", s)
}
