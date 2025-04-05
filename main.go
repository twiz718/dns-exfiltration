package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/twiz718/dns-exfiltration/pkg/server"
)

func main() {

	srv := server.NewServer()
	go srv.Run(5555)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", s)
}
