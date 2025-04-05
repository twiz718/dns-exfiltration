package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
	"github.com/twiz718/dns-exfiltration/pkg/internal"
)

type dnsHandler struct {
	exfilRE *regexp.Regexp
}

func NewHandler() *dnsHandler {
	return &dnsHandler{exfilRE: regexp.MustCompile(`^([a-fA-F0-9]{2,62})(?:\.([a-fA-F0-9]{2,62}))?(?:\.([a-fA-F0-9]{2,62}))?\.exfil$`)}
}

type Server struct {
	storage *expirable.LRU[string, internal.FileFromDNS]
}

func NewServer() *Server {
	return &Server{storage: expirable.NewLRU[string, internal.FileFromDNS](1000, nil, time.Minute*3)}
}

func (s *Server) Run(port int) {
	fmt.Println("Server is starting on port " + strconv.Itoa(port))

	srv := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	srv.Handler = NewHandler()
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set udp listener %s\n", err.Error())
	}
}

func (h *dnsHandler) ServeDNS(rw dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("dns request incoming")
	if len(r.Question) == 1 {
		fmt.Printf("%+v\n", r.Question)
	} else {
		fmt.Println("bad dns request, len(r.Question)=", len(r.Question))
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	q := r.Question[0]
	qInfo, err := h.parseQuestion(q)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("qInfo: %+v\n", qInfo)
	o := r.IsEdns0()
	oInfo, err := h.parseOption(o)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("oInfo: %+v\n", oInfo)
	m.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass}, A: net.ParseIP("127.0.0.1")})
	err = rw.WriteMsg(m)
	if err != nil {
		fmt.Println(err)
	}
}

type QuestionInfo struct {
	orig  string   // what we got from the dns question name
	sData []string // string representation of the data as received from the dns request
	bData []byte   // the byte data
}

type OptionInfo struct {
	chunkNum   int
	totalChunk int
}

func (h *dnsHandler) parseOption(option *dns.OPT) (*OptionInfo, error) {
	if option == nil {
		return nil, errors.New("nil option")

	}
	if len(option.Option) == 0 {
		return nil, errors.New("options len is 0")
	}

	for _, opt := range option.Option {
		switch opt.(type) {
		case *dns.EDNS0_LOCAL:
			o := opt.(*dns.EDNS0_LOCAL)
			fmt.Println(o)
			fmt.Println("yay a local option:", strconv.Itoa(int(o.Code))+" = "+string(o.Data))

		default:
			fmt.Println("not a local option")
		}

	}
	return nil, nil
}

// valid format for exfiltration:
//
//	hex chunk up to 62 chars (data) followed by up to 2 more chunks (max of 3 total chunks allowed based on max dns domain name length rules)
//	always ending with .exfil, see the unit tests in server_test.go for examples of valid/invalid requests.
func (h *dnsHandler) parseQuestion(question dns.Question) (*QuestionInfo, error) {
	name := strings.TrimRight(question.Name, ".")
	qi := &QuestionInfo{sData: []string{}, bData: []byte{}, orig: name}
	parts := h.exfilRE.FindStringSubmatch(name)
	if parts == nil {
		return qi, errors.New("could not match exfiltration pattern from dns question name")
	}

	first, second, third := parts[1], parts[2], parts[3]
	// Rule: all segments (if present) must be even-length (valid hex pairs)
	for _, seg := range []string{first, second, third} {
		if seg != "" && len(seg)%2 != 0 {
			return qi, errors.New("a segment did not have a valid amount of hex characters (len not divisble evenly by 2)")
		}
	}

	if (second != "" || third != "") && len(first) != 62 {
		return qi, errors.New("first segment must be 62 chars when additional segments exist")
	}
	if third != "" && len(second) != 62 {
		return qi, errors.New("second segment must be 62 chars when third is present")
	}

	// Enforce: if more than 1 segment, first must be exactly 62
	if (second != "" || third != "") && len(first) != 62 {
		return qi, errors.New("more than one data segment present but the first one is not 62 chars long")
	}

	fmt.Printf("parts:\n%+v\n", parts)

	qi.sData = make([]string, len(parts)-1)
	for _, chunk := range []string{first, second, third} {
		if len(chunk) > 0 {
			fmt.Printf("working on chunk (%v)\n", chunk)
			qi.sData = append(qi.sData, chunk)
			d, err := hex.DecodeString(chunk)
			if err != nil {
				return qi, err
			}
			qi.bData = append(qi.bData, d...)
		}
	}

	return qi, nil
}
