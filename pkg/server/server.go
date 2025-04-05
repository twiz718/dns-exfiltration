package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
	"github.com/twiz718/dns-exfiltration/pkg/internal"
)

type dnsHandler struct {
	exfilRE *regexp.Regexp
	storage *expirable.LRU[string, internal.FileFromDNS]
	debug   bool
}

func NewHandler(debug bool) *dnsHandler {
	return &dnsHandler{
		exfilRE: regexp.MustCompile(`^([a-fA-F0-9]{2,62})(?:\.([a-fA-F0-9]{2,62}))?(?:\.([a-fA-F0-9]{2,62}))?\.exfil$`),
		storage: expirable.NewLRU[string, internal.FileFromDNS](1000, nil, time.Minute*3),
		debug:   debug,
	}
}

type Server struct {
	debug    bool
	doneChan chan bool
}

func NewServer(debug bool, done chan bool) *Server {
	return &Server{debug: debug, doneChan: done}
}

func (s *Server) Run(port int) {
	log.Println("Server is starting on port " + strconv.Itoa(port))

	srv := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	h := NewHandler(s.debug)
	srv.Handler = h
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-s.doneChan:
				return
			case <-ticker.C:
				log.Println(h.StorageInfo())
			}
		}
	}()
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set udp listener %s\n", err.Error())
	}
}

func (h *dnsHandler) StorageInfo() string {
	if h.storage != nil {
		keys := h.storage.Keys()
		if len(keys) == 0 {
			return "Cache is currently empty."
		} else {
			return fmt.Sprintf("Number of keys in cache: %v. Keys = %+v", len(keys), keys)
		}
	}
	return ""
}

func (h *dnsHandler) ServeDNS(rw dns.ResponseWriter, r *dns.Msg) {
	if h.debug {
		log.Println("dns request incoming")
	}
	if len(r.Question) == 1 {
		if h.debug {
			log.Printf("%+v\n", r.Question)
		}

	} else {
		if h.debug {
			log.Println("bad dns request, len(r.Question)=", len(r.Question))
		}
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	q := r.Question[0]
	qInfo, err := h.parseQuestion(q)
	if err != nil {
		if h.debug {
			log.Println(err)
		}
	}
	if h.debug {
		log.Printf("qInfo: %+v\n", qInfo)
	}
	o := r.IsEdns0()
	oInfo, err := h.parseOption(o)
	if err != nil {
		if h.debug {
			log.Println(err)
		}
	}
	if h.debug {
		log.Printf("oInfo: %+v\n", oInfo)
	}
	if len(qInfo.bData) > 0 && len(oInfo.md5OfFile) == 32 {
		d := internal.DataChunk{Start: oInfo.startingChunkNum, End: oInfo.endingChunkNum, Data: qInfo.bData}
		existingData, _ := h.storage.Get(oInfo.md5OfFile)
		if len(existingData.DataChunks) == 0 {
			existingData.DataChunks = make(map[int]internal.DataChunk, oInfo.totalChunks)
			log.Printf("Incoming file with md5: %v, expected number of chunks: %v\n", oInfo.md5OfFile, oInfo.totalChunks)
		}
		existingData.DataChunks[oInfo.startingChunkNum] = d
		h.storage.Add(oInfo.md5OfFile, existingData)
		if oInfo.endingChunkNum == oInfo.totalChunks {
			if h.debug {
				log.Println("GOT LAST CHUNK!")
				log.Printf("%+v\n", existingData)
			}
			err = h.writeToFile(oInfo.md5OfFile)
			if err != nil {
				if h.debug {
					log.Println(err)
				}
			}
			log.Println("Finished writing data for " + oInfo.md5OfFile)
		}
	}
	m.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass}, A: net.ParseIP("127.0.0.1")})
	err = rw.WriteMsg(m)
	if err != nil {
		if h.debug {
			log.Println(err)
		}
	}
}

type QuestionInfo struct {
	orig  string   // what we got from the dns question name
	sData []string // string representation of the data as received from the dns request
	bData []byte   // the byte data
}

type OptionInfo struct {
	startingChunkNum int
	endingChunkNum   int
	totalChunks      int
	md5OfFile        string
}

// writeToFile will save the file identified by its md5 hash from the lru cache to disk and expire it from the cache.
func (h *dnsHandler) writeToFile(md5 string) error {
	if h.storage == nil {
		return errors.New("cache is not initialized, cannot read from it")
	}

	data, _ := h.storage.Get(md5)
	fo, err := os.Create(md5 + ".data")
	if err != nil {
		return err
	}
	defer func() {
		fo.Close()
		h.storage.Remove(md5)
	}()

	keys := make([]int, 0, len(data.DataChunks))
	for i, _ := range data.DataChunks {
		if h.debug {
			log.Printf("i=%v\n", i)
		}
		keys = append(keys, i)
	}
	sort.Ints(keys)

	for _, i := range keys {
		chunk := data.DataChunks[i]
		if h.debug {
			log.Printf("writing chunk ")
			log.Println(i)
		}
		_, err := fo.Write(chunk.Data)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *dnsHandler) parseOption(option *dns.OPT) (*OptionInfo, error) {
	oInfo := &OptionInfo{}
	if option == nil {
		return oInfo, errors.New("nil option")

	}
	if len(option.Option) == 0 {
		return oInfo, errors.New("options len is 0")
	}

	for _, opt := range option.Option {
		switch o := opt.(type) {
		case *dns.EDNS0_LOCAL:
			if h.debug {
				log.Println("local option present:", strconv.Itoa(int(o.Code))+" = "+string(o.Data))
			}
			switch int(o.Code) {
			case internal.START_CHUNK_NUM:
				sInt, err := strconv.Atoi(string(o.Data))
				if err != nil {
					return oInfo, err
				}
				oInfo.startingChunkNum = sInt
			case internal.END_CHUNK_NUM:
				eInt, err := strconv.Atoi(string(o.Data))
				if err != nil {
					return oInfo, err
				}
				oInfo.endingChunkNum = eInt
			case internal.TOTAL_CHUNKS:
				tInt, err := strconv.Atoi(string(o.Data))
				if err != nil {
					return oInfo, err
				}
				oInfo.totalChunks = tInt
			case internal.MD5_OF_FILE:
				if len(string(o.Data)) != 32 {
					return oInfo, errors.New("invalid length of md5")
				}
				oInfo.md5OfFile = string(o.Data)
			}
		default:
			if h.debug {
				log.Println("not a local option")
			}
		}

	}
	return oInfo, nil
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

	if h.debug {
		log.Printf("parts:\n%+v\n", parts)
	}

	qi.sData = make([]string, len(parts)-1)
	for _, chunk := range []string{first, second, third} {
		if len(chunk) > 0 {
			if h.debug {
				log.Printf("working on chunk (%v)\n", chunk)
			}
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
