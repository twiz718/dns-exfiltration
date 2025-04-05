package server

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var validCases = []string{
	// ✅ One segment: 2–62 chars
	"ab58.exfil",
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.exfil", // 62 chars

	// ✅ Two segments: first = 62, second = 2–62
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.cd.exfil",
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.exfil", // second = 62

	// ✅ Three segments: first = 62, second = 62, third = 2–62
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.cd.exfil",
}

var invalidCases = []string{
	// ❌ Single segment too short
	"a.exfil",

	// ❌ First segment < 62 when additional segments present
	"ab.cd.exfil",
	"abc123.cd.ef.exfil",

	// ❌ First segment > 62
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab3.exfil", // 63 chars

	// ❌ Too many segments
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.cd.ef.gh.exfil",

	// ❌ Invalid characters
	"ab_cd.exfil",
	"1234.!!!!.exfil",

	// ❌ Incorrect ending
	"ab.cd.ef.extra",
	"ab.cd.ef.exfil.more",

	// ❌ Third segment present, but second segment < 62
	"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.cd.ef.exfil",
}

func TestRegexValid(t *testing.T) {
	h := NewHandler(false)
	for _, input := range validCases {
		q := new(dns.Question)
		q.Name = input
		qi, err := h.parseQuestion(*q)
		assert.NoError(t, err)
		if err != nil {
			break
		}
		assert.NotEmpty(t, qi.sData)
		assert.NotEmpty(t, qi.bData)
	}
}

func TestRegexInvalid(t *testing.T) {
	h := NewHandler(false)
	for _, input := range invalidCases {
		q := new(dns.Question)
		q.Name = input
		qi, err := h.parseQuestion(*q)
		assert.Error(t, err)
		if err == nil {
			break
		}
		assert.Empty(t, qi.sData)
		assert.Empty(t, qi.bData)
	}
}
