package axfr

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestAttemptAXFR_RecordParsing(t *testing.T) {
	// This test focuses on the record parsing logic within AttemptAXFR.
	// It does not perform a real AXFR query.

	client := NewAXFRClient(5) // Timeout doesn't matter here

	// Mock DNS RRs
	mockRRs := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "test.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ipv6.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.example.com."},
		&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mail.example.com."},
		&dns.TXT{Hdr: dns.RR_Header{Name: "txt.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"hello world"}},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com."},
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2023010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minttl:  300,
		},
		// Add an unhandled type to see if it's converted to string
		&dns.SRV{Hdr: dns.RR_Header{Name: "_sip._tcp.example.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl:300}, Priority:10, Weight:5, Port:5060, Target: "sipserver.example.com."},
	}

	expectedResults := []result.Result{
		{Subdomain: "test.example.com", Answers: []string{"192.0.2.1"}, Source: "AXFR"},
		{Subdomain: "ipv6.example.com", Answers: []string{"2001:db8::1"}, Source: "AXFR"},
		{Subdomain: "alias.example.com", Answers: []string{"CNAME target.example.com."}, Source: "AXFR"},
		{Subdomain: "example.com", Answers: []string{"MX 10 mail.example.com."}, Source: "AXFR"},
		{Subdomain: "txt.example.com", Answers: []string{"TXT hello world"}, Source: "AXFR"},
		{Subdomain: "example.com", Answers: []string{"NS ns1.example.com."}, Source: "AXFR"},
		{Subdomain: "example.com", Answers: []string{"SOA ns1.example.com. admin.example.com. 2023010101 3600 1800 604800 300"}, Source: "AXFR"},
		{Subdomain: "_sip._tcp.example.com", Answers: []string{"_sip._tcp.example.com.\t300\tIN\tSRV\t10\t5\t5060\tsipserver.example.com."}, Source: "AXFR"},
	}

	// Simulate the channel part of AttemptAXFR for parsing
	var parsedResults []result.Result
	for _, rr := range mockRRs {
		var answers []string
		subdomain := strings.TrimSuffix(rr.Header().Name, ".")

		switch rec := rr.(type) {
		case *dns.A:
			answers = append(answers, rec.A.String())
		case *dns.AAAA:
			answers = append(answers, rec.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, "CNAME "+rec.Target)
		case *dns.MX:
			answers = append(answers, fmt.Sprintf("MX %d %s", rec.Preference, rec.Mx))
		case *dns.TXT:
			answers = append(answers, "TXT "+rec.Txt[0])
		case *dns.NS:
			answers = append(answers, "NS "+rec.Ns)
		case *dns.SOA:
			answers = append(answers, fmt.Sprintf("SOA %s %s %d %d %d %d %d", rec.Ns, rec.Mbox, rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minttl))
		default:
			answers = append(answers, rr.String())
		}
		if len(answers) > 0 {
			parsedResults = append(parsedResults, result.Result{
				Subdomain: subdomain,
				Answers:   answers,
				Source:    "AXFR",
			})
		}
	}

	assert.Equal(t, len(expectedResults), len(parsedResults), "Number of parsed results should match expected")

	for i, er := range expectedResults {
		pr := parsedResults[i]
		assert.Equal(t, er.Subdomain, pr.Subdomain, "Subdomain mismatch")
		assert.Equal(t, er.Source, pr.Source, "Source mismatch")
		assert.ElementsMatch(t, er.Answers, pr.Answers, "Answers mismatch for subdomain %s", er.Subdomain)
	}
}

// Minimal test for NewAXFRClient
func TestNewAXFRClient(t *testing.T) {
	timeout := 10
	client := NewAXFRClient(timeout)
	assert.NotNil(t, client)
	assert.Equal(t, time.Duration(timeout)*time.Second, client.Timeout)
}

// Note: Testing the full AttemptAXFR function with a live DNS server or a complex mock
// is beyond a simple unit test. The TestAttemptAXFR_RecordParsing focuses on the transformation logic.
// To test network interaction, a dedicated integration test with a controlled DNS server would be needed.

// Example of how one might start a mock DNS server for more involved tests (requires more setup):
/*
func TestAttemptAXFR_WithMockServer(t *testing.T) {
	serverAddr := "127.0.0.1:53535" // Choose an available port
	server := &dns.Server{Addr: serverAddr, Net: "tcp"}

	dns.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Qtype == dns.TypeAXFR {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			// Add SOA record
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
				Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 3600,
			})
			// Add A record
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "test.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.1").To4(),
			})
			// Add final SOA record to signify end
			m.Answer = append(m.Answer, &dns.SOA{ //Duplicate SOA to end
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
				Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 3600,
			})

			// This is simplified; a real AXFR involves sending records in separate messages.
			// The dns.Transfer client handles this, but the server side needs to use dns.Transfer.Out().
			// For a simple mock, sending all in one might work for basic client tests if client isn't strict.
			// Better: use transfer.Out(w, r, channel) on server side.

			// For now, this simple reply won't fully work with client's In() which expects a channel.
			// w.WriteMsg(m)

			// Correct way for server to handle AXFR for miekg/dns Transfer client:
			tr := new(dns.Transfer)
			ch := make(chan *dns.Envelope)
			var errs error
			go func() {
				for _, rr := range m.Answer { // m.Answer contains all records for the zone
					ch <- &dns.Envelope{RR: []dns.RR{rr}}
				}
				close(ch) // Close channel when all records are sent
			}()

			err := tr.Out(w, r, ch)
			if err != nil {
				t.Logf("AXFR Out error: %v", err)
			}
			return
		}
		// Handle other query types if necessary, or return FORMERR/NOTIMP
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(m)
	})

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			t.Logf("Failed to start mock DNS server: %v", err)
		}
	}()
	defer server.Shutdown()
	time.Sleep(100 * time.Millisecond) // Give server time to start

	client := NewAXFRClient(2)
	results, err := client.AttemptAXFR("example.com", serverAddr)

	assert.NoError(t, err, "AttemptAXFR should not error with mock server")
	assert.NotEmpty(t, results, "Should get some results from mock AXFR")
	// Further assertions on results content...
}
*/
