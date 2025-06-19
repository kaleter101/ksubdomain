package runner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Global map to store DNS records for the mock server for each test.
// Keyed by test name to allow parallel tests if needed, though miekg/dns server might not like parallel binds on same port.
// For simplicity, tests might need to run sequentially if they use the same mock server port.
var mockDNSRecords sync.Map // map[string]map[string][]dns.RR (testName -> fqdn -> records)

const mockServerAddr = "127.0.0.1:55353" // Consistent port for mock server

func startMockDNSServer(t *testing.T, testSpecificRecords map[string][]dns.RR) *dns.Server {
	// Store records for this test instance
	// Using t.Name() as key for test-specific records
	mockDNSRecords.Store(t.Name(), testSpecificRecords)

	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		fqdn := strings.ToLower(q.Name)
		qType := q.Qtype

		// Retrieve records for the current test
		currentTestRecords, _ := mockDNSRecords.Load(t.Name())
		recordsForFqdn, ok := currentTestRecords.(map[string][]dns.RR)[fqdn]

		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		if ok {
			foundRecord := false
			for _, rr := range recordsForFqdn {
				if rr.Header().Rrtype == qType {
					msg.Answer = append(msg.Answer, dns.Copy(rr))
					foundRecord = true
				}
				// If query is for A, and we have a CNAME, add CNAME to Authority or Additional
				// For simplicity, let's assume direct match or NXDOMAIN/NODATA.
				// Real resolvers might add CNAMEs to answer section if QTYPE matches CNAME type.
			}
			if !foundRecord {
				// NODATA response (exists, but not for this type)
				// For wildcard tests, we mostly expect A or CNAME, or NXDOMAIN for non-matching.
				// If we want to simulate NODATA, we'd add SOA to Authority.
				// For now, NXDOMAIN is fine if no specific record of type matches.
				msg.SetRcode(r, dns.RcodeNameError) // Treat as NXDOMAIN if type doesn't match
			}
		} else {
			// Check for wildcard by stripping first label
			parts := strings.SplitN(fqdn, ".", 2)
			if len(parts) > 1 {
				wildcardFqdn := "*." + parts[1]
				wildcardRecords, wcOk := currentTestRecords.(map[string][]dns.RR)[wildcardFqdn]
				if wcOk {
					for _, rr := range wildcardRecords {
						if rr.Header().Rrtype == qType {
							// Must create a new RR with the original query name
							newRR := dns.Copy(rr)
							newRR.Header().Name = q.Name // Set the name to the queried name
							msg.Answer = append(msg.Answer, newRR)
						}
					}
				} else {
					msg.SetRcode(r, dns.RcodeNameError)
				}
			} else {
				msg.SetRcode(r, dns.RcodeNameError)
			}
		}
		err := w.WriteMsg(msg)
		if err != nil {
			t.Logf("Error writing message: %s", err)
		}
	}

	server := &dns.Server{Addr: mockServerAddr, Net: "udp", Handler: dns.HandlerFunc(handler)}
	go func() {
		//t.Logf("Starting mock DNS server for test %s on %s", t.Name(), mockServerAddr)
		err := server.ListenAndServe()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			//t.Errorf("Mock DNS server ListenAndServe() failed for test %s: %v", t.Name(), err)
			// This can fail if port is still in use from previous test; OS needs time to free it.
			// Consider using a global server instance or random ports if tests need to run fast & parallel.
		}
	}()
	time.Sleep(50 * time.Millisecond) // Give server a moment to start
	return server
}

func TestDetectWildcardCharacteristics_NoWildcard(t *testing.T) {
	records := map[string][]dns.RR{
		// Specific records, no wildcard pattern
		"rand1.testdomain.com.": {&dns.A{Hdr: dns.RR_Header{Name: "rand1.testdomain.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.1.1.1")}},
		"rand અલગ.testdomain.com.": {}, // Simulate NXDOMAIN by not adding it
	}
	server := startMockDNSServer(t, records)
	defer server.Shutdown()

	resolvers := []string{mockServerAddr}
	res, err := DetectWildcardCharacteristics("testdomain.com", resolvers, 500*time.Millisecond)

	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.False(t, res.IsWildcard, "Should not detect wildcard")
	assert.Empty(t, res.WildcardIPs)
	assert.Empty(t, res.WildcardCNAMEs)
}

func TestDetectWildcardCharacteristics_ARecordWildcard(t *testing.T) {
	records := map[string][]dns.RR{
		"*.testawild.com.": { // Wildcard A record
			&dns.A{Hdr: dns.RR_Header{Name: "*.testawild.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.1")},
			&dns.A{Hdr: dns.RR_Header{Name: "*.testawild.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.2")},
		},
		// Add one specific non-wildcard record to ensure threshold logic is tested
		"specific.testawild.com.": {&dns.A{Hdr: dns.RR_Header{Name: "specific.testawild.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}},
	}
	server := startMockDNSServer(t, records)
	defer server.Shutdown()

	resolvers := []string{mockServerAddr}
	// Override defaultProbeCount for faster test, ensuring enough probes hit wildcard
	originalProbeCount := defaultProbeCount
	probeCountForTest := 5 // Must be enough that (probeCountForTest-1)/probeCountForTest >= threshold
	defer func() { defaultProbeCount = originalProbeCount }()
	defaultProbeCount = probeCountForTest


	res, err := DetectWildcardCharacteristics("testawild.com", resolvers, 500*time.Millisecond)

	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.True(t, res.IsWildcard, "Should detect A record wildcard")
	assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, res.WildcardIPs)
	assert.Empty(t, res.WildcardCNAMEs)
}


func TestDetectWildcardCharacteristics_CNAMEWildcard(t *testing.T) {
	records := map[string][]dns.RR{
		"*.testcwild.com.": { // Wildcard CNAME record
			&dns.CNAME{Hdr: dns.RR_Header{Name: "*.testcwild.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "wildtarget.example.com."},
		},
		// wildtarget.example.com itself resolves to an IP
		"wildtarget.example.com.": {&dns.A{Hdr: dns.RR_Header{Name: "wildtarget.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("20.0.0.1")}},
	}
	server := startMockDNSServer(t, records)
	defer server.Shutdown()

	resolvers := []string{mockServerAddr}
	originalProbeCount := defaultProbeCount
	probeCountForTest := 5
	defer func() { defaultProbeCount = originalProbeCount }()
	defaultProbeCount = probeCountForTest

	res, err := DetectWildcardCharacteristics("testcwild.com", resolvers, 1*time.Second) // Increased timeout for CNAME then A

	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.True(t, res.IsWildcard, "Should detect CNAME wildcard")
	assert.Empty(t, res.WildcardIPs, "WildcardIPs should be empty if primary wildcard is CNAME") // IPs of the CNAME target are not wildcard IPs of the queried domain directly
	assert.ElementsMatch(t, []string{"wildtarget.example.com"}, res.WildcardCNAMEs)
}


func TestDetectWildcardCharacteristics_AmbiguousResults(t *testing.T) {
	// Simulate a scenario where random subdomains resolve to many different IPs,
	// not meeting the threshold for a simple wildcard.
	records := make(map[string][]dns.RR)
	for i := 0; i < defaultProbeCount; i++ {
		// Each random probe gets a unique IP
		records[fmt.Sprintf("rand%d.ambiguous.com.", i)] = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: fmt.Sprintf("rand%d.ambiguous.com.",i), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(fmt.Sprintf("1.1.1.%d", i+1))},
		}
	}
	server := startMockDNSServer(t, records)
	defer server.Shutdown()

	resolvers := []string{mockServerAddr}
	res, err := DetectWildcardCharacteristics("ambiguous.com", resolvers, 500*time.Millisecond)

	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.False(t, res.IsWildcard, "Should not detect simple wildcard for ambiguous results")
}

func TestDetectWildcardCharacteristics_NoResolvers(t *testing.T) {
	_, err := DetectWildcardCharacteristics("testdomain.com", []string{}, 1*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no resolvers provided")
}

func TestDetectWildcardCharacteristics_ResolversFail(t *testing.T) {
	// Using a non-responsive IP for resolver
	resolvers := []string{"127.0.0.1:10053"} // Assuming this port is not in use
	res, err := DetectWildcardCharacteristics("testdomain.com", resolvers, 100*time.Millisecond) // Short timeout

	assert.NoError(t, err) // Function should handle resolver errors gracefully
	assert.NotNil(t, res)
	assert.False(t, res.IsWildcard) // No responses, so no wildcard
	assert.Equal(t, 0, len(res.ProbeAnswers), "No answers should be recorded if all resolvers fail")
}

// Helper function tests
func TestUnique(t *testing.T) {
	assert.ElementsMatch(t, []string{"a", "b"}, unique([]string{"a", "b", "a"}))
	assert.Empty(t, unique([]string{}))
	assert.Equal(t, []string{"c"}, unique([]string{"c", "c", "c"}))
}

func TestContains(t *testing.T) {
	assert.True(t, contains([]string{"a", "b"}, "a"))
	assert.False(t, contains([]string{"a", "b"}, "c"))
	assert.False(t, contains([]string{}, "a"))
}
