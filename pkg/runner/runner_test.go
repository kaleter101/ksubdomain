package runner

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	// "github.com/boy-hack/ksubdomain/v2/pkg/core" - Not directly used in this new test file
	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/options"
	"github.com/boy-hack/ksubdomain/v2/pkg/device"
	"github.com/miekg/dns"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/assert"
	// "github.com/google/gopacket" - Not directly used, but layers is
	"github.com/google/gopacket/layers"
	// "github.com/google/gopacket/pcap" - pcap.Handle is used by Runner, but direct calls mocked/avoided
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/statusdb" // For manual statusDB interaction
	"sync/atomic" // For sendCount in test
)

// mockDNSRecordsRunnerTest stores DNS records for the mock server.
var mockDNSRecordsRunnerTest sync.Map // domain -> []dns.RR, keyed by t.Name()

const mockServerAddrRunnerTest = "127.0.0.1:55354" // Unique port for these tests

// startMockDNSServerForRunnerTest starts a DNS server for runner tests.
func startMockDNSServerForRunnerTest(t *testing.T, records map[string][]dns.RR) *dns.Server {
	mockDNSRecordsRunnerTest.Store(t.Name(), records)

	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		fqdn := strings.ToLower(q.Name)
		qType := q.Qtype
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		currentTestRecords, _ := mockDNSRecordsRunnerTest.Load(t.Name())
		if currentTestRecords == nil {
			msg.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(msg)
			return
		}

		recordsForFqdn, ok := currentTestRecords.(map[string][]dns.RR)[fqdn]
		// t.Logf("Mock DNS: Query for %s type %s. Found in map: %v", fqdn, dns.TypeToString[qType], ok)

		if ok {
			for _, rr := range recordsForFqdn {
				if rr.Header().Rrtype == qType {
					msg.Answer = append(msg.Answer, dns.Copy(rr))
				}
			}
		} else {
			parts := strings.SplitN(fqdn, ".", 2)
			if len(parts) > 1 {
				wildcardFqdn := "*." + parts[1]
				if wildcardRecords, wcOk := currentTestRecords.(map[string][]dns.RR)[wildcardFqdn]; wcOk {
					for _, rr := range wildcardRecords {
						if rr.Header().Rrtype == qType {
							copiedRR := dns.Copy(rr)
							copiedRR.Header().Name = q.Name
							msg.Answer = append(msg.Answer, copiedRR)
						}
					}
				} else {
					msg.SetRcode(r, dns.RcodeNameError)
				}
			} else {
				msg.SetRcode(r, dns.RcodeNameError)
			}
		}

		// If no answers but Rcode is still Success, it's NODATA. Add SOA if available.
		if len(msg.Answer) == 0 && msg.Rcode == dns.RcodeSuccess {
			soaFqdn := q.Name // Look for SOA for q.Name or its parent
			var soaRR dns.RR
			for {
				if soaRecords, soaOk := currentTestRecords.(map[string][]dns.RR)[soaFqdn]; soaOk {
					for _, rr := range soaRecords {
						if rr.Header().Rrtype == dns.TypeSOA {
							soaRR = rr
							break
						}
					}
				}
				if soaRR != nil { break }
				dotIndex := strings.Index(soaFqdn, ".")
				if dotIndex == -1 || dotIndex == len(soaFqdn)-1 {break}
				soaFqdn = soaFqdn[dotIndex+1:]
				if soaFqdn == "" {break} // Should not happen with FQDNs
			}
			if soaRR != nil {
				msg.Ns = append(msg.Ns, dns.Copy(soaRR))
			}
		}
		w.WriteMsg(msg)
	}

	server := &dns.Server{Addr: mockServerAddrRunnerTest, Net: "udp", Handler: dns.HandlerFunc(handler)}
	go func() {
		err := server.ListenAndServe()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			// t.Logf("Mock DNS server (runner test %s) ListenAndServe() error: %v", t.Name(), err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	return server
}

func TestDynamicNSDiscoveryAndUsage(t *testing.T) {
	if os.Getenv("CI") != "" {
        t.Skip("Skipping dynamic NS discovery test in CI due to potential network/timing issues with mock server and net.LookupIP or device access.")
    }
	gologger.DefaultLogger.SetLevel(gologger.Debug)

	testZoneFQDN := "testns.ksdns.local."
	testZone := strings.TrimSuffix(testZoneFQDN, ".")
	nsHostnameFQDN := "ns1.testns.ksdns.local."
	nsHostname := strings.TrimSuffix(nsHostnameFQDN, ".")
	nsIP := "127.0.0.10"

	records := map[string][]dns.RR{
		testZoneFQDN: {
			&dns.NS{Hdr: dns.RR_Header{Name: testZoneFQDN, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: nsHostnameFQDN},
			&dns.SOA{Hdr: dns.RR_Header{Name: testZoneFQDN, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: nsHostnameFQDN, Mbox: "admin."+testZoneFQDN, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300},
		},
		nsHostnameFQDN: {
			&dns.A{Hdr: dns.RR_Header{Name: nsHostnameFQDN, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(nsIP)},
		},
		"sub." + testZoneFQDN: {
			&dns.A{Hdr: dns.RR_Header{Name: "sub."+testZoneFQDN, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")},
		},
	}
	server := startMockDNSServerForRunnerTest(t, records)
	defer func() {
		server.Shutdown()
		mockDNSRecordsRunnerTest.Delete(t.Name()) // Clean up records for this test
	}()


	devices, err := device.GetDevices()
	if err != nil || len(devices) == 0 {
		t.Skip("Skipping dynamic NS test: No network devices found or error getting them.", err)
		return
	}
	activeDevice, err := device.AutoGetDevices(devices)
	if err != nil {
		t.Skip("Skipping dynamic NS test: Could not auto-select network device.", err)
		return
	}
	gologger.Infof("Using device: %s for dynamic NS test", activeDevice.Name)


	freePort, _ := freeport.GetFreePort()
	opt := &options.Options{
		Resolvers:    []string{mockServerAddrRunnerTest},
		Rate:         100,
		TimeOut:      2,
		Retry:        1,
		Silent:       false,
		EtherInfo:    activeDevice,
		OriginalDomains: []string{testZone},
		WildcardFilterMode: "none",
	}

	r, err := New(opt)
	assert.NoError(t, err)
	r.listenPort = freePort

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	// Start essential runner components for this test
	// recvChanel is crucial for processing responses that include NS records
	wg.Add(1)
	go func() { defer wg.Done(); r.recvChanel(ctx, &sync.WaitGroup{}) }() // Inner WaitGroup not used by this test's assertions

	// Manually add the domain to domainChan to simulate it being fed by loadDomainsFromSource
	// and then processed by sendCycle.
	// For a more direct test, we could call parts of sendCycle or recvChanel's processing logic.
	// Here, we will simulate the result of sendCycle: domain is in statusDB and packets are "sent".

	r.statusDB.Add(testZone, statusdb.Item{Domain: testZone, Dns: mockServerAddrRunnerTest, Time: time.Now()})

	// Simulate sending packets for all default types for the test zone
	// This would trigger NS record discovery if an NS record is returned by the mock server
	for _, dnsType := range defaultQueryTypes {
		send(testZone, mockServerAddrRunnerTest, r.options.EtherInfo, r.dnsID, uint16(r.listenPort), r.pcapHandle, dnsType)
		atomic.AddUint64(&r.sendCount, 1)
	}

	// Wait for NS discovery (net.LookupIP is async in recv.go)
	var discoveredCorrectly bool
	for i := 0; i < 40; i++ { // Poll for up to 4 seconds
		r.discoveredResolversMutex.RLock()
		ips, ok := r.discoveredResolvers[testZone]
		r.discoveredResolversMutex.RUnlock()
		if ok {
			if assert.Contains(t, ips, nsIP, "Discovered NS IP not found in map") {
				discoveredCorrectly = true
				gologger.Infof("Successfully discovered NS IP %s for zone %s", nsIP, testZone)
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	assert.True(t, discoveredCorrectly, "Failed to discover and store NS IP for %s. Check logs for NS resolution attempts.", testZone)

	if discoveredCorrectly {
		selectedResolverForSub := r.selectDNSServer("sub." + testZone)
		assert.Equal(t, nsIP, selectedResolverForSub, "selectDNSServer did not pick the discovered NS for subdomain query")
		gologger.Infof("Test: selectDNSServer correctly chose discovered NS %s for sub.%s", selectedResolverForSub, testZone)
	}

	cancel()
	wg.Wait()
	r.Close()
}


func TestDefaultQueryTypesPopulated(t *testing.T) {
	assert.NotEmpty(t, defaultQueryTypes, "defaultQueryTypes should not be empty")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeA, "Should query for A records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeMX, "Should query for MX records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeSOA, "Should query for SOA records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeCNAME, "Should query for CNAME records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeNS, "Should query for NS records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeAAAA, "Should query for AAAA records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypePTR, "Should query for PTR records by default")
	assert.Contains(t, defaultQueryTypes, layers.DNSTypeTXT, "Should query for TXT records by default")
	assert.Len(t, defaultQueryTypes, 8, "Should be 8 default query types")
}
