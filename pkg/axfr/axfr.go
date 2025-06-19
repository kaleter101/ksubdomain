package axfr

import (
	"fmt"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/miekg/dns"
	"time"
)

// AXFRClient holds configuration for AXFR attempts.
type AXFRClient struct {
	Timeout time.Duration
}

// NewAXFRClient creates a new AXFR client with a given timeout.
func NewAXFRClient(timeoutSeconds int) *AXFRClient {
	return &AXFRClient{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
}

// AttemptAXFR tries to perform a DNS Zone Transfer (AXFR) for the given domain
// from the specified name server.
func (c *AXFRClient) AttemptAXFR(domain string, nsServer string) ([]result.Result, error) {
	var results []result.Result

	client := new(dns.Client)
	client.Net = "tcp"
	client.Timeout = c.Timeout

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	// Ensure nsServer has a port, default to 53 if not specified
	addr := nsServer
	if _, _, err := dns.SplitHostPort(nsServer); err != nil {
		addr = fmt.Sprintf("%s:%d", nsServer, 53)
	}

	transfer := new(dns.Transfer)
	channel, err := transfer.In(msg, addr)
	if err != nil {
		return nil, fmt.Errorf("AXFR request failed: %w", err)
	}

	for envelope := range channel {
		if envelope.Error != nil {
			// TODO: Distinguish between different types of errors,
			// e.g., connection refused, transfer denied, timeout.
			return nil, fmt.Errorf("AXFR transfer error: %w", envelope.Error)
		}
		for _, rr := range envelope.RR {
			// Convert dns.RR to result.Result
			// This will depend on the structure of result.Result and what data we want to capture.
			// For now, let's assume result.Result has Subdomain and Answers fields.
			// We need to handle different RR types (A, AAAA, CNAME, MX, TXT, NS, SOA, etc.)
			// and format them appropriately.

			var answers []string
			subdomain := rr.Header().Name
			// Remove trailing dot from subdomain if present
			if len(subdomain) > 0 && subdomain[len(subdomain)-1] == '.' {
				subdomain = subdomain[:len(subdomain)-1]
			}


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
				answers = append(answers, "TXT "+rec.Txt[0]) // Assuming single TXT string for simplicity
			case *dns.NS:
				answers = append(answers, "NS "+rec.Ns)
			case *dns.SOA:
				answers = append(answers, fmt.Sprintf("SOA %s %s %d %d %d %d %d", rec.Ns, rec.Mbox, rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minttl))
			// Add more record types as needed (SRV, CAA, etc.)
			default:
				// For unhandled record types, store their string representation
				answers = append(answers, rr.String())
			}

			if len(answers) > 0 {
				// TODO: The result.Result might need a "Source" field.
				// For now, we're creating a new result for each record.
				// Depending on how results are grouped, this might need adjustment.
				// If a single subdomain has multiple records (e.g., multiple A records),
				// they should ideally be grouped. The current loop creates one result per RR.
				// This will be refined later.
				res := result.Result{
					Subdomain: subdomain, // This is the record's name, not necessarily a "subdomain" of the queried zone.
					Answers:   answers,
					Source:    "AXFR",
					// CNAMEChain would be empty or not applicable here unless derived
				}
				results = append(results, res)
			}
		}
	}

	if len(results) == 0 {
		// This can happen if the zone is empty or transfer was successful but yielded no records (unlikely for valid zones)
		// Or if the channel closed without error but also without data (e.g. REFUSED might close channel without error object sometimes)
		// Consider logging or returning a specific error/status if no records are received after a supposedly successful setup.
		// For now, returning empty results and no error if transfer itself didn't error out.
	}

	return results, nil
}
