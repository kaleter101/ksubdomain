package runner

import (
	"fmt"
	"github.com/boy-hack/ksubdomain/v2/pkg/core"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/miekg/dns"
	"strings"
	"time"
)

const (
	defaultProbeCount = 15 // Increased number of probes
	wildcardThreshold = 0.8 // 80% threshold for considering it a wildcard
)

// WildcardDetectionResult holds the results of wildcard detection.
type WildcardDetectionResult struct {
	IsWildcard      bool
	WildcardIPs     []string
	WildcardCNAMEs  []string
	ProbeAnswers    map[string][]string // Stores answers for each probe, useful for advanced analysis
}


// DetectWildcardCharacteristics performs DNS queries for random subdomains to detect wildcard patterns.
// It uses the provided list of resolvers.
func DetectWildcardCharacteristics(domain string, resolvers []string, timeout time.Duration) (*WildcardDetectionResult, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no resolvers provided for wildcard detection")
	}

	result := &WildcardDetectionResult{
		ProbeAnswers: make(map[string][]string),
	}

	ipCounts := make(map[string]int)
	cnameCounts := make(map[string]int)
	resolvedProbeCount := 0

	client := new(dns.Client)
	client.Timeout = timeout
	client.Net = "udp" // Using UDP for standard queries

	var allProbedIPs []string
	var allProbedCNAMEs []string

	for i := 0; i < defaultProbeCount; i++ {
		probeSubdomain := core.RandomStr(7) + "." + domain // Generate a random subdomain
		var probeAnswers []string

		// Try A record
		msgA := new(dns.Msg)
		msgA.SetQuestion(dns.Fqdn(probeSubdomain), dns.TypeA)

		var lastErr error
		var inA *dns.Msg
		// Try each resolver until one succeeds for this probe
		for _, resolver := range resolvers {
			resolverAddr := resolver
			if !strings.Contains(resolverAddr, ":") {
				resolverAddr = fmt.Sprintf("%s:53", resolverAddr)
			}
			inA, _, lastErr = client.Exchange(msgA, resolverAddr)
			if lastErr == nil && inA != nil && inA.Rcode == dns.RcodeSuccess {
				break
			}
		}


		if lastErr == nil && inA != nil && inA.Rcode == dns.RcodeSuccess {
			resolvedThisProbe := false
			for _, ans := range inA.Answer {
				if a, ok := ans.(*dns.A); ok {
					ipStr := a.A.String()
					ipCounts[ipStr]++
					allProbedIPs = append(allProbedIPs, ipStr)
					probeAnswers = append(probeAnswers, "A:"+ipStr)
					resolvedThisProbe = true
				}
				// Also check for CNAME in A query response (though less common for final answer)
				if c, ok := ans.(*dns.CNAME); ok {
					cnameTarget := strings.TrimSuffix(c.Target, ".")
					cnameCounts[cnameTarget]++
					allProbedCNAMEs = append(allProbedCNAMEs, cnameTarget)
					probeAnswers = append(probeAnswers, "CNAME:"+cnameTarget)
					// If CNAME found, we might not get an A record directly for the probe name
					// but the CNAME itself is a wildcard indicator.
					resolvedThisProbe = true
				}
			}
			if resolvedThisProbe {
				resolvedProbeCount++
			}
		} else if lastErr != nil {
			gologger.Debugf("Wildcard probe for %s (A) failed: %v (resolver: %s)", probeSubdomain, lastErr, resolvers)
		}


		// Try CNAME record explicitly if A record didn't give definitive CNAME
		// This is important if a wildcard is *.example.com CNAME wc.example.com
		// and wc.example.com then resolves to an IP. The A query for random.example.com
		// might directly return the IP of wc.example.com (due to recursive resolver).
		// An explicit CNAME query ensures we see the CNAME.
		msgCNAME := new(dns.Msg)
		msgCNAME.SetQuestion(dns.Fqdn(probeSubdomain), dns.TypeCNAME)

		var inCNAME *dns.Msg
		lastErr = nil
		for _, resolver := range resolvers {
			resolverAddr := resolver
			if !strings.Contains(resolverAddr, ":") {
				resolverAddr = fmt.Sprintf("%s:53", resolverAddr)
			}
			inCNAME, _, lastErr = client.Exchange(msgCNAME, resolverAddr)
			if lastErr == nil && inCNAME != nil && inCNAME.Rcode == dns.RcodeSuccess {
				break
			}
		}


		if lastErr == nil && inCNAME != nil && inCNAME.Rcode == dns.RcodeSuccess {
			foundCNAMEInExplicitQuery := false
			for _, ans := range inCNAME.Answer {
				if c, ok := ans.(*dns.CNAME); ok {
					cnameTarget := strings.TrimSuffix(c.Target, ".")
					// Avoid double counting if already found via A query's additional section
					if !contains(allProbedCNAMEs, cnameTarget) {
						cnameCounts[cnameTarget]++
						allProbedCNAMEs = append(allProbedCNAMEs, cnameTarget)
					}
					// Check if this CNAME is already in probeAnswers to avoid duplicates for this specific probe
					newAnswer := "CNAME:" + cnameTarget
					isNewAnswerForProbe := true
					for _, pa := range probeAnswers {
						if pa == newAnswer {
							isNewAnswerForProbe = false
							break
						}
					}
					if isNewAnswerForProbe {
						probeAnswers = append(probeAnswers, newAnswer)
					}
					foundCNAMEInExplicitQuery = true
				}
			}
			// If we found a CNAME, and no A record was found for the original probe name,
			// this contributes to resolvedProbeCount.
			if foundCNAMEInExplicitQuery && !strings.Contains(strings.Join(probeAnswers, ","), "A:") {
				// Check if we already incremented resolvedProbeCount for this probe due to CNAME in A response
				alreadyCounted := false
				for _, pa := range result.ProbeAnswers[probeSubdomain] {
					if strings.HasPrefix(pa, "CNAME:") {
						alreadyCounted = true
						break
					}
				}
				if !alreadyCounted {
					resolvedProbeCount++
				}
			}
		} else if lastErr != nil {
			gologger.Debugf("Wildcard probe for %s (CNAME) failed: %v (resolver: %s)", probeSubdomain, lastErr, resolvers)
		}
		if len(probeAnswers) > 0 {
			result.ProbeAnswers[probeSubdomain] = probeAnswers
		}
	}

	if resolvedProbeCount == 0 {
		gologger.Debugf("Wildcard detection for %s: No random probes resolved.", domain)
		result.IsWildcard = false // Or could be true if this is desired behavior for "everything NXDOMAIN"
		return result, nil
	}

	// Analyze IP counts
	for ip, count := range ipCounts {
		if float64(count)/float64(resolvedProbeCount) >= wildcardThreshold {
			result.IsWildcard = true
			result.WildcardIPs = append(result.WildcardIPs, ip)
		}
	}

	// Analyze CNAME counts
	for cname, count := range cnameCounts {
		if float64(count)/float64(resolvedProbeCount) >= wildcardThreshold {
			result.IsWildcard = true // CNAME wildcard
			result.WildcardCNAMEs = append(result.WildcardCNAMEs, cname)
		}
	}

	// If IsWildcard is true, ensure WildcardIPs and WildcardCNAMEs are unique
	if result.IsWildcard {
		result.WildcardIPs = unique(result.WildcardIPs)
		result.WildcardCNAMEs = unique(result.WildcardCNAMEs)
	}

	// Additional logic: if multiple distinct IPs/CNAMEs are common, it's complex.
	// For now, any IP/CNAME meeting threshold makes it a wildcard.
	// If *no* single IP/CNAME meets the threshold but many probes resolve, it's likely not a simple wildcard.
	if !result.IsWildcard && resolvedProbeCount > defaultProbeCount/2 {
		gologger.Debugf("Wildcard detection for %s: Probes resolved to diverse records, not a simple wildcard.", domain)
	}


	return result, nil
}

// unique returns a unique slice of strings
func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// contains checks if a slice of strings contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

[end of pkg/runner/wildcard.go]
