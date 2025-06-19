package utils

import (
	"testing"

	"github.com/boy-hack/ksubdomain/v2/pkg/runner" // For WildcardDetectionResult
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/stretchr/testify/assert"
)

func TestFilterWildCard_Basic(t *testing.T) {
	results := []result.Result{
		{Subdomain: "a.example.com", Answers: []string{"1.1.1.1"}, Source: "DNS"},
		{Subdomain: "b.example.com", Answers: []string{"1.1.1.1"}, Source: "DNS"}, // Wildcard IP
		{Subdomain: "c.example.com", Answers: []string{"2.2.2.2"}, Source: "DNS"},
		{Subdomain: "d.example.com", Answers: []string{"1.1.1.1", "3.3.3.3"}, Source: "DNS"}, // Has wildcard IP but also another
		{Subdomain: "e.example.com", Answers: []string{"CNAME c.wild.com"}, Source: "DNS"},
		{Subdomain: "f.example.com", Answers: []string{"CNAME wc.example.com"}, Source: "DNS"}, // Wildcard CNAME
		{Subdomain: "g.example.com", Answers: []string{"NS ns1.example.com"}, Source: "DNS"},
	}

	detectedWildcards := map[string]*runner.WildcardDetectionResult{
		"example.com": {
			IsWildcard:     true,
			WildcardIPs:    []string{"1.1.1.1"},
			WildcardCNAMEs: []string{"wc.example.com"},
		},
	}

	// Basic filtering should use the pre-detected wildcards primarily
	filtered := FilterWildCard(results, detectedWildcards)

	expectedSubdomains := []string{"c.example.com", "d.example.com", "e.example.com", "g.example.com"}
	var filteredSubdomains []string
	for _, r := range filtered {
		filteredSubdomains = append(filteredSubdomains, r.Subdomain)
	}
	assert.ElementsMatch(t, expectedSubdomains, filteredSubdomains)

	// Test case: result with only a wildcard IP should be filtered
	foundB := false
	for _, r := range filtered {
		if r.Subdomain == "b.example.com" {
			foundB = true
			break
		}
	}
	assert.False(t, foundB, "b.example.com (only wildcard IP) should have been filtered")

	// Test case: result with only a wildcard CNAME should be filtered
	foundF := false
	for _, r := range filtered {
		if r.Subdomain == "f.example.com" {
			foundF = true
			break
		}
	}
	assert.False(t, foundF, "f.example.com (only wildcard CNAME) should have been filtered")
}

func TestFilterWildCardAdvanced_WithPreDetection(t *testing.T) {
	results := []result.Result{
		{Subdomain: "a.example.com", Answers: []string{"1.1.1.1"}, Source: "DNS"}, // Pre-detected wildcard IP
		{Subdomain: "b.example.com", Answers: []string{"1.1.1.1", "2.2.2.2"}, Source: "DNS"}, // Has wildcard IP + other
		{Subdomain: "c.example.com", Answers: []string{"3.3.3.3"}, Source: "DNS"}, // Non-wildcard
		{Subdomain: "d.example.com", Answers: []string{"CNAME wc.example.com"}, Source: "DNS"}, // Pre-detected wildcard CNAME
		{Subdomain: "e.example.com", Answers: []string{"CNAME nonwild.example.com"}, Source: "DNS"},
	}
	detectedWildcards := map[string]*runner.WildcardDetectionResult{
		"example.com": {
			IsWildcard:     true,
			WildcardIPs:    []string{"1.1.1.1"},
			WildcardCNAMEs: []string{"wc.example.com"},
		},
	}

	filtered := FilterWildCardAdvanced(results, detectedWildcards)
	// Advanced filter uses a scoring system. IPs with score >= 50 are filtered.
	// Pre-detected IPs get score 75. So "1.1.1.1" will be filtered.
	// Pre-detected CNAMEs are directly marked as suspicious.

	expectedSubdomains := []string{"b.example.com", "c.example.com", "e.example.com"}
	// "a.example.com" should be filtered because its only IP "1.1.1.1" gets a high score.
	// "d.example.com" should be filtered due to suspicious CNAME.

	var filteredSubdomains []string
	for _, r := range filtered {
		filteredSubdomains = append(filteredSubdomains, r.Subdomain)
	}
	assert.ElementsMatch(t, expectedSubdomains, filteredSubdomains, "Mismatch in filtered subdomains for advanced filter")
}


func TestFilterWildCardAdvanced_FrequencyStillWorks(t *testing.T) {
	// Test that frequency analysis still works even if pre-detection missed something
	results := []result.Result{
		{Subdomain: "x1.freq.com", Answers: []string{"10.0.0.5"}, Source: "DNS"},
		{Subdomain: "x2.freq.com", Answers: []string{"10.0.0.5"}, Source: "DNS"},
		{Subdomain: "x3.freq.com", Answers: []string{"10.0.0.5"}, Source: "DNS"},
		{Subdomain: "x4.freq.com", Answers: []string{"10.0.0.5"}, Source: "DNS"},
		{Subdomain: "x5.freq.com", Answers: []string{"10.0.0.5"}, Source: "DNS"}, // 10.0.0.5 appears 5 times
		{Subdomain: "y.freq.com", Answers: []string{"10.0.0.6"}, Source: "DNS"},  // Appears once
	}
	// No pre-detected wildcards for freq.com
	detectedWildcards := map[string]*runner.WildcardDetectionResult{}

	// With totalDomains=6, 5 appearances is 83%, score for 10.0.0.5 should be high.
	// Freq > 30% => +40. PrefixVar 1/5=20% (low). Abs count 5 => +0. TLDVar 1 => -10. Score ~30.
	// Threshold is 35 for suspiciousIPs map, then 50 for filtering.
	// Let's make it more obvious: 8 domains, 7 for one IP.
	resultsForFreqTest := []result.Result{}
	for i:=0; i<7; i++ {
		resultsForFreqTest = append(resultsForFreqTest, result.Result{Subdomain: fmt.Sprintf("x%d.freq.com", i), Answers: []string{"10.0.0.5"}, Source: "DNS"})
	}
	resultsForFreqTest = append(resultsForFreqTest, result.Result{Subdomain: "y.freq.com", Answers: []string{"10.0.0.6"}, Source: "DNS"})
	// Now 10.0.0.5 is 7/8 = 87.5%. Score: Freq +40. PrefixVar 7/7=100% (high) +30 if prefixVariety > 10 (not here, prefixVariety=7).
	// Let's refine score: Freq +40. PrefixVarRatio 100, PrefixVar 7 => +20. Abs count 7 => +0. TLDVar 1 => -10. Total = 50.
	// So 10.0.0.5 should be filtered.

	filtered := FilterWildCardAdvanced(resultsForFreqTest, detectedWildcards)
	expectedSubdomains := []string{"y.freq.com"}
	var filteredSubdomains []string
	for _, r := range filtered {
		filteredSubdomains = append(filteredSubdomains, r.Subdomain)
	}
	assert.ElementsMatch(t, expectedSubdomains, filteredSubdomains, "Frequency analysis in advanced filter failed")
}


func TestWildFilterOutputResult_ModeSelection(t *testing.T) {
	results := []result.Result{{Subdomain: "a.example.com", Answers: []string{"1.1.1.1"}}}
	emptyWildcardInfo := make(map[string]*runner.WildcardDetectionResult)

	// Mode "none"
	filteredNone := WildFilterOutputResult("none", results, emptyWildcardInfo)
	assert.Equal(t, results, filteredNone, "Mode 'none' should return original results")

	// Mode "basic" - just ensure it doesn't panic, actual logic tested elsewhere
	// As FilterWildCard is complex, we assume it's tested by its own tests.
	// Here, we are testing that WildFilterOutputResult calls it.
	// To do that better, we'd need to mock FilterWildCard, which is too much for this.
	// So, just a smoke test.
	_ = WildFilterOutputResult("basic", results, emptyWildcardInfo)


	// Mode "advanced" - smoke test
	_ = WildFilterOutputResult("advanced", results, emptyWildcardInfo)

	// Unknown mode
	filteredUnknown := WildFilterOutputResult("unknown", results, emptyWildcardInfo)
	assert.Equal(t, results, filteredUnknown, "Unknown mode should return original results")

}

// Test getBaseDomain helper
func TestGetBaseDomain(t *testing.T) {
	assert.Equal(t, "example.com", getBaseDomain("www.example.com"))
	assert.Equal(t, "example.com", getBaseDomain("example.com"))
	assert.Equal(t, "example.co.uk", getBaseDomain("www.example.co.uk"))
	assert.Equal(t, "example.co.uk", getBaseDomain("sub.sub.example.co.uk"))
	assert.Equal(t, "localhost", getBaseDomain("localhost"))
	assert.Equal(t, "domain", getBaseDomain("domain")) // single part
}
