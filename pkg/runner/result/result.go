package result

type Result struct {
	Subdomain  string   `json:"subdomain"`
	Answers    []string `json:"answers"`
	CNAMEChain []string `json:"cname_chain,omitempty"`
	Source     string   `json:"source,omitempty"` // e.g., "DNS", "AXFR"
}
