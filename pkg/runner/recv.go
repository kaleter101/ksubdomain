package runner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"net"
	"strings"

	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/statusdb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// getBaseDomain extracts the base domain from a given domain string.
// e.g., "sub.example.com" -> "example.com", "example.com" -> "example.com".
// This is a simplified version; robust eTLD handling is more complex.
func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		// Handle cases like sub.sub.example.co.uk or example.com
		// This heuristic might need adjustment for complex TLDs (e.g. .com.cn)
		// A common approach is to check if the second to last part is a common TLD (co, com, org, net etc.)
		// and the last part is a country code or generic TLD.
		// For simplicity here, if more than 2 parts, take last two.
		// If a more robust eTLD/PSL library was available and simple to integrate, that would be better.
		// Example: if parts are [sub, example, co, uk], this takes "co.uk"
		// if parts are [www, example, com], this takes "example.com"
		// This needs to be consistent with how it's used for storing/retrieving from discoveredResolvers.
		// A simpler rule: if more than 2 parts, always take the last 2.
		// This means for "www.example.co.uk", it would consider "co.uk" the base, which is not ideal.
		// Let's refine:
		if len(parts) >= 2 {
			// Check for common TLD patterns like .co.uk, .com.au
			if len(parts) > 2 && (len(parts[len(parts)-2]) <= 3 && len(parts[len(parts)-1]) <= 3) {
				// Heuristic for something like "example.co.uk" -> "example.co.uk"
				// or "www.example.co.uk" -> "example.co.uk"
				return strings.Join(parts[len(parts)-3:], ".")
			}
			// Default for "www.example.com" -> "example.com"
			return strings.Join(parts[len(parts)-2:], ".")
		}
	}
	return domain // If 1 or 2 parts, it's already a base domain or a TLD itself.
}


// dnsRecord2String 将DNS记录转换为字符串
func dnsRecord2String(rr layers.DNSResourceRecord) (string, error) {
	if rr.Class == layers.DNSClassIN {
		switch rr.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if rr.IP != nil {
				return rr.IP.String(), nil
			}
		case layers.DNSTypeNS:
			if rr.NS != nil {
				return "NS " + string(rr.NS), nil
			}
		case layers.DNSTypeCNAME:
			if rr.CNAME != nil {
				return "CNAME " + string(rr.CNAME), nil
			}
		case layers.DNSTypePTR:
			if rr.PTR != nil {
				return "PTR " + string(rr.PTR), nil
			}
		case layers.DNSTypeTXT:
			if rr.TXT != nil {
				// TXT records can have multiple strings, gopacket's rr.TXT is already a []string
				// For simplicity, join them if multiple, or return the first.
				// Or, more accurately, represent them as they are if result.Answers can handle multiple strings per "answer type".
				// Current convention is "TYPE value". So for TXT, it might be "TXT value1" "TXT value2" if answers are split.
				// If a single string is expected, joining is common.
				if len(rr.TXTs) > 0 { // rr.TXTs is [][]byte
					var parts []string
					for _, txt := range rr.TXTs {
						parts = append(parts, string(txt))
					}
					return "TXT " + strings.Join(parts, " "), nil
				}
			}
		case layers.DNSTypeMX:
			if rr.MX != nil { // rr.MX is layers.DNSMX
				return fmt.Sprintf("MX %d %s", rr.MX.Preference, string(rr.MX.Name)), nil
			}
		case layers.DNSTypeSOA:
			if rr.SOA != nil { // rr.SOA is layers.DNSSOA
				return fmt.Sprintf("SOA %s %s %d %d %d %d %d",
					string(rr.SOA.MName), string(rr.SOA.RName),
					rr.SOA.Serial, rr.SOA.Refresh, rr.SOA.Retry,
					rr.SOA.Expire, rr.SOA.Minimum), nil
			}
		}
	}
	// For any other unhandled type or if data is nil
	return "", errors.New("dns record error or unhandled type")
}

// 预分配解码器对象池，避免频繁创建
var decoderPool = sync.Pool{
	New: func() interface{} {
		var eth layers.Ethernet
		var ipv4 layers.IPv4
		var ipv6 layers.IPv6
		var udp layers.UDP
		var dns layers.DNS
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &udp, &dns)

		return &decodingContext{
			parser:  parser,
			eth:     &eth,
			ipv4:    &ipv4,
			ipv6:    &ipv6,
			udp:     &udp,
			dns:     &dns,
			decoded: make([]gopacket.LayerType, 0, 5),
		}
	},
}

// decodingContext 解码上下文
type decodingContext struct {
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	ipv4    *layers.IPv4
	ipv6    *layers.IPv6
	udp     *layers.UDP
	dns     *layers.DNS
	decoded []gopacket.LayerType
}

// 解析DNS响应包并处理
func (r *Runner) processPacket(data []byte, dnsChanel chan<- layers.DNS) {
	// 从对象池获取解码器
	dc := decoderPool.Get().(*decodingContext)
	defer decoderPool.Put(dc)

	// 清空解码层类型切片
	dc.decoded = dc.decoded[:0]

	// 解析数据包
	err := dc.parser.DecodeLayers(data, &dc.decoded)
	if err != nil {
		return
	}

	// 检查是否为DNS响应
	if !dc.dns.QR {
		return
	}

	// 确认DNS ID匹配
	if dc.dns.ID != r.dnsID {
		return
	}

	// 确认有查询问题
	if len(dc.dns.Questions) == 0 {
		return
	}

	// 记录接收包数量
	atomic.AddUint64(&r.receiveCount, 1)

	// 向处理通道发送DNS响应
	select {
	case dnsChanel <- *dc.dns:
	}
}

// recvChanel 实现接收DNS响应的功能
func (r *Runner) recvChanel(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var (
		snapshotLen = 65536
		timeout     = 5 * time.Second
		err         error
	)
	inactive, err := pcap.NewInactiveHandle(r.options.EtherInfo.Device)
	if err != nil {
		gologger.Errorf("创建网络捕获句柄失败: %v", err)
		return
	}
	err = inactive.SetSnapLen(snapshotLen)
	if err != nil {
		gologger.Errorf("设置抓包长度失败: %v", err)
		return
	}
	defer inactive.CleanUp()

	if err = inactive.SetTimeout(timeout); err != nil {
		gologger.Errorf("设置超时失败: %v", err)
		return
	}

	err = inactive.SetImmediateMode(true)
	if err != nil {
		gologger.Errorf("设置即时模式失败: %v", err)
		return
	}

	handle, err := inactive.Activate()
	if err != nil {
		gologger.Errorf("激活网络捕获失败: %v", err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("udp and src port 53 and dst port %d", r.listenPort))
	if err != nil {
		gologger.Errorf("设置BPF过滤器失败: %v", err)
		return
	}

	// 创建DNS响应处理通道，缓冲大小适当增加
	dnsChanel := make(chan layers.DNS, 10000)

	// 使用多个协程处理DNS响应，提高并发效率
	processorCount := runtime.NumCPU() * 2
	var processorWg sync.WaitGroup
	processorWg.Add(processorCount)

	// 启动多个处理协程
	for i := 0; i < processorCount; i++ {
		go func() {
			defer processorWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case dns, ok := <-dnsChanel:
					if !ok {
						return
					}

					domainItem, ok := r.statusDB.Get(string(dns.Questions[0].Name))
					if !ok {
						// If not found in statusDB, it might have timed out or been cleaned up.
						continue
					}

					// Delete the current domain from statusDB as it's being processed.
					// CNAME targets will be added back to statusDB if further resolution is needed.
					r.statusDB.Del(string(dns.Questions[0].Name))

					if dns.ANCount > 0 {
						atomic.AddUint64(&r.successCount, 1)
						var answers []string
						var localCnameChain []string // CNAMEs found for the current domain resolution
						var hasNonCNAMERecord bool = false
						var currentQueryBaseDomain string // To store base domain of the current query

						// Determine base domain of the current query for NS discovery context
						if len(dns.Questions) > 0 {
							currentQueryBaseDomain = getBaseDomain(string(dns.Questions[0].Name))
						}

						for _, v := range dns.Answers {
							answer, err := dnsRecord2String(v)
							if err != nil {
								// Log or handle error if needed, or just skip
								continue
							}
							answers = append(answers, answer)

							switch v.Type {
							case layers.DNSTypeCNAME:
								cnameTarget := string(v.CNAME)
								if len(cnameTarget) > 0 && cnameTarget[len(cnameTarget)-1] == '.' {
									cnameTarget = cnameTarget[:len(cnameTarget)-1]
								}
								localCnameChain = append(localCnameChain, cnameTarget)

								if domainItem.CNAMEDepth < r.options.MaxCNAMERecs {
									newOriginalQuery := domainItem.Domain
									if domainItem.OriginalQuery != "" {
										newOriginalQuery = domainItem.OriginalQuery
									}
									newItem := statusdb.Item{
										Domain:        cnameTarget,
										Dns:           domainItem.Dns,
										Time:          time.Now(),
										Retry:         0,
										DomainLevel:   domainItem.DomainLevel,
										CNAMEDepth:    domainItem.CNAMEDepth + 1,
										OriginalQuery: newOriginalQuery,
									}
									r.statusDB.Add(cnameTarget, newItem)
									r.domainChan <- cnameTarget
								} else {
									gologger.Warningf("Max CNAME recursion depth %d reached for %s (target: %s)", r.options.MaxCNAMERecs, domainItem.Domain, cnameTarget)
								}
							case layers.DNSTypeA, layers.DNSTypeAAAA:
								hasNonCNAMERecord = true
							case layers.DNSTypeNS:
								nsHostname := string(v.NS)
								nsHostnameClean := strings.TrimSuffix(nsHostname, ".")
								// Resolve NS hostname to IP
								go func(nsHost string, authoritativeDomain string) {
									ips, err := net.LookupIP(nsHost)
									if err == nil && len(ips) > 0 {
										var ipStrings []string
										for _, ip := range ips {
											ipStrings = append(ipStrings, ip.String())
										}
										r.discoveredResolversMutex.Lock()
										defer r.discoveredResolversMutex.Unlock()

										// Add to existing list or create new
										currentDiscovered := r.discoveredResolvers[authoritativeDomain]
										newlyFoundIPs := []string{}
										for _, ipStr := range ipStrings {
											isNew := true
											for _, existingIP := range currentDiscovered {
												if existingIP == ipStr {
													isNew = false
													break
												}
											}
											if isNew {
												newlyFoundIPs = append(newlyFoundIPs, ipStr)
											}
										}
										if len(newlyFoundIPs) > 0 {
											r.discoveredResolvers[authoritativeDomain] = append(currentDiscovered, newlyFoundIPs...)
											gologger.Infof("Discovered NS for %s: %s (%v). Added to dynamic resolvers.", authoritativeDomain, nsHost, newlyFoundIPs)
										}
									} else if err != nil {
										gologger.Debugf("Failed to resolve NS hostname %s: %v", nsHost, err)
									}
								}(nsHostnameClean, currentQueryBaseDomain) // Use currentQueryBaseDomain
							}
						}

						finalSubdomain := domainItem.Domain
						if domainItem.OriginalQuery != "" {
							finalSubdomain = domainItem.OriginalQuery
						}

						// Construct the result.
						// The CNAMEChain in the result should ideally be the full chain leading to the final answer.
						// This might require combining domainItem.CNAMEChain (if we decide to store it there)
						// with localCnameChain. For now, let's use localCnameChain.
						// A more complete solution would accumulate the chain.
						// If domainItem itself was a CNAME target, its OriginalQuery field helps link back.

						currentResult := result.Result{
							Subdomain:  finalSubdomain, // Report under original query if applicable
							Answers:    answers,
							CNAMEChain: localCnameChain, // This specific step's CNAMEs
						}

						// When to send to resultChan:
						// 1. If there are non-CNAME answers (A, AAAA).
						// 2. If it's a CNAME resolution, but we've hit max depth.
						// 3. If it's a CNAME resolution, but it resolves to a CNAME that itself has no further resolution (e.g., CNAME to NXDOMAIN - though this is harder to detect here).
						// The key is to ensure that chains are followed, but intermediate CNAME steps don't prematurely hide the final result.
						// If localCnameChain is not empty AND there are no A/AAAA records, it means this is an intermediate CNAME step.
						// We rely on the recursive query for the CNAME target to eventually produce A/AAAA records.
						if hasNonCNAMERecord || (len(localCnameChain) > 0 && domainItem.CNAMEDepth >= r.options.MaxCNAMERecs) || len(localCnameChain) == 0 {
						    // If domainItem.OriginalQuery is set, it means the current dns.Question[0].Name was a CNAME itself.
							// We need to ensure the CNAMEChain is correctly built up.
							// This might involve retrieving the parent's CNAME chain from statusdb or passing it down.
							// For now, the CNAMEChain in the result only contains CNAMEs from *this* resolution step.
							// A truly full chain would require more state passing.

							// Let's refine the CNAMEChain for the result:
							// If the current domainItem had an OriginalQuery, it implies it was part of a CNAME chain.
							// We should try to prepend its own name to the localCnameChain if it's not already there
							// and if it's different from the finalSubdomain.
							// This part is tricky and might need a dedicated CNAME chain tracker.
							// For now, the CNAMEChain in result will be what was resolved *for* domainItem.Domain.
							// If domainItem.Domain was 'cname1.example.com' and it resolved to 'cname2.example.com',
							// then CNAMEChain will be ['cname2.example.com'].
							// If 'orig.example.com' CNAME 'cname1.example.com' CNAME 'cname2.example.com' A '1.2.3.4',
							// the final result for 'orig.example.com' should ideally show ['cname1.example.com', 'cname2.example.com'].
							// This requires accumulating the chain.

							// Simplification: if domainItem.OriginalQuery is present, this means domainItem.Domain is a CNAME.
							// The 'localCnameChain' contains what *it* resolves to.
							// The result for 'domainItem.OriginalQuery' will eventually be built.
							// We only send results that are "final" (A/AAAA) or hit recursion limit.
							r.resultChan <- currentResult
						}
					} else if domainItem.CNAMEDepth > 0 && domainItem.CNAMEDepth >= r.options.MaxCNAMERecs {
						// Handle case where a CNAME record resolution times out or returns no answer, but max depth is hit.
						// Report what we have for the original query.
						finalSubdomain := domainItem.Domain
						if domainItem.OriginalQuery != "" {
							finalSubdomain = domainItem.OriginalQuery
						}
						r.resultChan <- result.Result{
							Subdomain: finalSubdomain,
							Answers:   []string{}, // No answers found
							CNAMEChain: []string{domainItem.Domain}, // At least record itself if it was a CNAME
						}
					}
				}
			}
		}()
	}
	// 使用多个接收协程读取网络数据包
	packetChan := make(chan []byte, 10000)

	// 启动数据包接收协程
	go func() {
		for {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				if errors.Is(err, pcap.NextErrorTimeoutExpired) {
					continue
				}
				return
			}

			select {
			case <-ctx.Done():
				return
			case packetChan <- data:
				// 数据包已发送到处理通道
			}
		}
	}()

	// 启动多个数据包解析协程
	parserCount := runtime.NumCPU() * 2
	var parserWg sync.WaitGroup
	parserWg.Add(parserCount)

	for i := 0; i < parserCount; i++ {
		go func() {
			defer parserWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case data, ok := <-packetChan:
					if !ok {
						return
					}
					r.processPacket(data, dnsChanel)
				}
			}
		}()
	}

	// 等待上下文结束
	<-ctx.Done()

	// 关闭通道
	close(packetChan)
	close(dnsChanel)

	// 等待所有处理和解析协程结束
	parserWg.Wait()
	processorWg.Wait()
}
