package utils

import (
	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"sort"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner" // For WildcardDetectionResult
	"strings"
)

// Helper to extract base domain (e.g., example.com from sub.example.com)
// This is a simplified version, real TLD/eTLD handling is complex.
func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		// Handle cases like sub.sub.example.co.uk by joining last 3, or example.com by joining last 2
		// This needs to be smarter or rely on a pre-calculated BaseDomain in result.Result
		// For now, a common case:
		if len(parts) > 2 && (len(parts[len(parts)-2]) <= 3 && len(parts[len(parts)-1]) <= 3) { // e.g. co.uk, com.au
			return strings.Join(parts[len(parts)-3:], ".")
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}


type Pair struct {
	Key   string
	Value int
}
type PairList []Pair

func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

// A function to turn a map into a PairList, then sort and return it.
func sortMapByValue(m map[string]int) PairList {
	p := make(PairList, len(m))
	i := 0
	for k, v := range m {
		p[i] = Pair{k, v}
		i++
	}
	sort.Sort(p)
	return p
}

// WildFilterOutputResult 泛解析过滤结果
func WildFilterOutputResult(outputType string, results []result.Result, wildcardInfo map[string]*runner.WildcardDetectionResult) []result.Result {
	if outputType == "none" {
		return results
	} else if outputType == "basic" {
		return FilterWildCard(results, wildcardInfo)
	} else if outputType == "advanced" {
		return FilterWildCardAdvanced(results, wildcardInfo)
	}
	return results // Return original if filter type is unknown, or handle error
}

// FilterWildCard 基于Result类型数据过滤泛解析
// 传入参数为[]result.Result，返回过滤后的[]result.Result
// 通过分析整体结果，对解析记录中相同的ip进行阈值判断，超过则丢弃该结果
func FilterWildCard(results []result.Result, detectedWildcards map[string]*runner.WildcardDetectionResult) []result.Result {
	if len(results) == 0 {
		return results
	}

	gologger.Debugf("泛解析处理中，共 %d 条记录...\n", len(results))

	// 统计每个IP出现的次数
	ipFrequency := make(map[string]int)
	// 记录IP到域名的映射关系
	ipToDomains := make(map[string][]string)
	// 域名计数
	totalDomains := len(results)

	// 第一遍扫描，统计IP频率
	for _, res := range results {
		for _, answer := range res.Answers {
			// 跳过非IP的记录(CNAME等)
			if !strings.HasPrefix(answer, "CNAME ") && !strings.HasPrefix(answer, "NS ") &&
				!strings.HasPrefix(answer, "TXT ") && !strings.HasPrefix(answer, "PTR ") {
				ipFrequency[answer]++
				ipToDomains[answer] = append(ipToDomains[answer], res.Subdomain)
			}
		}
	}

	// 按出现频率排序IP
	sortedIPs := sortMapByValue(ipFrequency)

	// 确定疑似泛解析的IP列表
	// 使用两个标准：
	// 1. IP解析超过总域名数量的特定百分比(动态阈值)
	// 2. 该IP解析的子域名数量超过特定阈值
	suspiciousIPs := make(map[string]bool) // IP => isSuspiciousByFrequency

	// Populate suspiciousIPs from pre-detected wildcards
	if detectedWildcards != nil {
		for baseDomain, wcResult := range detectedWildcards {
			if wcResult.IsWildcard {
				gologger.Debugf("Using pre-detected wildcard IPs for %s: %v", baseDomain, wcResult.WildcardIPs)
				for _, ip := range wcResult.WildcardIPs {
					suspiciousIPs[ip] = true // Mark pre-detected wildcard IPs as initially suspicious
				}
				// Pre-detected CNAMEs will be handled later, directly against result answers.
			}
		}
	}

	// Frequency-based detection (can augment or work if pre-detection is missing for a base domain)
	for _, pair := range sortedIPs {
		ip := pair.Key
		count := pair.Value

		// If already marked by pre-detection, skip frequency check or use it to reinforce
		if suspiciousIPs[ip] {
			gologger.Debugf("IP %s already marked as suspicious by pre-detection.", ip)
			continue
		}

		// 计算该IP解析占总体的百分比
		percentage := float64(count) / float64(totalDomains) * 100
		var threshold float64
		if totalDomains < 100 { threshold = 30.0 } else if totalDomains < 1000 { threshold = 20.0 } else { threshold = 10.0 }
		absoluteThreshold := 70

		if percentage > threshold || count > absoluteThreshold {
			gologger.Debugf("IP %s marked as suspicious by frequency: (count: %d, %.2f%%)", ip, count, percentage)
			suspiciousIPs[ip] = true
		}
	}

	// 第二遍扫描，过滤结果
	var filteredResults []result.Result

	for _, res := range results {
		// 检查该域名的所有IP是否均为可疑IP
		// 如果有不可疑的IP，保留该记录
		validRecord := false
		var filteredAnswers []string

		currentBaseDomain := getBaseDomain(res.Subdomain)
		wcSpecificResult, wcSpecificInfoExists := detectedWildcards[currentBaseDomain]

		for _, answer := range res.Answers {
			isCNAMERecord := strings.HasPrefix(answer, "CNAME ")
			isNSRecord := strings.HasPrefix(answer, "NS ")
			isTXTRecord := strings.HasPrefix(answer, "TXT ")
			isPTRRecord := strings.HasPrefix(answer, "PTR ")
			isOtherNonIP := isNSRecord || isTXTRecord || isPTRRecord

			if isCNAMERecord {
				cnameTarget := strings.SplitN(answer, " ", 2)[1]
				isWildcardCNAME := false
				if wcSpecificInfoExists && wcResult.IsWildcard {
					for _, wcCNAME := range wcResult.WildcardCNAMEs {
						if cnameTarget == wcCNAME {
							isWildcardCNAME = true
							break
						}
					}
				}
				if !isWildcardCNAME {
					validRecord = true
					filteredAnswers = append(filteredAnswers, answer)
				} else {
					gologger.Debugf("Filtering CNAME record %s for %s due to pre-detected wildcard CNAME %s", answer, res.Subdomain, cnameTarget)
				}
			} else if isOtherNonIP {
				validRecord = true // Keep NS, TXT, PTR etc.
				filteredAnswers = append(filteredAnswers, answer)
			} else { // IP Record
				isWildcardIPByPreDetection := false
				if wcSpecificInfoExists && wcResult.IsWildcard {
					for _, wcIP := range wcResult.WildcardIPs {
						if answer == wcIP {
							isWildcardIPByPreDetection = true
							break
						}
					}
				}

				if isWildcardIPByPreDetection {
					gologger.Debugf("Filtering IP %s for %s due to pre-detected wildcard IP.", answer, res.Subdomain)
					// Do not add to filteredAnswers, and validRecord might become false if this is the only IP
				} else if !suspiciousIPs[answer] { // Not suspicious by frequency either
					validRecord = true
					filteredAnswers = append(filteredAnswers, answer)
				} else {
					gologger.Debugf("Filtering IP %s for %s due to frequency-based wildcard detection.", answer, res.Subdomain)
				}
			}
		}

		if validRecord && len(filteredAnswers) > 0 {
			// Ensure we don't add a result if all its original IPs were filtered out
			// and it only contained IPs.
			allIPsFiltered := true
			if len(res.Answers) > 0 && len(filteredAnswers) == 0 { // All answers were IPs and all were filtered
				 for _, origAnswer := range res.Answers {
					 if strings.HasPrefix(origAnswer, "CNAME ") || strings.HasPrefix(origAnswer, "NS ") ||
						strings.HasPrefix(origAnswer, "TXT ") || strings.HasPrefix(origAnswer, "PTR ") {
						allIPsFiltered = false // It had non-IPs, so empty filteredAnswers might be valid if those non-IPs were also filtered (e.g. wildcard CNAME)
						break
					 }
				 }
			} else if len(filteredAnswers) > 0 { // Some answers remain
				allIPsFiltered = false
			}


			if !allIPsFiltered {
				// If a result originally had only IPs, and all IPs were wildcard,
				// validRecord might still be false here. We need to ensure that if filteredAnswers is empty,
				// but it was because all IPs were filtered, we don't add it.
				// The logic for validRecord needs to be robust.
				// validRecord should be true if AT LEAST ONE answer was deemed non-wildcard.
				// If all answers are filtered out, len(filteredAnswers) will be 0.

				filteredRes := result.Result{
					Subdomain: res.Subdomain,
					Answers:   filteredAnswers,
					Source:    res.Source, // Preserve original source
					CNAMEChain: res.CNAMEChain, // Preserve CNAME chain
				}
				filteredResults = append(filteredResults, filteredRes)
			} else {
				gologger.Debugf("Subdomain %s removed entirely after wildcard filtering (all its answers were wildcards).", res.Subdomain)
			}
		}
	}

	gologger.Infof("泛解析过滤完成，从 %d 条记录中过滤出 %d 条有效记录\n",
		totalDomains, len(filteredResults))

	return filteredResults
}

// FilterWildCardAdvanced 提供更高级的泛解析检测算法
// 使用多种启发式方法和特征检测来识别泛解析
func FilterWildCardAdvanced(results []result.Result, detectedWildcards map[string]*runner.WildcardDetectionResult) []result.Result {
	if len(results) == 0 {
		return results
	}

	gologger.Debugf("高级泛解析检测开始，共 %d 条记录...\n", len(results))

	// 统计IP出现频率
	ipFrequency := make(map[string]int)
	// 统计每个IP解析的不同子域名前缀数量
	ipPrefixVariety := make(map[string]map[string]bool)
	// 统计IP解析的不同顶级域数量
	ipTLDVariety := make(map[string]map[string]bool)
	// 记录IP到域名的映射
	ipToDomains := make(map[string][]string)
	// 记录CNAME信息
	cnameRecords := make(map[string][]string)

	totalDomains := len(results)

	// 第一轮：收集统计信息
	for _, res := range results {
		subdomain := res.Subdomain
		parts := strings.Split(subdomain, ".")

		// 提取顶级域和前缀
		prefix := ""
		tld := ""
		if len(parts) > 1 {
			prefix = parts[0]
			tld = strings.Join(parts[1:], ".")
		} else {
			prefix = subdomain
			tld = subdomain
		}

		for _, answer := range res.Answers {
			if strings.HasPrefix(answer, "CNAME ") {
				// 提取CNAME目标
				cnameParts := strings.SplitN(answer, " ", 2)
				if len(cnameParts) == 2 {
					cnameTarget := cnameParts[1]
					cnameRecords[subdomain] = append(cnameRecords[subdomain], cnameTarget)
				}
				continue
			}

			// 只处理IP记录
			if !strings.HasPrefix(answer, "NS ") &&
				!strings.HasPrefix(answer, "TXT ") &&
				!strings.HasPrefix(answer, "PTR ") {
				// 计数IP频率
				ipFrequency[answer]++

				// 初始化IP的前缀集合和TLD集合
				if ipPrefixVariety[answer] == nil {
					ipPrefixVariety[answer] = make(map[string]bool)
				}
				if ipTLDVariety[answer] == nil {
					ipTLDVariety[answer] = make(map[string]bool)
				}

				// 记录这个IP解析了哪些不同的前缀和TLD
				ipPrefixVariety[answer][prefix] = true
				ipTLDVariety[answer][tld] = true

				// 记录IP到域名的映射
				ipToDomains[answer] = append(ipToDomains[answer], subdomain)
			}
		}
	}

	// 按照IP频率排序
	sortedIPs := sortMapByValue(ipFrequency)

	// 识别可疑IP列表
	suspiciousIPScores := make(map[string]float64) // IP -> 可疑度分数(0-100)

	// Incorporate pre-detected wildcard IPs into scoring
	if detectedWildcards != nil {
		for baseDomain, wcResult := range detectedWildcards {
			if wcResult.IsWildcard {
				gologger.Debugf("AdvFilter: Using pre-detected wildcard IPs for %s: %v", baseDomain, wcResult.WildcardIPs)
				for _, ip := range wcResult.WildcardIPs {
					suspiciousIPScores[ip] = 75.0 // Assign a high initial score for pre-detected wildcard IPs
				}
				// Pre-detected CNAMEs will be handled later.
			}
		}
	}


	for _, pair := range sortedIPs {
		ip := pair.Key
		count := pair.Value
		currentScore := suspiciousIPScores[ip] // Get pre-assigned score or 0

		// 因子1: IP频率百分比
		freqPercentage := float64(count) / float64(totalDomains) * 100

		// 因子2: 前缀多样性
		prefixVariety := len(ipPrefixVariety[ip])
		prefixVarietyRatio := float64(prefixVariety) / float64(count) * 100

		// 因子3: TLD多样性
		tldVariety := len(ipTLDVariety[ip])

		// 计算可疑度分数
		// 1. 频率因子 - Only add if not heavily scored by pre-detection
		if currentScore < 50 { // Avoid double-counting if already high from pre-detection
			if freqPercentage > 30 { currentScore += 40 } else if freqPercentage > 10 { currentScore += 20 } else if freqPercentage > 5 { currentScore += 10 }
		}


		// 2. 前缀多样性因子
		if prefixVarietyRatio > 90 && prefixVariety > 10 { currentScore += 30 } else if prefixVarietyRatio > 70 && prefixVariety > 5 { currentScore += 20 }

		// 3. 绝对数量因子
		if count > 100 { currentScore += 20 } else if count > 50 { currentScore += 10 } else if count > 20 { currentScore += 5 }

		// 4. TLD多样性因子 - If an IP serves multiple distinct domains, it's less likely a narrow wildcard for one.
		if tldVariety > 3 { currentScore -= 20 } else if tldVariety > 1 { currentScore -= 10 }

		// Cap score at 100
		if currentScore > 100 { currentScore = 100 }
		if currentScore < 0 { currentScore = 0 } // Should not happen with current logic

		if currentScore >= 35 { // Threshold to be considered suspicious
			gologger.Debugf("Suspicious IP (Adv): %s (Count: %d, Freq: %.2f%%, PrefixVar: %d/%d, TLDVar: %d, Score: %.2f)",
				ip, count, freqPercentage, prefixVariety, count, tldVariety, currentScore)
			suspiciousIPScores[ip] = currentScore
		} else {
			delete(suspiciousIPScores, ip) // Remove if score is too low
		}
	}


	// 第二轮：过滤结果
	var filteredResults []result.Result

	// CNAME聚类分析 + pre-detected CNAMEs
	cnameTargetCount := make(map[string]int)
	for _, targets := range cnameRecords {
		for _, target := range targets {
			cnameTargetCount[target]++
		}
	}

	// 识别可疑CNAME目标
	suspiciousCNAMEs := make(map[string]bool) // CNAME target => isSuspicious

	// Add pre-detected CNAMEs
	if detectedWildcards != nil {
		for baseDomain, wcResult := range detectedWildcards {
			if wcResult.IsWildcard {
				gologger.Debugf("AdvFilter: Using pre-detected wildcard CNAMEs for %s: %v", baseDomain, wcResult.WildcardCNAMEs)
				for _, wcCNAME := range wcResult.WildcardCNAMEs {
					suspiciousCNAMEs[wcCNAME] = true
				}
			}
		}
	}

	// CNAME frequency analysis (augment pre-detection)
	for cname, count := range cnameTargetCount {
		if suspiciousCNAMEs[cname] { // Already marked by pre-detection
			gologger.Debugf("AdvFilter: CNAME %s already marked as suspicious by pre-detection.", cname)
			continue
		}
		if count > 5 && float64(count)/float64(totalDomains)*100 > 10 { // Heuristic for frequency-based CNAME wildcard
			gologger.Debugf("AdvFilter: CNAME %s marked as suspicious by frequency (count: %d)", cname, count)
			suspiciousCNAMEs[cname] = true
		}
	}

	// 过滤结果
	for _, res := range results {
		var filteredAnswers []string
		isResultValid := true // Assume valid initially

		for _, answer := range res.Answers {
			isIPRecord := !strings.HasPrefix(answer, "CNAME ") &&
				!strings.HasPrefix(answer, "NS ") &&
				!strings.HasPrefix(answer, "TXT ") &&
				!strings.HasPrefix(answer, "PTR ")

			if isIPRecord {
				score, isSuspiciousIP := suspiciousIPScores[answer]
				if isSuspiciousIP && score >= 50 { // Stricter threshold for filtering in advanced mode
					// IP is suspicious, don't add it
					gologger.Debugf("AdvFilter: Filtering IP %s for %s (score: %.2f)", answer, res.Subdomain, score)
					continue
				}
				filteredAnswers = append(filteredAnswers, answer)
			} else if strings.HasPrefix(answer, "CNAME ") {
				cnameTarget := strings.SplitN(answer, " ", 2)[1]
				if suspiciousCNAMEs[cnameTarget] {
					// CNAME target is suspicious, don't add this CNAME record
					gologger.Debugf("AdvFilter: Filtering CNAME %s for %s (target: %s)", answer, res.Subdomain, cnameTarget)
					continue
				}
				filteredAnswers = append(filteredAnswers, answer)
			} else {
				// Non-IP, non-CNAME record (NS, TXT, etc.), keep it
				filteredAnswers = append(filteredAnswers, answer)
			}
		}

		// If all answers were filtered out, the result itself is invalid
		if len(res.Answers) > 0 && len(filteredAnswers) == 0 {
			isResultValid = false
			gologger.Debugf("AdvFilter: Subdomain %s removed entirely (all answers were wildcards or suspicious).", res.Subdomain)
		}

		if isResultValid && len(filteredAnswers) > 0 {
			filteredRes := result.Result{
				Subdomain:  res.Subdomain,
				Answers:    filteredAnswers,
				CNAMEChain: res.CNAMEChain, // Preserve CNAME chain
				Source:     res.Source,     // Preserve source
			}
			filteredResults = append(filteredResults, filteredRes)
		} else if isResultValid && len(res.Answers) == 0 { // Case: original result had no answers
			filteredResults = append(filteredResults, res) // Keep it as is
		}
	}

	gologger.Infof("高级泛解析过滤完成，从 %d 条记录中过滤出 %d 条有效记录\n",
		totalDomains, len(filteredResults))

	return filteredResults
}
