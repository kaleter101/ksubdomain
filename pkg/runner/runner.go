package runner

import (
	"context"
	"math"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/boy-hack/ksubdomain/v2/pkg/core"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/options"
	"github.com/boy-hack/ksubdomain/v2/pkg/device"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/statusdb"
	"github.com/boy-hack/ksubdomain/v2/pkg/axfr"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"go.uber.org/ratelimit"
)

// Runner 表示子域名扫描的运行时结构
type Runner struct {
	statusDB        *statusdb.StatusDb // 状态数据库
	options         *options.Options   // 配置选项
	rateLimiter     ratelimit.Limiter  // 速率限制器
	pcapHandle      *pcap.Handle       // 网络抓包句柄
	successCount    uint64             // 成功数量
	sendCount       uint64             // 发送数量
	receiveCount    uint64             // 接收数量
	failedCount     uint64             // 失败数量
	domainChan      chan string        // 域名发送通道
	resultChan      chan result.Result // 结果接收通道
	listenPort      int                // 监听端口
	dnsID           uint16             // DNS请求ID
	maxRetryCount   int                // 最大重试次数
	timeoutSeconds  int64              // 超时秒数
	initialLoadDone chan struct{}      // 初始加载完成信号
	predictLoadDone chan struct{}      // predict加载完成信号
	startTime       time.Time          // 开始时间
	stopSignal      chan struct{}      // 停止信号

	// Wildcard detection results
	baseDomains            []string // Store unique base domains from input
	wildcardDetectionMutex sync.Mutex // To protect access to wildcard results if updated concurrently
	domainWildcardInfo     map[string]*WildcardDetectionResult // Store wildcard results per base domain

	// Discovered NS resolvers
	discoveredResolvers      map[string][]string // baseDomain -> []nsIPs
	discoveredResolversMutex sync.RWMutex        // Mutex for discoveredResolvers
}

func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

// New 创建一个新的Runner实例
func New(opt *options.Options) (*Runner, error) {
	var err error
	version := pcap.Version()
	r := new(Runner)
	gologger.Infof(version)
	r.options = opt
	r.statusDB = statusdb.CreateMemoryDB()

	// 记录DNS服务器信息
	gologger.Infof("默认DNS服务器: %s\n", core.SliceToString(opt.Resolvers))
	if len(opt.SpecialResolvers) > 0 {
		var keys []string
		for k := range opt.SpecialResolvers {
			keys = append(keys, k)
		}
		gologger.Infof("特殊DNS服务器: %s\n", core.SliceToString(keys))
	}

	// 初始化网络设备
	r.pcapHandle, err = device.PcapInit(opt.EtherInfo.Device)
	if err != nil {
		return nil, err
	}

	// 设置速率限制
	cpuLimit := float64(runtime.NumCPU() * 10000)
	rateLimit := int(math.Min(cpuLimit, float64(opt.Rate)))
	r.rateLimiter = ratelimit.New(rateLimit)
	gologger.Infof("速率限制: %d pps\n", rateLimit)

	// 初始化通道
	r.domainChan = make(chan string, 50000)
	r.resultChan = make(chan result.Result, 5000)
	r.stopSignal = make(chan struct{})

	// 获取空闲端口
	freePort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	r.listenPort = freePort
	gologger.Infof("监听端口: %d\n", freePort)

	// 设置其他参数
	r.dnsID = 0x2021 // ksubdomain的生日
	r.maxRetryCount = opt.Retry
	r.timeoutSeconds = int64(opt.TimeOut)
	r.initialLoadDone = make(chan struct{})
	r.predictLoadDone = make(chan struct{})
	r.domainWildcardInfo = make(map[string]*WildcardDetectionResult)
	r.discoveredResolvers = make(map[string][]string)
	r.startTime = time.Now()


	// Perform initial wildcard detection for base domains if not in verify mode from stdin
	// This part is tricky because r.options.Domain is a channel.
	// We need a list of base domains. This is better handled in cmd/ksubdomain/enum.go
	// and results passed via options, or we need to collect base domains first.
	// For now, this logic will be primarily active if `options.OriginalDomains` (new field proposal) is populated.
	// Or, it could be done in RunEnumeration before processing starts.

	return r, nil
}

// selectDNSServer 根据域名智能选择DNS服务器
func (r *Runner) selectDNSServer(domain string) string {
	// Attempt to use discovered authoritative NS servers first
	r.discoveredResolversMutex.RLock()
	defer r.discoveredResolversMutex.RUnlock()

	// Iterate up the domain labels to find a match in discoveredResolvers
	// e.g., for "sub1.sub2.example.com", check:
	// 1. "sub1.sub2.example.com"
	// 2. "sub2.example.com"
	// 3. "example.com"
	tempDomain := domain
	for {
		if nsIPs, ok := r.discoveredResolvers[tempDomain]; ok && len(nsIPs) > 0 {
			// Found discovered NS for this zone or its parent. Use one of them.
			selectedNS := nsIPs[rand.Intn(len(nsIPs))]
			gologger.Debugf("Using discovered NS %s for domain %s (zone: %s)", selectedNS, domain, tempDomain)
			return selectedNS
		}
		dotIndex := strings.Index(tempDomain, ".")
		if dotIndex == -1 || dotIndex == len(tempDomain)-1 { // No more dots or malformed
			break
		}
		tempDomain = tempDomain[dotIndex+1:]
	}

	// Fallback to user-configured special resolvers
	if len(r.options.SpecialResolvers) > 0 {
		for suffix, servers := range r.options.SpecialResolvers {
			if strings.HasSuffix(domain, suffix) && len(servers) > 0 {
				gologger.Debugf("Using special resolver for domain %s (suffix: %s)", domain, suffix)
				return servers[rand.Intn(len(servers))]
			}
		}
	}

	// Fallback to general resolvers if no specific discovered or special resolvers found
	if len(r.options.Resolvers) > 0 {
		selectedResolver := r.options.Resolvers[rand.Intn(len(r.options.Resolvers))]
		// gologger.Debugf("Using general resolver %s for domain %s", selectedResolver, domain) // Can be too noisy
		return selectedResolver
	}

	// Should not happen if options are validated, but as a last resort:
	gologger.Warningf("No resolvers available for domain %s, defaulting to system or first known if any.", domain)
	// This could return a globally known public DNS as a last resort, or error.
	// For now, let's assume options.Resolvers always has something.
	// If r.options.Resolvers can be empty, this needs a more robust fallback.
	// Returning the first resolver if available, otherwise an empty string which will fail.
	if len(r.options.Resolvers) > 0 {
		return r.options.Resolvers[0]
	}
	return "" // This will likely cause an error upstream, which is intended if no resolvers.
}

// updateStatusBar 更新进度条状态
func (r *Runner) updateStatusBar() {
	if r.options.ProcessBar != nil {
		queueLength := r.statusDB.Length()
		elapsedSeconds := int(time.Since(r.startTime).Seconds())
		data := &processbar.ProcessData{
			SuccessIndex: r.successCount,
			SendIndex:    r.sendCount,
			QueueLength:  queueLength,
			RecvIndex:    r.receiveCount,
			FaildIndex:   r.failedCount,
			Elapsed:      elapsedSeconds,
		}
		r.options.ProcessBar.WriteData(data)
	}
}

// loadDomainsFromSource 从源加载域名
func (r *Runner) loadDomainsFromSource(wg *sync.WaitGroup) {
	defer wg.Done()
	// 从域名源加载域名
	for domain := range r.options.Domain {
		r.domainChan <- domain
	}
	// 通知初始加载完成
	r.initialLoadDone <- struct{}{}
}

// monitorProgress 监控扫描进度
func (r *Runner) monitorProgress(ctx context.Context, cancelFunc context.CancelFunc, wg *sync.WaitGroup) {
	var initialLoadCompleted bool = false
	var initialLoadPredict bool = false
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer wg.Done()
	for {
		select {
		case <-ticker.C:
			// 更新状态栏
			r.updateStatusBar()
			// 检查是否完成
			if initialLoadCompleted && initialLoadPredict {
				queueLength := r.statusDB.Length()
				if queueLength <= 0 {
					gologger.Printf("\n")
					gologger.Infof("扫描完毕")
					cancelFunc() // 使用传递的cancelFunc
					return
				}
			}
		case <-r.initialLoadDone:
			// 初始加载完成后启动重试机制
			go r.retry(ctx)
			initialLoadCompleted = true
		case <-r.predictLoadDone:
			initialLoadPredict = true
		case <-ctx.Done():
			return
		}
	}
}

// processPredictedDomains 处理预测的域名
func (r *Runner) processPredictedDomains(ctx context.Context, wg *sync.WaitGroup, predictChan chan string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case domain := <-predictChan:
			r.domainChan <- domain
		}
	}
}

// RunEnumeration 开始子域名枚举过程
func (r *Runner) RunEnumeration(ctx context.Context) {
	// Initial Wildcard Detection for base domains
	// This requires having the list of base domains.
	// Assuming r.options.OriginalDomains list is populated by the caller (e.g. main command)
	if r.options.WildcardFilterMode != "none" && len(r.options.OriginalDomains) > 0 {
		gologger.Infof("Performing initial wildcard detection...")
		// Timeout for wildcard detection can be shorter than general DNS timeout
		detectionTimeout := time.Duration(r.options.TimeOut) * time.Second / 2
		if detectionTimeout < 2*time.Second {
			detectionTimeout = 2 * time.Second // Minimum timeout
		}
		for _, baseDomain := range r.options.OriginalDomains {
			wildcardResult, err := DetectWildcardCharacteristics(baseDomain, r.options.Resolvers, detectionTimeout)
			if err != nil {
				gologger.Warningf("Error during wildcard detection for %s: %v", baseDomain, err)
			} else {
				r.wildcardDetectionMutex.Lock()
				r.domainWildcardInfo[baseDomain] = wildcardResult
				r.wildcardDetectionMutex.Unlock()
				if wildcardResult.IsWildcard {
					gologger.Infof("Wildcard detected for %s:", baseDomain)
					if len(wildcardResult.WildcardIPs) > 0 {
						gologger.Infof("  Wildcard IPs: %v", wildcardResult.WildcardIPs)
					}
					if len(wildcardResult.WildcardCNAMEs) > 0 {
						gologger.Infof("  Wildcard CNAMEs: %v", wildcardResult.WildcardCNAMEs)
					}
					// Optionally, augment r.options.WildIps here if the filtering logic primarily uses that
					// For now, the filtering logic will be modified to check r.domainWildcardInfo
				} else {
					gologger.Infof("No simple wildcard pattern detected for %s.", baseDomain)
				}
			}
		}
	}


	// 创建可取消的上下文
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	// 创建等待组
	wg := &sync.WaitGroup{}
	// Increment wg for base goroutines: recv, send, monitor, load, (predict if enabled), (axfr if enabled)
	// Initial count is 3 (recv, send, monitor)
	// loadDomainsFromSource will add 1 to wg internally but it's managed by this wg too.
	// It's better to initialize wg count accurately here.
	// Let's assume: recv, send, monitor are always there.
	// loadDomainsFromSource is also always there.
	// processPredictedDomains if r.options.Predict
	// performAXFR if r.options.AttemptAXFR
	// So, base is 4 (recv, send, monitor, load)
	baseGoRoutines := 4
	if r.options.Predict {
		baseGoRoutines++
	}
	if r.options.AttemptAXFR {
		baseGoRoutines++
	}
	wg.Add(baseGoRoutines)


	// 启动接收处理
	go r.recvChanel(ctx, wg)

	// 启动发送处理
	go r.sendCycle()

	// 监控进度
	go r.monitorProgress(ctx, cancelFunc, wg)

	// 创建预测域名通道
	predictChan := make(chan string, 1000)
	if r.options.Predict {
		wg.Add(1)
		// 启动预测域名处理
		go r.processPredictedDomains(ctx, wg, predictChan)
	} else {
		r.predictLoadDone <- struct{}{}
	}

	// 启动结果处理
	go r.handleResult(predictChan)

	// 从源加载域名
	go r.loadDomainsFromSource(wg)

	// Attempt AXFR if enabled
	if r.options.AttemptAXFR {
		wg.Add(1) // Add to waitgroup for AXFR goroutine
		go r.performAXFR(ctx, wg)
	}

	// 等待所有协程完成
	wg.Wait()

	// 关闭所有通道
	close(predictChan)
	// 安全关闭通道
	close(r.resultChan)
	close(r.domainChan)
}

// Close 关闭Runner并释放资源
func (r *Runner) Close() {
	// 关闭网络抓包句柄
	if r.pcapHandle != nil {
		r.pcapHandle.Close()
	}

	// 关闭状态数据库
	if r.statusDB != nil {
		r.statusDB.Close()
	}

	// 关闭所有输出器
	for _, out := range r.options.Writer {
		// Pass wildcardInfo to the Close method of outputters
		err := out.Close(r.domainWildcardInfo)
		if err != nil {
			gologger.Errorf("关闭输出器失败: %v", err)
		}
	}

	// 关闭进度条
	if r.options.ProcessBar != nil {
		r.options.ProcessBar.Close()
	}
}

// performAXFR attempts DNS Zone Transfers for domains with known Name Servers.
// It uses the SpecialResolvers map from options, which should be populated
// with domain -> []NS_IPs by the calling code (e.g., cmd/ksubdomain/enum.go).
func (r *Runner) performAXFR(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if len(r.options.SpecialResolvers) == 0 && !r.options.Stdin {
		// If no special resolvers (NS servers for target domains) are provided,
		// and not reading domains from stdin (where we might not know NS beforehand),
		// AXFR cannot be performed effectively for specific target domains.
		// This check might need refinement based on how input domains vs AXFR targets are handled.
		// For now, if AttemptAXFR is true but SpecialResolvers is empty, it implies
		// the user wants AXFR but hasn't provided domains for which NS were fetched,
		// or the NS fetching part in cmd didn't populate it.
		// A better approach might be to iterate r.options.Domain and try to get NS for each,
		// but that's more involved here.
		// gologger.Warningf("AXFR attempt enabled, but no specific Name Servers found for target domains in options.SpecialResolvers. AXFR will be skipped unless NS are discovered dynamically for domains from input.")
		// This message might be too noisy if AXFR is intended for domains from r.options.Domain directly.
		// The current structure of SpecialResolvers is domain -> []string of NS IPs.
		// This is typically populated if the `--ns` flag is used in `enum` command.
	}

	axfrClient := axfr.NewAXFRClient(r.options.AXFRTimeout)

	// We need a list of unique domains for which to attempt AXFR.
	// These are the keys of SpecialResolvers.
	// If SpecialResolvers is empty, but AXFR is on, it implies we might want to try AXFR
	// for domains directly from r.options.Domain if we can find their NS.
	// For simplicity, this initial implementation will only use r.options.SpecialResolvers.

	domainsToAxfr := make(map[string][]string)
	for domain, nsIPs := range r.options.SpecialResolvers {
		// Ensure domain is a base domain, not a subdomain from a dictionary.
		// This check is heuristic. A better way is to get the original list of target domains from options.
		// This part is tricky because r.options.Domain is a channel of generated subdomains.
		// We need the original list of *target zones* given by the user.
		// Assuming keys in SpecialResolvers are the target zones.
		domainsToAxfr[domain] = nsIPs
	}

	if len(domainsToAxfr) == 0 && r.options.Stdin {
		gologger.Warningf("AXFR enabled with stdin, but no specific NS servers mapped via --ns flag for input domains. AXFR may not be effective.")
		// In stdin mode without --ns, we don't have pre-fetched NS servers.
		// One could try to resolve NS for each domain from stdin here, but that adds complexity.
		// For now, AXFR will be most effective with --ns.
	}


	for domain, nsIPs := range domainsToAxfr {
		if ctx.Err() != nil { // Check context cancellation
			return
		}
		gologger.Infof("Attempting AXFR for domain %s using NS: %v", domain, nsIPs)
		for _, nsIP := range nsIPs {
			if ctx.Err() != nil {
				return
			}
			gologger.Debugf("AXFR: %s @ %s", domain, nsIP)
			results, err := axfrClient.AttemptAXFR(domain, nsIP)
			if err != nil {
				// Log common, non-critical errors at a lower level
				if strings.Contains(err.Error(), "REFUSED") || strings.Contains(err.Error(), "NOTIMP") ||
				   strings.Contains(err.Error(), "SERVFAIL") || strings.Contains(err.Error(), "i/o timeout") ||
				   strings.Contains(err.Error(), "connection refused") {
					gologger.Debugf("AXFR for %s @ %s failed: %v", domain, nsIP, err)
				} else {
					gologger.Warningf("AXFR for %s @ %s failed: %v", domain, nsIP, err)
				}
				continue // Try next NS server
			}

			if len(results) > 0 {
				gologger.Infof("AXFR for %s @ %s successful, %d records received.", domain, nsIP, len(results))
				for _, res := range results {
					// Ensure Source is set (should be done in axfrClient)
					// res.Source = "AXFR" // Double ensure, or rely on axfr.go
					select {
					case r.resultChan <- res:
					case <-ctx.Done():
						return
					}
				}
				break // Successfully transferred from one NS, typically no need to try others for the same domain.
			} else {
				gologger.Debugf("AXFR for %s @ %s resulted in 0 records.", domain, nsIP)
			}
		}
	}
}
