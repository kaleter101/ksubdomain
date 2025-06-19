package options

import (
	device2 "github.com/boy-hack/ksubdomain/v2/pkg/device"
	"strconv"

	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
)

type OptionMethod string

const (
	VerifyType OptionMethod = "verify"
	EnumType   OptionMethod = "enum"
	TestType   OptionMethod = "test"
)

type Options struct {
	Rate               int64              // 每秒发包速率
	Domain             chan string        // 域名输入
	Resolvers          []string           // dns resolvers
	Silent             bool               // 安静模式
	TimeOut            int                // 超时时间 单位(秒)
	Retry              int                // 最大重试次数
	Method             OptionMethod       // verify模式 enum模式 test模式
	Writer             []outputter.Output // 输出结构
	ProcessBar         processbar.ProcessBar
	EtherInfo          *device2.EtherTable // 网卡信息
	SpecialResolvers   map[string][]string // 可针对特定域名使用的dns resolvers
	WildcardFilterMode string              // 泛解析过滤模式: "basic", "advanced", "none"
	WildIps            []string
	Predict            bool  // 是否开启预测模式
	MaxCNAMERecs       uint8 // Maximum CNAME recursion depth
	AttemptAXFR        bool     // Whether to attempt AXFR
	AXFRTimeout        int      // Timeout in seconds for AXFR attempts
	PredictDictFile    string   // Custom dictionary file for prediction
	PredictPatternFile string   // Custom pattern file for prediction
	OriginalDomains    []string // List of original base domains provided by the user
}

func Band2Rate(bandWith string) int64 {
	suffix := string(bandWith[len(bandWith)-1])
	rate, _ := strconv.ParseInt(string(bandWith[0:len(bandWith)-1]), 10, 64)
	switch suffix {
	case "G":
		fallthrough
	case "g":
		rate *= 1000000000
	case "M":
		fallthrough
	case "m":
		rate *= 1000000
	case "K":
		fallthrough
	case "k":
		rate *= 1000
	default:
		gologger.Fatalf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(80) // 一个DNS包大概有74byte
	rate = rate / packSize
	return rate
}
func GetResolvers(resolvers []string) []string {
	// handle resolver
	var rs []string
	if resolvers != nil {
		for _, resolver := range resolvers {
			rs = append(rs, resolver)
		}
	} else {
		defaultDns := []string{
			"1.1.1.1",
			"8.8.8.8",
			"180.76.76.76", //百度公共 DNS
			"180.184.1.1",  //火山引擎
			"180.184.2.2",
		}
		rs = defaultDns
	}
	return rs
}

func (opt *Options) Check() {
	if opt.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
