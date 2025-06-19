package main

import (
	"bufio"
	"context"
	"math/rand"
	"os"

	core2 "github.com/boy-hack/ksubdomain/v2/pkg/core"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/ns"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/options"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
	output2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter/output"
	processbar2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
	"github.com/urfave/cli/v2"
)

var enumCommand = &cli.Command{
	Name:    string(options.EnumType),
	Aliases: []string{"e"},
	Usage:   "枚举域名",
	Flags: append(commonFlags, []cli.Flag{
		&cli.StringFlag{
			Name:     "filename",
			Aliases:  []string{"f"},
			Usage:    "字典路径",
			Required: false,
			Value:    "",
		},
		&cli.BoolFlag{
			Name:  "ns",
			Usage: "读取域名ns记录并加入到ns解析器中",
			Value: false,
		},
		&cli.StringFlag{
			Name:    "domain-list",
			Aliases: []string{"ds"},
			Usage:   "指定域名列表文件",
			Value:   "",
		},
		&cli.UintFlag{
			Name:  "max-cname-recs",
			Usage: "Maximum CNAME recursion depth",
			Value: 10, // Default value
		},
		&cli.BoolFlag{
			Name:  "axfr",
			Usage: "Attempt AXFR for authoritative NS of input domains",
			Value: false,
		},
		&cli.IntFlag{
			Name:  "axfr-timeout",
			Usage: "Timeout in seconds for AXFR attempts",
			Value: 10, // Default AXFR timeout
		},
		&cli.StringFlag{
			Name:  "predict-dict",
			Usage: "Custom dictionary file for prediction mode",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "predict-patterns",
			Usage: "Custom patterns file for prediction mode",
			Value: "",
		},
	}...),
	Action: func(c *cli.Context) error {
		if c.NumFlags() == 0 {
			cli.ShowCommandHelpAndExit(c, "enum", 0)
		}
		var domains []string
		var processBar processbar2.ProcessBar = &processbar2.ScreenProcess{}
		var err error
		var inputDomains []string // To store the initial list of domains for OriginalDomains

		// handle domain
		if c.StringSlice("domain") != nil {
			inputDomains = append(inputDomains, c.StringSlice("domain")...)
		}
		if c.Bool("stdin") {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				inputDomains = append(inputDomains, scanner.Text())
			}
		}
		if c.String("domain-list") != "" {
			filename := c.String("domain-list")
			f, err := os.Open(filename)
			if err != nil {
				gologger.Fatalf("打开文件:%s 出现错误:%s", filename, err.Error())
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				domain := scanner.Text()
				inputDomains = append(inputDomains, domain)
			}
		}

		// domains for generation will use inputDomains, wildIPS is populated from these.
		domains = inputDomains

		wildIPS := make([]string, 0)
		// The old IsWildCard call here was problematic for a few reasons:
		// 1. It used net.LookupIP, bypassing configured resolvers.
		// 2. It was called for each domain in the list, potentially repeatedly for the same base domain if user supplied subdomains.
		// 3. Its results (a simple []string of IPs) were not structured enough for the new detection.
		// The new DetectWildcardCharacteristics is called inside runner.RunEnumeration using OriginalDomains.
		// However, the current options.WildIps field is still used by some output filters.
		// We can pre-populate it here if needed, or rely on the runner's internal detection.
		// For now, let's comment out the old wildcard check here, as the main one is in the runner.
		// If options.WildIps needs to be populated for some legacy reason before runner starts,
		// we would need to call a simplified version of DetectWildcardCharacteristics here
		// or ensure OriginalDomains are processed early.
		/*
		if c.String("wild-filter-mode") != "none" {
			// This loop is problematic if `domains` contains generated subdomains already.
			// It should ideally run only on base domains.
			for _, domain := range domains { // Should be inputDomains or unique base domains from inputDomains
				// The old runner.IsWildCard is not suitable anymore.
				// We'd need to call the new DetectWildcardCharacteristics or similar.
				// For now, the main detection is in runner.RunEnumeration.
				// If we absolutely need to populate options.WildIps here, logic would be needed.
				// ok, ips := runner.IsWildCard(domain) // This is the old call
				// if ok {
				// wildIPS = append(wildIPS, ips...)
				// gologger.Infof("发现泛解析域名:%s", sub) // sub was undefined here, should be domain
				// }
			}
		}
		*/

		render := make(chan string)
		go func() {
			defer close(render)
			filename := c.String("filename")
			if filename == "" {
				subdomainDict := core2.GetDefaultSubdomainData()
				for _, domain := range domains { // uses `domains` which is now a copy of `inputDomains`
					for _, sub := range subdomainDict {
						dd := sub + "." + domain
						render <- dd
					}
				}
			} else {
				f2, err := os.Open(filename)
				if err != nil {
					gologger.Fatalf("打开文件:%s 出现错误:%s", c.String("filename"), err.Error())
				}
				defer f2.Close()
				iofile := bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				for iofile.Scan() {
					sub := iofile.Text()
					for _, domain := range domains { // uses `domains`
						render <- sub + "." + domain
					}
				}
			}
		}()
		// 取域名的dns,加入到resolver中
		specialDns := make(map[string][]string)
		defaultResolver := options.GetResolvers(c.StringSlice("resolvers"))
		if c.Bool("ns") {
			for _, domain := range domains { // uses `domains`
				nsServers, ips, err := ns.LookupNS(domain, defaultResolver[rand.Intn(len(defaultResolver))])
				if err != nil {
					continue
				}
				specialDns[domain] = ips
					gologger.Infof("发现泛解析域名:%s", sub)
				}
			}
		}

		render := make(chan string)
		go func() {
			defer close(render)
			filename := c.String("filename")
			if filename == "" {
				subdomainDict := core2.GetDefaultSubdomainData()
				for _, domain := range domains {
					for _, sub := range subdomainDict {
						dd := sub + "." + domain
						render <- dd
					}
				}
			} else {
				f2, err := os.Open(filename)
				if err != nil {
					gologger.Fatalf("打开文件:%s 出现错误:%s", c.String("filename"), err.Error())
				}
				defer f2.Close()
				iofile := bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				for iofile.Scan() {
					sub := iofile.Text()
					for _, domain := range domains {
						render <- sub + "." + domain
					}
				}
			}
		}()
		// 取域名的dns,加入到resolver中
		specialDns := make(map[string][]string)
		defaultResolver := options.GetResolvers(c.StringSlice("resolvers"))
		if c.Bool("ns") {
			for _, domain := range domains {
				nsServers, ips, err := ns.LookupNS(domain, defaultResolver[rand.Intn(len(defaultResolver))])
				if err != nil {
					continue
				}
				specialDns[domain] = ips
				gologger.Infof("%s ns:%v", domain, nsServers)
			}

		}
		if c.Bool("not-print") {
			processBar = nil
		}

		// 输出到屏幕
		if c.Bool("not-print") {
			processBar = nil
		}

		screenWriter, err := output2.NewScreenOutput(c.Bool("silent"))
		if err != nil {
			gologger.Fatalf(err.Error())
		}
		var writer []outputter.Output
		if !c.Bool("not-print") {
			writer = append(writer, screenWriter)
		}
		if c.String("output") != "" {
			outputFile := c.String("output")
			outputType := c.String("output-type")
			wildFilterMode := c.String("wild-filter-mode")
			switch outputType {
			case "txt":
				p, err := output2.NewPlainOutput(outputFile, wildFilterMode)
				if err != nil {
					gologger.Fatalf(err.Error())
				}
				writer = append(writer, p)
			case "json":
				p := output2.NewJsonOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			case "csv":
				p := output2.NewCsvOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			default:
				gologger.Fatalf("输出类型错误:%s 暂不支持", outputType)
			}
		}
		opt := &options.Options{
			Rate:               options.Band2Rate(c.String("band")),
			Domain:             render,
			Resolvers:          defaultResolver,
			Silent:             c.Bool("silent"),
			TimeOut:            c.Int("timeout"),
			Retry:              c.Int("retry"),
			Method:             options.VerifyType,
			Writer:             writer,
			ProcessBar:         processBar,
			SpecialResolvers:   specialDns,
			WildcardFilterMode: c.String("wild-filter-mode"),
			WildIps:            wildIPS,
			Predict:            c.Bool("predict"),
			MaxCNAMERecs:       uint8(c.Uint("max-cname-recs")),
			AttemptAXFR:        c.Bool("axfr"),
			AXFRTimeout:        c.Int("axfr-timeout"),
			PredictDictFile:    c.String("predict-dict"),
			PredictPatternFile: c.String("predict-patterns"),
			OriginalDomains:    inputDomains, // Pass the collected base domains
		}
		opt.Check()
		opt.EtherInfo = options.GetDeviceConfig(defaultResolver)
		ctx := context.Background()
		r, err := runner.New(opt)
		if err != nil {
			gologger.Fatalf("%s\n", err.Error())
			return nil
		}
		r.RunEnumeration(ctx)
		r.Close()
		return nil
	},
}
