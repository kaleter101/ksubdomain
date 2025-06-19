package output

import (
	"encoding/csv"
	"os"
	"strings" // Added for strings.Join

	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner" // Added for WildcardDetectionResult
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/boy-hack/ksubdomain/v2/pkg/utils"
)

type CsvOutput struct {
	domains        []result.Result
	filename       string
	wildFilterMode string
}

func NewCsvOutput(filename string, wildFilterMode string) *CsvOutput {
	f := new(CsvOutput)
	f.domains = make([]result.Result, 0)
	f.filename = filename
	f.wildFilterMode = wildFilterMode
	return f
}

func (f *CsvOutput) WriteDomainResult(domain result.Result) error {
	f.domains = append(f.domains, domain)
	return nil
}

func (f *CsvOutput) Close(wildcardInfo map[string]*runner.WildcardDetectionResult) error {
	gologger.Infof("写入csv文件:%s\n", f.filename)

	if len(f.domains) == 0 {
		gologger.Infof("没有发现子域名结果，CSV文件将为空\n")
		// Create file with headers even if no domains
		file, err := os.Create(f.filename)
		if err != nil {
			gologger.Errorf("创建空的CSV文件失败: %v", err)
			return err
		}
		defer file.Close()
		writer := csv.NewWriter(file)
		defer writer.Flush()
		header := []string{"Subdomain", "Answers", "Source", "CNAMEChain"}
		_ = writer.Write(header) // Write header
		return nil
	}

	results := utils.WildFilterOutputResult(f.wildFilterMode, f.domains, wildcardInfo)
	gologger.Infof("过滤后结果数量: %d\n", len(results))

	// 创建CSV文件
	file, err := os.Create(f.filename)
	if err != nil {
		gologger.Errorf("创建CSV文件失败: %v", err)
		return err
	}
	defer file.Close()

	// 创建CSV写入器
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	header := []string{"Subdomain", "Answers", "Source", "CNAMEChain"} // Added Source and CNAMEChain
	err = writer.Write(header)
	if err != nil {
		gologger.Errorf("写入CSV头部失败: %v", err)
		return err // If header fails, probably no point continuing
	}

	if len(results) == 0 {
		gologger.Infof("经过通配符过滤后没有有效结果，CSV文件将只包含头部\n")
		return nil
	}

	// 写入数据行
	for _, result := range results {
		// 将Answers数组转换为单个字符串，用分号分隔
		answersStr := ""
		if len(result.Answers) > 0 {
			answersStr = result.Answers[0]
			for i := 1; i < len(result.Answers); i++ {
				answersStr += ";" + result.Answers[i]
			}
		}

		err = writer.Write([]string{result.Subdomain, answersStr, result.Source, strings.Join(result.CNAMEChain, ";")})
		if err != nil {
			gologger.Errorf("写入CSV数据行失败: %v", err)
			continue // Skip problematic row
		}
	}
	gologger.Infof("CSV文件写入成功，共写入 %d 条记录", len(results))
	return nil
}
