# KSubdomain: 极速无状态子域名爆破工具

[![Release](https://img.shields.io/github/release/boy-hack/ksubdomain.svg)](https://github.com/boy-hack/ksubdomain/releases) [![Go Report Card](https://goreportcard.com/badge/github.com/boy-hack/ksubdomain)](https://goreportcard.com/report/github.com/boy-hack/ksubdomain) [![License](https://img.shields.io/github/license/boy-hack/ksubdomain)](https://github.com/boy-hack/ksubdomain/blob/main/LICENSE)

**KSubdomain 是一款基于无状态技术的子域名爆破工具，带来前所未有的扫描速度和极低的内存占用。** 告别传统工具的效率瓶颈，体验闪电般的 DNS 查询，同时拥有可靠的状态表重发机制，确保结果的完整性。 KSubdomain 支持 Windows、Linux 和 macOS，是进行大规模DNS资产探测的理想选择。

![](image.gif)

## 🚀 核心优势

*   **闪电般的速度:** 采用无状态扫描技术，直接操作网络适配器进行原始套接字发包，绕过系统内核的网络协议栈，实现惊人的发包速率。通过 `test` 命令可探测本地网卡的最大发送速度。
*   **极低的资源消耗:** 创新的内存管理机制，包括对象池和全局内存池，显著降低内存分配和 GC 压力，即使处理海量域名也能保持低内存占用。
*   **无状态设计:** 类似 Masscan 的无状态扫描，不从系统维护状态表，自建轻量状态表，从根本上解决了传统扫描工具的内存瓶颈和性能限制，以及解决了无状态扫描漏包问题。
*   **可靠的重发:** 内建智能重发机制，有效应对网络抖动和丢包，确保结果的准确性和完整性。
*   **跨平台支持:** 完美兼容 Windows, Linux, macOS。
*   **易于使用:** 简洁的命令行接口，提供验证 (verify) 和枚举 (enum) 两种模式，并内置常用字典。

## ⚡ 性能亮点

KSubdomain 在速度和效率上远超同类工具。以下是在 4 核 CPU、5M 带宽网络环境下，使用 10 万字典进行的对比测试：

| 工具         | 扫描模式 | 发包方式     | 命令                                                                       | 耗时           | 成功个数 | 备注                      |
| ------------ | -------- | ------------ | -------------------------------------------------------------------------- | -------------- | -------- | ------------------------- |
| **KSubdomain** | 验证     | pcap 网卡发包 | `time ./ksubdomain v -b 5m -f d2.txt -o k.txt -r dns.txt --retry 3 --np`  | **~30 秒**     | 1397     | `--np` 关闭实时打印       |
| massdns      | 验证     | pcap/socket  | `time ./massdns -r dns.txt -t A -w m.txt d2.txt --root -o L`                 | ~3 分 29 秒    | 1396     |                           |
| dnsx         | 验证     | socket       | `time ./dnsx -a -o d.txt -r dns.txt -l d2.txt -retry 3 -t 5000`             | ~5 分 26 秒    | 1396     | `-t 5000` 设置 5000 并发 |

**结论:** KSubdomain 的速度是 massdns 的 **7 倍**，是 dnsx 的 **10 倍** 以上！
## 🛠️ 技术革新 (v2.0)

KSubdomain 2.0 版本引入了多项底层优化，进一步压榨性能潜力：

1.  **状态表优化:**
    *   **分片锁 (Sharded Lock):** 替代全局锁，大幅减少锁竞争，提高并发写入效率。
    *   **高效哈希:** 优化键值存储，均匀分布域名，提升查找速度。
2.  **发包机制优化:**
    *   **对象池:** 复用 DNS 包结构体，减少内存分配和 GC 开销。
    *   **模板缓存:** 为相同 DNS 服务器复用以太网/IP/UDP 层数据，减少重复构建开销。
    *   **并行发送:** 多协程并行发包，充分利用多核 CPU 性能。
    *   **批量处理:** 批量发送域名请求，减少系统调用和上下文切换。
3.  **接收机制优化:**
    *   **对象池:** 复用解析器和缓冲区，降低内存消耗。
    *   **并行处理管道:** 接收 → 解析 → 处理三阶段并行，提高处理流水线效率。
    *   **缓冲区优化:** 增加内部 Channel 缓冲区大小，避免处理阻塞。
    *   **高效过滤:** 优化 BPF 过滤规则和包处理逻辑，快速丢弃无效数据包。
4.  **内存管理优化:**
    *   **全局内存池:** 引入 `sync.Pool` 管理常用数据结构，减少内存分配和碎片。
    *   **结构复用:** 复用 DNS 查询结构和序列化缓冲区。
5.  **架构与并发优化:**
    *   **动态并发:** 根据 CPU 核心数自动调整协程数量。
    *   **高效随机数:** 使用性能更优的随机数生成器。
    *   **自适应速率:** 根据网络状况和系统负载动态调整发包速率。
    *   **批量加载:** 批量加载和处理域名，降低单个域名处理的固定开销。

## 📦 安装

1.  **下载预编译二进制文件:** 前往 [Releases](https://github.com/boy-hack/ksubdomain/releases) 页面下载对应系统的最新版本。
2.  **安装 `libpcap` 依赖:**
    *   **Windows:** 下载并安装 [Npcap](https://npcap.com/) 驱动 (WinPcap 可能无效)。
    *   **Linux:** 已静态编译打包 `libpcap`，通常无需额外操作。若遇问题，请尝试安装 `libpcap-dev` 或 `libcap-devel` 包。
    *   **macOS:** 系统自带 `libpcap`，无需安装。
3.  **赋予执行权限 (Linux/macOS):** `chmod +x ksubdomain`
4.  **运行!**

### 源码编译 (可选)

确保您已安装 Go 1.23 版本和 `libpcap` 环境。

```bash
go install -v github.com/boy-hack/ksubdomain/v2/cmd/ksubdomain@latest
# 二进制文件通常位于 $GOPATH/bin 或 $HOME/go/bin
```

## 📖 使用说明

```bash
KSubdomain - 极速无状态子域名爆破工具

用法:
  ksubdomain [全局选项] 命令 [命令选项] [参数...]

版本:
  查看版本信息: ksubdomain --version

命令:
  enum, e    枚举模式: 提供主域名进行爆破
  verify, v  验证模式: 提供域名列表进行验证
  test       测试本地网卡最大发包速度
  help, h    显示命令列表或某个命令的帮助

全局选项:
  --help, -h     显示帮助 (默认: false)
  --version, -v  打印版本信息 (默认: false)
```

### 验证模式 (Verify)

验证模式用于快速检查提供的域名列表的存活状态。

```bash
./ksubdomain verify -h # 查看验证模式帮助，可缩写 ksubdomain v

USAGE:
   ksubdomain verify [command options] [arguments...]

OPTIONS:
   --filename value, -f value       验证域名的文件路径
   --domain value, -d value         域名
   --band value, -b value           宽带的下行速度，可以5M,5K,5G (default: "3m")
   --resolvers value, -r value      dns服务器，默认会使用内置dns
   --output value, -o value         输出文件名
   --output-type value, --oy value  输出文件类型: json, txt, csv (default: "txt")
   --silent                         使用后屏幕将仅输出域名 (default: false)
   --retry value                    重试次数,当为-1时将一直重试 (default: 3)
   --timeout value                  超时时间 (default: 6)
   --stdin                          接受stdin输入 (default: false)
   --not-print, --np                不打印域名结果 (default: false)
   --eth value, -e value            指定网卡名称
   --wild-filter-mode value         泛解析过滤模式[从最终结果过滤泛解析域名]: basic(基础), advanced(高级), none(不过滤) (default: "none")
   --predict                        启用预测域名模式 (default: false)
   --max-cname-recs value           CNAME解析最大递归深度 (default: 10)
   --predict-dict value             用于预测模式的自定义字典文件路径
   --predict-patterns value         用于预测模式的自定义模式文件路径
   --help, -h                       show help (default: false)

# 示例:
# 验证多个域名解析
./ksubdomain v -d xx1.example.com -d xx2example.com

# 从文件读取域名进行验证，保存为 output.txt
./ksubdomain v -f domains.txt -o output.txt

# 从标准输入读取域名，带宽限制为 10M
cat domains.txt | ./ksubdomain v --stdin -b 10M

# 启用预测模式，泛解析过滤，保存为csv
./ksubdomain v -f domains.txt --predict --wild-filter-mode advanced --oy csv -o output.csv
```

### 枚举模式 (Enum)

枚举模式基于字典和预测算法爆破指定域名下的子域名。

```bash
./ksubdomain enum -h # 查看枚举模式帮助,可简写 ksubdomain e

USAGE:
   ksubdomain enum [command options] [arguments...]

OPTIONS:
   --domain value, -d value         域名
   --band value, -b value           宽带的下行速度，可以5M,5K,5G (default: "3m")
   --resolvers value, -r value      dns服务器，默认会使用内置dns
   --output value, -o value         输出文件名
   --output-type value, --oy value  输出文件类型: json, txt, csv (default: "txt")
   --silent                         使用后屏幕将仅输出域名 (default: false)
   --retry value                    重试次数,当为-1时将一直重试 (default: 3)
   --timeout value                  超时时间 (default: 6)
   --stdin                          接受stdin输入 (default: false)
   --not-print, --np                不打印域名结果 (default: false)
   --eth value, -e value            指定网卡名称
   --wild-filter-mode value         泛解析过滤模式[从最终结果过滤泛解析域名]: basic(基础), advanced(高级), none(不过滤) (default: "none")
   --predict                        启用预测域名模式 (default: false)
   --max-cname-recs value           CNAME解析最大递归深度 (default: 10)
   --filename value, -f value       字典路径
   --ns                             读取域名ns记录并加入到ns解析器中 (default: false)
   --axfr                           尝试对域名的授权NS服务器进行AXFR域传送 (default: false)
   --axfr-timeout value             AXFR尝试的超时时间(秒) (default: 10)
   --predict-dict value             用于预测模式的自定义字典文件路径
   --predict-patterns value         用于预测模式的自定义模式文件路径
   --help, -h                       show help (default: false)

# 示例:
# 枚举多个域名
./ksubdomain e -d example.com -d hacker.com

# 从文件读取字典枚举，保存为 output.txt
./ksubdomain e -f sub.dict -o output.txt

# 从标准输入读取域名，带宽限制为 10M
cat domains.txt | ./ksubdomain e --stdin -b 10M

# 启用预测模式枚举域名，泛解析过滤，保存为csv
./ksubdomain e -d example.com --predict --wild-filter-mode advanced --oy csv -o output.csv

# 使用自定义预测字典和模式，并尝试AXFR (需配合--ns获取NS服务器)
./ksubdomain e -d example.com --ns --axfr --predict --predict-dict my.dict --predict-patterns my.cfg -o results.txt
```

## ✨ 新特性详解 (v2.x 新增)

*   **CNAME 递归解析 (Recursive CNAME Expansion):**
    *   KSubdomain 现在能够递归解析 CNAME 记录，直至找到最终的 A/AAAA 记录或达到最大递归深度。
    *   使用 `--max-cname-recs <深度>` 参数控制最大递归层数 (默认: 10)。

*   **AXFR 域传送尝试 (AXFR Attempt):**
    *   新增 AXFR (DNS Zone Transfer) 尝试功能。
    *   使用 `--axfr` 标记 (推荐与 `--ns` 配合使用，以自动获取目标域的授权 NS 服务器)。
    *   工具将尝试从授权 NS 服务器进行域传送，以获取全量 DNS 记录。
    *   可通过 `--axfr-timeout <秒数>` 设置 AXFR 请求的超时时间 (默认: 10 秒)。
    *   注意: 此功能通常仅对配置错误的 DNS 服务器有效。

*   **增强的子域名预测 (Enhanced Subdomain Prediction):**
    *   内置的预测字典 (`regular.dict`) 和模式 (`regular.cfg`) 得到了大幅扩充，增加了更多分类如 `[service]`, `[version]`, `[geo]`, `[number]` 以及更丰富的生成模式。
    *   用户现在可以通过 `--predict-dict <字典文件路径>` 和 `--predict-patterns <模式文件路径>` 提供自定义的预测字典和模式规则，实现更灵活和定制化的子域名生成。

*   **改进的泛解析检测与过滤 (Improved Wildcard Detection & Filtering):**
    *   泛解析检测机制得到显著增强。在扫描开始前，KSubdomain 会对用户提供的基础域名进行主动探测，识别其泛解析特征（如通配符 IP 地址和 CNAME 记录）。
    *   这些预先探测到的信息将被用于后续的泛解析过滤阶段 (`basic` 或 `advanced` 模式)，从而更准确地识别和过滤掉泛解析产生的无效结果。

## ✨ 原有特性与技巧

*   **带宽自动适配:** 只需使用 `-b` 参数指定你的公网下行带宽 (如 `-b 10m`), KSubdomain 会自动优化发包速率。
*   **测试最大速率:** 运行 `./ksubdomain test` 测试当前环境的最大理论发包速率。
*   **自动网卡检测:** KSubdomain 会自动检测可用网卡。
*   **进度显示:** 实时进度条显示 成功数 / 发送数 / 队列长度 / 接收数 / 失败数 / 已耗时。
*   **参数调优:** 根据网络质量和目标域名数量，调整 `--retry` 和 `--timeout` 参数以获得最佳效果。当 `--retry` 为 -1 时，将无限重试直至所有请求成功或超时。
*   **多种输出格式:** 支持 `txt` (实时输出), `json` (完成后输出), `csv` (完成后输出)。通过 `-o` 指定文件名后缀即可 (如 `result.json`)。
*   **环境变量配置:**
    *   `KSubdomainConfig`: 指定配置文件的路径。

## 💡 参考

*   原 KSubdomain 项目: [https://github.com/knownsec/ksubdomain](https://github.com/knownsec/ksubdomain)
*   从 Masscan, Zmap 源码分析到开发实践: [https://paper.seebug.org/1052/](https://paper.seebug.org/1052/)
*   KSubdomain 无状态域名爆破工具介绍: [https://paper.seebug.org/1325/](https://paper.seebug.org/1325/)
*   KSubdomain 与 massdns 的对比分析: [微信公众号文章链接](https://mp.weixin.qq.com/s?__biz=MzU2NzcwNTY3Mg==&mid=2247484471&idx=1&sn=322d5db2d11363cd2392d7bd29c679f1&chksm=fc986d10cbefe406f4bda22f62a16f08c71f31c241024fc82ecbb8e41c9c7188cfbd71276b81&token=76024279&lang=zh_CN#rd)