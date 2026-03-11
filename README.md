# DNS 检测器（boce_dns_checker）

一个基于Go语言开发的DNS检测工具，通过集成Boce API，支持跨多个地区和运营商的DNS解析结果查询，并提供本地缓存功能。

## 项目简介

DNS检测器可以检测域名在不同地区（如河北、浙江等）和不同运营商（如电信、联通、移动等）的DNS解析结果，帮助诊断DNS问题和验证全球DNS配置。

### 核心特性

- **跨地区跨运营商检测**：支持教育网、长城宽带、鹏博士、电信、联通、移动、铁通、广电等多家运营商
- **本地缓存机制**：采用SQLite数据库存储24小时缓存，加速重复查询
- **灵活的筛选**：支持排除或仅包含特定地区和运营商的结果
- **详细信息输出**：可选输出每个IP对应的地区和运营商信息
- **强制刷新**：支持强制从API拉取最新数据，绕过本地缓存
- **调试模式**：支持打印Boce接口请求详情，便于问题排查

## 技术架构

### 依赖

- **Go 1.22+**
- **gopkg.in/yaml.v3**：YAML配置文件解析
- **modernc.org/sqlite**：SQLite数据库驱动

### 核心模块

| 模块 | 功能 |
|------|------|
| BoceClient | 与Boce API交互，创建和查询DNS检测任务 |
| DBStore | SQLite本地数据库操作，实现缓存存储 |
| Config | 配置文件加载和参数验证 |

## 项目结构

```
dns_checker/
├── cmd/
│   └── dns_checker/
│       └── main.go          # 主程序入口
├── build/                   # 编译输出目录
│   ├── dns_checker_linux_amd64
│   └── dns_checker_darwin_arm64
├── config.yaml.example      # 配置文件示例
├── api.txt                  # Boce API文档
├── Makefile                 # 编译脚本
├── go.mod                   # Go模块依赖定义
└── README.md               # 本文件
```

## 安装使用

### 前置准备

1. 获取Boce API密钥：需要在[Boce官网](https://www.boce.com)申请API key
2. 创建配置文件：参考`config.yaml.example`创建`config.yaml`

### 编译

#### 全量编译（macOS + Linux）

```bash
make all
```

#### 编译特定平台

```bash
# macOS (ARM64)
make darwin-arm64

# Linux (AMD64)
make linux-amd64
```

#### 清理编译产物

```bash
make clean
```

### 配置

复制配置示例并填入API密钥：

```bash
cp config.yaml.example config.yaml
# 编辑 config.yaml，填入 boce.key
```

**config.yaml 配置项说明**：

```yaml
boce:
  key: "your_api_key"              # 必填：Boce API密钥
  area: "oversea"                  # 可选：区域（默认大陆，oversea为海外）
  base_url: "https://api.boce.com/v3"  # 可选：Boce API基础URL
  timeout_seconds: 15              # 可选：请求超时时间（秒）

db_path: "dns_checker.db"         # 可选：SQLite数据库文件路径
poll_interval_seconds: 10          # 可选：查询间隔（秒）
max_wait_seconds: 120              # 可选：最大等待时间（秒）
```

### 使用方法

#### 基本查询

```bash
./build/dns_checker_darwin_arm64 -h example.com
```

#### 完整参数说明

| 参数 | 长参数 | 说明 | 示例 |
|------|--------|------|------|
| `-h` | `--host` | **必填**：待检测域名 | `example.com` |
| `-e` | | 排除地区及运营商列表（逗号分隔） | `北京,电信,浙江,联通` |
| `-i` | | 仅包含地区及运营商列表（逗号分隔） | `北京,上海,浙江` |
| `-c` | | 配置文件路径 | `config.yaml` |
| `-db` | | SQLite文件路径（覆盖配置） | `/tmp/dns_checker.db` |
| `-v` | | 启用调试日志，打印Boce接口请求详情 | |
| `-d` | | 输出详细信息，展示每个IP的地区+运营商 | |
| `-f` | | 强制刷新本地缓存，直接从Boce接口拉取最新数据 | |

#### 使用示例

```bash
# 基本查询
./build/dns_checker_darwin_arm64 -h www.baidu.com

# 排除特定运营商
./build/dns_checker_darwin_arm64 -h www.baidu.com -e "电信,联通"

# 仅查询特定地区
./build/dns_checker_darwin_arm64 -h www.baidu.com -i "北京,上海,浙江"

# 输出详细信息
./build/dns_checker_darwin_arm64 -h www.baidu.com -d

# 强制刷新缓存
./build/dns_checker_darwin_arm64 -h www.baidu.com -f

# 启用调试日志
./build/dns_checker_darwin_arm64 -h www.baidu.com -v

# 使用自定义数据库和配置文件
./build/dns_checker_darwin_arm64 -h www.baidu.com -c /etc/dns_checker.yaml -db /var/lib/dns_checker.db
```

## 输出格式

### 标准输出

程序成功执行时返回JSON格式的结果：

```json
{
  "domain": "example.com",
  "ips": {
    "192.0.2.1": [
      {
        "region": "北京",
        "isp": "电信"
      }
    ]
  }
}
```

### 错误输出

出错时输出到stderr，包含完整的错误信息供诊断。

## 缓存机制

- **缓存目录**：SQLite本地数据库（默认`dns_checker.db`）
- **缓存有效期**：24小时
- **刷新策略**：
  - 无缓存或缓存过期时自动从API拉取
  - 使用`-f`标志强制刷新缓存