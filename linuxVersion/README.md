# 网络连接检测与进程终止工具

这是一个用于检测系统外联连接、查询威胁情报并终止可疑进程的Linux工具。

## 功能特性

- 🔍 检测系统外联TCP连接
- 🛡️ 查询微步威胁情报API
- 🎯 显示威胁等级、地理位置、运营商等信息
- ⚡ 支持终止多个可疑进程
- 📊 美观的信息展示格式
- 🇨🇳 威胁等级中文含义显示

## 威胁等级说明

程序会将微步API返回的威胁等级自动转换为中文含义：

| 英文等级 | 中文含义 | 处理建议 |
|---------|---------|----------|
| `critical` | 严重 (极高威胁，必须立即处理) | 必须立即处理 |
| `high` | 高危 (确认的恶意IP，建议立即处理) | 建议立即处理 |
| `medium` | 中危 (可疑IP，需要关注) | 需要关注 |
| `low` | 低危 (轻微威胁，建议监控) | 建议监控 |
| `info` | 信息 (仅提供情报信息，无直接威胁) | 仅作参考 |

## 系统兼容性

### ✅ 支持的Linux发行版

- **Ubuntu/Debian系列**
  - Ubuntu 18.04+
  - Debian 9+
  - Linux Mint

- **CentOS/RHEL系列**
  - CentOS 7+
  - RHEL 7+
  - Fedora 28+

- **其他发行版**
  - Alpine Linux 3.8+
  - Arch Linux
  - OpenSUSE

### ⚠️ 系统要求

1. **必需依赖**：
   - libcurl开发库
   - GCC编译器
   - /proc文件系统支持

2. **权限要求**：
   - 需要root权限或sudo权限来终止进程
   - 需要读取/proc目录的权限

## 安装步骤

### 1. 安装依赖

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libcurl4-openssl-dev
```

#### CentOS/RHEL/Fedora:
```bash
# CentOS/RHEL
sudo yum install gcc make libcurl-devel

# Fedora
sudo dnf install gcc make libcurl-devel
```

#### Alpine Linux:
```bash
apk add build-base curl-dev
```

### 2. 编译程序

```bash
gcc -o detect_and_kill detect_and_kill.c -lcurl
```

### 3. 运行程序

```bash
# 杀死程序需要root权限
sudo ./detect_and_kill

# 或者使用sudo
sudo ./detect_and_kill
```

## 使用说明

1. **启动程序**：运行 `sudo ./detect_and_kill`
2. **输入API Key**：输入您的微步威胁情报API Key
3. **查看结果**：程序会显示检测到的外联连接和威胁情报
4. **终止进程**：选择要终止的进程编号，或输入0退出

## 兼容性检查

程序会自动检查以下兼容性项目：

- ✅ /proc文件系统是否存在
- ✅ /proc/net/tcp文件是否可读
- ✅ /proc目录访问权限
- ✅ libcurl库是否可用

## 故障排除

### 常见问题

1. **编译错误：找不到curl/curl.h**
   ```bash
   # 安装libcurl开发库
   sudo apt-get install libcurl4-openssl-dev  # Ubuntu/Debian
   sudo yum install libcurl-devel             # CentOS/RHEL
   ```

2. **运行时错误：权限不足**
   ```bash
   # 使用sudo运行
   sudo ./detect_and_kill
   ```

3. **/proc文件系统不存在**
   - 某些嵌入式系统或容器环境可能不支持/proc
   - 程序会自动检测并提示错误

4. **网络连接失败**
   - 检查网络连接
   - 确认微步API Key有效
   - 检查防火墙设置

## 注意事项

- 程序需要root权限才能终止进程
- 请谨慎使用进程终止功能，确保不会误杀重要进程
- 微步API Key需要单独申请和配置
- 建议在测试环境中先验证程序功能

## 许可证

本程序仅供学习和研究使用，请遵守相关法律法规。
