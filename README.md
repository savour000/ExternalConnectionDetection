# Windows网络连接检测与进程终止工具

这是一个用于检测系统外联连接、查询威胁情报并终止可疑进程的Windows工具。

## 功能特性

- 🔍 检测系统外联TCP连接 (自动过滤内网地址)
- 🛡️ 查询微步威胁情报API (支持详细解析)
- 🎯 显示威胁等级、地理位置、运营商等信息
- 📍 显示进程完整路径、父进程、启动时间
- ⚡ 支持终止多个可疑进程
- 📊 美观的信息展示格式
- 🌐 支持多种HTTP请求方式 (WinHTTP、PowerShell、Socket)
- 🔤 完整的中文显示支持
- 🏠 智能内网地址过滤 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16等)

## 系统兼容性

### ✅ 支持的Windows版本

- **Windows 10/11** (推荐)
- **Windows Server 2016+**
- **Windows 8.1** (部分功能)

### ⚠️ 系统要求

1. **必需依赖**：
   - MinGW-w64或Visual Studio编译器
   - Windows SDK
   - 管理员权限

2. **权限要求**：
   - 需要管理员权限来终止进程
   - 需要网络访问权限

## 版本说明

### WinHTTP版本 (External_connection_detection.c)
- 使用Windows原生WinHTTP API
- 支持HTTPS请求
- 推荐使用

## 安装步骤

### 1. 安装编译器

#### 方法一：使用MinGW-w64 (推荐)
1. 下载并安装 [MinGW-w64](https://www.mingw-w64.org/downloads/)
2. 将MinGW的bin目录添加到系统PATH

#### 方法二：使用Visual Studio
1. 安装Visual Studio Community (免费)
2. 安装C++开发工具

### 2. 编译程序

#### 推荐:
```cmd
gcc -o External_connection_detection.exe External_connection_detection.c utils.c threatbook_api.c -lws2_32 -liphlpapi -lpsapi -lwinhttp
```

### 3. 运行程序

```cmd
# 终止需要管理员权限
External_connection_detection.exe

# 或者使用批处理文件
run_compile.bat
```

## 使用说明

1. **启动程序**：以管理员身份运行 `External_connection_detection.exe`
2. **自动运行**：程序需要手动输入微步API Key
3. **查看结果**：程序会显示检测到的外联连接和详细威胁情报
4. **终止进程**：选择要终止的进程编号，或输入0退出
5. **多次终止**：支持连续终止多个进程，程序会动态更新连接列表

## 增强功能

### 微步情报解析增强
- **威胁等级**: 显示中文含义 (高危/中危/低危)
- **判断结果**: 显示威胁类型 (傀儡机、垃圾邮件、扫描等)
- **场景信息**: 显示IP使用场景 (企业专线、数据中心等)
- **运营商**: 显示IP所属运营商
- **地理位置**: 显示国家、省份、城市信息
- **ASN信息**: 显示自治系统名称和号码
- **置信度**: 显示威胁情报的置信度级别
- **更新时间**: 显示情报数据的更新时间

### 进程信息增强
- **完整路径**: 显示进程的完整文件路径
- **父进程**: 显示父进程的PID
- **启动时间**: 显示进程的启动时间

### 内网地址过滤
- **自动过滤**: 自动过滤内网地址，只显示外网连接
- **过滤范围**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8等
- **提高效率**: 减少噪音，专注于外部威胁检测

## 兼容性检查

程序会自动检查以下兼容性项目：

- ✅ Windows API是否可用
- ✅ 网络连接是否正常
- ✅ 管理员权限是否具备
- ✅ WinHTTP API是否可用

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
- 程序使用预设的微步API Key，无需额外配置
- 建议在测试环境中先验证程序功能

## 许可证

本程序仅供学习和研究使用，请遵守相关法律法规。
