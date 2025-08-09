@echo off
chcp 65001 >nul
echo [*] 设置控制台编码为UTF-8
echo [*] 编译增强版本 (模块化版本，支持详细微步情报解析)...
echo [*] 编译主程序并链接资源文件...
gcc -o External_connection_detection.exe External_connection_detection.c utils.c threatbook_api.c -lws2_32 -liphlpapi -lpsapi -lwinhttp
if %errorlevel% equ 0 (
    echo [*] 编译成功，运行程序...
    echo [*] 增强功能包括:
    echo [*] - 模块化设计 (utils.c, threatbook_api.c)
    echo [*] - 详细进程信息 (路径、父进程、启动时间)
    echo [*] - 增强的微步情报解析 (判断结果、场景、运营商、位置、ASN等)
    echo [*] - 中文威胁等级显示
    echo [*] - 内网地址过滤
    echo [*] 清理临时文件...
    del resource.o >nul 2>&1
    echo [*] 程序已结束，按任意键关闭窗口...
    pause >nul
) else (
    echo [-] 编译失败，请检查gcc是否安装
    pause
)
