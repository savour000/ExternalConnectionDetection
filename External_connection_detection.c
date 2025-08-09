#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include "utils.h"
#include "threatbook_api.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winhttp.lib")

#define MAX_LINE 512
#define MAX_IP 128
#define MAX_CMD 256
#define MAX_APIKEY 256
#define MAX_RESPONSE 8192

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char process_name[256];
    char full_path[MAX_PATH];
    DWORD pid;
    DWORD parent_pid;
    char start_time[64];
} ConnectionInfo;

ConnectionInfo connections[MAX_IP];
int connection_count = 0;

// 获取进程详细信息
void get_process_details(DWORD pid, char *processName, char *fullPath, DWORD *parentPid, char *startTime) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    
    if (hProcess != NULL) {
        // 获取完整路径
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, fullPath, &size)) {
            // 提取文件名部分
            char* filename = strrchr(fullPath, '\\');
            if (filename) {
                strcpy(processName, filename + 1);
            } else {
                strcpy(processName, fullPath);
            }
        }
        
        // 获取父进程ID
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == pid) {
                        *parentPid = pe32.th32ParentProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        
        // 获取进程启动时间
        FILETIME createTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
            SYSTEMTIME st;
            FileTimeToSystemTime(&createTime, &st);
            sprintf(startTime, "%04d-%02d-%02d %02d:%02d:%02d", 
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        } else {
            strcpy(startTime, "未知");
        }
        
        CloseHandle(hProcess);
    } else {
        strcpy(processName, "unknown");
        strcpy(fullPath, "unknown");
        *parentPid = 0;
        strcpy(startTime, "未知");
    }
}

int main() {
    char apikey[MAX_APIKEY];
    
    // 设置控制台编码为UTF-8，解决中文乱码问题
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[-] WSAStartup 失败\n");
        return 1;
    }
    
    printf("[*] Windows版本网络连接检测工具 (公开版)\n");
    printf("[*] 显示详细进程信息\n");
    
    // 检查管理员权限
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    
    if (!isAdmin) {
        printf("[!] 警告: 当前未以管理员权限运行\n");
        printf("[!] 某些功能可能受限，如进程终止功能可能无法正常工作\n");
        printf("[!] 建议以管理员权限重新运行程序以获得完整功能\n");
        printf("[!] 程序将继续运行，但可能无法终止某些系统进程\n\n");
    } else {
        printf("[+] Windows系统兼容性检查通过 (管理员权限)\n");
    }
    
    // 获取用户输入的API key
    printf("\n[*] 请输入微步API Key: ");
    if (fgets(apikey, sizeof(apikey), stdin) == NULL) {
        fprintf(stderr, "[-] 读取API Key失败\n");
        WSACleanup();
        return 1;
    }
    
    // 移除换行符
    apikey[strcspn(apikey, "\n")] = 0;
    
    // 检查API key是否为空
    if (strlen(apikey) == 0) {
        fprintf(stderr, "[-] API Key不能为空\n");
        WSACleanup();
        return 1;
    }
    
    printf("[+] API Key已设置\n");

    // 获取TCP连接信息
    MIB_TCPTABLE_OWNER_PID* pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    
    // 获取所需缓冲区大小
    if (GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
    } else {
        fprintf(stderr, "[-] 无法获取TCP表大小\n");
        WSACleanup();
        return 1;
    }
    
    if (pTcpTable == NULL) {
        fprintf(stderr, "[-] 内存分配失败\n");
        WSACleanup();
        return 1;
    }
    
    // 获取TCP表
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
        printf("\n[+] 检测到以下外联连接 (已过滤内网地址)：\n");
        printf("┌─────────────────────────────────────────────────────────────────────────────────────┐\n");
        
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
            
            // 只处理已建立的连接
            if (row.dwState == MIB_TCP_STATE_ESTAB) {
                // 转换IP地址
                struct in_addr local_addr, remote_addr;
                local_addr.s_addr = row.dwLocalAddr;
                remote_addr.s_addr = row.dwRemoteAddr;
                
                char remote_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &remote_addr, remote_ip, INET_ADDRSTRLEN);
                
                // 过滤掉内网地址
                if (!is_private_ip(remote_ip)) {
                    // 获取进程详细信息
                    char processName[MAX_PATH];
                    char fullPath[MAX_PATH];
                    DWORD parentPid;
                    char startTime[64];
                    
                    get_process_details(row.dwOwningPid, processName, fullPath, &parentPid, startTime);
                    
                    printf("│ %d. IP: %s | PID: %lu | 进程: %s\n", 
                           connection_count + 1, remote_ip, row.dwOwningPid, processName);
                    printf("│    路径: %s\n", fullPath);
                    printf("│    父进程PID: %lu | 启动时间: %s\n", parentPid, startTime);
                    printf("├─────────────────────────────────────────────────────────────────────────────────────┤\n");
                    
                    // 保存连接信息
                    if (connection_count < MAX_IP) {
                        strncpy(connections[connection_count].ip, remote_ip, INET_ADDRSTRLEN);
                        connections[connection_count].pid = row.dwOwningPid;
                        strncpy(connections[connection_count].process_name, processName, 255);
                        strncpy(connections[connection_count].full_path, fullPath, MAX_PATH - 1);
                        connections[connection_count].parent_pid = parentPid;
                        strncpy(connections[connection_count].start_time, startTime, 63);
                        connections[connection_count].process_name[255] = '\0';
                        connections[connection_count].full_path[MAX_PATH - 1] = '\0';
                        connections[connection_count].start_time[63] = '\0';
                        connection_count++;
                    }
                }
            }
        }
        
    } else {
        fprintf(stderr, "[-] GetExtendedTcpTable 失败，错误码: %d\n", dwRetVal);
    }
    
    free(pTcpTable);
    
    if (connection_count == 0) {
        printf("[*] 未检测到外联连接\n");
        WSACleanup();
        return 0;
    }
    
    // 查询威胁情报
    printf("\n[*] 开始查询威胁情报...\n");
    for (int i = 0; i < connection_count; i++) {
        query_threatbook_winhttp(connections[i].ip, apikey);
    }
    
    // 进程终止功能
    int choice;
    int terminated_count = 0;
    
    while (1) {
        if (!isAdmin) {
            printf("\n[!] 注意: 当前未以管理员权限运行，进程终止功能可能受限\n");
        }
        printf("\n是否要终止某个进程？输入编号 (0 表示不终止): ");
        scanf("%d", &choice);

        if (choice == 0) {
            if (terminated_count == 0) {
                printf("[*] 未选择任何进程终止。\n");
            } else {
                printf("[*] 已终止 %d 个进程，退出程序。\n", terminated_count);
            }
            break;
        } else if (choice > 0 && choice <= connection_count) {
            DWORD target_pid = connections[choice - 1].pid;
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, target_pid);
            
            if (hProcess != NULL) {
                if (TerminateProcess(hProcess, 1)) {
                    printf("[+] 成功终止进程 PID: %lu (%s)\n", target_pid, connections[choice - 1].process_name);
                    printf("[+] 进程路径: %s\n", connections[choice - 1].full_path);
                    terminated_count++;
                    
                    // 从列表中移除已终止的进程
                    for (int i = choice - 1; i < connection_count - 1; i++) {
                        connections[i] = connections[i + 1];
                    }
                    connection_count--;
                    
                    // 如果所有进程都被终止了，退出循环
                    if (connection_count == 0) {
                        printf("[*] 所有进程已终止，退出程序。\n");
                        break;
                    }
                    
                    // 重新显示剩余的连接
                    printf("\n[+] 剩余的外联连接：\n");
                    printf("┌─────────────────────────────────────────────────────────────────────────────────────┐\n");
                    for (int i = 0; i < connection_count; i++) {
                        printf("│ %d. IP: %s | PID: %lu | 进程: %s\n",
                               i + 1, connections[i].ip, connections[i].pid, connections[i].process_name);
                        printf("│    路径: %s\n", connections[i].full_path);
                        printf("│    父进程PID: %lu | 启动时间: %s\n", connections[i].parent_pid, connections[i].start_time);
                        printf("├─────────────────────────────────────────────────────────────────────────────────────┤\n");
                    }
                    printf("└─────────────────────────────────────────────────────────────────────────────────────┘\n");
                } else {
                    DWORD error = GetLastError();
                    fprintf(stderr, "[-] 终止失败，错误码: %lu\n", error);
                    if (!isAdmin && error == ERROR_ACCESS_DENIED) {
                        printf("[!] 权限不足，无法终止该进程。请以管理员权限运行程序。\n");
                    }
                }
                CloseHandle(hProcess);
            } else {
                DWORD error = GetLastError();
                fprintf(stderr, "[-] 无法打开进程，错误码: %lu\n", error);
                if (!isAdmin && error == ERROR_ACCESS_DENIED) {
                    printf("[!] 权限不足，无法访问该进程。请以管理员权限运行程序。\n");
                }
            }
        } else {
            printf("[-] 无效的选择，请输入 0-%d 之间的数字\n", connection_count);
        }
    }
    
    printf("[+] 程序运行完成\n");
    
    // 添加暂停功能，等待用户按任意键退出
    printf("\n[*] 按任意键退出程序...\n");
    getchar();  // 清除之前scanf留下的换行符
    getchar();  // 等待用户输入
    
    WSACleanup();
    return 0;
}
