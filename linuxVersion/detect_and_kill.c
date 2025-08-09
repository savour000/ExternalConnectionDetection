#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>

#define MAX_LINE 512
#define MAX_IP 128
#define MAX_CMD 256
#define MAX_APIKEY 256

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char process_name[256];
    int pid;
} ConnectionInfo;

ConnectionInfo connections[MAX_IP];
int connection_count = 0;

// 用于接收微步返回内容
struct string {
    char *ptr;
    size_t len;
};

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(1);
    if (s->ptr) s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;
    return size * nmemb;
}

// 解析JSON响应中的关键信息
void parse_threatbook_response(const char *response, const char *ip) {
    printf("\n[+] 微步情报 - %s:\n", ip);
    printf("┌─────────────────────────────────────────────────────────────┐\n");
    
    // 检查是否包含错误信息
    if (strstr(response, "\"response_code\":0") == NULL) {
        printf("│ 查询失败或返回错误\n");
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    // 查找IP对应的数据块
    char ip_pattern[256];
    snprintf(ip_pattern, sizeof(ip_pattern), "\"%s\":", ip);
    char *ip_data_start = strstr(response, ip_pattern);
    if (!ip_data_start) {
        printf("│ 未找到IP %s 的数据\n", ip);
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    // 提取威胁等级
    char *severity_start = strstr(ip_data_start, "\"severity\":\"");
    if (severity_start) {
        severity_start += 12;
        char *severity_end = strchr(severity_start, '"');
        if (severity_end) {
            char severity[32] = {0};
            strncpy(severity, severity_start, severity_end - severity_start);
            
            // 将威胁等级转换为中文含义
            char severity_chinese[64] = {0};
            if (strcmp(severity, "critical") == 0) {
                strcpy(severity_chinese, "严重 (极高威胁，必须立即处理)");
            } else if (strcmp(severity, "high") == 0) {
                strcpy(severity_chinese, "高危 (确认的恶意IP，建议立即处理)");
            } else if (strcmp(severity, "medium") == 0) {
                strcpy(severity_chinese, "中危 (可疑IP，需要关注)");
            } else if (strcmp(severity, "low") == 0) {
                strcpy(severity_chinese, "低危 (轻微威胁，建议监控)");
            } else if (strcmp(severity, "info") == 0) {
                strcpy(severity_chinese, "信息 (仅提供情报信息，无直接威胁)");
            } else {
                // 如果遇到未知的威胁等级，显示原文
                snprintf(severity_chinese, sizeof(severity_chinese), "%s (未知等级)", severity);
            }
            
            printf("│ 威胁等级: %s\n", severity_chinese);
        }
    }
    
    // 提取判断结果 (新格式是数组)
    char *judgments_start = strstr(ip_data_start, "\"judgments\":[");
    if (judgments_start) {
        judgments_start = strchr(judgments_start, '[');
        if (judgments_start) {
            judgments_start++;
            char *judgments_end = strchr(judgments_start, ']');
            if (judgments_end) {
                char judgments[512] = {0};
                strncpy(judgments, judgments_start, judgments_end - judgments_start);
                if (strlen(judgments) > 0) {
                    // 处理数组格式，移除引号和逗号
                    char clean_judgments[512] = {0};
                    int j = 0;
                    for (int i = 0; i < strlen(judgments) && j < sizeof(clean_judgments) - 1; i++) {
                        if (judgments[i] != '"' && judgments[i] != '\\') {
                            clean_judgments[j++] = judgments[i];
                        }
                    }
                    printf("│ 威胁类型: %s\n", clean_judgments);
                } else {
                    printf("│ 威胁类型: 无\n");
                }
            }
        }
    }
    
    // 提取地理位置信息
    char *country_start = strstr(ip_data_start, "\"country\":\"");
    if (country_start) {
        country_start += 11;
        char *country_end = strchr(country_start, '"');
        if (country_end) {
            char country[64] = {0};
            strncpy(country, country_start, country_end - country_start);
            
            char *province_start = strstr(ip_data_start, "\"province\":\"");
            char *city_start = strstr(ip_data_start, "\"city\":\"");
            
            if (province_start && city_start) {
                province_start += 12;
                city_start += 9;
                char *province_end = strchr(province_start, '"');
                char *city_end = strchr(city_start, '"');
                
                if (province_end && city_end) {
                    char province[64] = {0};
                    char city[64] = {0};
                    strncpy(province, province_start, province_end - province_start);
                    strncpy(city, city_start, city_end - city_start);
                    printf("│ 地理位置: %s %s %s\n", country, province, city);
                }
            } else {
                printf("│ 地理位置: %s\n", country);
            }
        }
    }
    
    // 提取运营商信息
    char *carrier_start = strstr(ip_data_start, "\"carrier\":\"");
    if (carrier_start) {
        carrier_start += 11;
        char *carrier_end = strchr(carrier_start, '"');
        if (carrier_end) {
            char carrier[64] = {0};
            strncpy(carrier, carrier_start, carrier_end - carrier_start);
            printf("│ 运营商: %s\n", carrier);
        }
    }
    
    // 提取ASN信息
    char *asn_info_start = strstr(ip_data_start, "\"info\":\"");
    if (asn_info_start) {
        asn_info_start += 8;
        char *asn_info_end = strchr(asn_info_start, '"');
        if (asn_info_end) {
            char asn_info[128] = {0};
            strncpy(asn_info, asn_info_start, asn_info_end - asn_info_start);
            printf("│ ASN信息: %s\n", asn_info);
        }
    }
    
    // 提取是否为恶意IP
    char *malicious_start = strstr(ip_data_start, "\"is_malicious\":");
    if (malicious_start) {
        malicious_start += 15;
        if (strncmp(malicious_start, "true", 4) == 0) {
            printf("│ 恶意IP: 是\n");
        } else {
            printf("│ 恶意IP: 否\n");
        }
    }
    
    // 提取置信度
    char *confidence_start = strstr(ip_data_start, "\"confidence_level\":\"");
    if (confidence_start) {
        confidence_start += 20;
        char *confidence_end = strchr(confidence_start, '"');
        if (confidence_end) {
            char confidence[32] = {0};
            strncpy(confidence, confidence_start, confidence_end - confidence_start);
            printf("│ 置信度: %s\n", confidence);
        }
    }
    
    // 提取场景信息
    char *scene_start = strstr(ip_data_start, "\"scene\":\"");
    if (scene_start) {
        scene_start += 9;
        char *scene_end = strchr(scene_start, '"');
        if (scene_end) {
            char scene[64] = {0};
            strncpy(scene, scene_start, scene_end - scene_start);
            printf("│ 使用场景: %s\n", scene);
        }
    }
    
    // 提取评估信息
    char *active_start = strstr(ip_data_start, "\"active\":\"");
    if (active_start) {
        active_start += 10;
        char *active_end = strchr(active_start, '"');
        if (active_end) {
            char active[32] = {0};
            strncpy(active, active_start, active_end - active_start);
            printf("│ 活跃度: %s\n", active);
        }
    }
    
    // 提取蜜罐命中信息
    char *honeypot_start = strstr(ip_data_start, "\"honeypot_hit\":");
    if (honeypot_start) {
        honeypot_start += 15;
        if (strncmp(honeypot_start, "true", 4) == 0) {
            printf("│ 蜜罐命中: 是\n");
        } else {
            printf("│ 蜜罐命中: 否\n");
        }
    }
    
    // 提取历史行为信息
    char *hist_behavior_start = strstr(ip_data_start, "\"hist_behavior\":[");
    if (hist_behavior_start) {
        hist_behavior_start = strchr(hist_behavior_start, '[');
        if (hist_behavior_start) {
            hist_behavior_start++;
            char *hist_behavior_end = strchr(hist_behavior_start, ']');
            if (hist_behavior_end) {
                char hist_behavior[512] = {0};
                strncpy(hist_behavior, hist_behavior_start, hist_behavior_end - hist_behavior_start);
                if (strlen(hist_behavior) > 0) {
                    // 提取历史行为中的类别和描述
                    char *category_start = strstr(hist_behavior, "\"category\":\"");
                    if (category_start) {
                        category_start += 12;
                        char *category_end = strchr(category_start, '"');
                        if (category_end) {
                            char category[128] = {0};
                            strncpy(category, category_start, category_end - category_start);
                            printf("│ 历史行为: %s\n", category);
                        }
                    }
                } else {
                    printf("│ 历史行为: 无\n");
                }
            }
        }
    }
    
    // 提取更新时间
    char *update_time_start = strstr(ip_data_start, "\"update_time\":\"");
    if (update_time_start) {
        update_time_start += 15;
        char *update_time_end = strchr(update_time_start, '"');
        if (update_time_end) {
            char update_time[64] = {0};
            strncpy(update_time, update_time_start, update_time_end - update_time_start);
            printf("│ 更新时间: %s\n", update_time);
        }
    }
    
    printf("└─────────────────────────────────────────────────────────────┘\n");
}

// 使用 CURL 查询微步
void query_threatbook(const char *ip, const char *apikey) {
    CURL *curl;
    CURLcode res;
    struct string response;
    char url[512];

    snprintf(url, sizeof(url),
             "https://api.threatbook.cn/v3/scene/ip_reputation?apikey=%s&resource=%s",
             apikey, ip);

    init_string(&response);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            parse_threatbook_response(response.ptr, ip);
        } else {
            fprintf(stderr, "[-] 查询 %s 失败: %s\n", ip, curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }

    free(response.ptr);
}

// 查找 inode 所对应的进程
int get_pid_by_inode(const char *inode, char *process_name) {
    DIR *proc = opendir("/proc");
    struct dirent *entry;

    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;

        char fd_path[512];
        int ret = snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
        if (ret < 0 || ret >= (int)sizeof(fd_path)) {
            continue; // 路径太长，跳过
        }
        
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            char link[512];
            char target[512];
            ret = snprintf(link, sizeof(link), "%s/%s", fd_path, fd_entry->d_name);
            if (ret < 0 || ret >= (int)sizeof(link)) {
                continue; // 路径太长，跳过
            }
            
            ssize_t len = readlink(link, target, sizeof(target) - 1);
            if (len != -1) {
                target[len] = '\0';
                if (strstr(target, inode)) {
                    ret = snprintf(process_name, 256, "/proc/%s/cmdline", entry->d_name);
                    if (ret < 0 || ret >= 256) {
                        // 路径太长，使用默认值
                        strncpy(process_name, "unknown", 255);
                        process_name[255] = '\0';
                    } else {
                        FILE *cmd = fopen(process_name, "r");
                        if (cmd) {
                            if (fgets(process_name, 256, cmd) == NULL) {
                                strncpy(process_name, "unknown", 255);
                                process_name[255] = '\0';
                            }
                            fclose(cmd);
                        }
                    }
                    closedir(fd_dir);
                    closedir(proc);
                    return atoi(entry->d_name);
                }
            }
        }
        closedir(fd_dir);
    }

    closedir(proc);
    return -1;
}

// 解析 /proc/net/tcp
void parse_tcp_connections() {
    FILE *fp = fopen("/proc/net/tcp", "r");
    char line[MAX_LINE];
    fgets(line, MAX_LINE, fp);  // 跳过标题行

    while (fgets(line, MAX_LINE, fp)) {
        char local_addr[128], rem_addr[128], state[8], inode[32];
        int local_port, rem_port;

        sscanf(line, "%*d: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%x %2s %*s %*s %*s %*s %s",
               local_addr, &local_port, rem_addr, &rem_port, state, inode);

        if (strcmp(state, "01") != 0) continue;  // 只处理 ESTABLISHED

        struct in_addr ip_addr;
        unsigned int ip_hex;
        sscanf(rem_addr, "%X", &ip_hex);
        ip_addr.s_addr = htonl(ip_hex);
        const char *ip_str = inet_ntoa(ip_addr);

        int i;
        for (i = 0; i < connection_count; i++) {
            if (strcmp(connections[i].ip, ip_str) == 0)
                break;
        }

        if (i == connection_count) {
            strncpy(connections[connection_count].ip, ip_str, sizeof(connections[connection_count].ip) - 1);
            connections[connection_count].ip[sizeof(connections[connection_count].ip) - 1] = '\0';
            connections[connection_count].pid = get_pid_by_inode(inode, connections[connection_count].process_name);
            connection_count++;
        }
    }

    fclose(fp);
}

// 检查文件是否存在
int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

// 检查系统兼容性
int check_system_compatibility() {
    printf("[*] 检查系统兼容性...\n");
    
    // 检查 /proc 文件系统
    if (!file_exists("/proc/net/tcp")) {
        fprintf(stderr, "[-] 错误: /proc/net/tcp 不存在，系统可能不支持 /proc 文件系统\n");
        return 0;
    }
    
    if (!file_exists("/proc")) {
        fprintf(stderr, "[-] 错误: /proc 目录不存在，系统可能不支持 /proc 文件系统\n");
        return 0;
    }
    
    // 检查是否有权限读取 /proc
    DIR *proc = opendir("/proc");
    if (!proc) {
        fprintf(stderr, "[-] 错误: 无法访问 /proc 目录，请检查权限\n");
        return 0;
    }
    closedir(proc);
    
    printf("[+] 系统兼容性检查通过\n");
    return 1;
}

int main() {
    char apikey[MAX_APIKEY];
    
    printf("请输入微步 API Key: ");
    fgets(apikey, sizeof(apikey), stdin);
    // 移除换行符
    apikey[strcspn(apikey, "\n")] = 0;
    
    if (strlen(apikey) == 0) {
        fprintf(stderr, "[-] API Key 不能为空\n");
        return 1;
    }
    
    if (!check_system_compatibility()) {
        return 1;
    }

    parse_tcp_connections();

    printf("\n[+] 检测到以下外联连接：\n");
    for (int i = 0; i < connection_count; i++) {
        printf("%d. IP: %s | PID: %d | 进程: %s\n",
               i + 1, connections[i].ip, connections[i].pid, connections[i].process_name);
    }

    for (int i = 0; i < connection_count; i++) {
        query_threatbook(connections[i].ip, apikey);
    }

    int choice;
    int terminated_count = 0;
    
    while (1) {
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
            int target_pid = connections[choice - 1].pid;
            if (kill(target_pid, SIGKILL) == 0) {
                printf("[+] 成功终止进程 PID: %d (%s)\n", target_pid, connections[choice - 1].process_name);
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
                for (int i = 0; i < connection_count; i++) {
                    printf("%d. IP: %s | PID: %d | 进程: %s\n",
                           i + 1, connections[i].ip, connections[i].pid, connections[i].process_name);
                }
            } else {
                perror("[-] 终止失败");
            }
        } else {
            printf("[-] 无效的选择，请输入 0-%d 之间的数字\n", connection_count);
        }
    }

    return 0;
}
