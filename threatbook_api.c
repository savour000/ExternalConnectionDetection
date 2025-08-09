#include "threatbook_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>

#define MAX_RESPONSE 8192

// 使用WinHTTP查询微步API
void query_threatbook_winhttp(const char *ip, const char *apikey) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    char response[MAX_RESPONSE] = {0};
    int response_len = 0;
    
    printf("\n[+] 微步情报 - %s (WinHTTP请求):\n", ip);
    printf("┌─────────────────────────────────────────────────────────────┐\n");
    
    // 使用WinHTTP发送请求
    hSession = WinHttpOpen(L"Windows Network Detection Tool/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        printf("│ 错误: WinHttpOpen 失败，错误码: %lu\n", GetLastError());
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    hConnect = WinHttpConnect(hSession, L"8.141.112.250", 19005, 0);
    
    if (!hConnect) {
        printf("│ 错误: WinHttpConnect 失败，错误码: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "/ip_reputation/?apikey=%s&resource=%s", apikey, ip);
    
    // 转换为宽字符
    wchar_t wpath[512];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 512);
    
    hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath,
                                NULL, WINHTTP_NO_REFERER,
                                WINHTTP_DEFAULT_ACCEPT_TYPES,
                                0);  // 移除WINHTTP_FLAG_SECURE，使用HTTP
    
    if (!hRequest) {
        printf("│ 错误: WinHttpOpenRequest 失败，错误码: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    bResults = WinHttpSendRequest(hRequest,
                                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    
    if (!bResults) {
        printf("│ 错误: WinHttpSendRequest 失败，错误码: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    
    if (!bResults) {
        printf("│ 错误: WinHttpReceiveResponse 失败，错误码: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("└─────────────────────────────────────────────────────────────┘\n");
        return;
    }
    
    // 读取响应
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            printf("│ 错误: WinHttpQueryDataAvailable 失败，错误码: %lu\n", GetLastError());
            break;
        }
        
        if (dwSize == 0) {
            break;
        }
        
        pszOutBuffer = (LPSTR)malloc(dwSize + 1);
        if (!pszOutBuffer) {
            printf("│ 错误: 内存分配失败\n");
            break;
        }
        
        ZeroMemory(pszOutBuffer, dwSize + 1);
        
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                           dwSize, &dwDownloaded)) {
            printf("│ 错误: WinHttpReadData 失败，错误码: %lu\n", GetLastError());
            free(pszOutBuffer);
            break;
        }
        
        // 添加到响应缓冲区
        if (response_len + dwDownloaded < MAX_RESPONSE) {
            memcpy(response + response_len, pszOutBuffer, dwDownloaded);
            response_len += dwDownloaded;
        }
        
        free(pszOutBuffer);
        
    } while (dwSize > 0);
    
    // 解析响应
    if (response_len > 0) {
        response[response_len] = '\0';
        
        // 增强的JSON解析
        if (strstr(response, "\"response_code\":0") != NULL) {
            printf("│ 查询成功\n");
            
            // 提取威胁等级
            char *severity_start = strstr(response, "\"severity\":\"");
            if (severity_start) {
                severity_start += 12;
                char *severity_end = strchr(severity_start, '"');
                if (severity_end) {
                    char severity[32] = {0};
                    strncpy(severity, severity_start, severity_end - severity_start);
                    
                    // 转换威胁等级为中文含义
                    if (strcmp(severity, "high") == 0) {
                        printf("│ 威胁等级: 高危 (恶意IP，建议立即处理)\n");
                    } else if (strcmp(severity, "medium") == 0) {
                        printf("│ 威胁等级: 中危 (可疑IP，需要关注)\n");
                    } else if (strcmp(severity, "low") == 0) {
                        printf("│ 威胁等级: 低危 (一般风险，建议监控)\n");
                    } else if (strcmp(severity, "info") == 0) {
                        printf("│ 威胁等级: 信息 (一般信息，无需处理)\n");
                    } else {
                        printf("│ 威胁等级: %s\n", severity);
                    }
                }
            }
            
            // 提取是否为恶意IP
            char *malicious_start = strstr(response, "\"is_malicious\":");
            if (malicious_start) {
                malicious_start += 15;
                if (strncmp(malicious_start, "true", 4) == 0) {
                    printf("│ 恶意IP: 是\n");
                } else {
                    printf("│ 恶意IP: 否\n");
                }
            }
            
            // 提取判断结果 (judgments)
            char *judgments_start = strstr(response, "\"judgments\":[");
            if (judgments_start) {
                judgments_start = strchr(judgments_start, '[');
                if (judgments_start) {
                    judgments_start++;
                    char *judgments_end = strchr(judgments_start, ']');
                    if (judgments_end) {
                        char judgments[512] = {0};
                        strncpy(judgments, judgments_start, judgments_end - judgments_start);
                        if (strlen(judgments) > 0) {
                            // 处理数组格式，移除引号和反斜杠
                            char clean_judgments[512] = {0};
                            int j = 0;
                            for (int i = 0; i < strlen(judgments) && j < sizeof(clean_judgments) - 1; i++) {
                                if (judgments[i] != '"' && judgments[i] != '\\') {
                                    clean_judgments[j++] = judgments[i];
                                }
                            }
                            printf("│ 判断结果: %s\n", clean_judgments);
                        } else {
                            printf("│ 判断结果: 无\n");
                        }
                    }
                }
            }
            
            // 提取场景 (scene)
            char *scene_start = strstr(response, "\"scene\":\"");
            if (scene_start) {
                scene_start += 9;
                char *scene_end = strchr(scene_start, '"');
                if (scene_end) {
                    char scene[128] = {0};
                    strncpy(scene, scene_start, scene_end - scene_start);
                    if (strlen(scene) > 0) {
                        printf("│ 场景: %s\n", scene);
                    } else {
                        printf("│ 场景: 未知\n");
                    }
                }
            }
            
            // 提取运营商 (carrier)
            char *carrier_start = strstr(response, "\"carrier\":\"");
            if (carrier_start) {
                carrier_start += 11;
                char *carrier_end = strchr(carrier_start, '"');
                if (carrier_end) {
                    char carrier[128] = {0};
                    strncpy(carrier, carrier_start, carrier_end - carrier_start);
                    if (strlen(carrier) > 0) {
                        printf("│ 运营商: %s\n", carrier);
                    } else {
                        printf("│ 运营商: 未知\n");
                    }
                }
            }
            
            // 提取位置信息
            char *location_start = strstr(response, "\"location\":{");
            if (location_start) {
                // 提取国家
                char *country_start = strstr(location_start, "\"country\":\"");
                if (country_start) {
                    country_start += 11;
                    char *country_end = strchr(country_start, '"');
                    if (country_end) {
                        char country[64] = {0};
                        strncpy(country, country_start, country_end - country_start);
                        if (strlen(country) > 0) {
                            printf("│ 国家: %s\n", country);
                        } else {
                            printf("│ 国家: 未知\n");
                        }
                    }
                }
                
                // 提取省份
                char *province_start = strstr(location_start, "\"province\":\"");
                if (province_start) {
                    province_start += 12;
                    char *province_end = strchr(province_start, '"');
                    if (province_end) {
                        char province[64] = {0};
                        strncpy(province, province_start, province_end - province_start);
                        if (strlen(province) > 0) {
                            printf("│ 省份: %s\n", province);
                        } else {
                            printf("│ 省份: 未知\n");
                        }
                    }
                }
                
                // 提取城市
                char *city_start = strstr(location_start, "\"city\":\"");
                if (city_start) {
                    city_start += 8;
                    char *city_end = strchr(city_start, '"');
                    if (city_end) {
                        char city[64] = {0};
                        strncpy(city, city_start, city_end - city_start);
                        if (strlen(city) > 0) {
                            printf("│ 城市: %s\n", city);
                        } else {
                            printf("│ 城市: 未知\n");
                        }
                    }
                }
            }
            
            // 提取ASN信息
            char *asn_start = strstr(response, "\"asn\":{");
            if (asn_start) {
                // 检查ASN对象是否为空
                char *asn_end = strstr(asn_start, "}");
                if (asn_end && (asn_end - asn_start) > 7) {
                    // ASN对象不为空，提取信息
                    // 提取ASN名称
                    char *asn_info_start = strstr(asn_start, "\"info\":\"");
                    if (asn_info_start) {
                        asn_info_start += 8;
                        char *asn_info_end = strchr(asn_info_start, '"');
                        if (asn_info_end) {
                            char asn_info[128] = {0};
                            strncpy(asn_info, asn_info_start, asn_info_end - asn_info_start);
                            if (strlen(asn_info) > 0) {
                                printf("│ ASN: %s\n", asn_info);
                            }
                        }
                    }
                    
                    // 提取ASN号码
                    char *asn_number_start = strstr(asn_start, "\"number\":");
                    if (asn_number_start) {
                        asn_number_start += 9;
                        char *asn_number_end = strchr(asn_number_start, ',');
                        if (!asn_number_end) asn_number_end = strchr(asn_number_start, '}');
                        if (asn_number_end) {
                            char asn_number[32] = {0};
                            int number_len = asn_number_end - asn_number_start;
                            if (number_len > 0 && number_len < sizeof(asn_number)) {
                                strncpy(asn_number, asn_number_start, number_len);
                                asn_number[number_len] = '\0';
                                // 去除可能的空格
                                char *trim_start = asn_number;
                                while (*trim_start == ' ' || *trim_start == '\t') trim_start++;
                                char *trim_end = trim_start + strlen(trim_start) - 1;
                                while (trim_end > trim_start && (*trim_end == ' ' || *trim_end == '\t' || *trim_end == '}')) {
                                    *trim_end = '\0';
                                    trim_end--;
                                }
                                if (strlen(trim_start) > 0) {
                                    printf("│ ASN号码: %s\n", trim_start);
                                }
                            }
                        }
                    }
                } else {
                    printf("│ ASN: 未知\n");
                }
            }
            
            // 提取置信度
            char *confidence_start = strstr(response, "\"confidence_level\":\"");
            if (confidence_start) {
                confidence_start += 19;
                char *confidence_end = strchr(confidence_start, '"');
                if (confidence_end) {
                    char confidence[32] = {0};
                    strncpy(confidence, confidence_start, confidence_end - confidence_start);
                    
                    // 显示置信度及其含义
                    if (strcmp(confidence, "高") == 0 || strcmp(confidence, "high") == 0) {
                        printf("│ 置信度: 高 - 恶意可信度高，建议立即处理\n");
                    } else if (strcmp(confidence, "中") == 0 || strcmp(confidence, "medium") == 0) {
                        printf("│ 置信度: 中 - 恶意可信度中等，需要关注\n");
                    } else if (strcmp(confidence, "低") == 0 || strcmp(confidence, "low") == 0) {
                        printf("│ 置信度: 低 - 恶意可信度低，可继续观察\n");
                    } else {
                        printf("│ 置信度: %s\n", confidence);
                    }
                }
            } else {
                printf("│ 置信度: 未提供\n");
            }
            
            // 提取评估信息 (evaluation)
            char *evaluation_start = strstr(response, "\"evaluation\":{");
            if (evaluation_start) {
                // 提取活跃度
                char *active_start = strstr(evaluation_start, "\"active\":\"");
                if (active_start) {
                    active_start += 10;
                    char *active_end = strchr(active_start, '"');
                    if (active_end) {
                        char active[32] = {0};
                        strncpy(active, active_start, active_end - active_start);
                        printf("│ 活跃度: %s\n", active);
                    }
                }
                
                // 提取蜜罐命中
                char *honeypot_start = strstr(evaluation_start, "\"honeypot_hit\":");
                if (honeypot_start) {
                    honeypot_start += 15;
                    if (strncmp(honeypot_start, "true", 4) == 0) {
                        printf("│ 蜜罐命中: 是\n");
                    } else {
                        printf("│ 蜜罐命中: 否\n");
                    }
                }
            }
            
            // 提取历史行为 (hist_behavior)
            char *hist_start = strstr(response, "\"hist_behavior\":[");
            if (hist_start) {
                hist_start = strchr(hist_start, '[');
                if (hist_start) {
                    hist_start++;
                    char *hist_end = strchr(hist_start, ']');
                    if (hist_end && (hist_end - hist_start) > 2) {
                        // 有历史行为数据
                        printf("│ 历史行为: 有记录\n");
                        
                        // 提取行为类别
                        char *category_start = strstr(hist_start, "\"category\":\"");
                        if (category_start) {
                            category_start += 12;
                            char *category_end = strchr(category_start, '"');
                            if (category_end) {
                                char category[128] = {0};
                                strncpy(category, category_start, category_end - category_start);
                                printf("│ 行为类别: %s\n", category);
                            }
                        }
                        
                        // 提取标签名称
                        char *tag_name_start = strstr(hist_start, "\"tag_name\":\"");
                        if (tag_name_start) {
                            tag_name_start += 12;
                            char *tag_name_end = strchr(tag_name_start, '"');
                            if (tag_name_end) {
                                char tag_name[128] = {0};
                                strncpy(tag_name, tag_name_start, tag_name_end - tag_name_start);
                                printf("│ 标签名称: %s\n", tag_name);
                            }
                        }
                        
                        // 提取标签描述
                        char *tag_desc_start = strstr(hist_start, "\"tag_desc\":\"");
                        if (tag_desc_start) {
                            tag_desc_start += 12;
                            char *tag_desc_end = strstr(tag_desc_start, "\",\"");
                            if (tag_desc_end) {
                                char tag_desc[512] = {0};
                                strncpy(tag_desc, tag_desc_start, tag_desc_end - tag_desc_start);
                                printf("│ 行为描述: %s\n", tag_desc);
                            }
                        }
                    } else {
                        printf("│ 历史行为: 无记录\n");
                    }
                }
            }
            
            // 提取更新时间
            char *update_start = strstr(response, "\"update_time\":\"");
            if (update_start) {
                update_start += 15;
                char *update_end = strchr(update_start, '"');
                if (update_end) {
                    char update_time[64] = {0};
                    strncpy(update_time, update_start, update_end - update_start);
                    printf("│ 更新时间: %s\n", update_time);
                }
            }
            
        } else {
            printf("│ 查询失败或返回错误\n");
            // 尝试提取错误信息
            char *verbose_start = strstr(response, "\"verbose_msg\":\"");
            if (verbose_start) {
                verbose_start += 14;
                char *verbose_end = strchr(verbose_start, '"');
                if (verbose_end) {
                    char verbose_msg[256] = {0};
                    strncpy(verbose_msg, verbose_start, verbose_end - verbose_start);
                    printf("│ 错误信息: %s\n", verbose_msg);
                }
            }
        }
    } else {
        printf("│ 未收到响应\n");
    }
    
    // 清理资源
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    printf("└─────────────────────────────────────────────────────────────┘\n");
}

