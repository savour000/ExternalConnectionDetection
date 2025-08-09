#include "utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>

// 检查是否为内网地址
int is_private_ip(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }
    
    unsigned int ip_int = ntohl(addr.s_addr);
    
    // 检查是否为内网地址
    // 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    if ((ip_int & 0xFF000000) == 0x0A000000) {
        return 1;
    }
    
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if ((ip_int & 0xFFF00000) == 0xAC100000) {
        return 1;
    }
    
    // 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    if ((ip_int & 0xFFFF0000) == 0xC0A80000) {
        return 1;
    }
    
    // 127.0.0.0/8 (127.0.0.0 - 127.255.255.255) - 本地回环
    if ((ip_int & 0xFF000000) == 0x7F000000) {
        return 1;
    }
    
    // 169.254.0.0/16 (169.254.0.0 - 169.254.255.255) - 链路本地地址
    if ((ip_int & 0xFFFF0000) == 0xA9FE0000) {
        return 1;
    }
    
    // 224.0.0.0/4 (224.0.0.0 - 239.255.255.255) - 多播地址
    if ((ip_int & 0xF0000000) == 0xE0000000) {
        return 1;
    }
    
    // 240.0.0.0/4 (240.0.0.0 - 255.255.255.255) - 保留地址
    if ((ip_int & 0xF0000000) == 0xF0000000) {
        return 1;
    }
    
    return 0;
}
