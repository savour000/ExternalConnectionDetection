#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

// 检查是否为内网地址
int is_private_ip(const char *ip);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H
