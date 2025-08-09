#ifndef THREATBOOK_API_H
#define THREATBOOK_API_H

#ifdef __cplusplus
extern "C" {
#endif

// 使用WinHTTP查询微步API
void query_threatbook_winhttp(const char *ip, const char *apikey);

#ifdef __cplusplus
}
#endif

#endif // THREATBOOK_API_H
