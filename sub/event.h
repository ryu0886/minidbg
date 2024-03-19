#ifndef EVENT_DEF
#define EVENT_DEF

#ifdef __cplusplus
extern "C" {
#endif
#include "pri_def.h"
void _api_parameter(char* re, size_t re_len, pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook, BOOL bPost);
#ifdef __cplusplus
}
#endif

#endif //EVENT_DEF