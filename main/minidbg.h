#ifndef MINI_DEBUG
#define MINI_DEBUG

#ifdef __cplusplus
extern "C" {
#endif

#include "pub_def.h"

int minidbg_init(pminidbg_context* ctx);
int minidbg_deinit(pminidbg_context* ctx);
int minidbg_set(pminidbg_context ctx);
int minidbg_unset(pminidbg_context ctx);
int minidbg_parse_w(pminidbg_context ctx, const wchar_t* cfg, const wchar_t* hook);
int minidbg_parse(pminidbg_context ctx, const char* cfg, const char* hook);
int minidbg_parse_str(pminidbg_context ctx);
int minidbg_run(pminidbg_context ctx);

#ifdef __cplusplus
}
#endif

#endif //MINI_DEBUG