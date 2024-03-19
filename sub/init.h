#ifndef INIT__DEF
#define INIT__DEF

#ifdef __cplusplus
extern "C" {
#endif
#include "pri_def.h"
int _minidbg_run_wd(minidbg_context* ctx);
typedef struct _cb_context
{
    wchar_t* image;
    unsigned long pid;
    unsigned long ppid;
    void* reserve;
}cb_context;
typedef void (*_cb_type) (minidbg_context* ctx, cb_context* cb_ctx);
void _find_interesting_process(pminidbg_context ctx, _cb_type pf_cb);
int _minidbg_parse_internal(pminidbg_context ctx);
#ifdef __cplusplus
}
#endif

#endif //INIT__DEF