#ifndef FUNCTION__DEF
#define FUNCTION__DEF

#ifdef __cplusplus
extern "C" {
#endif
#include "pri_def.h"
//internal
void _minidbg_init(minidbg_context* ctx);
void _minidbg_deinit(minidbg_context* ctx);
void _minidbg_set(pminidbg_context ctx);
void _minidbg_unset(pminidbg_context ctx);
void _dump_exeception_info(EXCEPTION_DEBUG_INFO* pException);
void _dump_event(DEBUG_EVENT* _event);
void _dump_context(HANDLE hThread);
void _dump_buffer(pminidbg_context ctx, DWORD pid,void* addr, char* buf, size_t buf_len);
void log_event(const char* input);
void api_event(const char* input);
void _init_module(pminidbg_context ctx, const wchar_t* module_cfg);
void _init_api(pminidbg_context ctx, wchar_t* api_cfg);
void _init_hook_w(pminidbg_context ctx, const wchar_t* hook);
void _init_one_line_hook(pminidbg_context ctx, wchar_t * line);
void _init_api_flag(pminidbg_context ctx, wchar_t* api_flag_cfg);
void _init_p_basename(pminidbg_context ctx, wchar_t* p_basename_cfg);
void _init_p_substr(pminidbg_context ctx, wchar_t* p_substr_cfg);
void _init_process(pminidbg_context ctx, wchar_t* process_cfg);
void _init_cfg_w(pminidbg_context ctx, const wchar_t* cfg);
void _init_one_line_cfg(pminidbg_context ctx, wchar_t* line);
void _patch_peb(pminidbg_context ctx, DWORD pid, DWORD tid, void* peb);
BOOL _get_module_name(pminidbg_context ctx, DWORD pid, MEMORY_BASIC_INFORMATION* mbi, char* buf, size_t buf_len);
BOOL _protect_memory(pminidbg_context ctx, DWORD pid, void* addr, size_t len, DWORD dwNewP, DWORD* dwOldP);
BOOL _read_memory(pminidbg_context ctx, DWORD pid, void* addr, char* buf, size_t buf_len);
BOOL _write_memory(pminidbg_context ctx, DWORD pid, void* addr, char* buf, size_t buf_len);
BOOL _get_module_and_offset_from_addr(pminidbg_context ctx, DWORD pid, char* buf, size_t buf_len, unsigned __int64* offset, void* ret);
void _get_machine_type(pminidbg_context ctx, DWORD pid, DWORD tid, void* base, unsigned short* machine_type);
char* _parse_return_address(pminidbg_context ctx, DWORD pid, DWORD tid, char* buf, size_t buf_len, void* ret, hook_ds* phook);
void _dump_hook(pminidbg_context ctx);
void _write_dump(pminidbg_context ctx, DWORD pid, char* prefix_name);
#ifdef __cplusplus
}
#endif

#endif //FUNCTION__DEF