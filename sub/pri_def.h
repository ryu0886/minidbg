#ifndef PRIVATE_DEF
#define PRIVATE_DEF

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CMD_LEN 1024
#define MAX_IMAGE_LEN 512

//flag
#define API_FLAG_PRE_HOOK     (0x00000001)
#define API_FLAG_PRE_EVENT    (0x00000002)
#define API_FLAG_POST_HOOK    (0x00000004)
#define API_FLAG_POST_EVENT   (0x00000008)
#define API_FLAG_CREATE_DUMP  (0x00000010)
#define API_FLAG_MESSAGEBOX   (0x00000020)
#define API_FLAG_CHECK_RETURN (0x00000040)
#define API_FLAG_EXIT_DBG     (0x00000080)
#define API_FLAG_ASM_SKIP     (0x00010000)
#define API_FLAG_RET          (0x00020000)
#define API_FLAG_BRANCH       (0x00040000)
#define API_FLAG_BRANCHCC     (0x00080000)
#define API_FLAG_CALL         (0x00100000)
#define API_FLAG_CALLCC       (0x00200000)
#define API_FLAG_BREAKPOINT   (0x00400000)


#define MAX_UNIT_NUMBER 0x10000
#define MASK_UNIT_ID 0xffff
#define MAX_API_NUMBER 0x20000
#define MAX_MODULE_NUMBER 0x100
#define GET_UNIT_CONTEXT(ctx,id) (ctx->_unit[id&MASK_UNIT_ID])
#define GET_THREAD_CONTEXT(ctx,id) (ctx->_thread[id&MASK_UNIT_ID])
#define MAX_IMAGE_PATH 1024
#define MAX_HOOK_NUMBER 0x20000
#define MAX_LIST_NUMBER 0x100
#define MAX_API_FLAG_NUMBER 0x1000

//
//api_ds
//
#define PARAMETER_UNIT (sizeof(DWORD))
#define MAX_MOD_RAW_NAME_SIZE  (sizeof(__int64)*32)
#define MAX_MOD_BASE_NAME_SIZE (sizeof(__int64)*16)
#define MAX_API_NAME_SIZE      (sizeof(__int64)*24*PARAMETER_UNIT)
#define MAX_FWD_NAME_SIZE      (sizeof(__int64)*24)
#define MAX_PARAMETER_SIZE     (sizeof(__int64)*10*PARAMETER_UNIT)
#define MAX_BACKUP_SIZE        (sizeof(__int64)*10)
#define MAX_RESERVE_SIZE       (sizeof(__int64)*4)


typedef struct _api_ds
{
    char mod_raw_name[MAX_MOD_RAW_NAME_SIZE];
    char mod_base_name[MAX_MOD_BASE_NAME_SIZE];
    char api_name[MAX_API_NAME_SIZE];
    char forward_name[MAX_FWD_NAME_SIZE];
    char param[MAX_PARAMETER_SIZE];
    char backup[MAX_BACKUP_SIZE];
    char reserve[MAX_RESERVE_SIZE];
    __int64 first_asm_len;
    __int64 pre_offset;
    __int64 post_offset;
    __int64 offset;
    __int64 base;
    __int64 ordinal;
    __int64 flag;
    __int64 x_addr;
}api_ds;
//
//end api_ds
//

typedef struct _api_flag_ds
{
    char mod_base_name[MAX_MOD_BASE_NAME_SIZE];
    char api_name[MAX_API_NAME_SIZE];
    char param[MAX_PARAMETER_SIZE];
    __int64 offset;
    __int64 flag;
}api_flag_ds;

enum{
    MODULE_FLAG_NONE,
    MODULE_FLAG_INIT
};

typedef struct _module_ds
{
    LIST_ENTRY entry;
    char* base;
    char mod_full_path[MAX_PATH];
    char mod_name[MAX_PATH];
    int flag;
    unsigned short machine_type;
    LIST_ENTRY hook_list;
}module_ds;

enum{
    HOOK_PRE_FLAG_NONE,
    HOOK_PRE_FLAG_ON,
    HOOK_PRE_FLAG_TRAP,
};

enum{
    HOOK_POST_FLAG_NONE,
    HOOK_POST_FLAG_ON
};

#define MAX_POST_BACKUP_SIZE 4
#define MAX_PARAMETER_NUM 8
typedef struct _hook_ds
{
    LIST_ENTRY entry;
    DWORD tid;
    int preflag;
    int postflag;
    char post_backup[MAX_POST_BACKUP_SIZE];
    DWORD64 hook_param[MAX_PARAMETER_NUM];
    DWORD64 hook_ret;
    char sp_buf[1024];
#ifdef _WIN64
    WOW64_CONTEXT wow64_context;
    _CONTEXT context;
#else
    _CONTEXT context;
#endif
    char* api_begin;
    char api_backup[MAX_BACKUP_SIZE];
    api_ds* ref;
    module_ds* mod_ref;
}hook_ds;


enum{
    UNIT_FLAG_NONE,
    UNIT_FLAG_INIT
};

typedef struct _unit_context
{
    void* id;
    HANDLE h;
    void* base;
    int wow64;
    char szPath[MAX_IMAGE_PATH];
    int flag;
    LIST_ENTRY mod_list;
}unit_context;

typedef struct _thread_context
{
    void* tid;
    void* pid;
    HANDLE h;
}thread_context;

enum{
    PROCESS_LIST_FLAG_NONE,
    PROCESS_LIST_FLAG_SUBSTRING,
    PROCESS_LIST_FLAG_FULL_I_STRING,
    PROCESS_LIST_FLAG_PROCESS_BASENAME
};

typedef struct _proc_image_ds
{
    wchar_t _image[256];
    int flag;
}proc_image_ds;

typedef struct _minidbg_context
{
    wchar_t _image[1024];
    wchar_t _cmd[2048];
    proc_image_ds _list[MAX_LIST_NUMBER];
    int _list_count;
    api_ds _api[MAX_API_NUMBER];
    int _api_count;
    api_flag_ds _api_flag[MAX_API_FLAG_NUMBER];
    int _api_flag_count;
    unit_context _unit[MAX_UNIT_NUMBER];
    int _proc_count;
    thread_context _thread[MAX_UNIT_NUMBER];
    int _thread_count;
    void* _unit_lock;
    void* _watch_thread_h;
    unsigned _watch_thread_id;
    void* _watch_thread_quit_event;
    long _cur_heartbeat;
    unsigned long b_start_check_hb;
    void* _parent_h;
    
#ifdef _WIN64
    api_ds _api_x86[MAX_API_NUMBER];
    int _api_x86_count;
#endif
}minidbg_context, *pminidbg_context;

#ifdef __cplusplus
}
#endif

#endif //PRIVATE_DEF