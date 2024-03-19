#include "stdafx.h"
#include "minidbg.h"
#include "minternl.h"
#include "pub_def.h"
#include "pri_def.h"
#include "global.h"
#include "func_def.h"
#include "init.h"
#include "event.h"
#include "cls_def.h"
#include <windows.h>
#include <psapi.h>
#pragma warning( push )
#pragma warning( disable : 4005 )
#include <ntstatus.h>
#pragma warning( pop )
#include <winternl.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "psapi")
#pragma comment(lib, "version")

#include "library/libstring/strapi.h"
#include "library/libwin/win.h"


int minidbg_init(pminidbg_context* ctx)
{
    InitFreq();
    *ctx = (pminidbg_context)malloc(sizeof(minidbg_context));
    memset(*ctx,0,sizeof(minidbg_context));
    _minidbg_init(*ctx);
    (*ctx)->_watch_thread_quit_event = CreateEventW(NULL,TRUE,FALSE,NULL);
    (*ctx)->_cur_heartbeat = 0;
    (*ctx)->b_start_check_hb = FALSE;
#ifdef _DEBUG
    gOption|=OPTION_DEBUG;
#endif
    return 0;
}

int minidbg_deinit(pminidbg_context* ctx)
{
    _minidbg_deinit(*ctx);
    if((*ctx)->_watch_thread_h)
    {
        SetEvent((*ctx)->_watch_thread_quit_event);
        WaitForSingleObject((*ctx)->_watch_thread_h,INFINITE);
        CloseHandle((*ctx)->_watch_thread_h);
        (*ctx)->_watch_thread_h = 0;
    }
    if((*ctx)->_watch_thread_quit_event)
    {
        CloseHandle((*ctx)->_watch_thread_quit_event);
        (*ctx)->_watch_thread_quit_event = 0;
    }
    free(*ctx);
    *ctx = 0;
    return 0;
}


int minidbg_parse_w(pminidbg_context ctx, const wchar_t* cfg, const wchar_t* hook)
{
    int ret=0;
    _init_cfg_w(ctx, cfg);
    _init_hook_w(ctx, hook);
    ret=_minidbg_parse_internal(ctx);
    return 0;
}

int minidbg_parse(pminidbg_context ctx, const char* cfg, const char* hook)
{
    int ret = 0;
    wchar_t* _cfg_w = 0;
    wchar_t* _hook_w = 0;
    ansy2unicode(cfg, &_cfg_w);
    ansy2unicode(hook, &_hook_w);
    ret = minidbg_parse_w(ctx, _cfg_w, _hook_w);
    freestrbufw(&_cfg_w);
    freestrbufw(&_hook_w);
    return ret;
}

int minidbg_parse_str(pminidbg_context ctx)
{
    int ret=0;
    wchar_t *_tmp_line = 0;
    wchar_t* _default_cfg_w = 0;
    wchar_t* _default_hook_w = 0;
    ansy2unicode(_default_cfg, &_default_cfg_w);
    ansy2unicode(_default_hook, &_default_hook_w);
    //cfg

    _tmp_line = _default_cfg_w;
    while(_tmp_line)
    {
        wchar_t * _next_line = wcschr(_tmp_line, L'\n');
        if (_next_line) *_next_line = L'\0';
        _init_one_line_cfg(ctx,_tmp_line);
        if(gOption & OPTION_DEBUG) wprintf(L"minidbg_parse_str:%s\n",_tmp_line);
        if (_next_line) *_next_line = L'\n';
        _tmp_line = _next_line ? (_next_line+1) : NULL;
    }
    
    //hook

    _tmp_line = _default_hook_w;
    while(_tmp_line)
    {
        wchar_t * _next_line = wcschr(_tmp_line, L'\n');
        if (_next_line) *_next_line = L'\0';
        _init_one_line_hook(ctx,_tmp_line);
        if(gOption & OPTION_DEBUG) wprintf(L"%s\n",_tmp_line);
        if (_next_line) *_next_line = L'\n';
        _tmp_line = _next_line ? (_next_line+1) : NULL;
    }
    freestrbufw(&_default_cfg_w);
    freestrbufw(&_default_hook_w);
    
    ret=_minidbg_parse_internal(ctx);
    return 0;
}

int minidbg_set(pminidbg_context ctx)
{
    _minidbg_set(ctx);
    return 0;
}

int minidbg_unset(pminidbg_context ctx)
{
    _minidbg_unset(ctx);
    return 0;
}


#define SHA256_CHAR_LEN 128
void _process_event(pminidbg_context ctx, DWORD pid, DWORD tid, DWORD ppid, char* path, wchar_t* cmd, void* peb, void* wow64_peb)
{
    char _sha256[SHA256_CHAR_LEN+1];
    char _version_info[128];
    char re[2048];
    
    char szcmd[1024];
    wch2utf8(szcmd,sizeof(szcmd),cmd);
    
    char _tmp_buf[1024];
    char _tmp_buf2[1024];
    memset(_sha256,0,sizeof(_sha256));
    memset(_version_info,0,sizeof(_version_info));
    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,%d,process,%d,%s,%s,%p,%p,sha256:%s,%s",
        GetTimeStamp(),
        pid,
        tid,
        ppid,
        format_str(_tmp_buf,sizeof(_tmp_buf),path),
        format_str(_tmp_buf2,sizeof(_tmp_buf2),szcmd),
        peb,
        wow64_peb,
        calc_sha256_file(path,(char (&)[128])_sha256),
        get_file_version(path,_version_info,sizeof(_version_info))
        );

    api_event(re);
}

void _thread_event(pminidbg_context ctx, DWORD pid, DWORD tid, void* start_address)
{
    char re[2048];
    char mod_name[64];
    unsigned __int64 offset;
    char _tmp_buf[1024];

    mod_name[0]=0;
    _get_module_and_offset_from_addr(ctx,pid,mod_name,sizeof(mod_name),&offset,start_address);
    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,%d,thread,0x%p (%s+0x%llx)",
        GetTimeStamp(),
        pid,
        tid,
        start_address,
        format_str(_tmp_buf,sizeof(_tmp_buf),mod_name),
        offset
        );

    api_event(re);
}

void _dll_event(pminidbg_context ctx, DWORD pid, DWORD tid, char* path, void* base)
{
    char _sha256[SHA256_CHAR_LEN+1];
    char _version_info[128];
    char re[2048];
    char _tmp_buf[1024];

    memset(_sha256,0,sizeof(_sha256));
    memset(_version_info,0,sizeof(_version_info));
    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,%d,module,%s,base:0x%p,sha256:%s,%s",
        GetTimeStamp(),
        pid,
        tid,
        format_str(_tmp_buf,sizeof(_tmp_buf),path),
        base,
        calc_sha256_file(path,(char (&)[128])_sha256),
        get_file_version(path,_version_info,sizeof(_version_info))
        );

    api_event(re);
}



void _handle_process(pminidbg_context ctx, DWORD pid, DWORD tid, char* path)
{
    char cmd_buf[MAX_CMD_LEN+2];
    char image_buf[MAX_IMAGE_LEN+2];
    unsigned long ppid=0;
    void* peb=0;
    void* wow64_peb=0;
    memset(cmd_buf,0,sizeof(cmd_buf));
    memset(image_buf,0,sizeof(image_buf));
    _query_proc_info(GET_UNIT_CONTEXT(ctx,pid).h,&ppid,&peb,&wow64_peb,image_buf,sizeof(image_buf),cmd_buf,sizeof(cmd_buf));
    
    if(peb)
    {
        if(gOption & OPTION_PATCH_PEB) _patch_peb(ctx,pid,tid,peb);
    }
    
    if(wow64_peb)
    {
        if(gOption & OPTION_PATCH_PEB) _patch_peb(ctx,pid,tid,wow64_peb);
    }

    _process_event(ctx,pid,tid,ppid,path,(wchar_t*)cmd_buf,peb,wow64_peb);
}

void _add_process_module(pminidbg_context ctx, DWORD pid, DWORD tid, char* path, void* base);

void _add_process_unit(pminidbg_context ctx, DWORD pid, DWORD tid, char* path, LPVOID base)
{
    CAutoLock _auto(ctx->_unit_lock);
    if(GET_UNIT_CONTEXT(ctx,pid).h == NULL)
    {
        GET_UNIT_CONTEXT(ctx,pid).h = OpenProcess(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION |
            PROCESS_DUP_HANDLE
            ,
            FALSE,
            pid);
#pragma warning( push )
#pragma warning( disable : 4312 )
        GET_UNIT_CONTEXT(ctx,pid).id = (void*)pid;
#pragma warning( pop )
        GET_UNIT_CONTEXT(ctx,pid).base = base;
        strncpy_s(GET_UNIT_CONTEXT(ctx,pid).szPath,path,_TRUNCATE);
        IsWow64Process(GET_UNIT_CONTEXT(ctx,pid).h,&GET_UNIT_CONTEXT(ctx,pid).wow64);
        InitializeListHead(&GET_UNIT_CONTEXT(ctx,pid).mod_list);
        GET_UNIT_CONTEXT(ctx,pid).flag = UNIT_FLAG_INIT;
        _handle_process(ctx,pid,tid,path);
        //
        //
        //
        _add_process_module(ctx,pid,tid,path,base);
        //
    }
    ctx->_proc_count++;
}

void _remove_process_unit(pminidbg_context ctx, DWORD id)
{
    CAutoLock _auto(ctx->_unit_lock);
    if(GET_UNIT_CONTEXT(ctx,id).h)
    {
        LIST_ENTRY* mod_head = NULL;
        LIST_ENTRY* mod_next = NULL;
        CloseHandle(GET_UNIT_CONTEXT(ctx,id).h);
        GET_UNIT_CONTEXT(ctx,id).id = 0;
        mod_head = &(GET_UNIT_CONTEXT(ctx,id).mod_list);
        mod_next = mod_head->Flink;
        while(mod_next != mod_head)
        {
            LIST_ENTRY* hook_head = NULL;
            LIST_ENTRY* hook_next = NULL;
            module_ds* item = CONTAINING_RECORD(mod_next,module_ds,entry);
            //
            //
            hook_head = &item->hook_list;
            hook_next = hook_head->Flink;
            while(hook_next != hook_head)
            {
                hook_ds* phk = CONTAINING_RECORD(hook_next,hook_ds,entry);
                hook_next = hook_next->Flink;
                free(phk);
            }
            //
            //
            mod_next = mod_next->Flink;
            free(item);
        }
        GET_UNIT_CONTEXT(ctx,id).flag = UNIT_FLAG_NONE;
    }
    ctx->_proc_count--;
}

void _add_thread_unit(pminidbg_context ctx, DWORD pid, DWORD tid)
{
    CAutoLock _auto(ctx->_unit_lock);
    if(GET_THREAD_CONTEXT(ctx,tid).h == NULL)
    {
        GET_THREAD_CONTEXT(ctx,tid).h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, (DWORD)tid);
#pragma warning( push )
#pragma warning( disable : 4312 )
        GET_THREAD_CONTEXT(ctx,tid).tid = (void*)tid;
        GET_THREAD_CONTEXT(ctx,tid).pid = (void*)pid;
#pragma warning( pop )
    }
    ctx->_thread_count++;
}

void _remove_thread_unit(pminidbg_context ctx, DWORD pid, DWORD tid)
{
    CAutoLock _auto(ctx->_unit_lock);
    if(GET_THREAD_CONTEXT(ctx,tid).h)
    {
        CloseHandle(GET_THREAD_CONTEXT(ctx,tid).h);
    }
    ctx->_thread_count--;
}

void _restore_pre_hook(pminidbg_context ctx, DWORD id, hook_ds* phook)
{
    BOOL bret;
    DWORD dwNewP = PAGE_EXECUTE_READWRITE;
    DWORD dwOldP;
    HANDLE h = GET_UNIT_CONTEXT(ctx,id).h;
    char* addr_begin = phook->api_begin;
    char* backup = phook->api_backup;
    int len = (int)phook->ref->first_asm_len;

    if(gOption & OPTION_DEBUG) printf("[_restore_pre_hook]%s!%s=%p>\n",phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);

    _protect_memory(ctx,id,addr_begin,len,dwNewP,&dwOldP);

    _write_memory(ctx,id,addr_begin,backup,len);
    
    if(gOption & OPTION_DEBUG)
        for(int i=0;i<len;i++)
        {
            printf("backup[%d]=%x\n",i,(unsigned char)backup[i]);
        }
    bret = FlushInstructionCache(h,addr_begin,len);
    if(gOption & OPTION_DEBUG) printf("FlushInstructionCache:%d\n", bret);

    _protect_memory(ctx,id,addr_begin,len,dwOldP,&dwOldP);
}

void _install_pre_hook(pminidbg_context ctx, DWORD pid, hook_ds* phook)
{
    DWORD dwNewP = PAGE_EXECUTE_READWRITE;
    DWORD dwOldP;
    HANDLE h = GET_UNIT_CONTEXT(ctx,pid).h;
    BOOL bret;
    int i;
    char buf[sizeof(phook->api_backup)];
    char* backup = phook->api_backup;
    int len = (int)phook->ref->first_asm_len;
    char* begin_addr = phook->api_begin;

    if(gOption & OPTION_DEBUG) printf("[%d][_install_pre_hook]%s!%s=%p>\n",pid,phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);

    if(phook->ref->flag & API_FLAG_ASM_SKIP)
    {
        if(gOption & OPTION_DEBUG) printf("skip bc API_FLAG_ASM_SKIP\n");
        return;
    }

    phook->preflag = HOOK_PRE_FLAG_ON;

    _protect_memory(ctx,pid,begin_addr,len,dwNewP,&dwOldP);
    _read_memory(ctx,pid,begin_addr,backup,len);

    for(i=0;i<len;i++) buf[i] = '\x90';
    buf[phook->ref->pre_offset] = '\xcc';

    _write_memory(ctx,pid,begin_addr,(char*)buf,len);

    bret = FlushInstructionCache(h,begin_addr,len);

    if(gOption & OPTION_DEBUG) printf("FlushInstructionCache:%d\n", bret);

    _protect_memory(ctx,pid,begin_addr,len,dwOldP,&dwOldP);
}

void _install_post_hook(pminidbg_context ctx, DWORD pid, hook_ds* phook)
{
    DWORD dwNewP = PAGE_EXECUTE_READWRITE;
    DWORD dwOldP;
    HANDLE h = GET_UNIT_CONTEXT(ctx,pid).h;
    BOOL bret;
    char buf[sizeof(phook->post_backup)];
    char* post_addr = phook->api_begin + phook->ref->post_offset;

    if(gOption & OPTION_DEBUG) printf("[_install_post_hook]%s!%s=%p>\n",phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);

    if( 0 == phook->ref->post_offset)
    {
        if(gOption & OPTION_DEBUG) printf("skip bc ret is unknown\n");
        return;
    }

    phook->postflag = HOOK_POST_FLAG_ON;

    _protect_memory(ctx,pid,post_addr,sizeof(phook->post_backup),dwNewP,&dwOldP);
    _read_memory(ctx,pid,post_addr,phook->post_backup,sizeof(phook->post_backup));

    buf[0] = '\xcc';
    memcpy(&buf[1],phook->post_backup,sizeof(buf)-1);

    _write_memory(ctx,pid,post_addr,buf,sizeof(buf));

    bret = FlushInstructionCache(h,post_addr,sizeof(phook->post_backup));

    if(gOption & OPTION_DEBUG) printf("FlushInstructionCache:%d\n", bret);

    _protect_memory(ctx,pid,post_addr,sizeof(phook->post_backup),dwOldP,&dwOldP);
}

void _init_module_hook(pminidbg_context ctx, DWORD pid, DWORD tid, module_ds* mod)
{
    if(gOption & OPTION_DEBUG) printf("[%d][_init_module_hook]%s,%s,%p,0x%x>>>>>>>>>>\n",pid,mod->mod_full_path,mod->mod_name,mod->base,mod->machine_type);
#ifdef _WIN64
    if(mod->machine_type == IMAGE_FILE_MACHINE_I386)
    {
    //wow64 dll
        for(int i=0;i<(ctx->_api_x86_count);i++)
        {
            if(
                (
                ctx->_api_x86[i].base == (__int64)mod->base 
                ||
                0 == _stricmp(mod->mod_full_path,ctx->_api_x86[i].mod_raw_name)
                )
                &&
                ctx->_api_x86[i].offset
                )
            {
                char* addr = (char*)mod->base+ctx->_api_x86[i].offset;
                hook_ds* phook = (hook_ds*)malloc(sizeof(hook_ds));
                if(phook)
                {
                    memset(phook,0,sizeof(hook_ds));
                    phook->preflag = HOOK_PRE_FLAG_NONE;
                    phook->postflag = HOOK_POST_FLAG_NONE;
                    phook->api_begin = addr;
                    phook->ref = &ctx->_api_x86[i];
                    phook->mod_ref = mod;
                    InsertHeadList(&mod->hook_list,&phook->entry);

                    if(phook->ref->flag & API_FLAG_PRE_HOOK) _install_pre_hook(ctx,pid,phook);
                    if(phook->ref->flag & API_FLAG_POST_HOOK) _install_post_hook(ctx,pid,phook);
                    
                }
            }
        }
    //
    //wow64 dll
    //
    }
    else
    {
#endif

    for(int i=0;i<(ctx->_api_count);i++)
    {
        if( 
            (
            ctx->_api[i].base == (__int64)mod->base 
            ||
            0 == _stricmp(mod->mod_full_path,ctx->_api[i].mod_raw_name)
            )
            &&
            ctx->_api[i].offset
            )
        {
            char* addr = (char*)mod->base+ctx->_api[i].offset;
            hook_ds* phook = (hook_ds*)malloc(sizeof(hook_ds));
            if(phook)
            {
                memset(phook,0,sizeof(hook_ds));
                phook->preflag = HOOK_PRE_FLAG_NONE;
                phook->postflag = HOOK_POST_FLAG_NONE;
                phook->api_begin = addr;
                phook->ref = &ctx->_api[i];
                phook->mod_ref = mod;
                InsertHeadList(&mod->hook_list,&phook->entry);

                if(phook->ref->flag & API_FLAG_PRE_HOOK) _install_pre_hook(ctx,pid,phook);
                if(phook->ref->flag & API_FLAG_POST_HOOK) _install_post_hook(ctx,pid,phook);

            }
        }
    }

#ifdef _WIN64
    }
#endif

    if(gOption & OPTION_DEBUG) printf("[%d][_init_module_hook]%s,%s,%p,0x%x<<<<<<<<<<\n",pid,mod->mod_full_path,mod->mod_name,mod->base,mod->machine_type);
}

void _add_process_module(pminidbg_context ctx, DWORD pid, DWORD tid, char* path, void* base)
{
    BOOL found = FALSE;
    module_ds* _p_mod = NULL;
    LIST_ENTRY* mod_head = NULL;
    LIST_ENTRY* mod_next = NULL;
    CAutoLock _auto(ctx->_unit_lock);
    
    _dll_event(ctx,pid,tid,path,base);

    mod_head = &(GET_UNIT_CONTEXT(ctx,pid).mod_list);
    mod_next = mod_head->Flink;
    while(mod_next != mod_head)
    {
        _p_mod = CONTAINING_RECORD(mod_next,module_ds,entry);
        if(_p_mod->base == base)
        {
            found = TRUE;
            break;
        }
        mod_next=mod_next->Flink;
    }
    
    if(found)
    {

    }
    else
    {
        _p_mod = (module_ds*)malloc(sizeof(module_ds));
        if(_p_mod)
        {
            _p_mod->base = (char*)base;
            _p_mod->flag = MODULE_FLAG_NONE;
            strncpy_s(_p_mod->mod_full_path,path,_TRUNCATE);
            get_module_base_name(_p_mod->mod_full_path,_p_mod->mod_name,sizeof(_p_mod->mod_name));
            //
            _get_machine_type(ctx,pid,tid,_p_mod->base,&_p_mod->machine_type);
            //
            InitializeListHead(&_p_mod->hook_list);
            InsertHeadList(&(GET_UNIT_CONTEXT(ctx,pid).mod_list),&_p_mod->entry);
        }
    }

    if(MODULE_FLAG_NONE == _p_mod->flag)
    {
        _init_module_hook(ctx,pid,tid,_p_mod);
        _p_mod->flag = MODULE_FLAG_INIT;
    }
}

void _deinit_module_hook(pminidbg_context ctx, DWORD pid, DWORD tid, module_ds* mod)
{
    LIST_ENTRY* hook_head = NULL;
    LIST_ENTRY* hook_next = NULL;
    hook_head = &mod->hook_list;
    hook_next = hook_head->Flink;
    while(hook_next != hook_head)
    {
        hook_ds* phk = CONTAINING_RECORD(hook_next,hook_ds,entry);

        hook_next = hook_next->Flink;
        free(phk);
    }
}

void _remove_process_module(pminidbg_context ctx, DWORD pid, DWORD tid, void* base)
{
    LIST_ENTRY* mod_head = NULL;
    LIST_ENTRY* mod_next = NULL;

    CAutoLock _auto(ctx->_unit_lock);


    mod_head = &(GET_UNIT_CONTEXT(ctx,pid).mod_list);
    mod_next = mod_head->Flink;
    while(mod_next != mod_head)
    {
        module_ds* mod = CONTAINING_RECORD(mod_next,module_ds,entry);
        if(mod->base == base)
        {
            _deinit_module_hook(ctx,pid,tid,mod);
            RemoveEntryList(&mod->entry);
            free(mod);
            break;
        }
        mod_next=mod_next->Flink;
    }

}

void _handle_pre_reg(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook, void* ax, void* bx, void* cx, void* dx, void* bp, void* sp, void* r8, void* r9, void* r10, void* r11)
{
    int i=0;
    size_t cur = 0;
    char* buf = phook->sp_buf;
    _read_memory(ctx,pid,sp,phook->sp_buf,sizeof(phook->sp_buf));
    if(gOption & OPTION_DEBUG) _dump_buffer(ctx,pid,sp,buf,sizeof(buf));

    if(phook->mod_ref->machine_type == IMAGE_FILE_MACHINE_I386)
    {
        //return address
        phook->hook_ret = *((DWORD*)&buf[cur]);
        cur += sizeof(DWORD);
        //
        for(i=0;i<MAX_PARAMETER_NUM;i++)
        {
            phook->hook_param[i] = *((DWORD*)&buf[cur]+i);
        }
    }
    else
    {
#ifdef _WIN64
        //return address
        phook->hook_ret = *((DWORD64*)&buf[cur]);
        cur += sizeof(DWORD64);
        
        phook->hook_param[0] = (DWORD64)cx;
        phook->hook_param[1] = (DWORD64)dx;
        phook->hook_param[2] = (DWORD64)r8;
        phook->hook_param[3] = (DWORD64)r9;

        *((DWORD64*)&buf[cur]+0) = (DWORD64)cx;
        *((DWORD64*)&buf[cur]+1) = (DWORD64)dx;
        *((DWORD64*)&buf[cur]+2) = (DWORD64)r8;
        *((DWORD64*)&buf[cur]+3) = (DWORD64)r9;

        for(i=4;i<MAX_PARAMETER_NUM;i++)
        {
            phook->hook_param[i] = *((DWORD64*)&buf[cur]+i);
        }
#else
        //return address
        phook->hook_ret = *((DWORD*)&buf[cur]);
        cur += sizeof(DWORD);
        //
        for(i=0;i<MAX_PARAMETER_NUM;i++)
        {
            phook->hook_param[i] = *((DWORD*)&buf[cur]+i);
        }
#endif
    }
    
}

void _handle_post_reg(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook, void* ax, void* bx, void* cx, void* dx, void* bp, void* sp, void* r8, void* r9, void* r10, void* r11)
{
    if(phook->mod_ref->machine_type == IMAGE_FILE_MACHINE_I386)
    {

    }
    else if(phook->mod_ref->machine_type == IMAGE_FILE_MACHINE_AMD64)
    {
        if( 
            0 == _stricmp(phook->ref->api_name,"NtQueryInformationProcess")
            ||
            0 == _stricmp(phook->ref->api_name,"ZwQueryInformationProcess")
            )
        {
            if(gOption & OPTION_DEBUG) printf("%s(p0:%llx,p1:%llx,p2:%llx,p3:%llx,p4:%llx,p5:%llx,p6:%llx,p7:%llx)\n",phook->ref->api_name,phook->hook_param[0],phook->hook_param[1],phook->hook_param[2],phook->hook_param[3],phook->hook_param[4],phook->hook_param[5],phook->hook_param[6],phook->hook_param[7]);
            if(phook->hook_param[1] == 7)
            {
                DWORD_PTR nDebug;

                if(phook->hook_param[3] >= sizeof(DWORD_PTR))
                {
                    _read_memory(ctx,pid,(void*)phook->hook_param[2],(char*)&nDebug,sizeof(nDebug));
                    //
                    if(nDebug != 0)
                    {
                        if(gOption & OPTION_DEBUG) printf("found check debug port: %x\n",(DWORD)nDebug);
                        nDebug=0;
                        _write_memory(ctx,pid,(void*)phook->hook_param[2],(char*)&nDebug,sizeof(nDebug));
                    }
                }
            }
        }
    }
}

void _handle_flag(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook)
{
    if(phook->ref->flag & API_FLAG_EXIT_DBG)
    {
        BOOL bRet = DebugActiveProcessStop(pid);
        if(gOption & OPTION_DEBUG) printf("DebugActiveProcessStop(%d)=%d,%d\n",pid,bRet,GetLastError());
    }
    
    if(phook->ref->flag & API_FLAG_CREATE_DUMP)
    {
        _write_dump(ctx,pid,phook->ref->api_name);
    }

    if(phook->ref->flag & API_FLAG_MESSAGEBOX)
    {
        MessageBoxA(0,phook->ref->api_name,"",0);
    }
}

void _handle_pre_hook(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook)
{
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,tid);
    if(gOption & OPTION_DEBUG) printf("[_handle_pre_hook]%s!%s=%p>\n",phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);
    if(hThread)
    {
#ifdef _WIN64
        if(phook->mod_ref->machine_type == IMAGE_FILE_MACHINE_I386)
        {
            WOW64_CONTEXT _context;
            memset(&_context,0,sizeof(_context));
            _context.ContextFlags = CONTEXT_FULL;
            Wow64GetThreadContext(hThread,&_context);
#pragma warning( push )
#pragma warning( disable : 4312 )
            _handle_pre_reg(ctx,pid,tid,phook,(void*)_context.Eax,(void*)_context.Ebx,(void*)_context.Ecx,(void*)_context.Edx,(void*)_context.Ebp,(void*)_context.Esp,0,0,0,0);
#pragma warning( pop )
            if(gOption & OPTION_DEBUG) printf("[wow64]EFlags:%x\n",_context.EFlags);
            if(gOption & OPTION_DEBUG) printf("[wow64]Eip:%x\n",_context.Eip);
            if(gOption & OPTION_DEBUG) printf("[wow64]asm len:%d\n",(int)phook->ref->first_asm_len);
            _context.EFlags|=0x100;
            _context.Eip = _context.Eip-1;
            _restore_pre_hook(ctx,pid,phook);
            Wow64SetThreadContext(hThread, &_context);
            phook->preflag = HOOK_PRE_FLAG_TRAP;
            phook->tid = tid;
            phook->wow64_context = _context;
        }
        else
#endif
        {
            CONTEXT _context;
            memset(&_context,0,sizeof(_context));
            _context.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &_context);
#ifdef _WIN64
            _handle_pre_reg(ctx,pid,tid,phook,(void*)_context.Rax,(void*)_context.Rbx,(void*)_context.Rcx,(void*)_context.Rdx,(void*)_context.Rbp,(void*)_context.Rsp,(void*)_context.R8,(void*)_context.R9,(void*)_context.R10,(void*)_context.R11);
#else
            _handle_pre_reg(ctx,pid,tid,phook,(void*)_context.Eax,(void*)_context.Ebx,(void*)_context.Ecx,(void*)_context.Edx,(void*)_context.Ebp,(void*)_context.Esp,0,0,0,0);
#endif

            if(gOption & OPTION_DEBUG) printf("EFlags:%x\n",_context.EFlags);
#ifdef _WIN64
            if(gOption & OPTION_DEBUG) printf("Rip:%llx\n",_context.Rip);
#else
            if(gOption & OPTION_DEBUG) printf("Eip:%x\n",_context.Eip);
#endif
            if(gOption & OPTION_DEBUG) printf("asm len:%d\n",(int)phook->ref->first_asm_len);
            _context.EFlags|=0x100;
#ifdef _WIN64
            _context.Rip = _context.Rip-1;
#else
            _context.Eip = _context.Eip-1;
#endif
            _restore_pre_hook(ctx,pid,phook);
            SetThreadContext(hThread, &_context);
            phook->preflag = HOOK_PRE_FLAG_TRAP;
            phook->tid = tid;
            phook->context = _context;
        }

        CloseHandle(hThread);
    }
}



void _handle_post_hook(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook)
{
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,tid);
    if(gOption & OPTION_DEBUG) printf("[_handle_hook]%s!%s=%p>\n",phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);
    if(hThread)
    {
#ifdef _WIN64
        if(phook->mod_ref->machine_type == IMAGE_FILE_MACHINE_I386)
        {
            WOW64_CONTEXT _context;
            memset(&_context,0,sizeof(_context));
            _context.ContextFlags = CONTEXT_FULL;
            Wow64GetThreadContext(hThread,&_context);
#pragma warning( push )
#pragma warning( disable : 4312 )
            _handle_post_reg(ctx,pid,tid,phook,(void*)_context.Eax,(void*)_context.Ebx,(void*)_context.Ecx,(void*)_context.Edx,(void*)_context.Ebp,(void*)_context.Esp,0,0,0,0);
#pragma warning( pop )
            Wow64SetThreadContext(hThread, &_context);
        }
        else
#endif
        {
            CONTEXT _context;
            memset(&_context,0,sizeof(_context));
            _context.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &_context);
#ifdef _WIN64
            _handle_post_reg(ctx,pid,tid,phook,(void*)_context.Rax,(void*)_context.Rbx,(void*)_context.Rcx,(void*)_context.Rdx,(void*)_context.Rbp,(void*)_context.Rsp,(void*)_context.R8,(void*)_context.R9,(void*)_context.R10,(void*)_context.R11);
#else
            _handle_post_reg(ctx,pid,tid,phook,(void*)_context.Eax,(void*)_context.Ebx,(void*)_context.Ecx,(void*)_context.Edx,(void*)_context.Ebp,(void*)_context.Esp,0,0,0,0);
#endif
            
            SetThreadContext(hThread, &_context);
        }

        CloseHandle(hThread);
    }
}

void _handle_rerun(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook)
{
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,tid);
    if(hThread)
    {
#ifdef _WIN64
        if(phook->mod_ref->machine_type == IMAGE_FILE_MACHINE_I386)
        {
            WOW64_CONTEXT _context;
            memset(&_context,0,sizeof(_context));
            _context.ContextFlags = CONTEXT_FULL;
            Wow64GetThreadContext(hThread,&_context);

            _context.Eip = _context.Eip-1;
            
            Wow64SetThreadContext(hThread, &_context);
        }
        else
#endif
        {
            CONTEXT _context;
            memset(&_context,0,sizeof(_context));
            _context.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &_context);
#ifdef _WIN64
            _context.Rip = _context.Rip-1;
#else
            _context.Eip = _context.Eip-1;
#endif

            SetThreadContext(hThread, &_context);
        }


        CloseHandle(hThread);
    }
}


#define MAX_EVENT_LEN 8192
#define MAX_RETURN_LEN 5120
#define MAX_PARAMETER_LEN 1024
void _api_pre_event(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook)
{
    char p_re[MAX_PARAMETER_LEN];
    char re[MAX_EVENT_LEN];
    void* ret_address = 0;
    char _ret_buf[MAX_RETURN_LEN];

    ret_address = (void*)phook->hook_ret;

    if(FALSE == ctx->b_start_check_hb) ctx->b_start_check_hb = TRUE;

    if(phook->ref->param[0])
    {
        _api_parameter(p_re,sizeof(p_re),ctx,pid,tid,phook,FALSE);
    }
    else
    {
        _snprintf_s(p_re,sizeof(p_re),_TRUNCATE,"void");
    }

    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,%d,api,%s!%s,%s,API=0x%p,RA=0x%p,%s",
        GetTimeStamp(),
        pid,
        tid,
        phook->ref->mod_base_name,
        phook->ref->api_name,
        p_re,
        phook->api_begin,
        ret_address,
        _parse_return_address(ctx,pid,tid,_ret_buf,sizeof(_ret_buf),ret_address,phook)
        );

    api_event(re);
}

void _api_post_event(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook)
{
    char p_re[MAX_PARAMETER_LEN];
    char re[MAX_EVENT_LEN];
    void* ret_address=0;
    char _ret_buf[MAX_RETURN_LEN];

    ret_address = (void*)phook->hook_ret;

    if(phook->ref->param[0])
    {
        _api_parameter(p_re,sizeof(p_re),ctx,pid,tid,phook,TRUE);
    }
    else
    {
        _snprintf_s(p_re,sizeof(p_re),_TRUNCATE,"void");
    }

    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,%d,api,%s!%s,%s,API=0x%p,RA=0x%p,%s",
        GetTimeStamp(),
        pid,
        tid,
        phook->ref->mod_base_name,
        phook->ref->api_name,
        p_re,
        phook->api_begin,
        ret_address,
        _parse_return_address(ctx,pid,tid,_ret_buf,sizeof(_ret_buf),ret_address,phook)
        );

    api_event(re);
}

void _debug_event(pminidbg_context ctx, DWORD pid, DWORD tid, hook_ds* phook, char* msg)
{
    char re[2048];

    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,%d,%s!%s,msg:%s",
        GetTimeStamp(),
        pid,
        tid,
        phook->ref->mod_base_name,
        phook->ref->api_name,
        msg
        );

    api_event(re);
}

int _handle_breakpoint(pminidbg_context ctx, DWORD pid, DWORD tid, EXCEPTION_DEBUG_INFO* except)
{
    char re[2048];
    int ret = FALSE;
    LIST_ENTRY* mod_head = NULL;
    LIST_ENTRY* mod_next = NULL;
    if(gOption & OPTION_DEBUG) printf("[_handle_breakpoint]pid:%d,tid:%d,code:0x%x,addr:%p\n",pid,tid,except->ExceptionRecord.ExceptionCode,except->ExceptionRecord.ExceptionAddress);
    CAutoLock _auto(ctx->_unit_lock);

    if(GET_UNIT_CONTEXT(ctx,pid).flag == UNIT_FLAG_INIT)
    {
        mod_head = &GET_UNIT_CONTEXT(ctx,pid).mod_list;
        mod_next = mod_head->Flink;
        while(mod_next != mod_head)
        {
            LIST_ENTRY* hook_head = NULL;
            LIST_ENTRY* hook_next = NULL;
            module_ds* pmod = CONTAINING_RECORD(mod_next,module_ds,entry);

            hook_head = &pmod->hook_list;
            hook_next = hook_head->Flink;
            while(hook_next != hook_head)
            {
                hook_ds* phook = CONTAINING_RECORD(hook_next,hook_ds,entry);
                if(
                    (phook->api_begin+phook->ref->pre_offset) == except->ExceptionRecord.ExceptionAddress
                    )
                {
                    if(gOption & OPTION_DEBUG) printf("[%d]######PRE######%s!%s=%p######\n",pid,phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);
                    _snprintf_s(re,sizeof(re),_TRUNCATE,",%s!%s,preflag:%d", phook->ref->mod_base_name, phook->ref->api_name,phook->preflag);
                    log_event(re);
                    if(phook->preflag == HOOK_PRE_FLAG_ON)
                    {
                        _handle_flag(ctx, pid, tid, phook);
                        _handle_pre_hook(ctx, pid, tid, phook);
                        if(phook->ref->flag&API_FLAG_PRE_EVENT) _api_pre_event(ctx, pid, tid, phook);
                    }
                    else if(phook->preflag == HOOK_PRE_FLAG_TRAP)
                    {
                        _handle_rerun(ctx, pid, tid, phook);
                    }
                    else //API_FLAG_ASM_SKIP such as CC
                    {
                        _handle_flag(ctx, pid, tid, phook);
                        if(phook->ref->flag&API_FLAG_PRE_EVENT) _api_pre_event(ctx, pid, tid, phook);
                    }
                    
                    ret = TRUE;
                    break;
                }
                else if(
                    (phook->api_begin+phook->ref->post_offset) == except->ExceptionRecord.ExceptionAddress
                    )
                {
                    if(gOption & OPTION_DEBUG) printf("[%d]######POST######%s!%s=%p######\n",pid,phook->mod_ref->mod_full_path,phook->ref->api_name,phook->api_begin);
                    
                    if(phook->postflag == HOOK_POST_FLAG_ON)
                    {
                        _handle_post_hook(ctx, pid, tid, phook);
                        if(phook->ref->flag&API_FLAG_POST_EVENT) _api_post_event(ctx, pid, tid, phook);
                    }

                    ret = TRUE;
                    break;
                }
                hook_next=hook_next->Flink;
            }

            mod_next=mod_next->Flink;
        }
    }

    return ret;
}

int _handle_single_step(pminidbg_context ctx, DWORD pid, DWORD tid, EXCEPTION_DEBUG_INFO* except)
{
    int ret = FALSE;
    LIST_ENTRY* mod_head = NULL;
    LIST_ENTRY* mod_next = NULL;
    if(gOption & OPTION_DEBUG) printf("[_handle_single_step]pid:%d,tid:%d,code:0x%x,addr:%p\n",pid,tid,except->ExceptionRecord.ExceptionCode,except->ExceptionRecord.ExceptionAddress);
    CAutoLock _auto(ctx->_unit_lock);

    if(GET_UNIT_CONTEXT(ctx,pid).flag == UNIT_FLAG_INIT)
    {
        mod_head = &GET_UNIT_CONTEXT(ctx,pid).mod_list;
        mod_next = mod_head->Flink;
        while(mod_next != mod_head)
        {
            LIST_ENTRY* hook_head = NULL;
            LIST_ENTRY* hook_next = NULL;
            module_ds* pmod = CONTAINING_RECORD(mod_next,module_ds,entry);

            hook_head = &pmod->hook_list;
            hook_next = hook_head->Flink;
            while(hook_next != hook_head)
            {
                hook_ds* phook = CONTAINING_RECORD(hook_next,hook_ds,entry);
                if(
                    phook->preflag == HOOK_PRE_FLAG_TRAP &&

                    (
                        (phook->api_begin+phook->ref->first_asm_len) == except->ExceptionRecord.ExceptionAddress
                        ||
                        (phook->ref->x_addr) == (__int64)except->ExceptionRecord.ExceptionAddress
                        
                    )
                    //
                    )
                {

                    if(gOption & OPTION_DEBUG) printf("rehook:%s!%s=%p\n",phook->ref->mod_base_name,phook->ref->api_name,phook->api_begin);
                    _install_pre_hook(ctx,pid,phook);
                    ret = TRUE;
                    break;
                }
                hook_next=hook_next->Flink;
            }

            mod_next=mod_next->Flink;
        }
    }

    return ret;
}


void _handle_post(pminidbg_context ctx, DWORD pid)
{


}


DWORD _handle_exception(pminidbg_context ctx, DWORD pid, DWORD tid, EXCEPTION_DEBUG_INFO* except)
{
    DWORD ret;
    ret = DBG_EXCEPTION_NOT_HANDLED;
    switch(except->ExceptionRecord.ExceptionCode)
    { 
    case EXCEPTION_ACCESS_VIOLATION: 

        break;

    case STATUS_WX86_BREAKPOINT:
        ret = DBG_EXCEPTION_NOT_HANDLED;
        if(_handle_breakpoint(ctx,pid,tid,except))ret=DBG_CONTINUE;
        break;

    case EXCEPTION_BREAKPOINT: 
        ret = DBG_EXCEPTION_NOT_HANDLED;
        if(_handle_breakpoint(ctx,pid,tid,except))ret=DBG_CONTINUE;
        break;

    case EXCEPTION_DATATYPE_MISALIGNMENT: 

        break;

    case STATUS_WX86_SINGLE_STEP:
        ret = DBG_EXCEPTION_HANDLED;
        if(_handle_single_step(ctx,pid,tid,except))ret=DBG_CONTINUE;
        break;

    case EXCEPTION_SINGLE_STEP: 
        ret = DBG_EXCEPTION_HANDLED;
        if(_handle_single_step(ctx,pid,tid,except))ret=DBG_CONTINUE;
        break;

    case DBG_CONTROL_C: 

        break;

    default:
        // Handle other exceptions. 
        break;
    }

    return ret;
}

void _enum_process_cb_internal(cb_context* cb_ctx,const wchar_t* image_buf,const wchar_t* cmd_buf)
{
    char _sha256[SHA256_CHAR_LEN+1];
    char _version_info[128];
    char re[2048];
    
    char szImage[MAX_IMAGE_LEN];
    wch2utf8(szImage,sizeof(szImage),image_buf);
    
    char szCmd[MAX_CMD_LEN];
    wch2utf8(szCmd,sizeof(szCmd),cmd_buf);
    
    char _tmp_buf[1024];
    char _tmp_buf2[1024];
    memset(_sha256,0,sizeof(_sha256));
    memset(_version_info,0,sizeof(_version_info));
    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%0.8x,%d,enum,%d,%s,%s,sha256:%s,%s",
        GetTimeStamp(),
        cb_ctx->pid,
        cb_ctx->ppid,
        format_str(_tmp_buf,sizeof(_tmp_buf),szImage),
        format_str(_tmp_buf2,sizeof(_tmp_buf2),szCmd),
        calc_sha256_file(szImage,(char (&)[128])_sha256),
        get_file_version(szImage,_version_info,sizeof(_version_info))
        );

    api_event(re);
}

void _enum_process_cb(pminidbg_context ctx, cb_context* cb_ctx)
{
    if(cb_ctx&&cb_ctx->pid)
    {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION |
            PROCESS_DUP_HANDLE
            ,
            FALSE,
            cb_ctx->pid);
        if(hProcess)
        {
            char cmd_buf[MAX_CMD_LEN+2];
            char image_buf[MAX_IMAGE_LEN+2];
            unsigned long ppid=0;
            void* peb=0;
            void* wow64_peb=0;
            memset(cmd_buf,0,sizeof(cmd_buf));
            memset(image_buf,0,sizeof(image_buf));
            _query_proc_info(hProcess,&ppid,&peb,&wow64_peb,image_buf,sizeof(image_buf),cmd_buf,sizeof(cmd_buf));
            _enum_process_cb_internal(cb_ctx,(const wchar_t*)image_buf,(const wchar_t*)cmd_buf);
            CloseHandle(hProcess);
        }
    }
    
    
}



#define SAMPLE_SUFFIX_LEN 6
int minidbg_run(pminidbg_context ctx)
{
    BOOL bRet;
    char re[2048];
    char utf[512];
    char* _ptr_;
    wchar_t* p_image = NULL;
    wchar_t* p_cmd = NULL;
    WCHAR szTmp[2048];
    WCHAR szIMAGE[1024];
    WCHAR szCMD[1024];
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DEBUG_EVENT _event;
	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    szIMAGE[0]=0;
    szCMD[0]=0;

    _find_interesting_process(ctx,_enum_process_cb);
    
    _minidbg_run_wd(ctx);
    if(0==wcscmp(ctx->_image,L"<NULL>"))
    {
        p_image = NULL;
    }
    else if(0==wcscmp(ctx->_image,L"<SELF>"))
    {
        DWORD len = GetModuleFileNameW(NULL,szIMAGE,_countof(szIMAGE));
        p_image = NULL;
        if(len>SAMPLE_SUFFIX_LEN)
        {
            if(
                (szIMAGE[len-1] == L'E' || szIMAGE[len-1] == L'e') &&
                (szIMAGE[len-2] == L'X' || szIMAGE[len-2] == L'x') &&
                (szIMAGE[len-3] == L'E' || szIMAGE[len-3] == L'e') &&
                (szIMAGE[len-4] == L'.')
                )
            {
                if(szIMAGE[len-5] == L'4' && szIMAGE[len-6] == L'6')
                {
                    szIMAGE[len-6]=0;
                    wcsncpy_s(gApiEventName,szIMAGE,_TRUNCATE);
                    wcsncat_s(gApiEventName,L".log",_TRUNCATE);
                    wcsncpy_s(gLogName,szIMAGE,_TRUNCATE);
                    wcsncat_s(gLogName,L"_debug.log",_TRUNCATE);
                    wcsncpy_s(&szIMAGE[len-6],SAMPLE_SUFFIX_LEN,L".bat",_TRUNCATE);

                    minidbg_unset(ctx);
                    minidbg_set(ctx);
                }
                else
                {
                    szIMAGE[len-4]=0;
                    wcsncpy_s(gApiEventName,szIMAGE,_TRUNCATE);
                    wcsncat_s(gApiEventName,L".log",_TRUNCATE);
                    wcsncpy_s(gLogName,szIMAGE,_TRUNCATE);
                    wcsncat_s(gLogName,L"_debug.log",_TRUNCATE);
                    wcsncpy_s(&szIMAGE[len-4],SAMPLE_SUFFIX_LEN,L".bat",_TRUNCATE);

                    minidbg_unset(ctx);
                    minidbg_set(ctx);
                }
                p_image = szIMAGE;
            }
            
        }
        if(p_image && !PathFileExists(p_image))
        {

            p_image = NULL;
        }
    }
    else
    {
        p_image = ctx->_image;
    }
    
    if(0==wcscmp(ctx->_cmd,L"<NULL>"))
    {
        p_cmd = NULL;
    }
    else if(0==wcscmp(ctx->_cmd,L"<SELF>"))
    {
        p_cmd = szCMD;
    }
    else
    {
        p_cmd = ctx->_cmd;
    }
    
    bRet = CreateProcessW(
            p_image,
            p_cmd,
            0,
            0,
            TRUE,
            DEBUG_PROCESS,
            NULL,
            NULL,
            &si,
            &pi);
    if(
        bRet
        )
    {
        while(WaitForDebugEvent(&_event, INFINITE))
        {
            DWORD dwContinueStatus = DBG_CONTINUE;
            _dump_event(&_event);
            InterlockedIncrement(&g_heartbeat);

            switch (_event.dwDebugEventCode)
            {
            case EXCEPTION_DEBUG_EVENT:
                _dump_exeception_info(&_event.u.Exception);
                if(_event.u.Exception.dwFirstChance)
                {
                    dwContinueStatus = _handle_exception(ctx,_event.dwProcessId,_event.dwThreadId,&_event.u.Exception);
                }
                else
                {
                    HANDLE hProc = NULL;

                    if(gOption & OPTION_2ND_CHANCE_MSGBOX)MessageBoxA(0,"","",0);
                    if(gOption & OPTION_DEBUG) printf("second chance.., kill process(%d)\n", _event.dwProcessId);
                    if(gOption & OPTION_2ND_CHANCE_DUMP)_write_dump(ctx,_event.dwProcessId,"crash");
                    hProc = OpenProcess(PROCESS_TERMINATE,FALSE,_event.dwProcessId);
                    if(hProc)
                    {
                        TerminateProcess(hProc,0);
                        if(gOption & OPTION_DEBUG) printf("TerminateProcess(%d):%d\n",_event.dwProcessId,GetLastError());
                        CloseHandle(hProc);
                    }
                }
                
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                _add_thread_unit(ctx,_event.dwProcessId,_event.dwThreadId);
                _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%p", _event.u.CreateThread.lpStartAddress);
                log_event(re);
                log_event(",");
                _dump_context(_event.u.CreateThread.hThread);
                _thread_event(ctx,_event.dwProcessId,_event.dwThreadId,_event.u.CreateThread.lpStartAddress);
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                GetFinalPathNameByHandleW(_event.u.CreateProcessInfo.hFile, szTmp, _countof(szTmp), FILE_NAME_NORMALIZED);
                wch2utf8(utf,sizeof(utf),szTmp);
                _ptr_ = utf;
                if(0 == _strnicmp(_ptr_,"\\\\?\\",4))_ptr_=_ptr_+4;
                _add_process_unit(ctx,_event.dwProcessId,_event.dwThreadId,_ptr_,_event.u.CreateProcessInfo.lpBaseOfImage);
                //
                _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%p,%s,%d", GET_UNIT_CONTEXT(ctx,_event.dwProcessId).base, GET_UNIT_CONTEXT(ctx,_event.dwProcessId).szPath, GET_UNIT_CONTEXT(ctx,_event.dwProcessId).wow64);
                log_event(re);
                _add_thread_unit(ctx,_event.dwProcessId,_event.dwThreadId);
                _thread_event(ctx,_event.dwProcessId,_event.dwThreadId,_event.u.CreateProcessInfo.lpStartAddress);
                CloseHandle(_event.u.CreateProcessInfo.hFile);
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                _remove_thread_unit(ctx,_event.dwProcessId,_event.dwThreadId);
                _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%x", _event.u.ExitThread.dwExitCode);
                log_event(re);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                _remove_process_unit(ctx,_event.dwProcessId);
                _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%x", _event.u.ExitProcess.dwExitCode);
                log_event(re);
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if(GetFinalPathNameByHandleW(_event.u.LoadDll.hFile, szTmp, _countof(szTmp), FILE_NAME_NORMALIZED))
                {
                    wch2utf8(utf,sizeof(utf),szTmp);
                    _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%p,%s",_event.u.LoadDll.lpBaseOfDll, utf);
                    log_event(re);
                    _ptr_ = utf;
                    if(0 == _strnicmp(_ptr_,"\\\\?\\",4))_ptr_=_ptr_+4;
                    _add_process_module(ctx,_event.dwProcessId,_event.dwThreadId,_ptr_,_event.u.LoadDll.lpBaseOfDll);
                }
                CloseHandle(_event.u.LoadDll.hFile);
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                _snprintf_s(re,sizeof(re),_TRUNCATE,"0x%p",_event.u.UnloadDll.lpBaseOfDll);
                log_event(re);
                _remove_process_module(ctx,_event.dwProcessId,_event.dwThreadId,_event.u.UnloadDll.lpBaseOfDll);
                
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
                {
                    if(gOption & OPTION_DBGPRINT)
                    {
                        char* _buf = new char[_event.u.DebugString.nDebugStringLength];
                        if(_buf)
                        {
                            SIZE_T nRead = 0;
                            BOOL bres = ReadProcessMemory(GET_UNIT_CONTEXT(ctx,_event.dwProcessId).h,_event.u.DebugString.lpDebugStringData,_buf,_event.u.DebugString.nDebugStringLength,&nRead);
                            if(bres)
                            {
                                if(_event.u.DebugString.fUnicode)
                                {
                                    wch2utf8(utf,sizeof(utf),(wchar_t*)_buf);
                                    printf(utf);
                                }
                                else
                                {
                                    printf(_buf);
                                }
                            }

                            delete [] _buf;
                        }
                    }
                }
                break;
            case RIP_EVENT:
                break;
            default:
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                _snprintf_s(re,sizeof(re),_TRUNCATE,"Unexpected DebugEvent");
                log_event(re);
                break;
            }

            log_event("\r\n");
            ContinueDebugEvent(_event.dwProcessId, _event.dwThreadId, (DWORD)dwContinueStatus);
        };

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        
    }
    _snprintf_s(re,sizeof(re),_TRUNCATE,"<<<\r\n");
    log_event(re);
    return 0;
}


