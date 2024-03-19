#ifndef GLOBAL_DEF
#define GLOBAL_DEF

#ifdef __cplusplus
extern "C" {
#endif

//gOption
#define OPTION_DEBUG 0x01
#define OPTION_DUMPHOOK 0x02
#define OPTION_DBGPRINT 0x04
#define OPTION_PATCH_PEB 0x08
#define OPTION_DETAIL 0x10
#define OPTION_2ND_CHANCE_DUMP 0x20
#define OPTION_2ND_CHANCE_MSGBOX 0x40
#define OPTION_ADJ_PRIVILEGE 0x80
#define OPTION_STR_IN_BASE64 0x100
#define OPTION_STACK_TRACE 0x200
#define OPTION_CHECK_RETURN_ALL 0x400

extern int gOption;

extern wchar_t gApiEventName[256];
extern wchar_t gLogName[256];
extern wchar_t gTempDir[256];
extern wchar_t gHookDumpName32[256];
extern wchar_t gHookDumpName64[256];
extern wchar_t gX86Data[256];
extern unsigned long gDelayTimeInSec;
extern unsigned long gWDInterval;
extern void* g_log;
extern void* g_log_lock;
extern void* g_api_event;
extern void* g_api_event_lock;
extern long g_heartbeat;
extern const char _default_cfg[];
extern const char _default_hook[];

#ifdef __cplusplus
}
#endif

#endif //GLOBAL_DEF