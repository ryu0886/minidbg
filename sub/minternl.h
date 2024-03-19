#ifndef MINI_INTERNAL_DEF
#define MINI_INTERNAL_DEF

#ifdef __cplusplus
extern "C" {
#endif

void InitFreq();
long GetTimeStamp();
void adjust_privilege(const wchar_t* lpPrivilegeName,unsigned long bEnablePrivilege);
const char* get_module_base_name(const char* module_full_path, char* buf, int buf_len);
const char* calc_sha256_buffer(char* pBuf, size_t ulLen, char (&sha256)[128]);
const char* calc_sha256_file(char* path, char (&sha256)[128]);
const char* get_file_version(const char* path, char* buf, unsigned long len);
const char* format_str(char* szOut, size_t len, const char* szIn);
int wch2utf8(char *szOut, int outlen, const wchar_t* szInput);
int is_basename(wchar_t* image_path, wchar_t* basename);
unsigned char* SkipJumps(unsigned char* pbCode);
unsigned long DisassembleFirstIns(void* pFunction, unsigned long dwMinLen, unsigned long* flag);
unsigned long FindFirstRetOffset(void* pFunction, unsigned long dwMinLen);
int _read_memory_by_handle(void* hProc, void* addr, char* buf, size_t buf_len);
void _query_proc_info(void* hProc,unsigned long* ppid,void** peb,void** wow64_peb,char* image_buf,size_t image_buf_len,char* cmd_buf,size_t cmd_buf_len);

#ifdef __cplusplus
}
#endif

#endif //MINI_INTERNAL_DEF