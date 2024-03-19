#ifndef __STR_LIB
#define __STR_LIB

#ifdef __cplusplus
extern "C" {
#endif

long unicode2ansy(const wchar_t * input, char ** out);
long ansy2unicode(const char * input, wchar_t ** out);
void freestrbufa(char** pin);
void freestrbufw(wchar_t** pin);
char* strrstr(char* input, char* search);

#ifdef __cplusplus
}
#endif

#endif //__STR_LIB
