#ifndef __WIN_API_DEF
#define __WIN_API_DEF

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _LIST_ENTRY *PLIST_ENTRY;
void InitializeListHead(PLIST_ENTRY ListHead);
void InsertHeadList(PLIST_ENTRY ListHead,PLIST_ENTRY Entry);
void RemoveEntryList(PLIST_ENTRY Entry);

#ifdef __cplusplus
}
#endif

#endif //__WIN_API_DEF