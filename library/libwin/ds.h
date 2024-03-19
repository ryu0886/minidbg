#ifndef __DS_DEF
#define __DS_DEF

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push,1)
#pragma pack(pop)

#pragma pack(push,8)
typedef struct _object_attributes_32 {
    unsigned long Length;
    unsigned long RootDirectory;
    unsigned long ObjectName;
    unsigned long Attributes;
    unsigned long SecurityDescriptor;
    unsigned long SecurityQualityOfService;
} object_attributes_32;

typedef struct _object_attributes_64 {
    unsigned long Length;
    unsigned __int64 RootDirectory;
    unsigned __int64 ObjectName;
    unsigned long Attributes;
    unsigned __int64 SecurityDescriptor;
    unsigned __int64 SecurityQualityOfService;
} object_attributes_64;


typedef struct _unicode_string_32 {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned long  Buffer;
} unicode_string_32;

typedef struct _unicode_string_64 {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned __int64  Buffer;
} unicode_string_64;

typedef struct _ansi_string_32 {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned long  Buffer;
} ansi_string_32;

typedef struct _ansi_string_64 {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned __int64  Buffer;
} ansi_string_64;

typedef struct _client_id_32
{
    unsigned long UniqueProcess;
    unsigned long UniqueThread;
} client_id_32;

typedef struct _client_id_64
{
    unsigned __int64 UniqueProcess;
    unsigned __int64 UniqueThread;
} client_id_64;

#pragma pack(pop)



#ifdef __cplusplus
}
#endif

#endif //__DS_DEF

