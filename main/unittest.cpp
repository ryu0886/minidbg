#include "stdafx.h"
#include <string.h>
#include <windows.h>
#include <winternl.h>
#include <exception>
#include <iostream>
#include "library/libwin/ds.h"
#include "minternl.h"

char * ch2hex(char *szOut, size_t outlen, const char* input, size_t in_len)
{
    if(outlen < in_len*2) return "";
    memset(szOut,0,outlen);
    if(input == 0)
    {

    }
    else
    {
        for(size_t i=0;i<in_len;i++)
        {
            _snprintf_s(szOut+i*2,3,_TRUNCATE,"%02X",(unsigned char)input[i]);
        }
    }
    return szOut;
}

int _test_ch2hex()
{
    char _hex[256];
    char _buffer[64] = "\xF1\x90\x35\x34\x33\x34\x00\x77";
    char a=-5;
    printf("%s\n",ch2hex(_hex,sizeof(_hex),_buffer,sizeof(_buffer)));
    printf("%02X\n",a);
    printf("%02X\n",(unsigned char)a);
    printf("%d\n",a);
    printf("%d\n",(unsigned char)a);
    //F1903534333400770000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    //FFFFFFFB
    //FB
    //-5
    //251
    return 0;
}

int _test_struct()
{
    //OBJECT_ATTRIBUTES
    printf("object_attributes_32:%lld\n",(DWORD64)sizeof(object_attributes_32));
    printf("\tLength:%d\n",FIELD_OFFSET(object_attributes_32,Length));
    printf("\tRootDirectory:%d\n",FIELD_OFFSET(object_attributes_32,RootDirectory));
    printf("\tObjectName:%d\n",FIELD_OFFSET(object_attributes_32,ObjectName));
    printf("\tAttributes:%d\n",FIELD_OFFSET(object_attributes_32,Attributes));
    printf("\tSecurityDescriptor:%d\n",FIELD_OFFSET(object_attributes_32,SecurityDescriptor));
    printf("\tSecurityQualityOfService:%d\n",FIELD_OFFSET(object_attributes_32,SecurityQualityOfService));

    printf("object_attributes_64:%lld\n",(DWORD64)sizeof(object_attributes_64));
    printf("\tLength:%d\n",FIELD_OFFSET(object_attributes_64,Length));
    printf("\tRootDirectory:%d\n",FIELD_OFFSET(object_attributes_64,RootDirectory));
    printf("\tObjectName:%d\n",FIELD_OFFSET(object_attributes_64,ObjectName));
    printf("\tAttributes:%d\n",FIELD_OFFSET(object_attributes_64,Attributes));
    printf("\tSecurityDescriptor:%d\n",FIELD_OFFSET(object_attributes_64,SecurityDescriptor));
    printf("\tSecurityQualityOfService:%d\n",FIELD_OFFSET(object_attributes_64,SecurityQualityOfService));

    printf("OBJECT_ATTRIBUTES:%lld\n",(DWORD64)sizeof(OBJECT_ATTRIBUTES));
    printf("\tLength:%d\n",FIELD_OFFSET(OBJECT_ATTRIBUTES,Length));
    printf("\tRootDirectory:%d\n",FIELD_OFFSET(OBJECT_ATTRIBUTES,RootDirectory));
    printf("\tObjectName:%d\n",FIELD_OFFSET(OBJECT_ATTRIBUTES,ObjectName));
    printf("\tAttributes:%d\n",FIELD_OFFSET(OBJECT_ATTRIBUTES,Attributes));
    printf("\tSecurityDescriptor:%d\n",FIELD_OFFSET(OBJECT_ATTRIBUTES,SecurityDescriptor));
    printf("\tSecurityQualityOfService:%d\n",FIELD_OFFSET(OBJECT_ATTRIBUTES,SecurityQualityOfService));
    
    //UNICODE_STRING
    printf("unicode_string_32:%lld\n",(DWORD64)sizeof(unicode_string_32));
    printf("\tLength:%d\n",FIELD_OFFSET(unicode_string_32,Length));
    printf("\tMaximumLength:%d\n",FIELD_OFFSET(unicode_string_32,MaximumLength));
    printf("\tBuffer:%d\n",FIELD_OFFSET(unicode_string_32,Buffer));

    printf("unicode_string_64:%lld\n",(DWORD64)sizeof(unicode_string_64));
    printf("\tLength:%d\n",FIELD_OFFSET(unicode_string_64,Length));
    printf("\tMaximumLength:%d\n",FIELD_OFFSET(unicode_string_64,MaximumLength));
    printf("\tBuffer:%d\n",FIELD_OFFSET(unicode_string_64,Buffer));

    printf("UNICODE_STRING:%lld\n",(DWORD64)sizeof(UNICODE_STRING));
    printf("\tLength:%d\n",FIELD_OFFSET(UNICODE_STRING,Length));
    printf("\tMaximumLength:%d\n",FIELD_OFFSET(UNICODE_STRING,MaximumLength));
    printf("\tBuffer:%d\n",FIELD_OFFSET(UNICODE_STRING,Buffer));
    
    
    return 0;
}

int _test_winapi()
{

#ifndef _WIN64
    printf("minidbg.exe:%p\n",GetModuleHandleA("minidbg.exe"));
    printf("minidbg.exe:%p\n",GetModuleHandleW(L"minidbg.exe"));
#else
    printf("minidbg64.exe:%p\n",GetModuleHandleA("minidbg64.exe"));
    printf("minidbg64.exe:%p\n",GetModuleHandleW(L"minidbg64.exe"));
#endif
    printf("%p\n",GetModuleHandleA(""));
    printf("%p\n",GetModuleHandleA(NULL));
    printf("%p\n",GetModuleHandleW(NULL));

    printf("testvirm.exe:%p\n",LoadLibraryA("C:\\git\\testkit\\testvirm.exe"));
    printf("testvirm.exe:%p\n",LoadLibraryW(L"C:\\git\\testkit\\testvirm.exe"));
    printf("testvirm64.exe:%p\n",LoadLibraryA("C:\\git\\testkit\\testvirm64.exe"));
    printf("testvirm64.exe:%p\n",LoadLibraryW(L"C:\\git\\testkit\\testvirm64.exe"));

    return 0;
}

int _test_cpp()
{
    wchar_t* input = L"0x100 ";
    unsigned long ret = wcstoul(input,0,16);
    wprintf(L"%s=%d\n",input,ret);
    return 0;
}

int _test_mem()
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T nret;
    size_t code_len = 0x1024;
    void* code = VirtualAllocEx(GetCurrentProcess(),0,code_len,MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    char* input = (char*)code+5;
    nret = VirtualQueryEx(
        GetCurrentProcess(),
        input,
        &mbi,
        sizeof(mbi)
        );
    printf("addr:%p,base:%p,alloc:%p,alloc_protect:%x,size:%x,state:%x,protect:%x,type:%x\n",
        input,mbi.BaseAddress,mbi.AllocationBase,mbi.AllocationProtect,(DWORD)mbi.RegionSize,mbi.State,mbi.Protect,mbi.Type);
    return 0;
}

int _test_xxx()
{
    STARTUPINFO si;
    TCHAR szModuleName[MAX_PATH];
    TCHAR szTitle[64];
    szModuleName[0] = 0;
    GetModuleFileName(NULL,szModuleName,sizeof(szModuleName)/sizeof(TCHAR));
    szTitle[0]=0;
    GetConsoleTitle(szTitle,sizeof(szTitle)/sizeof(TCHAR));
    si.cb=sizeof(si);
    GetStartupInfo(&si);
    _tprintf(_T("szModuleName:%s,szTitle:%s,%s\n"),szModuleName,szTitle,si.lpTitle);
    return 0;
}

int _test_readmem(int argc, _TCHAR* argv[])
{
    DWORD pid=_ttoi(argv[0]);
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE
        ,
        FALSE,
        pid
        );
    if(hProcess)
    {
        BOOL bRet;
        char buf[32];
        void* addr = GetProcAddress(GetModuleHandleA("ntdll"),"NtCreateFile");
        bRet = _read_memory_by_handle(hProcess,addr,buf,sizeof(buf));
        _tprintf(_T("pid:%d,addr:%p,bRet:%d,%x,%x\n"),pid,addr,bRet,(unsigned char)buf[0],(unsigned char)buf[1]);
        CloseHandle(hProcess);
    }
    return 0;
}


//
int g_i=0;
int g_seh_count=0;

void dump_exception_record(EXCEPTION_RECORD *exr)
{
    printf("ExceptionRecord.ExceptionCode:0x%x\n",exr->ExceptionCode);
    printf("ExceptionRecord.ExceptionFlags:0x%x\n",exr->ExceptionFlags);
    printf("ExceptionRecord.ExceptionRecord:0x%p\n",exr->ExceptionRecord);
    if(exr->ExceptionRecord)dump_exception_record(exr->ExceptionRecord);
    printf("ExceptionRecord.ExceptionAddress:0x%p\n",exr->ExceptionAddress);
    printf("ExceptionRecord.NumberParameters:%d\n",exr->NumberParameters);
}

void dump_exception(EXCEPTION_POINTERS* ep)
{
    printf("ep:0x%p\n",ep);
    dump_exception_record(ep->ExceptionRecord);
#ifdef _WIN64
    printf("ContextRecord.Rip:0x%llx\n",ep->ContextRecord->Rip);
#else
    printf("ContextRecord.Eip:0x%x\n",ep->ContextRecord->Eip);
#endif
}

int seh_filter(unsigned int code, EXCEPTION_POINTERS* ep)
{
    printf("code:0x%x\n",code);
    dump_exception(ep);

    return EXCEPTION_EXECUTE_HANDLER;
}

int _test_seh_basic(int argc, _TCHAR* argv[])
{
    TCHAR* _start = _T("");
    TCHAR* _exception = _T("");
    TCHAR* _end = _T("");
    if(argc>0) _start=argv[0];
    if(argc>1) _exception=argv[1];
    if(argc>2) g_seh_count=_ttoi(argv[2]);
    if(argc>3) _end=argv[3];
    
    if(0 == _tcscmp(_start,_T("msg")))
    {
        MessageBoxA(0,"handled\n",0,0);
    }
    else if(0 == _tcscmp(_start,_T("print")))
    {
        printf("handled\n");
    }
    else
    {
        
    }
    
    __try
    {
        if(0 == _tcscmp(_exception,_T("inv")))
        {
            void (*pfunc)() = (void (*)())(0x12345678);
            pfunc();
        }
        else if(0 == _tcscmp(_exception,_T("bp")))
        {
            DebugBreak();
        }
    }
    __except(seh_filter(GetExceptionCode(), GetExceptionInformation()))
    {
        printf("__except\n");
        while(g_i<g_seh_count)
        {
            HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if(INVALID_HANDLE_VALUE != hFile)
            {
                CloseHandle(hFile);
                printf("%d\r",g_i);
                g_i++;
            }
            Sleep(500);
        }
        printf("__except...done\n");
    }

    while(g_i<g_seh_count)
    {
        HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
            printf("%d\r",g_i);
            g_i++;
        }
        Sleep(500);
    }

    if(0 == _tcscmp(_end,_T("msg")))
    {
        MessageBoxA(0,"done.\n",0,0);
    }
    else if(0 == _tcscmp(_end,_T("print")))
    {
        printf("done.\n");
    }
    else
    {
        
    }
    
    return 0;
}


LONG WINAPI
VectoredHandler1(EXCEPTION_POINTERS* exp)
{
    printf("VectoredHandler1\n");
    dump_exception(exp);
    if (exp->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        printf("BreakPoint at 0x%p skipped.\n", exp->ExceptionRecord->ExceptionAddress);
        PCONTEXT Context = exp->ContextRecord;

        // The breakpoint instruction is 0xCC (int 3), just one byte in size.
        // Advance to the next instruction. Otherwise, this handler will just be called ad infinitum.
#ifdef _AMD64_
        Context->Rip++;
#else
        Context->Eip++;
#endif    
        // Continue execution from the instruction at Context->Rip/Eip.
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // IT's not a break intruction. Continue searching for an exception handler.
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI
VectoredHandler2(EXCEPTION_POINTERS* exp)
{
    printf("VectoredHandler2\n");
    dump_exception(exp);

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI
VectoredHandler0(EXCEPTION_POINTERS* exp)
{
    printf("VectoredHandler0\n");
    dump_exception(exp);
    while(g_i<g_seh_count)
    {
        HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
            printf("%d\r",g_i);
            g_i++;
        }
        Sleep(500);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int _test_seh_vector(int argc, _TCHAR* argv[])
{
    TCHAR* _start = _T("");
    TCHAR* _exception = _T("");
    TCHAR* _end = _T("");
    if(argc>0) _start=argv[0];
    if(argc>1) _exception=argv[1];
    if(argc>2) g_seh_count=_ttoi(argv[2]);
    if(argc>3) _end=argv[3];
    
    PVOID hVeh1 = AddVectoredExceptionHandler(TRUE, VectoredHandler1);
    PVOID hVeh2 = AddVectoredExceptionHandler(FALSE, VectoredHandler2);
    PVOID hVeh0 = AddVectoredExceptionHandler(TRUE, VectoredHandler0);
    
    if(0 == _tcscmp(_start,_T("msg")))
    {
        MessageBoxA(0,"handled\n",0,0);
    }
    else if(0 == _tcscmp(_start,_T("print")))
    {
        printf("handled\n");
    }
    else
    {
        
    }
    
    if(0 == _tcscmp(_exception,_T("inv")))
    {
        void (*pfunc)() = (void (*)())(0x12345678);
        pfunc();
    }
    else if(0 == _tcscmp(_exception,_T("bp")))
    {
        DebugBreak();
    }

    while(g_i<g_seh_count)
    {
        HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
            printf("%d\r",g_i);
            g_i++;
        }
        Sleep(500);
    }

    if(0 == _tcscmp(_end,_T("msg")))
    {
        MessageBoxA(0,"done.\n",0,0);
    }
    else if(0 == _tcscmp(_end,_T("print")))
    {
        printf("done.\n");
    }
    else
    {
        
    }
    
    if (hVeh1)
        RemoveVectoredExceptionHandler(hVeh1);
    if (hVeh2)
        RemoveVectoredExceptionHandler(hVeh2);
    if (hVeh0)
        RemoveVectoredExceptionHandler(hVeh0);
    
    return 0;
}

LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS* exp)
{
    printf("MyUnhandledExceptionFilter\n");
    dump_exception(exp);

    while(g_i<g_seh_count)
    {
        HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
            printf("%d\r",g_i);
            g_i++;
        }
        Sleep(500);
    }
    return EXCEPTION_EXECUTE_HANDLER; 
} 

int _test_seh_unhandler(int argc, _TCHAR* argv[])
{
    TCHAR* _start = _T("");
    TCHAR* _exception = _T("");
    TCHAR* _end = _T("");
    if(argc>0) _start=argv[0];
    if(argc>1) _exception=argv[1];
    if(argc>2) g_seh_count=_ttoi(argv[2]);
    if(argc>3) _end=argv[3];
    
    EXCEPTION_REGISTRATION_RECORD* pex_reg_r = 0;
    
    SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);

    if(0 == _tcscmp(_start,_T("msg")))
    {
        MessageBoxA(0,"handled\n",0,0);
    }
    else if(0 == _tcscmp(_start,_T("print")))
    {
        printf("handled\n");
    }
    else
    {
        
    }

    if(0 == _tcscmp(_exception,_T("inv")))
    {
        void (*pfunc)() = (void (*)())(0x12345678);
        pfunc();
    }
    else if(0 == _tcscmp(_exception,_T("bp")))
    {
        DebugBreak();
    }

    while(g_i<g_seh_count)
    {
        HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
            printf("%d\r",g_i);
            g_i++;
        }
        Sleep(500);
    }

    if(0 == _tcscmp(_end,_T("msg")))
    {
        MessageBoxA(0,"done.\n",0,0);
    }
    else if(0 == _tcscmp(_end,_T("print")))
    {
        printf("done.\n");
    }
    else
    {
        
    }
    
    return 0;
}

#pragma optimize( "g", off )
int _test_seh_cpp(int argc, _TCHAR* argv[])
{
    TCHAR* _start = _T("");
    TCHAR* _exception = _T("");
    TCHAR* _end = _T("");
    if(argc>0) _start=argv[0];
    if(argc>1) _exception=argv[1];
    if(argc>2) g_seh_count=_ttoi(argv[2]);
    if(argc>3) _end=argv[3];

    if(0 == _tcscmp(_start,_T("msg")))
    {
        MessageBoxA(0,"handled\n",0,0);
    }
    else if(0 == _tcscmp(_start,_T("print")))
    {
        printf("handled\n");
    }
    else
    {
        
    }


    try
    {
        if(0 == _tcscmp(_exception,_T("inv")))
        {
            void (*pfunc)() = (void (*)())(0x12345678);
            pfunc();
        }
        else if(0 == _tcscmp(_exception,_T("bp")))
        {
            DebugBreak();
        }
        else if(0 == _tcscmp(_exception,_T("sw")))
        {
            throw std::exception();
        }
        while(g_i<g_seh_count)
        {
            HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if(INVALID_HANDLE_VALUE != hFile)
            {
                CloseHandle(hFile);
                printf("%d\r",g_i);
                g_i++;
            }
            Sleep(500);
        }
    }
    //catch(std::exception& exc)
    //{
    //    std::cerr << exc.what();
    catch(...)
    {
        printf("catch\n");
        while(g_i<g_seh_count)
        {
            HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if(INVALID_HANDLE_VALUE != hFile)
            {
                CloseHandle(hFile);
                printf("%d\r",g_i);
                g_i++;
            }
            Sleep(500);
        }
        printf("catch...done\n");
    }

    
    while(g_i<g_seh_count)
    {
        HANDLE hFile = CreateFileA(".null.txt",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
            printf("%d\r",g_i);
            g_i++;
        }
        Sleep(500);
    }

    if(0 == _tcscmp(_end,_T("msg")))
    {
        MessageBoxA(0,"done.\n",0,0);
    }
    else if(0 == _tcscmp(_end,_T("print")))
    {
        printf("done.\n");
    }
    else
    {
        
    }
    
    return 0;
}
#pragma optimize( "g", on )

int unittest(int argc, _TCHAR* argv[])
{
    if(argc>=3)
    {
        printf("unittest...");
        if(0 == _tcscmp(argv[2],_T("ch2hex")))
        {
            printf("_test_ch2hex...\n");
            _test_ch2hex();
        }
        else if(0 == _tcscmp(argv[2],_T("struct")))
        {
            printf("_test_struct...\n");
            _test_struct();
        }
        else if(0 == _tcscmp(argv[2],_T("winapi")))
        {
            printf("_test_winapi...\n");
            _test_winapi();
        }
        else if(0 == _tcscmp(argv[2],_T("cpp")))
        {
            printf("_test_cpp...\n");
            _test_cpp();
        }
        else if(0 == _tcscmp(argv[2],_T("mem")))
        {
            printf("_test_mem...\n");
            _test_mem();
        }
        else if(0 == _tcscmp(argv[2],_T("rmem")))
        {
            printf("_test_readmem...\n");
            _test_readmem(argc-3,&argv[3]);
        }
        else if(0 == _tcscmp(argv[2],_T("sehb")))
        {
            printf("_test_seh_basic...\n");
            _test_seh_basic(argc-3,&argv[3]);
        }
        else if(0 == _tcscmp(argv[2],_T("sehv")))
        {
            printf("_test_seh_vector...\n");
            _test_seh_vector(argc-3,&argv[3]);
        }
        else if(0 == _tcscmp(argv[2],_T("sehu")))
        {
            printf("_test_seh_unhandler...\n");
            _test_seh_unhandler(argc-3,&argv[3]);
        }
        else if(0 == _tcscmp(argv[2],_T("sehc")))
        {
            //need /EHa but BP is not support
            printf("_test_seh_cpp...\n");
            _test_seh_cpp(argc-3,&argv[3]);
        }
        else
        {
            printf("_test_xxx...\n");
            _test_xxx();
        }
        printf("unittest...done\n");
    }
    return 0;
}