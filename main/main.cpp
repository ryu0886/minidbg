#include "stdafx.h"
#include "minidbg.h"
#include <windows.h>
#include <shlwapi.h>
#include "resource.h"

#pragma comment(lib, "shlwapi")

pminidbg_context ctx;

int init(int argc, _TCHAR* argv[])
{
    minidbg_init(&ctx);
    if(argc==1)
    {
        minidbg_parse_str(ctx);
    }
    else if(argc > 2)
    {
#ifdef _UNICODE
        minidbg_parse_w(ctx,argv[1],argv[2]);
#else
        minidbg_parse(ctx,argv[1],argv[2]);
#endif
    }
    else
    {
        minidbg_parse_w(ctx,L"minidbg.cfg.txt",L"hooklist.txt");
    }

    return 0;
}

int deinit()
{
    minidbg_deinit(&ctx);
    return 0;
}

int run()
{
    minidbg_set(ctx);
    minidbg_run(ctx);
    minidbg_unset(ctx);
    return 0;
}

void drop_file(TCHAR* path)
{
    HRSRC hrsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_APP64),_T("BINARY"));
    if(hrsrc)
    {
        HGLOBAL hLoaded = LoadResource( NULL,hrsrc);
        LPVOID lpLock =  LockResource( hLoaded);
        DWORD dwSize = SizeofResource(NULL, hrsrc);
        HANDLE hFile = CreateFile(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        DWORD dwByteWritten;
        WriteFile(hFile, lpLock , dwSize , &dwByteWritten , NULL);
        CloseHandle(hFile);
        FreeResource(hLoaded);
    }
}

void _launch(TCHAR* path, TCHAR* cmd)
{
    BOOL bRet;
    HANDLE hCurrentProcess = 0;
    TCHAR szTitle[64];
    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;
    memset(&si,0,sizeof(si));
    ((STARTUPINFO*)&si)->cb = sizeof(si);
    
    DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&hCurrentProcess,SYNCHRONIZE,TRUE,0);
    _sntprintf_s(szTitle,_TRUNCATE,_T("%p"),hCurrentProcess);
    ((STARTUPINFO*)&si)->lpTitle = (LPTSTR)szTitle;
    
    bRet = CreateProcess(
        path,
        cmd,
        NULL,
        NULL,
        TRUE,
        NORMAL_PRIORITY_CLASS|CREATE_DEFAULT_ERROR_MODE,
        NULL,
        NULL,
        (STARTUPINFO*)&si,
        &pi
        );

    if(bRet)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if(hCurrentProcess) CloseHandle(hCurrentProcess);
    }

}

#define BASENAME64 _T("64.exe")
void launch_64(int argc, _TCHAR* argv[])
{
    TCHAR szName[MAX_PATH];
    DWORD ret = GetModuleFileName(NULL,szName,_countof(szName));
    if(ret)
    {
        DWORD i=ret;
        while(i>0)
        {
            if(szName[i] == '.')
            {
                szName[i]=0;
                break;
            }
            i--;
        }
        _tcsncat_s(szName,BASENAME64,_TRUNCATE);
        if(!PathFileExists(szName))
        {
            drop_file(szName);
        }

        TCHAR szCmd[MAX_PATH];
        _tcsncpy_s(szCmd,szName,_TRUNCATE);
        for(int i=1;i<argc;i++)
        {
            _tcsncat_s(szCmd,L" ",_TRUNCATE);
            _tcsncat_s(szCmd,argv[i],_TRUNCATE);
        }
        _launch(szName,szCmd);
    }

}

int unittest(int argc, _TCHAR* argv[]);

#define FLAG_NO_WOW64_CHECK (0x00000001)

int _tmain(int argc, _TCHAR* argv[])
{
    int flag = 0;
    
    if(argc >= 2 && 0 == _tcscmp(argv[1],_T("unittest")))
    {
        unittest(argc,argv);
        return 0;
    }
    
    if(argc > 3)
    {
        flag = _ttoi(argv[3]);
    }
    
#ifdef _WIN64
    init(argc,argv);
#else
    init(argc,argv);
    
    if(flag & FLAG_NO_WOW64_CHECK)
    {
        
    }
    else
    {
        BOOL bWow64 = FALSE;
        if(IsWow64Process(GetCurrentProcess(),&bWow64) && bWow64)
        {
            //wow64
            launch_64(argc,argv);
            goto Exit;
        }
        else
        {

        }
    }
#endif
    run();
    goto Exit;
Exit:
    deinit();
    return 0;
}