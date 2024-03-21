# minidbg - The Windows API Monitoring Tool

## Design
The tool is leveraging [Windows Debug API](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/) to implement a debugger to install breakpoint on interesting APIs and get API events.
The basic flow is
```
//...
    {
        while(WaitForDebugEvent(&_event, INFINITE))
        {
            DWORD dwContinueStatus = DBG_CONTINUE;
            //...

            switch (_event.dwDebugEventCode)
            {
            case EXCEPTION_DEBUG_EVENT:
                //...
                dwContinueStatus = _handle_exception(...);
                //...
                break;
            //...
            default:
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                //...
                break;
            }
            //...
            ContinueDebugEvent(_event.dwProcessId, _event.dwThreadId, (DWORD)dwContinueStatus);
        };
        //
    }

    //...

```

## Configuration
The example for adding interesting Windows APIs.
```
;
api:ntdll.dll!NtCreateFile,p$$$x$$$o$$$x$$$x$$$x$$$x$$$x$$$x$$$x$$$x$$$,3
;
api:user32.dll!MessageBoxTimeoutW,x$$$w$$$w$$$x$$$x$$$x$$$,3
;
```

## How to Build
The build environment can be downloaded from [EWDK](https://learn.microsoft.com/en-us/legal/windows/hardware/enterprise-wdk-license-2022).
Assuming EWDK is mounted on "D:".
Open "cmd.exe" and call "SetupBuildEnv.cmd"
```
call D:\BuildEnv\SetupBuildEnv.cmd
```
Then you've set up the build environment then go to repository
```
msbuild /p:platform=x64 /p:configuration=release main/minidbg.vcxproj
msbuild /p:platform=x86 /p:configuration=release main/minidbg.vcxproj
```
The output file will be
```
output\minidbg.exe
```
