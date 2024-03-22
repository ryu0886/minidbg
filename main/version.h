#ifndef _MY_VERSION_H
#define _MY_VERSION_H

#define _STR_(x) #x
#define STR(x) _STR_(x)

#define VERSION_MAJOR     0
#define VERSION_MINOR     9
#define VERSION_REVISION  3
#define VERSION_BUILD     13221
#define V_VERSION   STR(VERSION_MAJOR) "." STR(VERSION_MINOR) "." STR(VERSION_REVISION) "." STR(VERSION_BUILD)
#define V_PRODUCT   "Cloud Scanner"
#define V_APPNAME   "winapp"
#define V_COMPANY   "WTH"
#define V_LEGAL     "Copyright (C) 2024"

#endif
