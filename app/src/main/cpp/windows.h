#ifndef _ANDROID_WINDOWS_COMPAT_H
#define _ANDROID_WINDOWS_COMPAT_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

typedef unsigned int UINT;
typedef int BOOL;
typedef unsigned char BYTE;
typedef void* PVOID;
typedef void* HANDLE;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#endif
