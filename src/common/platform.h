#pragma once

#include "platform-config.h"

/* Convenience macros for platform checks */

#ifndef INITD_PLATFORM_LINUX
#define INITD_PLATFORM_LINUX 0
#endif

#ifndef INITD_PLATFORM_BSD
#define INITD_PLATFORM_BSD 0
#endif

#ifndef INITD_PLATFORM_DARWIN
#define INITD_PLATFORM_DARWIN 0
#endif

#ifndef INITD_PLATFORM_HURD
#define INITD_PLATFORM_HURD 0
#endif

#ifndef INITD_HAVE_EPOLL
#define INITD_HAVE_EPOLL 0
#endif

#ifndef INITD_HAVE_KQUEUE
#define INITD_HAVE_KQUEUE 0
#endif

#ifndef INITD_HAVE_PIDFILE
#define INITD_HAVE_PIDFILE 0
#endif

