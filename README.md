# PCS I/O (Parallel Cloud Storage library)

## Description
pcs_io is a C cross platform library implementing async event loop with coroutines, context and other features.

## Features

1. Basic event loop APIs: timers, jobs, thread pool jobs etc.
1. Usage of native OS asynchronous APIs support: epoll, Windows IOCP, SUN ports, BSD kqueue, RDMA
1. Full memory usage accounting and wrapped malloc APIs
1. coroutines support with:
** I/O blocking APIs for files, sockets, pipes, SSL sockets. 
** timeouts and I/O cancellation (via context)
** contexts support similar to Golang
** multi-threading support with Coroutines scheduler
** coroutines waitqueues, mutexes etc.
1. simple config files API support
1. built-in cross platform getopt_long support
1. basic containers (RB tree, lists, heap)
1. Network address abstraction layer
1. internal scatter gather bufqueue and user pipes

## Built-in debug features and capabilities

* Async compressed on the fly logging with GZIP/ZSTD support
* Address and thread sanitizer support
* Built-in profiler and watchdog monitoring event loop is really non-blocking (and catching kernel issues, swap out etc.)
* Memory accounting with detailed per-line reporting
* BUG_ON() assertions and call trace dumps on errors / crashes
