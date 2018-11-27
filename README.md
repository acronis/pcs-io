# PCS I/O (Parallel Cloud Storage library)

## Description
pcs_io is a C cross platform library implementing async event loop with coroutines, context and other features.

## Features

# Basic event loop APIs: timers, jobs, thread pool jobs etc.
# Usage of native OS asynchronous APIs support: epoll, Windows IOCP, SUN ports, BSD kqueue, RDMA
# Full memory usage accounting and wrapped malloc APIs
# coroutines support with:
** I/O blocking APIs for files, sockets, pipes, SSL sockets. 
** timeouts and I/O cancellation (via context)
** contexts support similar to Golang
** multi-threading support with Coroutines scheduler
** coroutines waitqueues, mutexes etc.
# simple config files API support
# built-in cross platform getopt_long support
# basic containers (RB tree, lists, heap)
# Network address abstraction layer
# internal scatter gather bufqueue and user pipes

## Built-in debug features and capabilities

* Async compressed on the fly logging with GZIP/ZSTD support
* Address and thread sanitizer support
* Built-in profiler and watchdog monitoring event loop is really non-blocking (and catching kernel issues, swap out etc.)
* Memory accounting with detailed per-line reporting
* BUG_ON() assertions and call trace dumps on errors / crashes
