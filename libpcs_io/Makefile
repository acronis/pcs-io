include ../Makefile.inc

LIBPCS_IO=libpcs_io.so
LIBOBJS=pcs_sock.o pcs_sock_conn.o pcs_sock_io.o pcs_sock_listen.o pcs_net_addr.o pcs_net_utils.o \
	pcs_sock_ssl.o pcs_sock_ssl_st.o pcs_sock_ssl_mt.o \
	pcs_process.o pcs_epoll.o pcs_kqueue.o pcs_sun_port.o pcs_event_ioconn.o pcs_ioconn.o \
	pcs_compat.o pcs_aio.o pcs_sync_io.o pcs_sync_ioreq.o pcs_file_job.o \
	rbtree.o minheap.o timer.o log.o bug.o md5.o crc32.o crc32_sse.o crc32_arm_wrapper.o crc64.o adler32.o \
	pcs_profiler.o pcs_watchdog.o logrotate.o pool_allocator.o pcs_config_file.o user.o \
	pcs_signal.o pcs_random.o getopt_long.o \
	pcs_malloc.o pcs_thread.o pcs_coroutine.o pcs_co_locks.o pcs_co_io.o \
	lz4.o lz4_estimate.o parse_diskspace.o \
	qselect.o regdump.o syslog.o pcs_shaper.o bufqueue.o pcs_upipe.o pcs_dir.o \
	pcs_splice.o pcs_error.o ssl_helpers.o pcs_cpuid.o std_list.o pcs_context.o pcs_mr_malloc.o \
	pcs_ucontext.o
LIBOBJS += $(if $(PCS_ENABLE_RDMA), pcs_rdma_conn.o pcs_rdma_listen.o pcs_rdma_io.o)
LIBOBJS_ASM=crc32_neon.o

COREHDRS=$(shell ls *.h | grep -v license)

CFLAGS += -fPIC -I.
CFLAGS += $(if $(PCS_ENABLE_ZSTD), -D_ENABLE_ZSTD_COMPRESSION,)
CFLAGS += $(if $(PCS_ENABLE_INTEL_ISAL), -DPCS_ENABLE_INTEL_ISAL,)
CFLAGS += $(if $(findstring Linux,$(UNAME)), -DHAVE_LIBUNWIND -DHAVE_LINUX_CAPS)

lz4.o: CFLAGS += -O3
lz4_estimate.o: CFLAGS += -O3
crc32_sse.o: CFLAGS += -O3
LDFLAGS += -fPIC
LDLIBS += -lssl -lcrypto
LDLIBS += $(if $(PCS_ENABLE_ZSTD), -lzstd,)
LDLIBS += $(if $(PCS_ENABLE_INTEL_ISAL), -lisal,)
LDLIBS += $(if $(PCS_ENABLE_RDMA), -lrdmacm -libverbs,)
LDLIBS += $(if $(findstring Linux,$(UNAME)), -lunwind)

ifdef PCS_TCMALLOC
	LIBTCMALLOC += -Wl,-Bstatic -Wl,-whole-archive -ltcmalloc_minimal -Wl,-no-whole-archive -Wl,-Bdynamic -lstdc++
endif
LIBAIO=$(if $(findstring Linux,$(UNAME)),-laio)
LIBRT=$(if $(findstring Linux,$(UNAME)),-lrt)

all: $(LIBPCS_IO)

$(LIBPCS_IO): $(LIBOBJS) $(LIBOBJS_ASM)
	$(CC) $(LDFLAGS) -shared $(SONAME_FLAGS) -o $@.$(LIB_VER) $^ $(LIBTCMALLOC) $(LIBAIO) $(LIBRT)  $(LDLIBS) -lz
	ln -sf $@.$(LIB_VER) $@.$(SONAME_MJ_VER)
	ln -sf $@.$(LIB_VER) $@

depend dep:
	$(CC) $(CFLAGS) -M $(LIBOBJS:.o=.c) > .depend
	$(CC) $(CFLAGS) -M $(LIBOBJS_ASM:.o=.S) >> .depend

PKG_CFG_CFLAGS += $(if $(PCS_ADDR_SANIT),-fsanitize=address -fno-omit-frame-pointer,)
PKG_CFG_LDFLAGS += $(if $(PCS_ADDR_SANIT),-lasan,)

libpcs_io-$(SONAME_MJ_VER).pc:
	sed "s/__VERSION/$(PCS_BUILD_VERSION)/;s/_PKG_CFG_CFLAGS/$(PKG_CFG_CFLAGS)/;s/_PKG_CFG_LDFLAGS/$(PKG_CFG_LDFLAGS)/" libpcs_io.pc > $@
	cat $@

clean:
	rm -rf *.so.*
	rm -f *.o *.a *.so *.8 .depend
	rm -f *.gcda *.gcno
	rm -f libpcs_io-$(SONAME_MJ_VER).pc

install-core-headers:
	install -d $(INSTALL_PREFIX)/usr/include/pcs-core
	for hdr in $(COREHDRS); do install -m 644 $$hdr $(INSTALL_PREFIX)/usr/include/pcs-core; done

install-devel-libs: libpcs_io-$(SONAME_MJ_VER).pc
	install -d $(INSTALL_PREFIX)/$(PCS_LIB_DIR)
	install -d $(INSTALL_PREFIX)/$(PCS_LIB_DIR)/pkgconfig
	install -m 644 libpcs_io-$(SONAME_MJ_VER).pc $(INSTALL_PREFIX)/$(PCS_LIB_DIR)/pkgconfig

install: $(LIBPCS_IO) install-core-headers install-devel-libs
	install -d $(INSTALL_PREFIX)/$(PCS_INCLUDE_DIR)
	install -m 644 std_list.h log.h pcs_types.h rbtree.h bug.h pcs_compat.h pcs_config.h pcs_align.h \
		timer.h pcs_error.h $(INSTALL_PREFIX)/$(PCS_INCLUDE_DIR)
	install $(LIBPCS_IO).$(LIB_VER) $(INSTALL_PREFIX)/$(PCS_LIB_DIR)
	ln -sf $(LIBPCS_IO).$(LIB_VER) $(INSTALL_PREFIX)/$(PCS_LIB_DIR)/$(LIBPCS_IO)
	ln -sf $(LIBPCS_IO).$(LIB_VER) $(INSTALL_PREFIX)/$(PCS_LIB_DIR)/$(LIBPCS_IO).$(SONAME_MJ_VER)

ifeq (.depend,$(wildcard .depend))
include .depend
else
all: depend
endif
