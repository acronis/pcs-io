CC ?= gcc
LD ?= ld
AR ?= ar

cc-option = $(shell $(CC) -Werror $(1:-Wno-%=-W%) -c -x c /dev/null -o /dev/null >/dev/null 2>&1 && echo "$(1)")

UNAME := $(shell uname)
MACHINE := $(shell uname -m)

libdir.x86_64 = /usr/lib64
libdir.i686   = /usr/lib


PCS_PRODUCT_NAME = $(if $(PRODUCT_NAME),$(PRODUCT_NAME),vstorage)
PCS_USER ?= vstorage
PCS_BIN_DIR ?= /usr/bin
PCS_CFG_DIR ?= /etc/$(PCS_PRODUCT_NAME)
PCS_LIB_DIR ?= $(libdir.$(MACHINE))
PCS_INCLUDE_DIR ?= /usr/include/pcs
PCS_LIBEXEC_DIR ?= /usr/libexec/$(PCS_PRODUCT_NAME)
PCS_SHARE_DIR ?= /usr/share/$(PCS_PRODUCT_NAME)
PCS_VAR_LIB_DIR ?= /var/lib/$(PCS_PRODUCT_NAME)
PCS_VAR_RUN_DIR ?= /var/run/$(PCS_PRODUCT_NAME)
PCS_VAR_LOG_DIR ?= /var/log/$(PCS_PRODUCT_NAME)
PCS_GCOV_DIR ?= /var/lib/$(PCS_PRODUCT_NAME)-gcov

#PCS_ENABLE_LICENSING ?= 1
PCS_ENABLE_DNS_RESOLVER ?= 1
#PCS_ENABLE_AVAHI_RESOLVER ?= 1
PCS_ENABLE_MDNS_RESOLVER ?= 1

CFLAGS_USER := $(CFLAGS)
BUILD_CFLAGS := -Wall -Wextra -Werror -Wstrict-prototypes -Wno-sign-compare -Wno-unused-parameter
BUILD_CFLAGS += $(call cc-option,-Wno-type-limits,)
BUILD_CFLAGS += $(call cc-option,-Wno-missing-field-initializers,)
BUILD_CFLAGS += $(call cc-option,-Wno-address-of-packed-member,)
BUILD_CFLAGS += $(call cc-option,-Wno-format-truncation,)
BUILD_CFLAGS += $(call cc-option,-Wno-packed-not-aligned,)
ifneq ($(UNAME),SunOS)
# Solaris requires ssp_noshared library to be provided by toolchain to link executable files compiled with stack protector
# TODO: For reliable detection need try to link executable compiled with given option
BUILD_CFLAGS += $(call cc-option,-fstack-protector-all,)
endif
BUILD_CFLAGS += -fno-strict-aliasing -fno-omit-frame-pointer $(TARGET_ARCH)
BUILD_CFLAGS += $(if $(PCS_TCMALLOC),-fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free,)
BUILD_CFLAGS += $(if $(DEBUG),-DDEBUG -O0 -g,-O2 -g)
BUILD_CFLAGS += -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
BUILD_CFLAGS += $(if $(PCS_ADDR_SANIT),-fsanitize=address -fno-omit-frame-pointer,)
BUILD_CFLAGS += $(if $(PCS_CODE_COVERAGE),-fprofile-arcs  -ftest-coverage,)
BUILD_CFLAGS += $(if $(PCS_PRODUCT_NAME),-D__PCS_PRODUCT_NAME=$(PCS_PRODUCT_NAME),)
BUILD_CFLAGS += $(if $(VENDOR_NAME),-D__PCS_VENDOR_NAME=$(VENDOR_NAME),)
BUILD_CFLAGS += $(if $(PRODUCT_NAME_LONG),-D__PCS_PRODUCT_NAME_LONG=$(PRODUCT_NAME_LONG),)
BUILD_CFLAGS += $(if $(PCS_USER),-D__PCS_USER=$(PCS_USER),-D__PCS_USER=$(PCS_PRODUCT_NAME))
BUILD_CFLAGS += $(if $(PCS_BUILD_VERSION),-D__PCS_BUILD_VERSION=$(PCS_BUILD_VERSION),)
BUILD_CFLAGS += $(if $(PCS_CFG_DIR),-D__PCS_CFG_DIR=$(PCS_CFG_DIR),)
BUILD_CFLAGS += $(if $(PCS_LIBEXEC_DIR),-D__PCS_LIBEXEC_DIR=$(PCS_LIBEXEC_DIR),)

BUILD_CFLAGS += $(if $(PCS_ENABLE_DNS_RESOLVER),-D_ENABLE_DNS_RESOLVER=1)
BUILD_CFLAGS += $(if $(PCS_ENABLE_AVAHI_RESOLVER),-D_ENABLE_AVAHI_RESOLVER=1)
BUILD_CFLAGS += $(if $(PCS_ENABLE_MDNS_RESOLVER),-D_ENABLE_MDNS_RESOLVER=1)

BUILD_CFLAGS += $(if $(USE_VALGRIND),-DUSE_VALGRIND=1)
BUILD_CFLAGS += $(if $(COROUTINE_ABORT_ON_MUTEX_TIMEOUT),-DCOROUTINE_ABORT_ON_MUTEX_TIMEOUT=1)

BUILD_CFLAGS += $(if $(PCS_ENABLE_RDMA), -DPCS_ENABLE_RDMA,)

BUILD_CFLAGS += $(CFLAGS_USER)

LDFLAGS += -g -rdynamic $(TARGET_ARCH)
LDFLAGS += $(if $(PCS_CODE_COVERAGE),-fprofile-arcs,)
LDFLAGS += $(if $(PCS_ADDR_SANIT),-fsanitize=address,)
ifeq ($(UNAME),Darwin)
	LDENV="DYLD_LIBRARY_PATH"
	LDFLAGS += -Wl,-dead_strip_dylibs -undefined error
	SONAME_FLAG = -install_name
	BUILD_CFLAGS += -Wno-deprecated-declarations $(shell pkg-config --cflags openssl)
	LDFLAGS += $(shell pkg-config --libs-only-L openssl)
else ifeq ($(UNAME),SunOS)
	LDENV="LD_LIBRARY_PATH"
	BUILD_CFLAGS += -D_POSIX_PTHREAD_SEMANTICS -D_XOPEN_SOURCE=600L -D_POSIX_C_SOURCE=200112L -D__EXTENSIONS__
	LDLIBS += -lsocket
else
	LDENV="LD_LIBRARY_PATH"
	LDFLAGS += -Wl,--as-needed -Wl,--no-undefined -Wl,--allow-shlib-undefined
endif

CFLAGS += $(BUILD_CFLAGS)

SONAME_FLAG ?= -soname
LDLIBS += -lpthread -ldl

VZKERNEL_VERSION ?=$(shell uname -r)
VZKERNEL_HEADERS ?= /lib/modules/$(VZKERNEL_VERSION)/build/include
SONAME_MJ_VER ?= 1
SONAME_MN_VER ?= 0.0
SONAME_FLAGS=-Wl,$(SONAME_FLAG),$@.$(SONAME_MJ_VER)
LIB_VER=$(SONAME_MJ_VER).$(SONAME_MN_VER)

# Avoid double rebuild of tools and tests
%: %.c
.PRECIOUS: %.o
