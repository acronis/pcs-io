include Makefile.inc

SUBDIRS=libpcs_io
SUBDIRS_COV=libpcs_io
SUBDIRS_INSTALL=libpcs_io

all:
	@set -e; \
	for d in $(SUBDIRS); do $(MAKE) -C $$d all ; done

install_coverage: all
	install -d $(INSTALL_PREFIX)/$(PCS_GCOV_DIR)
	install -d $(INSTALL_PREFIX)/$(PCS_GCOV_DIR)/$(PCS_BUILD_VERSION)
	find . -name *.gcno | tar cfz ../coverage-$(PCS_BUILD_VERSION).tar.gz -T -
	install ../coverage-$(PCS_BUILD_VERSION).tar.gz $(INSTALL_PREFIX)/$(PCS_GCOV_DIR)
	rm -f ../coverage-$(PCS_BUILD_VERSION).tar.gz

install-deps:
	yum install -y gcc gcc-c++ fuse-devel openssl-devel avahi-devel zlib-devel ncurses-devel libaio-devel openssl-static asciidoc libxml2-devel json-c-devel json-c-devel avahi-devel libzstd-devel libunwind-devel libcap-devel libibverbs-devel

install:
	@set -e; \
	install -d $(INSTALL_PREFIX)/$(PCS_LIBEXEC_DIR)
	install -d $(INSTALL_PREFIX)/$(PCS_VAR_LIB_DIR)
	install -d $(INSTALL_PREFIX)/$(PCS_VAR_LOG_DIR)
	install -d $(INSTALL_PREFIX)/$(PCS_VAR_RUN_DIR)
	for d in $(SUBDIRS_INSTALL); do $(MAKE) -C $$d install ; done

depend dep:
	@set -e; \
	for d in $(SUBDIRS); do $(MAKE) -C $$d depend ; done

clean:
	@for d in $(SUBDIRS) man; do $(MAKE) -C $$d clean ; done

tags: FORCE
	ctags -R

cscope: FORCE
	find . -name '*.c' -print -o -name '*.h' -print | cscope -q -R -b -i -

FORCE:
