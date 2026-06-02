# PREFIX should be only writable by the root to avoid privilege escalation with launchd or sudo
PREFIX ?= /opt/socket_vmnet

# DEBUG=1 is known to break reproducible builds
DEBUG ?=

export SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
SOURCE_DATE_EPOCH_ISO8601 := $(shell date -u -Iseconds -r $(SOURCE_DATE_EPOCH) | sed -e s/+00:00/Z/)

TAR ?= tar --uid=0 --gid=0 --numeric-owner
TOUCH ?= touch -d $(SOURCE_DATE_EPOCH_ISO8601)
# Not necessary to use GNU's gzip
GZIP ?= gzip -9 -n
DIFFOSCOPE ?= diffoscope
STRIP ?= strip

CFLAGS ?= -O3 -Wall -Wextra -pedantic
ifeq ($(DEBUG),1)
	CFLAGS += -g
endif

VERSION ?= $(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_TRIMMED := $(VERSION:v%=%)

CFLAGS += -DVERSION=\"$(VERSION)\"

# libfw/c-fw provides the ACL + conntrack + HCL front-end (it vendors libhcl/c-hcl).
CFW := third_party/c-fw
CHCL := $(CFW)/third_party/c-hcl
CFLAGS += -I$(CFW) -I$(CHCL)
CFW_OBJS := $(CFW)/acl.o $(CFW)/json.o $(CFW)/conntrack.o $(CFW)/acl_hcl.o $(CHCL)/hcl.o

LDFLAGS ?=
VMNET_LDFLAGS = -framework vmnet

# ARCH support arm64 and x86_64
ARCH ?=

ifneq (,$(findstring arm64,$(ARCH)))
	HOST ?= --host arm-apple-darwin
	CFLAGS += -arch arm64
else ifneq (,$(findstring x86_64,$(ARCH)))
	HOST ?= --host x86_64-apple-darwin
	CFLAGS += -arch x86_64
endif

# Interface name for bridged mode. Empty value (default) disables bridged mode.
BRIDGED ?=

all: socket_vmnet socket_vmnet_client

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

socket_vmnet: $(patsubst %.c, %.o, $(wildcard *.c)) $(CFW_OBJS)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $(VMNET_LDFLAGS) $^

socket_vmnet_client: $(patsubst %.c, %.o, $(wildcard client/*.c))
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^

install.bin: socket_vmnet socket_vmnet_client
	logger "Installing executables for socket_vmnet $(VERSION) in $(DESTDIR)/$(PREFIX)/bin"
	mkdir -p "$(DESTDIR)/$(PREFIX)/bin"
	cp -a socket_vmnet "$(DESTDIR)/$(PREFIX)/bin/socket_vmnet"
	cp -a socket_vmnet_client "$(DESTDIR)/$(PREFIX)/bin/socket_vmnet_client"
	$(STRIP) "$(DESTDIR)/$(PREFIX)/bin/socket_vmnet"
	$(STRIP) "$(DESTDIR)/$(PREFIX)/bin/socket_vmnet_client"

install.doc: README.md LICENSE launchd etc_sudoers.d
	logger "Installing documentation for socket_vmnet $(VERSION) in $(DESTDIR)/$(PREFIX)/share/doc"
	mkdir -p "$(DESTDIR)/$(PREFIX)/share/doc/socket_vmnet"
	cp -a $? "$(DESTDIR)/$(PREFIX)/share/doc/socket_vmnet"

install.launchd.plist: launchd/*.plist
	sed -e "s@/opt/socket_vmnet@$(PREFIX)@g" launchd/io.github.lima-vm.socket_vmnet.plist > "$(DESTDIR)/Library/LaunchDaemons/io.github.lima-vm.socket_vmnet.plist"

ifneq ($(BRIDGED),)
	sed -e "s@/opt/socket_vmnet@$(PREFIX)@g" -e "s/en0/$(BRIDGED)/g" launchd/io.github.lima-vm.socket_vmnet.bridged.en0.plist > "$(DESTDIR)/Library/LaunchDaemons/io.github.lima-vm.socket_vmnet.bridged.$(BRIDGED).plist"
endif

define load_launchd
	# Hint: try `launchctl enable system/$(1)` if the `launchctl bootstrap` command below fails
	logger "Installing launchd service for socket_vmnet $(VERSION) in $(DESTDIR)/Library/LaunchDaemons/$(1).plist"
	launchctl bootstrap system "$(DESTDIR)/Library/LaunchDaemons/$(1).plist"
	launchctl enable system/$(1)
	launchctl kickstart -kp system/$(1)
endef

install.launchd: install.launchd.plist
	$(call load_launchd,io.github.lima-vm.socket_vmnet)
ifneq ($(BRIDGED),)
	$(call load_launchd,io.github.lima-vm.socket_vmnet.bridged.$(BRIDGED))
endif

install: install.bin install.doc install.launchd

.PHONY: uninstall.bin
uninstall.bin:
	logger "Uninstalling executables for socket_vmnet"
	rm -f "$(DESTDIR)/$(PREFIX)/bin/socket_vmnet"
	rm -f "$(DESTDIR)/$(PREFIX)/bin/socket_vmnet_client"

.PHONY: uninstall.doc
uninstall.doc:
	rm -rf "$(DESTDIR)/$(PREFIX)/share/doc/socket_vmnet"

define unload_launchd
	logger "Uninstalling launchd service for socket_vmnet"
	launchctl bootout system "$(DESTDIR)/Library/LaunchDaemons/$(1).plist" || true
endef

.PHONY: uninstall.launchd
uninstall.launchd:
	$(call unload_launchd,io.github.lima-vm.socket_vmnet)
ifneq ($(BRIDGED),)
	$(call unload_launchd,io.github.lima-vm.socket_vmnet.bridged.$(BRIDGED))
endif

uninstall.launchd.plist: uninstall.launchd
	rm -f "$(DESTDIR)/Library/LaunchDaemons/io.github.lima-vm.socket_vmnet.plist"
ifneq ($(BRIDGED),)
	rm -f "$(DESTDIR)/Library/LaunchDaemons/io.github.lima-vm.socket_vmnet.bridged.$(BRIDGED).plist"
endif

.PHONY: uninstall.run
uninstall.run:
	rm -f /var/run/socket_vmnet*

uninstall: uninstall.launchd.plist uninstall.doc uninstall.bin uninstall.run

.PHONY: clean
clean:
	rm -f socket_vmnet socket_vmnet_client *.o client/*.o
	rm -f $(CFW_OBJS)
	rm -f test/*_test *.profraw *.profdata

# Unit tests for the dependency-free, vmnet-independent modules (run anywhere,
# no root, no code signing). The vmnet datapath itself is validated separately
# on real hardware (see DESIGN.md).
# AddressSanitizer is opt-in (SANITIZE=address) because its runtime dylib is not
# resolvable under every clang (e.g. a pkgx-provided toolchain). The default
# build is portable; enable it on a system clang with `make test SANITIZE=address`.
SANITIZE ?=
TEST_CFLAGS := -I. -O0 -g -Wall -Wextra -DACL_FAULT_INJECT -DCT_FAULT_INJECT
ifneq ($(strip $(SANITIZE)),)
TEST_CFLAGS += -fsanitize=$(SANITIZE)
endif

# socket_vmnet's own vmnet-independent units. The ACL / conntrack / HCL engines
# now live in libfw/c-fw and are tested in that repo.
.PHONY: test
test: test.acl
	$(CC) $(TEST_CFLAGS) -DVERSION='"test"' -DCLI_FAULT_INJECT cli.c test/cli_test.c -o test/cli_test
	./test/cli_test
	$(CC) $(TEST_CFLAGS) forward.c test/forward_test.c -o test/forward_test
	./test/forward_test

# Offline integration smoke for the ACL front-end: builds the daemon and checks
# that good .hcl/.json rulesets load (and reach vmnet) while a malformed one
# fails closed. Needs the vmnet framework to link, but no root. The full
# datapath test (frames through a VM) needs root + Lima -- see
# ACL.md ("Testing the ACL integration").
.PHONY: test.acl
test.acl: socket_vmnet
	sh test/acl_smoke.sh

# Coverage report for the unit-tested modules via llvm-cov.
COVER_CFLAGS = $(TEST_CFLAGS) -fprofile-instr-generate -fcoverage-mapping
.PHONY: cover
cover:
	rm -f *.profraw *.profdata
	$(CC) $(COVER_CFLAGS) -DVERSION='"test"' -DCLI_FAULT_INJECT cli.c test/cli_test.c -o test/cli_test
	LLVM_PROFILE_FILE=cli.profraw ./test/cli_test >/dev/null
	$(CC) $(COVER_CFLAGS) forward.c test/forward_test.c -o test/forward_test
	LLVM_PROFILE_FILE=forward.profraw ./test/forward_test >/dev/null
	xcrun llvm-profdata merge -sparse cli.profraw -o cli.profdata
	xcrun llvm-cov report ./test/cli_test -instr-profile=cli.profdata cli.c
	xcrun llvm-profdata merge -sparse forward.profraw -o forward.profdata
	xcrun llvm-cov report ./test/forward_test -instr-profile=forward.profdata forward.c

define make_artifacts
	$(MAKE) clean
	rm -rf _artifacts/$(1)
	$(MAKE) ARCH=$(1) DESTDIR=_artifacts/$(1) install.bin install.doc
	file -bp _artifacts/$(1)/$(PREFIX)/bin/socket_vmnet | grep -q "Mach-O 64-bit executable $(1)"
	# BSD tar does not have `--mtime=TIMESTAMP` option
	find _artifacts/$(1) -exec $(TOUCH) {} \;
	# BSD tar does not have `--sort=name` option
	(cd _artifacts/$(1) && find -s . -print0 | $(TAR) -cf ../socket_vmnet-$(VERSION_TRIMMED)-$(1).tar --null -n --files-from /dev/stdin)
	$(GZIP) _artifacts/socket_vmnet-$(VERSION_TRIMMED)-$(1).tar
	rm -rf _artifacts/$(1)
	$(MAKE) clean
endef

.PHONY: artifacts
artifacts:
	rm -rf _artifacts
	$(call make_artifacts,x86_64)
	$(call make_artifacts,arm64)
	sw_vers | tee _artifacts/build-env.txt
	echo --- >> _artifacts/build-env.txt
	pkgutil --pkg-info=com.apple.pkg.CLTools_Executables | tee -a _artifacts/build-env.txt
	echo --- >> _artifacts/build-env.txt
	$(CC) --version | tee -a _artifacts/build-env.txt
	(cd _artifacts ; shasum -a 256 *) > SHA256SUMS
	mv SHA256SUMS _artifacts/SHA256SUMS
	$(TOUCH) _artifacts/* _artifacts

.PHONY: test.repro
test.repro:
	rm -rf _artifacts.0 _artifacts.1
	$(MAKE) artifacts
	mv _artifacts _artifacts.0
	$(MAKE) artifacts
	mv _artifacts _artifacts.1
	$(DIFFOSCOPE) _artifacts.0/ _artifacts.1/
